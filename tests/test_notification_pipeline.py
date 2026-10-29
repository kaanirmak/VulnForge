import time
import pytest
import httpx
from vulnforge.notifications import (
    scrub_sensitive_notification_content,
    is_critical_escalation,
    NotificationAggregator,
    NotificationDeduplicator,
    NotificationDispatcher,
    format_slack_notification,
    format_teams_notification,
    format_email_notification
)


def test_scrub_sensitive_notification_content():
    # 1. Bearer token
    assert "Bearer [REDACTED_TOKEN]" in scrub_sensitive_notification_content("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz")

    # 2. AWS Key
    assert "[REDACTED_AWS_KEY]" in scrub_sensitive_notification_content("Found AWS key: AKIAIOSFODNN7EXAMPLE in config")

    # 3. GitHub PAT
    assert "[REDACTED_GITHUB_TOKEN]" in scrub_sensitive_notification_content("Export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz")

    # 4. Private key block
    key_block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAz7...lots of key bytes...\n-----END RSA PRIVATE KEY-----"
    scrubbed_key = scrub_sensitive_notification_content(key_block)
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed_key
    assert "MIIEowIBAAKCAQ" not in scrubbed_key

    # 5. URL query params and basic auth
    url_text = "Check endpoint https://api.internal/webhook?token=mysecretpassword123&env=prod"
    scrubbed_url = scrub_sensitive_notification_content(url_text)
    assert "token=[REDACTED]" in scrubbed_url
    assert "mysecretpassword123" not in scrubbed_url

    # 6. Deep nested structures (dict and list)
    payload = {
        'repo': 'org/repo',
        'details': {
            'snippet': 'aws_secret_key = "secret_value_123456"',
            'headers': ['Authorization: Bearer supersecrettoken'],
            'url': 'https://admin:pass1234@cluster.local/api'
        }
    }
    scrubbed_payload = scrub_sensitive_notification_content(payload)
    assert "supersecrettoken" not in str(scrubbed_payload)
    assert "pass1234" not in str(scrubbed_payload)
    assert "[REDACTED_TOKEN]" in scrubbed_payload['details']['headers'][0]


def test_is_critical_escalation():
    # Regular low/medium finding
    assert not is_critical_escalation('scan_completed', {'severity': 'medium', 'priority': 'P2'})
    assert not is_critical_escalation('scan_completed', {'severity': 'low', 'epss': 0.15})

    # Critical severity
    assert is_critical_escalation('scan_completed', {'severity': 'critical'})
    assert is_critical_escalation('critical_finding', {'severity': 'high'})

    # P0 priority
    assert is_critical_escalation('scan_completed', {'priority': 'P0'})

    # CISA KEV active exploitation
    assert is_critical_escalation('scan_completed', {'severity': 'medium', 'cisa_kev': True})
    assert is_critical_escalation('scan_completed', {'severity': 'high', 'is_kev': True})

    # High EPSS probability
    assert is_critical_escalation('scan_completed', {'severity': 'medium', 'epss': 0.85})

    # Explicit escalation flag
    assert is_critical_escalation('remediation_ready', {'escalate': True})


def test_notification_deduplicator():
    dedup = NotificationDeduplicator(cooldown_seconds=300.0)
    channel_id = 'chan-123'
    repo = 'my-org/my-service'
    event_type = 'scan_completed'
    details = {'finding_id': 'f-999', 'severity': 'medium'}

    t0 = 1000.0
    # 1. First emission: allowed
    send, reason, fp1 = dedup.evaluate(channel_id, repo, event_type, details, now=t0)
    assert send is True
    assert reason == 'allowed'

    # 2. Immediate duplicate: suppressed
    send, reason, fp2 = dedup.evaluate(channel_id, repo, event_type, details, now=t0 + 60.0)
    assert send is False
    assert reason == 'suppressed_duplicate'
    assert fp1 == fp2

    # 3. Different channel or different repo: allowed
    send, reason, _ = dedup.evaluate('chan-456', repo, event_type, details, now=t0 + 60.0)
    assert send is True
    assert reason == 'allowed'

    # 4. Same channel and repo but after cooldown: allowed
    send, reason, _ = dedup.evaluate(channel_id, repo, event_type, details, now=t0 + 301.0)
    assert send is True
    assert reason == 'allowed'


def test_notification_deduplicator_critical_escalation_bypass():
    dedup = NotificationDeduplicator(cooldown_seconds=3600.0)
    channel_id = 'chan-123'
    repo = 'my-org/my-service'
    event_type = 'scan_completed'

    # Send medium finding at t0
    t0 = 2000.0
    send, reason, _ = dedup.evaluate(channel_id, repo, event_type, {'finding_id': 'f-1', 'severity': 'medium'}, now=t0)
    assert send is True

    # Same finding is later flagged as critical CISA KEV (escalation)
    send, reason, _ = dedup.evaluate(
        channel_id, repo, event_type,
        {'finding_id': 'f-1', 'severity': 'critical', 'cisa_kev': True},
        now=t0 + 120.0
    )
    # Must bypass the 1 hour cooldown!
    assert send is True
    assert reason == 'critical_escalation_bypass'

    # Flood guard: within 60s, same critical is rate limited
    send, reason, _ = dedup.evaluate(
        channel_id, repo, event_type,
        {'finding_id': 'f-1', 'severity': 'critical', 'cisa_kev': True},
        now=t0 + 130.0
    )
    assert send is False
    assert reason == 'critical_rate_limited'


def test_notification_aggregator():
    findings = [
        {'id': 'f1', 'package': 'requests', 'severity': 'medium', 'summary': 'Certificate validation bypass'},
        {'id': 'f2', 'package': 'log4j-core', 'severity': 'critical', 'cisa_kev': True, 'summary': 'Remote Code Execution'},
        {'id': 'f3', 'package': 'urllib3', 'severity': 'low', 'summary': 'Header CRLF injection'},
        {'id': 'f4', 'package': 'flask', 'severity': 'high', 'summary': 'Session cookie disclosure'},
        {'id': 'f5', 'package': 'django', 'severity': 'high', 'summary': 'SQL Injection'},
        {'id': 'f6', 'package': 'pillow', 'severity': 'critical', 'summary': 'Buffer overflow in TIFF parser'},
    ]

    digest = NotificationAggregator.aggregate_findings('org/web-service', findings, scan_id='scan-xyz')
    assert digest['event_type'] == 'scan_completed'
    assert 'Scan digest for org/web-service: 6 findings (2 critical, 2 high)' in digest['title']
    assert digest['title'].startswith('🚨')

    details = digest['details']
    assert details['total_findings'] == 6
    assert details['severity_breakdown']['critical'] == 2
    assert details['severity_breakdown']['high'] == 2
    assert details['severity_breakdown']['medium'] == 1
    assert details['severity_breakdown']['low'] == 1
    assert details['cisa_kev_count'] == 1
    assert details['has_critical'] is True

    # CISA KEV must be first in top_findings
    top_findings = details['top_findings']
    assert len(top_findings) <= 5
    assert top_findings[0]['package'] == 'log4j-core'
    assert top_findings[0]['cisa_kev'] is True


@pytest.mark.anyio
async def test_notification_dispatcher_full_pipeline():
    sent_requests = []

    def mock_handler(request: httpx.Request):
        sent_requests.append(request)
        return httpx.Response(200, json={'ok': True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    dispatcher = NotificationDispatcher(http_client=client)

    channel = {
        'id': 'chan-slack',
        'kind': 'slack',
        'target': 'https://hooks.slack.com/services/T00/B00/XXXX',
        'events': ['scan_completed']
    }

    # 1. Dispatch with secret token in details and critical severity
    details = {
        'repo': 'my-org/auth-service',
        'finding_id': 'f-999',
        'severity': 'critical',
        'message': 'Leaked secret detected: ghp_11223344556677889900aabbccddeeff1122 with Bearer eyJhbGciOiJIUzI1NiJ9.token',
        'url': 'https://app.vulnforge.com/findings/f-999?token=secret123'
    }

    res = await dispatcher.dispatch(channel, 'critical_finding', 'RCE Vulnerability in Auth', details)
    assert res['delivered'] is True
    assert res['escalated'] is True
    assert len(sent_requests) == 1

    payload = res['payload']
    assert '[CRITICAL ESCALATION]' in payload['blocks'][0]['text']['text']
    assert 'ghp_112233' not in str(payload)
    assert '[REDACTED_GITHUB_TOKEN]' in str(payload)
    assert '[REDACTED_TOKEN]' in str(payload)
    assert 'secret123' not in str(payload)

    # 2. Dispatch duplicate non-critical within cooldown -> suppressed
    normal_channel = {
        'id': 'chan-email',
        'kind': 'email',
        'target': 'secops@example.com',
        'events': ['scan_completed']
    }
    normal_details = {
        'repo': 'my-org/auth-service',
        'finding_id': 'f-888',
        'severity': 'medium',
        'message': 'Minor informational notice'
    }

    res1 = await dispatcher.dispatch(normal_channel, 'scan_completed', 'Scan finished', normal_details)
    assert res1['status'] == 'sent'
    assert res1['delivered'] is True

    # Immediate resend of same finding
    res2 = await dispatcher.dispatch(normal_channel, 'scan_completed', 'Scan finished', normal_details)
    assert res2['status'] == 'suppressed_duplicate'
    assert res2['delivered'] is False
