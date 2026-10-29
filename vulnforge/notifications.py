"""Notification formatting, deduplication, aggregation, escalation, and dispatch for email, Slack, and Microsoft Teams integrations."""
import hashlib
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import httpx

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
URL_REGEX = re.compile(r'^https://[A-Za-z0-9_.\-~%/?#=&]+$')

SUPPORTED_CHANNELS = ('email', 'slack', 'teams')
SUPPORTED_EVENTS = ('scan_completed', 'critical_finding', 'critical_escalation', 'remediation_ready', 'test_ping')

# Sensitive secret patterns for redaction
_SENSITIVE_PATTERNS = [
    # Private keys
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    # Bearer tokens / JWT
    (re.compile(r'(?i)\bbearer\s+[A-Za-z0-9\-_=.]+'), 'Bearer [REDACTED_TOKEN]'),
    # AWS Access Key
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
    # GitHub Personal Access Token / PAT
    (re.compile(r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b'), '[REDACTED_GITHUB_TOKEN]'),
    # Generic tokens/passwords in key-value / env form
    (re.compile(r'(?i)\b(api_key|apikey|secret_key|secret|password|access_token|private_key)\s*[:=]\s*["\']?[a-zA-Z0-9\-_\.~+/=]{8,}["\']?'), r'\1=[REDACTED]'),
    # URL credentials (http://user:pass@host)
    (re.compile(r'(https?://[^:]+):([^@]+)@'), r'\1:[REDACTED]@'),
    # Query string secrets
    (re.compile(r'(?i)([?&](?:token|password|secret|api_key|apikey|key)=)[^&#\s]+'), r'\1[REDACTED]'),
]


def scrub_sensitive_notification_content(value: Any) -> Any:
    """Recursively scrub sensitive secrets, API keys, credentials, and tokens from notification content."""
    if isinstance(value, str):
        scrubbed = value
        for pattern, replacement in _SENSITIVE_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed
    elif isinstance(value, dict):
        return {k: scrub_sensitive_notification_content(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [scrub_sensitive_notification_content(elem) for elem in value]
    return value


def is_critical_escalation(event_type: str, details: dict) -> bool:
    """Determine if a finding or notification warrants immediate critical escalation."""
    if event_type in ('critical_escalation', 'critical_finding'):
        return True
    if details.get('escalate') is True or details.get('is_escalation') is True:
        return True
    severity = str(details.get('severity', '')).lower()
    priority = str(details.get('priority', '')).upper()
    if severity in ('critical', 'crit') or priority == 'P0':
        return True
    if details.get('cisa_kev') is True or details.get('is_kev') is True:
        return True
    try:
        epss = float(details.get('epss', 0.0))
        if epss >= 0.70:
            return True
    except (ValueError, TypeError):
        pass
    return False


def validate_channel_target(kind: str, target: str) -> None:
    target = target.strip()
    if kind == 'email':
        if not EMAIL_REGEX.match(target):
            raise ValueError(f'Invalid email address for notification target: {target}')
    elif kind in ('slack', 'teams'):
        if not URL_REGEX.match(target):
            raise ValueError(f'Invalid webhook HTTPS URL for {kind} notification: {target}')
    else:
        raise ValueError(f'Unsupported notification channel kind: {kind}')


def format_email_notification(event_type: str, title: str, details: dict) -> dict:
    subject = f"[VulnForge Alert] {title}"
    lines = [
        f"VulnForge Notification: {title}",
        f"Event: {event_type}",
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(details.get('timestamp', time.time())))}",
        ""
    ]
    for k, v in details.items():
        if k != 'timestamp':
            lines.append(f"{k}: {v}")
    body = "\n".join(lines)
    html = f"<h3>{title}</h3><p><strong>Event:</strong> {event_type}</p><ul>"
    for k, v in details.items():
        if k != 'timestamp':
            html += f"<li><strong>{k}:</strong> {v}</li>"
    html += "</ul>"
    return {'subject': subject, 'body': body, 'html': html}


def format_slack_notification(event_type: str, title: str, details: dict) -> dict:
    message = details.get('message', title)
    repo = details.get('repo', 'N/A')
    severity = details.get('severity', 'info').upper()
    is_escalated = details.get('escalated', False) or severity == 'CRITICAL'
    header_prefix = "🚨 VulnForge Critical Alert: " if is_escalated else "🛡️ VulnForge: "
    blocks = [
        {
            'type': 'header',
            'text': {'type': 'plain_text', 'text': f"{header_prefix}{title[:140]}"}
        },
        {
            'type': 'section',
            'fields': [
                {'type': 'mrkdwn', 'text': f"*Event:*\n`{event_type}`"},
                {'type': 'mrkdwn', 'text': f"*Severity:*\n`{severity}`"},
                {'type': 'mrkdwn', 'text': f"*Repository:*\n`{repo}`"},
                {'type': 'mrkdwn', 'text': f"*Time:*\n<!date^{int(details.get('timestamp', time.time()))}^{{date_num}} {{time_secs}}|{time.time()}>"}
            ]
        }
    ]
    if 'url' in details:
        blocks.append({
            'type': 'section',
            'text': {'type': 'mrkdwn', 'text': f"<{details['url']}|View details in VulnForge>"}
        })
    return {
        'text': f"[VulnForge] {title}: {message}",
        'blocks': blocks
    }


def format_teams_notification(event_type: str, title: str, details: dict) -> dict:
    message = details.get('message', title)
    repo = details.get('repo', 'N/A')
    severity = str(details.get('severity', 'info')).upper()
    is_escalated = details.get('escalated', False) or severity == 'CRITICAL'
    facts = [
        {'name': 'Event', 'value': event_type},
        {'name': 'Repository', 'value': repo},
        {'name': 'Severity', 'value': severity}
    ]
    for k, v in details.items():
        if k not in ('message', 'repo', 'severity', 'timestamp', 'url', 'escalated'):
            facts.append({'name': k, 'value': str(v)})

    card = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': 'E81123' if (is_escalated or details.get('severity') in ('critical', 'high')) else '0076D7',
        'summary': title,
        'title': f"VulnForge: {title}",
        'sections': [
            {
                'activityTitle': title,
                'activitySubtitle': event_type,
                'facts': facts,
                'text': message
            }
        ]
    }
    if 'url' in details:
        card['potentialAction'] = [
            {
                '@type': 'OpenUri',
                'name': 'Open in VulnForge',
                'targets': [{'os': 'default', 'uri': details['url']}]
            }
        ]
    return card


class NotificationAggregator:
    """Aggregates multiple individual scan findings into a concise, unified digest notification."""

    @staticmethod
    def aggregate_findings(repo: str, findings: List[Dict[str, Any]], scan_id: Optional[str] = None) -> Dict[str, Any]:
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        cisa_kev_count = 0
        top_findings = []

        for f in findings:
            sev = str(f.get('severity', 'info')).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts['info'] += 1

            if f.get('cisa_kev') or f.get('is_kev'):
                cisa_kev_count += 1

        # Sort findings: critical first, then high, etc.
        priority_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                0 if x.get('cisa_kev') else 1,
                priority_map.get(str(x.get('severity', 'info')).lower(), 9)
            )
        )

        for item in sorted_findings[:5]:
            top_findings.append({
                'id': item.get('id') or item.get('finding_id'),
                'package': item.get('package_name') or item.get('package') or item.get('target', 'unknown'),
                'severity': item.get('severity', 'info'),
                'summary': item.get('summary') or item.get('rule_id') or item.get('message', ''),
                'cisa_kev': bool(item.get('cisa_kev') or item.get('is_kev')),
                'fix_version': item.get('recommended_version') or item.get('fixed_version')
            })

        total = len(findings)
        has_critical = severity_counts['critical'] > 0 or cisa_kev_count > 0
        title = f"Scan digest for {repo}: {total} findings ({severity_counts['critical']} critical, {severity_counts['high']} high)"
        if has_critical:
            title = f"🚨 {title}"

        details = {
            'repo': repo,
            'scan_id': scan_id or 'scan-' + uuid.uuid4().hex[:8],
            'total_findings': total,
            'severity_breakdown': severity_counts,
            'cisa_kev_count': cisa_kev_count,
            'top_findings': top_findings,
            'has_critical': has_critical,
            'severity': 'critical' if severity_counts['critical'] > 0 else ('high' if severity_counts['high'] > 0 else 'medium'),
            'message': f"{total} total findings detected in {repo}. Breakdown: {severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low."
        }
        return {
            'event_type': 'scan_completed',
            'title': title,
            'details': details
        }


class NotificationDeduplicator:
    """Manages notification fingerprints and dedup cooldowns, bypassing for critical risk escalations."""

    def __init__(self, cooldown_seconds: float = 3600.0):
        self.cooldown_seconds = cooldown_seconds
        self._history: Dict[str, float] = {}  # fingerprint -> last_sent_at

    @staticmethod
    def compute_fingerprint(channel_id: str, repo: str, event_type: str, alert_key: str) -> str:
        raw = f"{channel_id}:{repo}:{event_type}:{alert_key}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def evaluate(self, channel_id: str, repo: str, event_type: str, details: dict, now: Optional[float] = None) -> Tuple[bool, str, str]:
        """
        Evaluate if notification should be sent.
        Returns: (should_send, reason, fingerprint)
        """
        if now is None:
            now = time.time()

        alert_key = str(details.get('finding_id') or details.get('scan_id') or details.get('advisory_id') or details.get('plan_id') or details.get('message') or '')
        fingerprint = self.compute_fingerprint(channel_id, repo, event_type, alert_key)

        is_critical = is_critical_escalation(event_type, details)
        last_sent = self._history.get(fingerprint)

        if is_critical:
            # Critical escalation bypasses cooldown, with a minimal 60s flood guard
            if last_sent is not None and (now - last_sent) < 60.0:
                return False, 'critical_rate_limited', fingerprint
            self._history[fingerprint] = now
            return True, 'critical_escalation_bypass', fingerprint

        if last_sent is not None and (now - last_sent) < self.cooldown_seconds:
            return False, 'suppressed_duplicate', fingerprint

        self._history[fingerprint] = now
        return True, 'allowed', fingerprint


class NotificationDispatcher:
    def __init__(self, http_client: Optional[httpx.AsyncClient] = None, deduplicator: Optional[NotificationDeduplicator] = None):
        self.http_client = http_client
        self.deduplicator = deduplicator or NotificationDeduplicator()

    async def dispatch(self, channel: dict, event_type: str, title: str, details: dict) -> dict:
        kind = channel.get('kind')
        target = channel.get('target', '')
        validate_channel_target(kind, target)

        # 1. Scrub sensitive content (secrets, tokens, credentials)
        scrubbed_title = scrub_sensitive_notification_content(title)
        scrubbed_details = scrub_sensitive_notification_content(details)

        # 2. Check for critical risk escalation
        is_escalated = is_critical_escalation(event_type, scrubbed_details)
        if is_escalated:
            scrubbed_details['escalated'] = True
            if not scrubbed_title.startswith('🚨') and not '[CRITICAL ESCALATION]' in scrubbed_title:
                scrubbed_title = f"🚨 [CRITICAL ESCALATION] {scrubbed_title}"

        # 3. Deduplication check
        channel_id = str(channel.get('id', 'default'))
        repo = str(scrubbed_details.get('repo', 'all'))
        should_send, dedup_reason, fingerprint = self.deduplicator.evaluate(channel_id, repo, event_type, scrubbed_details)
        if not should_send:
            return {
                'channel_id': channel.get('id'),
                'kind': kind,
                'target': target,
                'status': dedup_reason,
                'delivered': False,
                'fingerprint': fingerprint,
                'escalated': is_escalated
            }

        enriched_details = {
            'timestamp': time.time(),
            **scrubbed_details
        }

        if kind == 'email':
            payload = format_email_notification(event_type, scrubbed_title, enriched_details)
            return {
                'channel_id': channel.get('id'),
                'kind': 'email',
                'target': target,
                'status': 'sent',
                'delivered': True,
                'fingerprint': fingerprint,
                'escalated': is_escalated,
                'payload': payload
            }
        elif kind == 'slack':
            payload = format_slack_notification(event_type, scrubbed_title, enriched_details)
        elif kind == 'teams':
            payload = format_teams_notification(event_type, scrubbed_title, enriched_details)
        else:
            raise ValueError(f"Unknown notification channel kind: {kind}")

        client = self.http_client or httpx.AsyncClient(timeout=15.0)
        owns_client = self.http_client is None
        try:
            res = await client.post(target, json=payload, headers={'Content-Type': 'application/json'})
            delivered = 200 <= res.status_code < 300
            return {
                'channel_id': channel.get('id'),
                'kind': kind,
                'target': target,
                'status_code': res.status_code,
                'status': 'delivered' if delivered else 'delivery_failed',
                'delivered': delivered,
                'fingerprint': fingerprint,
                'escalated': is_escalated,
                'payload': payload
            }
        finally:
            if owns_client:
                await client.aclose()
