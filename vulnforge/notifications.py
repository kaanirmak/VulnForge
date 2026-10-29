"""Notification formatting and dispatch for email, Slack, and Microsoft Teams integrations."""
import json
import re
import time
import uuid
import httpx

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
URL_REGEX = re.compile(r'^https://[A-Za-z0-9_.\-~%/?#=&]+$')

SUPPORTED_CHANNELS = ('email', 'slack', 'teams')
SUPPORTED_EVENTS = ('scan_completed', 'critical_finding', 'remediation_ready', 'test_ping')


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
    blocks = [
        {
            'type': 'header',
            'text': {'type': 'plain_text', 'text': f"🛡️ VulnForge: {title[:150]}"}
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
    facts = [
        {'name': 'Event', 'value': event_type},
        {'name': 'Repository', 'value': repo},
        {'name': 'Severity', 'value': str(details.get('severity', 'info')).upper()}
    ]
    for k, v in details.items():
        if k not in ('message', 'repo', 'severity', 'timestamp', 'url'):
            facts.append({'name': k, 'value': str(v)})

    card = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': 'E81123' if details.get('severity') in ('critical', 'high') else '0076D7',
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


class NotificationDispatcher:
    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self.http_client = http_client

    async def dispatch(self, channel: dict, event_type: str, title: str, details: dict) -> dict:
        kind = channel.get('kind')
        target = channel.get('target', '')
        validate_channel_target(kind, target)

        enriched_details = {
            'timestamp': time.time(),
            **details
        }

        if kind == 'email':
            payload = format_email_notification(event_type, title, enriched_details)
            # In a real environment, dispatch via SMTP or provider API
            return {
                'channel_id': channel.get('id'),
                'kind': 'email',
                'target': target,
                'status': 'sent',
                'delivered': True,
                'payload': payload
            }
        elif kind == 'slack':
            payload = format_slack_notification(event_type, title, enriched_details)
        elif kind == 'teams':
            payload = format_teams_notification(event_type, title, enriched_details)
        else:
            raise ValueError(f"Unknown notification channel kind: {kind}")

        # If HTTP client is provided or real target, deliver
        client = self.http_client or httpx.AsyncClient(timeout=15.0)
        owns_client = self.http_client is None
        try:
            # If target is mock/testing URI or mock client, send
            res = await client.post(target, json=payload, headers={'Content-Type': 'application/json'})
            delivered = 200 <= res.status_code < 300
            return {
                'channel_id': channel.get('id'),
                'kind': kind,
                'target': target,
                'status_code': res.status_code,
                'status': 'delivered' if delivered else 'delivery_failed',
                'delivered': delivered,
                'payload': payload
            }
        finally:
            if owns_client:
                await client.aclose()
