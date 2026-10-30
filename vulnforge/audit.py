"""Audit logging, redaction, and operator access auditing for VulnForge."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(token|secret|password|passwd|private_key|api_key|auth|authorization|credential|csrf|cookie|session_id)",
    re.IGNORECASE,
)

SECRET_VALUE_PATTERNS = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{16,}"), "gh_***REDACTED***"),
    (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+"), "Bearer ***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***REDACTED***"),
    (re.compile(r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def mask_sensitive_audit_data(data: Any) -> Any:
    """Recursively mask sensitive values and patterns in audit event payloads."""
    if isinstance(data, dict):
        masked: Dict[str, Any] = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                masked[k] = "***REDACTED***"
            else:
                masked[k] = mask_sensitive_audit_data(v)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_audit_data(item) for item in data]
    elif isinstance(data, str):
        masked_str = data
        for pattern, replacement in SECRET_VALUE_PATTERNS:
            masked_str = pattern.sub(replacement, masked_str)
        return masked_str
    return data


def audit_operator_access(
    store: Any,
    operator_actor: str,
    organization_id: str,
    action: str,
    justification: str,
    *,
    repo: Optional[str] = None,
    job_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> int:
    """Audit an operator/admin privileged operation on customer tenant data.
    
    Enforces non-empty justification (e.g. ticket ID, operational incident ID).
    """
    if not justification or not justification.strip():
        raise ValueError("Operator access requires a non-empty audit justification")

    target_repo = repo or f"organization:{organization_id}"
    audit_details = dict(details or {})
    audit_details.update({
        "organization_id": organization_id,
        "operator_justification": justification.strip(),
        "job_id": job_id,
        "correlation_id": correlation_id,
        "client_ip": client_ip,
        "operator_access": True,
    })

    return store.audit_event(
        repo=target_repo,
        finding_id=None,
        actor=f"operator:{operator_actor}",
        action=f"operator_access:{action}",
        details=audit_details,
        organization_id=organization_id,
        job_id=job_id,
        correlation_id=correlation_id,
        client_ip=client_ip,
    )


def query_audit_events(
    store: Any,
    *,
    organization_id: Optional[str] = None,
    repo: Optional[str] = None,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    job_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Query audit events with filtering across actor, organization, repo, and job_id."""
    with store.conn() as c:
        query = "SELECT id, repo, finding_id, actor, action, details, created_at FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if repo:
            query += " AND repo = ?"
            params.append(repo)
        if actor:
            query += " AND actor LIKE ?"
            params.append(f"%{actor}%")
        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit * 3 if (organization_id or job_id) else limit)

        rows = c.execute(query, tuple(params)).fetchall()

    results: List[Dict[str, Any]] = []
    for r in rows:
        row_dict = dict(r)
        raw_details = row_dict.get("details")
        details_dict: Dict[str, Any] = {}
        if isinstance(raw_details, str):
            try:
                details_dict = json.loads(raw_details)
            except Exception:
                details_dict = {"raw": raw_details}
        elif isinstance(raw_details, dict):
            details_dict = raw_details

        row_dict["details"] = details_dict

        # Filter by organization_id if specified
        if organization_id:
            ev_org = details_dict.get("organization_id")
            if not ev_org and row_dict["repo"].startswith("organization:"):
                ev_org = row_dict["repo"].split("organization:", 1)[1]
            if ev_org != organization_id:
                continue

        # Filter by job_id if specified
        if job_id and details_dict.get("job_id") != job_id:
            continue

        results.append(row_dict)
        if len(results) >= limit:
            break

    return results

