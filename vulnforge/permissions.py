"""Deny-by-default organization permissions, independent of operator credentials."""

READ=frozenset(('project.read','finding.read','scan.read','impact.read','export.read'))
PERMISSIONS={
    'org_admin':READ|{'finding.triage','finding.accept_risk','finding.suppress','audit.read'},
    'maintainer':READ|{'finding.triage','finding.accept_risk','finding.suppress'},
    'analyst':READ|{'finding.triage'},
    'viewer':READ,
    'auditor':READ|{'audit.read'},
}


def permits(role,permission):
    return permission in PERMISSIONS.get(role,frozenset())
