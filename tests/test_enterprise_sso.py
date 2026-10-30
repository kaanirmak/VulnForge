import time
import jwt
import pytest

from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.sso import EnterpriseSSO, SSOConfig


def test_enterprise_sso_token_decode_and_role_mapping():
    secret = "test-sso-secret-key-12345-very-secure-32bytes-secret"
    issuer = "https://idp.example.com"
    client_id = "vf-client-app"

    config = SSOConfig(
        issuer=issuer,
        client_id=client_id,
        default_role="viewer",
        group_role_mapping={
            "Security-Admins": "org_admin",
            "DevOps-Engineers": "maintainer",
            "Sec-Analysts": "analyst",
        },
        enforce_sso=True,
    )
    sso = EnterpriseSSO(config, signing_key_or_jwks=secret)

    # 1. Generate valid token with Security-Admins group
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": client_id,
        "sub": "user_12345",
        "email": "sarah@example.com",
        "name": "Sarah Connor",
        "groups": ["Engineering", "Security-Admins"],
        "iat": now,
        "exp": now + 3600,
        "nonce": "secure-nonce-1",
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    # Decode and validate
    claims = sso.decode_and_validate_token(token, nonce="secure-nonce-1")
    assert claims["sub"] == "user_12345"
    assert claims["email"] == "sarah@example.com"

    # Role resolution
    role = sso.resolve_role(claims)
    assert role == "org_admin"

    # Default role fallback
    claims_fallback = {"sub": "user_2", "groups": ["General-Staff"]}
    assert sso.resolve_role(claims_fallback) == "viewer"


def test_enterprise_sso_jit_provisioning_and_sync(tmp_path):
    db_path = str(tmp_path / "sso_jit.db")
    store = Store(db_path)
    identities = Identities(store)

    # Create organization
    admin_user = identities.record_github_user(9001, "initial-admin")
    org = identities.create_organization(admin_user["id"], "Enterprise Corp")

    config = SSOConfig(
        issuer="https://auth.enterprisecorp.com",
        client_id="vf-app-1",
        default_role="analyst",
        group_role_mapping={"CloudSec": "maintainer"},
    )
    sso = EnterpriseSSO(config)

    # First login -> JIT provisioning
    claims_1 = {
        "sub": "okta_998877",
        "email": "alex@enterprisecorp.com",
        "name": "Alex Mercer",
        "groups": ["CloudSec"],
    }
    res1 = sso.jit_provision_user(store, org["id"], claims_1)
    assert res1["action"] == "sso_jit_created"
    assert res1["role"] == "maintainer"

    # Verify user in database
    with store.conn() as c:
        m = c.execute("SELECT role FROM memberships WHERE organization_id=? AND user_id=?", (org["id"], res1["user_id"])).fetchone()
        assert m["role"] == "maintainer"

    # Second login with updated groups -> Role synchronization
    claims_2 = {
        "sub": "okta_998877",
        "email": "alex@enterprisecorp.com",
        "name": "Alex Mercer",
        "groups": [],  # Lost CloudSec group -> falls back to default role 'analyst'
    }
    res2 = sso.jit_provision_user(store, org["id"], claims_2)
    assert res2["action"] == "sso_role_synced"
    assert res2["role"] == "analyst"

    with store.conn() as c:
        m2 = c.execute("SELECT role FROM memberships WHERE organization_id=? AND user_id=?", (org["id"], res1["user_id"])).fetchone()
        assert m2["role"] == "analyst"


def test_enterprise_sso_enforcement():
    config_enforced = SSOConfig(issuer="https://idp.com", client_id="c1", enforce_sso=True)
    sso_enforced = EnterpriseSSO(config_enforced)

    assert sso_enforced.check_sso_enforcement("enterprise_sso") is True
    assert sso_enforced.check_sso_enforcement("github_oauth") is False
    assert sso_enforced.check_sso_enforcement("local_password") is False

    config_open = SSOConfig(issuer="https://idp.com", client_id="c1", enforce_sso=False)
    sso_open = EnterpriseSSO(config_open)
    assert sso_open.check_sso_enforcement("github_oauth") is True
