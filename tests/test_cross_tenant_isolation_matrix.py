from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.identity import Identities

ORIGIN = "http://127.0.0.1:8000"


@pytest.fixture
def dual_tenant_env(tmp_path):
    db_path = str(tmp_path / "dual_tenant.db")
    cfg = Config(
        database_path=db_path,
        admin_token="test-admin-token-1234567890123456",
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        public_origin=ORIGIN,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
    )
    store = Store(db_path)
    app = create_app(cfg=cfg, store=store)
    client = TestClient(app, base_url=ORIGIN)

    identities = Identities(store)

    # 1. Tenant Alpha Setup
    u_alpha_admin = identities.record_github_user(1001, "alpha-admin")
    u_alpha_viewer = identities.record_github_user(1002, "alpha-viewer")
    org_alpha = identities.create_organization(u_alpha_admin["id"], "Alpha Corporation")["id"]
    identities.set_membership(org_alpha, u_alpha_viewer["id"], "viewer", u_alpha_admin["id"])

    repo_alpha = "alpha-corp/security-service"
    store.upsert_repo(repo_alpha, 111, "main")
    identities.record_repository_ownership(org_alpha, repo_alpha, u_alpha_admin["id"], "ev-alpha")

    # Seed Alpha data
    store.save_finding(
        repo=repo_alpha,
        key="alpha-find-01",
        category="sast",
        severity="critical",
        title="SQL Injection in Alpha Login",
        file_path="auth.py",
        commit_sha="a" * 40,
        details={"confidential": "alpha-secret-data"},
    )
    store.replace_inventory(repo_alpha, [Dependency("alpha-lib", "1.0.0", "npm", "package.json")])
    scan_alpha_id = store.start_scan(repo_alpha, "dependencies", "a" * 40)
    store.finish_scan(scan_alpha_id, "complete", {"files_scanned": 5}, [])

    # 2. Tenant Beta Setup
    u_beta_admin = identities.record_github_user(2001, "beta-admin")
    org_beta = identities.create_organization(u_beta_admin["id"], "Beta Enterprises")["id"]

    repo_beta = "beta-corp/payments-engine"
    store.upsert_repo(repo_beta, 222, "main")
    identities.record_repository_ownership(org_beta, repo_beta, u_beta_admin["id"], "ev-beta")

    # Seed Beta data
    store.save_finding(
        repo=repo_beta,
        key="beta-find-01",
        category="sast",
        severity="critical",
        title="Payment Gateway Auth Bypass",
        file_path="pay.py",
        commit_sha="b" * 40,
        details={"confidential": "beta-payment-vault-secret"},
    )
    store.replace_inventory(repo_beta, [Dependency("stripe", "10.0.0", "pypi", "requirements.txt")])
    scan_beta_id = store.start_scan(repo_beta, "dependencies", "b" * 40)
    store.finish_scan(scan_beta_id, "complete", {"files_scanned": 8}, [])

    # Sessions
    sessions = AuthSessions(store, cfg)
    token_alpha_admin, csrf_alpha_admin = sessions.create(u_alpha_admin["id"])
    token_alpha_viewer, csrf_alpha_viewer = sessions.create(u_alpha_viewer["id"])
    token_beta_admin, csrf_beta_admin = sessions.create(u_beta_admin["id"])

    return {
        "cfg": cfg,
        "store": store,
        "client": client,
        "sessions": sessions,
        "alpha": {
            "org_id": org_alpha,
            "admin_token": token_alpha_admin,
            "admin_csrf": csrf_alpha_admin,
            "viewer_token": token_alpha_viewer,
            "viewer_csrf": csrf_alpha_viewer,
            "repo": repo_alpha,
            "scan_id": scan_alpha_id,
        },
        "beta": {
            "org_id": org_beta,
            "admin_token": token_beta_admin,
            "admin_csrf": csrf_beta_admin,
            "repo": repo_beta,
            "scan_id": scan_beta_id,
        },
    }


def test_cross_tenant_organization_and_repo_isolation(dual_tenant_env):
    client: TestClient = dual_tenant_env["client"]
    alpha = dual_tenant_env["alpha"]
    beta = dual_tenant_env["beta"]
    sessions: AuthSessions = dual_tenant_env["sessions"]

    # Authenticate as Alpha Admin
    client.cookies.set(sessions.cookie_prefix + "session", alpha["admin_token"])
    client.cookies.set(sessions.cookie_prefix + "csrf", alpha["admin_csrf"])

    # 1. Alpha Admin cannot access Beta's organization repositories
    r_beta_repos = client.get(f"/api/v1/organizations/{beta['org_id']}/repositories")
    assert r_beta_repos.status_code in (403, 404)

    # 2. Alpha Admin cannot access Beta's project health
    r_beta_health = client.get(f"/api/v1/organizations/{alpha['org_id']}/repositories/{beta['repo']}/health")
    assert r_beta_health.status_code == 404

    # 3. Alpha Admin cannot access Beta's audit events
    r_beta_audit = client.get(f"/api/v1/organizations/{beta['org_id']}/audit/events")
    assert r_beta_audit.status_code in (403, 404)


def test_cross_tenant_scan_and_finding_isolation(dual_tenant_env):
    client: TestClient = dual_tenant_env["client"]
    alpha = dual_tenant_env["alpha"]
    beta = dual_tenant_env["beta"]
    store: Store = dual_tenant_env["store"]
    sessions: AuthSessions = dual_tenant_env["sessions"]

    # Get finding IDs
    with store.conn() as c:
        f_alpha = c.execute("SELECT id FROM findings WHERE repo=?", (alpha["repo"],)).fetchone()[0]
        f_beta = c.execute("SELECT id FROM findings WHERE repo=?", (beta["repo"],)).fetchone()[0]

    # Authenticate as Alpha Admin
    client.cookies.set(sessions.cookie_prefix + "session", alpha["admin_token"])
    client.cookies.set(sessions.cookie_prefix + "csrf", alpha["admin_csrf"])

    # Alpha Admin cannot view Beta's finding
    r_find_beta = client.get(f"/api/v1/organizations/{alpha['org_id']}/findings/{f_beta}")
    assert r_find_beta.status_code == 404

    # Alpha Admin CAN view own finding
    r_find_alpha = client.get(f"/api/v1/organizations/{alpha['org_id']}/findings/{f_alpha}")
    assert r_find_alpha.status_code == 200
    assert r_find_alpha.json()["key"] == "alpha-find-01"


def test_role_and_queue_isolation(dual_tenant_env):
    client: TestClient = dual_tenant_env["client"]
    alpha = dual_tenant_env["alpha"]
    beta = dual_tenant_env["beta"]
    store: Store = dual_tenant_env["store"]
    sessions: AuthSessions = dual_tenant_env["sessions"]

    # Authenticate as Alpha Viewer (read-only role in Alpha)
    client.cookies.set(sessions.cookie_prefix + "session", alpha["viewer_token"])
    client.cookies.set(sessions.cookie_prefix + "csrf", alpha["viewer_csrf"])

    # Alpha Viewer cannot mutate notification channels
    r_create_channel = client.post(
        f"/api/v1/organizations/{alpha['org_id']}/notifications/channels",
        json={"name": "Hacked Channel", "kind": "email", "target": "hacker@evil.com", "events": ["finding.new"], "enabled": True},
        headers={"x-csrf-token": alpha["viewer_csrf"], "origin": ORIGIN},
    )
    assert r_create_channel.status_code == 403

    # Alpha Viewer cannot purge organization data
    r_purge = client.delete(
        f"/api/v1/organizations/{alpha['org_id']}/data",
        headers={"x-csrf-token": alpha["viewer_csrf"], "origin": ORIGIN},
    )
    assert r_purge.status_code == 403

    # Queue Isolation: Job enqueued for Beta cannot be claimed as Alpha context
    store.enqueue("scan", beta["repo"], {"payload": "secret-beta-code"}, "key-queue-beta-1")
    claimed = store.claim()
    assert claimed is not None
    assert claimed["repo"] == beta["repo"]
    assert claimed["organization_id"] == beta["org_id"]

