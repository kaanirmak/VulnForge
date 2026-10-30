import time
from fastapi.testclient import TestClient
import pytest

from support import managed_config as Config
from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData, ResourceNotFound


def test_membership_removal_revokes_sessions_and_authority(tmp_path):
    """Verify that removing membership immediately deletes sessions and revokes access."""
    db_path = str(tmp_path / "membership_revoke.db")
    cfg = Config(database_path=db_path)
    store = Store(db_path)
    identities = Identities(store)
    auth = AuthSessions(store, cfg)

    # Create admin and member
    admin_user = identities.record_github_user(2001, "org-admin-user")
    org = identities.create_organization(admin_user["id"], "Acme Corp")

    member_user = identities.record_github_user(2002, "regular-member")
    identities.set_membership(org["id"], member_user["id"], "analyst", admin_user["id"])

    # Create active session for member
    token, csrf = auth.create(member_user["id"])
    assert token is not None

    with store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM user_sessions WHERE user_id=?", (member_user["id"],)).fetchone()[0] == 1

    # Member can access org
    orgs = identities.list_organizations(member_user["id"])
    assert any(o["id"] == org["id"] for o in orgs)

    # Admin removes member
    identities.remove_membership(org["id"], member_user["id"], admin_user["id"])

    # Verify sessions for removed user are deleted
    with store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM user_sessions WHERE user_id=?", (member_user["id"],)).fetchone()[0] == 0

    # User no longer has membership
    orgs_after = identities.list_organizations(member_user["id"])
    assert not any(o["id"] == org["id"] for o in orgs_after)


def test_repo_ownership_removal_revokes_access(tmp_path):
    """Verify that unbinding a repository immediately revokes tenant access to it."""
    db_path = str(tmp_path / "repo_unbind.db")
    store = Store(db_path)
    identities = Identities(store)

    user = identities.record_github_user(3001, "dev-lead")
    org = identities.create_organization(user["id"], "Beta Org")

    repo = "beta-org/api-gateway"
    store.upsert_repo(repo, 700, "main")
    identities.record_repository_ownership(org["id"], repo, user["id"], "conn-700")

    org_data = OrganizationData(store, org["id"], user["id"], "hash-dev")
    health = org_data.project_health(repo)
    assert health["repo"] == repo

    # Remove repository ownership
    identities.remove_repository_ownership(org["id"], repo, user["id"])

    # Attempting to access now raises ResourceNotFound
    with pytest.raises(ResourceNotFound):
        org_data.project_health(repo)
