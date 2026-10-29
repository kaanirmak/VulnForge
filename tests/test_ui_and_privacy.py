from pathlib import Path
from fastapi.testclient import TestClient
import pytest
from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities

ORIGIN = 'http://127.0.0.1:8000'


def test_account_html_accessibility_and_responsive_elements():
    html_path = Path(__file__).resolve().parent.parent / 'vulnforge' / 'account.html'
    content = html_path.read_text(encoding='utf-8')

    # 1. Responsive & Viewport
    assert 'meta name="viewport" content="width=device-width,initial-scale=1"' in content
    assert 'min-height:44px' in content
    assert 'min-width:44px' in content
    assert 'touch-action:manipulation' in content

    # 2. Accessibility & ARIA
    assert 'class="skip-link"' in content
    assert 'href="#workspace"' in content
    assert 'role="status"' in content
    assert 'aria-live="polite"' in content
    assert 'role="alert"' in content
    assert 'id="session-expired-alert"' in content
    assert 'aria-label=' in content

    # 3. Informative Empty States
    assert 'empty-box' in content
    assert 'Henüz bağlı bir proje yok' in content
    assert 'açık güvenlik bulgusu bulunmuyor' in content

    # 4. Privacy & Connection management
    assert 'id="privacy-section"' in content
    assert 'disconnectRepo' in content
    assert 'Bağlantıyı Kaldır' in content


@pytest.fixture
def privacy_fixture(tmp_path):
    store = Store(str(tmp_path / 'vulnforge.db'))
    identity = Identities(store)

    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'Alpha SecOps')
    org_id = org['id']

    viewer = identity.record_github_user(102, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    repo = 'alpha-sec/app'
    store.upsert_repo(repo, 101, 'main')
    identity.record_repository_ownership(org_id, repo, owner['id'], 'server-verified-123')

    cfg = Config(
        database_path=store.path,
        admin_token='operator-only',
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        github_oauth_client_id='mock_id',
        github_oauth_client_secret='mock_secret',
        public_origin=ORIGIN
    )
    app = create_app(cfg, store)

    return {
        'store': store,
        'identity': identity,
        'app': app,
        'cfg': cfg,
        'org_id': org_id,
        'owner': owner,
        'viewer': viewer,
        'repo': repo
    }


def test_repository_connection_deletion_and_privacy(privacy_fixture):
    app = privacy_fixture['app']
    store = privacy_fixture['store']
    cfg = privacy_fixture['cfg']
    org_id = privacy_fixture['org_id']
    owner = privacy_fixture['owner']
    viewer = privacy_fixture['viewer']
    repo = privacy_fixture['repo']

    sessions = AuthSessions(store, cfg)

    # 1. Verify repo is initially listed
    owner_token, owner_csrf = sessions.create(owner['id'])
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(sessions.cookie_prefix + 'session', owner_token)
    client.cookies.set(sessions.cookie_prefix + 'csrf', owner_csrf)

    res = client.get(f'/api/v1/organizations/{org_id}/repositories')
    assert res.status_code == 200
    assert any(r['full_name'] == repo for r in res.json()['items'])

    # 2. Viewer cannot disconnect repository (403 RoleDenied)
    viewer_token, viewer_csrf = sessions.create(viewer['id'])
    v_client = TestClient(app, base_url=ORIGIN)
    v_client.cookies.set(sessions.cookie_prefix + 'session', viewer_token)
    v_client.cookies.set(sessions.cookie_prefix + 'csrf', viewer_csrf)

    v_headers = {'x-csrf-token': viewer_csrf, 'origin': ORIGIN}
    del_res_viewer = v_client.delete(f'/api/v1/organizations/{org_id}/repositories/{repo}', headers=v_headers)
    assert del_res_viewer.status_code == 403

    # 3. Org Admin successfully disconnects repository
    o_headers = {'x-csrf-token': owner_csrf, 'origin': ORIGIN}
    del_res = client.delete(f'/api/v1/organizations/{org_id}/repositories/{repo}', headers=o_headers)
    assert del_res.status_code == 200
    assert del_res.json()['status'] == 'disconnected'
    assert del_res.json()['repo'] == repo

    # 4. Verify repo is no longer listed in organization
    res_after = client.get(f'/api/v1/organizations/{org_id}/repositories')
    assert res_after.status_code == 200
    assert not any(r['full_name'] == repo for r in res_after.json()['items'])

    # 5. Subsequent delete returns 404 Not Found
    del_res_again = client.delete(f'/api/v1/organizations/{org_id}/repositories/{repo}', headers=o_headers)
    assert del_res_again.status_code == 404

    # 6. Verify audit trail recorded repository deletion
    with store.conn() as c:
        audit_events = c.execute(
            'SELECT action, details FROM audit_events WHERE repo=? ORDER BY created_at DESC',
            (repo,)
        ).fetchall()
        assert any(dict(a)['action'] == 'repository_ownership_deleted' for a in audit_events)
