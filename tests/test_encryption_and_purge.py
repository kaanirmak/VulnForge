from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.encryption import (
    DataEncryptor,
    DecryptionError,
    create_encrypted_backup,
    restore_encrypted_backup
)
from vulnforge.identity import Identities

ORIGIN = 'http://127.0.0.1:8000'


def test_data_encryptor_authenticated_aes_gcm():
    key = DataEncryptor.generate_key()
    assert len(key) == 64

    secret_message = b"Confidential customer security findings and encryption keys."
    ciphertext = DataEncryptor.encrypt(secret_message, key)

    assert ciphertext.startswith(b'VFENC1\x00')
    assert secret_message not in ciphertext

    # Successful decryption
    decrypted = DataEncryptor.decrypt(ciphertext, key)
    assert decrypted == secret_message

    # Tampered ciphertext fails with DecryptionError
    corrupt_ciphertext = bytearray(ciphertext)
    corrupt_ciphertext[-1] ^= 0x01
    with pytest.raises(DecryptionError, match="authentication tag mismatch or invalid key"):
        DataEncryptor.decrypt(bytes(corrupt_ciphertext), key)

    # Wrong key fails with DecryptionError
    wrong_key = DataEncryptor.generate_key()
    with pytest.raises(DecryptionError, match="authentication tag mismatch or invalid key"):
        DataEncryptor.decrypt(ciphertext, wrong_key)


def test_encrypted_backup_and_restore_cycle(tmp_path):
    # 1. Create a live database with data
    db_file = tmp_path / 'original.db'
    store = Store(str(db_file))
    store.upsert_repo('org/repo', 1, 'main')
    store.save_finding('org/repo', 'f-1', 'sast', 'high', 'SQL Injection', 'app.py', 'a'*40, {})

    # 2. Perform encrypted backup
    key = DataEncryptor.generate_key()
    backup_file = tmp_path / 'backup.enc'
    meta = create_encrypted_backup(db_file, backup_file, key)

    assert backup_file.exists()
    assert b'SQLite format 3' not in backup_file.read_bytes()
    assert meta['source_bytes'] > 0
    assert meta['backup_bytes'] > meta['source_bytes']

    # 3. Restore to a new location
    restored_file = tmp_path / 'restored.db'
    restore_meta = restore_encrypted_backup(backup_file, restored_file, key)

    assert restored_file.exists()
    assert restore_meta['restored_sha256'] == meta['source_sha256']

    # 4. Verify data integrity in restored database
    restored_store = Store(str(restored_file))
    with restored_store.conn() as c:
        row = c.execute("SELECT title FROM findings WHERE key='f-1'").fetchone()
        assert row is not None
        assert row['title'] == 'SQL Injection'


def test_customer_organization_data_purge_lifecycle(tmp_path):
    db_path = str(tmp_path / 'vulnforge.db')
    store = Store(db_path)
    identity = Identities(store)

    # Setup tenant
    owner = identity.record_github_user(101, 'alpha-owner')
    org = identity.create_organization(owner['id'], 'Alpha Corp')
    org_id = org['id']

    viewer = identity.record_github_user(102, 'alpha-viewer')
    identity.set_membership(org_id, viewer['id'], 'viewer', owner['id'])

    repo = 'alpha-corp/backend'
    store.upsert_repo(repo, 1, 'main')
    identity.record_repository_ownership(org_id, repo, owner['id'], 'verified-fixture')

    # Seed data
    store.save_finding(repo, 'find-1', 'dependency', 'critical', 'Critical RCE', 'lock', 'a'*40, {})
    store.replace_inventory(repo, [Dependency('vuln-pkg', '1.0.0', 'npm', 'package.json')])
    scan_id = store.start_scan(repo, 'dependencies', 'a'*40)
    store.finish_scan(scan_id, 'complete', {}, [])

    cfg = Config(
        database_path=db_path,
        admin_token='test-admin-token-1234567890123456',
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        github_oauth_client_id='test-oauth-id',
        github_oauth_client_secret='test-oauth-sec',
        public_origin=ORIGIN
    )
    app = create_app(cfg, store)

    sessions = AuthSessions(store, cfg)
    owner_token, owner_csrf = sessions.create(owner['id'])
    viewer_token, viewer_csrf = sessions.create(viewer['id'])

    client = TestClient(app, base_url=ORIGIN)

    # 1. Non-admin (viewer) cannot purge data (403 Forbidden)
    client.cookies.set(sessions.cookie_prefix + 'session', viewer_token)
    client.cookies.set(sessions.cookie_prefix + 'csrf', viewer_csrf)
    res_v = client.delete(
        f'/api/v1/organizations/{org_id}/data',
        headers={'x-csrf-token': viewer_csrf, 'origin': ORIGIN}
    )
    assert res_v.status_code == 403

    # 2. Org admin purges organization data (200 OK)
    client.cookies.set(sessions.cookie_prefix + 'session', owner_token)
    client.cookies.set(sessions.cookie_prefix + 'csrf', owner_csrf)
    res_o = client.delete(
        f'/api/v1/organizations/{org_id}/data',
        headers={'x-csrf-token': owner_csrf, 'origin': ORIGIN}
    )
    assert res_o.status_code == 200
    assert res_o.json()['status'] == 'purged'
    assert repo in res_o.json()['purged_repositories']

    # 3. Verify all findings, inventory, and scans are completely purged from db
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM findings WHERE repo=?', (repo,)).fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM dependency_inventory WHERE repo=?', (repo,)).fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM scans WHERE repo=?', (repo,)).fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM repository_ownership WHERE organization_id=?', (org_id,)).fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM memberships WHERE organization_id=?', (org_id,)).fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM organizations WHERE id=?', (org_id,)).fetchone()[0] == 0

        # Audit event preserved for accountability
        audit = c.execute("SELECT action FROM audit_events WHERE repo=? ORDER BY created_at DESC", (f"org:{org_id}",)).fetchone()
        assert audit is not None
        assert audit['action'] == 'organization_data_purged'

    # 4. Subsequent queries for organization return 404 Not Found
    res_after = client.get(f'/api/v1/organizations/{org_id}/overview')
    assert res_after.status_code == 404
