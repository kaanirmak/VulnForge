import hashlib
import hmac
import json
import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.vault import SecretVault, ScopedVaultView

ORIGIN = 'http://127.0.0.1:8000'


def make_sig(secret: str, payload: bytes) -> str:
    return 'sha256=' + hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()


def test_vault_basic_storage_and_least_privilege_scoping():
    vault = SecretVault()
    vault.set_secret('worker_database_url', 'postgresql://worker@db.internal:5432/vf')
    vault.set_secret('github_oauth_client_secret', 'super_secret_oauth_secret')
    vault.set_secret('github_private_key', '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----')
    vault.set_secret('webhook_secret', 'webhook_secret_key_12345678')

    # 1. Worker view has least-privilege access
    worker_view = vault.scoped_view('worker')
    assert worker_view.get_secret('worker_database_url') == 'postgresql://worker@db.internal:5432/vf'

    # Worker cannot access OAuth secrets or private keys
    with pytest.raises(PermissionError, match="Component 'worker' is not authorized to access secret 'github_oauth_client_secret'"):
        worker_view.get_secret('github_oauth_client_secret')

    with pytest.raises(PermissionError, match="Component 'worker' is not authorized to access secret 'github_private_key'"):
        worker_view.get_secret('github_private_key')

    # 2. API view has access to customer db and webhook, but not private key
    api_view = vault.scoped_view('api')
    assert api_view.get_secret('webhook_secret') == 'webhook_secret_key_12345678'

    with pytest.raises(PermissionError, match="Component 'api' is not authorized to access secret 'github_private_key'"):
        api_view.get_secret('github_private_key')

    # 3. GitHub App component has access to private key
    gh_view = vault.scoped_view('github_app')
    assert 'MIIE' in gh_view.get_secret('github_private_key')


def test_key_rotation_with_grace_period():
    vault = SecretVault()
    k1 = 'initial_webhook_secret_version_1'
    k2 = 'rotated_webhook_secret_version_2'
    vault.set_secret('webhook_secret', k1)

    payload = b'{"action":"ping","zen":"Favor focus over features."}'
    sig1 = make_sig(k1, payload)
    sig2 = make_sig(k2, payload)

    t0 = 1000.0
    # Before rotation: K1 is valid, K2 is invalid
    assert vault.verify_hmac_signature('webhook_secret', payload, sig1, now=t0) is True
    assert vault.verify_hmac_signature('webhook_secret', payload, sig2, now=t0) is False

    # Rotate to K2 with 3600s grace period
    rot_meta = vault.rotate_secret('webhook_secret', k2, grace_period_seconds=3600.0, now=t0)
    assert rot_meta['status'] == 'rotated'

    # Within grace period (t0 + 120s): both K1 and K2 are valid
    t_grace = t0 + 120.0
    assert vault.verify_hmac_signature('webhook_secret', payload, sig1, now=t_grace) is True
    assert vault.verify_hmac_signature('webhook_secret', payload, sig2, now=t_grace) is True

    # After grace period expires (t0 + 3601s): K2 is valid, old K1 is revoked
    t_expired = t0 + 3601.0
    assert vault.verify_hmac_signature('webhook_secret', payload, sig1, now=t_expired) is False
    assert vault.verify_hmac_signature('webhook_secret', payload, sig2, now=t_expired) is True


def test_webhook_api_zero_downtime_rotation(tmp_path):
    db_path = str(tmp_path / 'vulnforge.db')
    k1 = 'initial_wh_secret_value_12345678'
    k2 = 'new_rotated_wh_secret_value_9876'

    cfg = Config(
        environment='development',
        database_path=db_path,
        webhook_secret=k1,
        admin_token='test-admin-token-1234567890123456'
    )
    store = Store(db_path)
    app = create_app(cfg, store)
    client = TestClient(app, base_url=ORIGIN)

    payload = json.dumps({'zen': 'Keep it simple.', 'hook_id': 123}).encode('utf-8')
    headers_base = {
        'Content-Type': 'application/json',
        'X-GitHub-Delivery': 'del-test-1',
        'X-GitHub-Event': 'ping'
    }

    # 1. Send webhook with K1 signature -> 202 Accepted
    res1 = client.post('/github/webhook', content=payload, headers={**headers_base, 'X-Hub-Signature-256': make_sig(k1, payload)})
    assert res1.status_code == 202

    # 2. Rotate webhook secret in vault
    app.state.vault.rotate_secret('webhook_secret', k2, grace_period_seconds=3600.0)

    # 3. Webhook signed with old K1 still accepted during grace period -> 202 Accepted
    res_old = client.post('/github/webhook', content=payload, headers={**headers_base, 'X-GitHub-Delivery': 'del-test-2', 'X-Hub-Signature-256': make_sig(k1, payload)})
    assert res_old.status_code == 202

    # 4. Webhook signed with new K2 immediately accepted -> 202 Accepted
    res_new = client.post('/github/webhook', content=payload, headers={**headers_base, 'X-GitHub-Delivery': 'del-test-3', 'X-Hub-Signature-256': make_sig(k2, payload)})
    assert res_new.status_code == 202

    # 5. Invalid signature rejected with 403 Forbidden
    res_bad = client.post('/github/webhook', content=payload, headers={**headers_base, 'X-GitHub-Delivery': 'del-test-4', 'X-Hub-Signature-256': 'sha256=invalid'})
    assert res_bad.status_code == 403
