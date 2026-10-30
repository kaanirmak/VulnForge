from fastapi.testclient import TestClient
import pytest
from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.network import (
    is_safe_egress_endpoint,
    validate_database_network_isolation,
    IngressRateLimiter
)

ORIGIN = 'http://127.0.0.1:8000'


def test_database_network_isolation_rules():
    # 1. Private RFC 1918 and internal hosts are allowed in production
    validate_database_network_isolation('postgresql://user:pass@10.0.1.5:5432/mydb', environment='production')
    validate_database_network_isolation('postgresql://user:pass@172.20.0.10:5432/mydb', environment='production')
    validate_database_network_isolation('postgresql://user:pass@192.168.1.50:5432/mydb', environment='production')
    validate_database_network_isolation('postgresql://user:pass@db.prod.internal:5432/mydb', environment='production')
    validate_database_network_isolation('postgresql://user:pass@db.cluster.local:5432/mydb', environment='production')
    validate_database_network_isolation('postgresql://user:pass@127.0.0.1:5432/mydb', environment='production')

    # 2. Public host without SSL rejected in production
    with pytest.raises(ValueError, match="is a public endpoint but does not enforce TLS"):
        validate_database_network_isolation('postgresql://user:pass@203.0.113.10:5432/mydb', environment='production')

    with pytest.raises(ValueError, match="is a public endpoint but does not enforce TLS"):
        validate_database_network_isolation('postgresql://user:pass@mydb.cloud.provider.com:5432/mydb', environment='production')

    # 3. Public host with SSL allowed
    validate_database_network_isolation('postgresql://user:pass@mydb.cloud.provider.com:5432/mydb?sslmode=require', environment='production')
    validate_database_network_isolation('postgresql://user:pass@203.0.113.10:5432/mydb?sslmode=verify-full', environment='production')

    # 4. Cloud metadata / link-local addresses strictly forbidden in all environments
    with pytest.raises(ValueError, match="Connection to metadata/link-local address"):
        validate_database_network_isolation('postgresql://user:pass@169.254.169.254:5432/mydb', environment='development')

    with pytest.raises(ValueError, match="Connection to metadata/link-local address"):
        validate_database_network_isolation('postgresql://user:pass@0.0.0.0:5432/mydb', environment='production')


def test_egress_network_ssrf_boundaries():
    # Safe public HTTPS endpoints
    assert is_safe_egress_endpoint('https://api.github.com/repos') is True
    assert is_safe_egress_endpoint('https://api.osv.dev/v1/query') is True
    assert is_safe_egress_endpoint('https://pypi.org/pypi/requests/json') is True

    # Insecure plaintext HTTP forbidden
    assert is_safe_egress_endpoint('http://api.github.com/repos') is False

    # SSRF targets (cloud metadata and private networks) forbidden
    assert is_safe_egress_endpoint('https://169.254.169.254/latest/meta-data/') is False
    assert is_safe_egress_endpoint('https://127.0.0.1:8000/internal') is False
    assert is_safe_egress_endpoint('https://localhost:8000/internal') is False
    assert is_safe_egress_endpoint('https://10.0.0.1/admin') is False
    assert is_safe_egress_endpoint('https://192.168.1.1/admin') is False
    assert is_safe_egress_endpoint('https://service.cluster.local/api') is False


def test_ingress_rate_limiter():
    limiter = IngressRateLimiter(limit=3, window_seconds=60.0)
    client_key = 'test-client-1'

    now = 1000.0
    # Requests 1..3 allowed
    ok1, rem1, _ = limiter.is_allowed(client_key, now=now)
    assert ok1 is True and rem1 == 2

    ok2, rem2, _ = limiter.is_allowed(client_key, now=now + 1.0)
    assert ok2 is True and rem2 == 1

    ok3, rem3, _ = limiter.is_allowed(client_key, now=now + 2.0)
    assert ok3 is True and rem3 == 0

    # Request 4 blocked with retry_after
    ok4, rem4, retry = limiter.is_allowed(client_key, now=now + 3.0)
    assert ok4 is False
    assert rem4 == 0
    assert retry > 0

    # Request after window expiry allowed again
    ok5, rem5, _ = limiter.is_allowed(client_key, now=now + 61.0)
    assert ok5 is True


def test_security_headers_and_tls_ingress(tmp_path):
    db_path = str(tmp_path / 'vulnforge.db')
    cfg = Config(
        environment='development',
        database_path=db_path,
        admin_token='test-admin-token-1234567890123456'
    )
    store = Store(db_path)
    app = create_app(cfg, store)
    client = TestClient(app, base_url=ORIGIN)

    # 1. Normal request receives strict security headers
    res = client.get('/health')
    assert res.status_code == 200
    headers = res.headers
    assert headers.get('X-Content-Type-Options') == 'nosniff'
    assert headers.get('X-Frame-Options') == 'DENY'
    assert headers.get('Referrer-Policy') == 'no-referrer'
    assert 'Content-Security-Policy' in headers
    assert 'X-RateLimit-Limit' in headers
    assert 'X-RateLimit-Remaining' in headers

    # 2. TLS request receives Strict-Transport-Security (HSTS)
    tls_res = client.get('/health', headers={'x-forwarded-proto': 'https'})
    assert tls_res.status_code == 200
    assert 'max-age=63072000' in tls_res.headers.get('Strict-Transport-Security', '')


def test_production_tls_required(tmp_path):
    db_path = str(tmp_path / 'prod_sim.db')
    prod_cfg = Config(
        environment='production',
        database_url='postgresql://op@10.0.0.1:5432/vf_prod',
        customer_database_url='postgresql://cust@10.0.0.1:5432/vf_prod',
        worker_database_url='postgresql://work@10.0.0.1:5432/vf_prod',
        webhook_secret='super_secret_webhook_key_32_characters_prod!',
        admin_token='prod_admin_secret_token_at_least_32_chars_long',
        github_oauth_client_id='prod-oauth-id',
        github_oauth_client_secret='prod-oauth-secret-123456',
        public_origin='https://vulnforge.example.com',
        allow_insecure_local_auth=False
    )
    store = Store(db_path)
    app = create_app(prod_cfg, store)
    client = TestClient(app, base_url='https://vulnforge.example.com')

    # Non-TLS HTTP in production rejected with 403 TLS_REQUIRED
    res = client.get('/health', headers={'x-forwarded-proto': 'http'})
    assert res.status_code == 403
    assert res.json()['error_code'] == 'TLS_REQUIRED'

    # Valid HTTPS in production succeeds
    res_tls = client.get('/health', headers={'x-forwarded-proto': 'https'})
    assert res_tls.status_code == 200
    assert 'Strict-Transport-Security' in res_tls.headers
