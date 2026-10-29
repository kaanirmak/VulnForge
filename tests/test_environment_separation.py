import pytest
from vulnforge.config import Config, validate_cross_environment_isolation


def test_environment_values_and_properties():
    dev_cfg = Config(environment='development')
    assert dev_cfg.is_development is True
    assert dev_cfg.is_staging is False
    assert dev_cfg.is_production is False

    staging_cfg = Config(environment='staging')
    assert staging_cfg.is_development is False
    assert staging_cfg.is_staging is True
    assert staging_cfg.is_production is False

    with pytest.raises(ValueError, match="Invalid environment: testing"):
        Config(environment='testing')


def test_production_environment_strict_invariants():
    valid_prod_kwargs = {
        'environment': 'production',
        'database_url': 'postgresql://operator@db.prod.internal:5432/vulnforge',
        'customer_database_url': 'postgresql://customer@db.prod.internal:5432/vulnforge',
        'worker_database_url': 'postgresql://worker@db.prod.internal:5432/vulnforge',
        'webhook_secret': 'super_secure_webhook_secret_32_chars_prod!',
        'admin_token': 'prod_admin_secret_token_at_least_32_chars_long',
        'github_oauth_client_id': 'prod-oauth-id',
        'github_oauth_client_secret': 'prod-oauth-secret-123456',
        'public_origin': 'https://vulnforge.example.com',
        'allow_insecure_local_auth': False
    }

    # 1. Valid production config passes
    prod_cfg = Config(**valid_prod_kwargs)
    assert prod_cfg.is_production is True

    # 2. Insecure local auth forbidden in production
    with pytest.raises(ValueError, match="Insecure local auth is strictly forbidden in production"):
        Config(**{**valid_prod_kwargs, 'allow_insecure_local_auth': True})

    # 3. Missing separated PostgreSQL database URLs
    with pytest.raises(ValueError, match="Production environment requires separated PostgreSQL database URLs"):
        Config(**{**valid_prod_kwargs, 'customer_database_url': ''})

    # 4. Short webhook secret rejected
    with pytest.raises(ValueError, match="requires a high-entropy webhook secret of at least 32 characters"):
        Config(**{**valid_prod_kwargs, 'webhook_secret': 'too_short'})

    # 5. Short admin token rejected
    with pytest.raises(ValueError, match="Production admin token must be at least 32 characters"):
        Config(**{**valid_prod_kwargs, 'admin_token': 'short_token'})

    # 6. Loopback or HTTP public origin rejected in production
    with pytest.raises(ValueError, match="Production public origin must use HTTPS"):
        Config(**{**valid_prod_kwargs, 'public_origin': 'http://127.0.0.1:8000'})

    with pytest.raises(ValueError, match="Production public origin must use HTTPS"):
        Config(**{**valid_prod_kwargs, 'public_origin': 'https://localhost:8000'})


def test_cross_environment_isolation_verification():
    dev = Config(
        environment='development',
        database_path='./data/dev.db',
        webhook_secret='dev_webhook_secret_123',
        admin_token='dev_token_123'
    )
    staging = Config(
        environment='staging',
        database_url='postgresql://staging@staging-db:5432/vf_staging',
        webhook_secret='staging_secret_key_distinct_value_123',
        admin_token='staging_admin_token_distinct_val'
    )
    prod = Config(
        environment='production',
        database_url='postgresql://op@prod-db:5432/vf_prod',
        customer_database_url='postgresql://cust@prod-db:5432/vf_prod',
        worker_database_url='postgresql://work@prod-db:5432/vf_prod',
        webhook_secret='super_secure_webhook_secret_32_chars_prod!',
        admin_token='prod_admin_secret_token_at_least_32_chars_long',
        github_oauth_client_id='prod-oauth-id',
        github_oauth_client_secret='prod-oauth-secret-123456',
        public_origin='https://app.vulnforge.com'
    )

    # Valid isolated configuration
    validate_cross_environment_isolation({
        'development': dev,
        'staging': staging,
        'production': prod
    })

    # Staging sharing production database URL
    leak_db_staging = Config(
        environment='staging',
        database_url='postgresql://op@prod-db:5432/vf_prod',
        webhook_secret='staging_secret_key_distinct_value_123'
    )
    with pytest.raises(ValueError, match="share the same database_url"):
        validate_cross_environment_isolation({
            'staging': leak_db_staging,
            'production': prod
        })

    # Staging sharing production webhook secret
    leak_secret_staging = Config(
        environment='staging',
        database_url='postgresql://staging@staging-db:5432/vf_staging',
        webhook_secret='super_secure_webhook_secret_32_chars_prod!'
    )
    with pytest.raises(ValueError, match="share the same webhook_secret"):
        validate_cross_environment_isolation({
            'staging': leak_secret_staging,
            'production': prod
        })


def test_config_from_env_loads_environment():
    env_vars = {
        'VULNFORGE_ENV': 'staging',
        'WEBHOOK_SECRET': 'test_staging_secret'
    }
    cfg = Config.from_env(env=env_vars)
    assert cfg.environment == 'staging'
    assert cfg.is_staging is True
