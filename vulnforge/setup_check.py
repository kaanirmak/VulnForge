"""Offline setup preflight. No provider requests, database writes or secret output."""
import argparse
import json
import os
import re
import stat

from .config import Config

ENV_KEYS=frozenset('''WEBHOOK_SECRET ADMIN_TOKEN OPERATOR_CREDENTIALS GITHUB_APP_ID GITHUB_PRIVATE_KEY_PATH
    DATABASE_PATH DATABASE_URL DATABASE_AUTO_MIGRATE CUSTOMER_DATABASE_URL ENABLE_AUTO_PR ENABLE_CHECKS
    ENABLE_KEV SCAN_INTERVAL_SECONDS GITHUB_API_URL OSV_API_URL SCAN_MODE ALLOW_MANAGED_SOURCE_ACCESS
    MANAGED_SCAN_CONSENT_ID INTELLIGENCE_MODE ALLOW_EXTERNAL_PACKAGE_METADATA OSV_ALLOWED_PACKAGES
    PRIVATE_PACKAGE_PATTERNS OPERATOR_REPORT_TOKEN GITHUB_OAUTH_CLIENT_ID GITHUB_OAUTH_CLIENT_SECRET
    PUBLIC_ORIGIN ALLOW_INSECURE_LOCAL_AUTH CUSTOMER_API_PREVIEW GITHUB_CONNECTION_PREVIEW
    RUNNER_OIDC_PREVIEW RUNNER_TRUSTED_WORKFLOWS GITHUB_APP_KEY_FILE'''.split())


def private_read(path,limit):
    descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(descriptor,'rb') as source:
        info=os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=limit or
            (os.name=='posix' and (info.st_uid!=os.getuid() or info.st_mode&0o077))):
            raise ValueError('A private owner-only regular file is required')
        data=source.read(limit+1)
        if len(data)>limit:raise ValueError('Configuration size limit')
        return data


def read_env(path):
    result={}
    for line in private_read(path,32768).decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        key,separator,value=line.partition('=');key=key.strip();value=value.strip()
        if not separator or key not in ENV_KEYS or key in result or '$' in value or '\x00' in value:
            raise ValueError('Unsupported environment file entry')
        if value.startswith("'"):
            if not value.endswith("'"):raise ValueError('Invalid quoted value')
            value=value[1:-1]
        elif value.startswith('"'):
            value=json.loads(value)
            if not isinstance(value,str):raise ValueError('String value required')
        result[key]=value
    return result


def inspect(cfg):
    key_valid=False
    if cfg.private_key_path:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
            from cryptography.exceptions import UnsupportedAlgorithm
            key=load_pem_private_key(private_read(cfg.private_key_path,65536),password=None)
            key_valid=isinstance(key,RSAPrivateKey) and key.key_size>=2048
        except (OSError,ValueError,TypeError,UnsupportedAlgorithm):pass
    checks={
        'github_app_id':bool(re.fullmatch(r'[1-9][0-9]{0,18}',cfg.app_id)),
        'github_oauth':cfg.oauth_enabled and len(cfg.github_oauth_client_secret)>=20,
        'private_rsa_key':key_valid,
        'loopback_preview':cfg.customer_api_preview and cfg.github_connection_preview,
        'source_gates_closed':cfg.scan_mode=='customer_runner' and not cfg.allow_managed_source_access and not cfg.enable_auto_pr,
        'external_package_sharing_closed':cfg.intelligence_mode=='disabled' and not cfg.allow_external_package_metadata,
        'operator_credentials':bool(cfg.operator_credentials) and not cfg.admin_token,
        'webhook_secret':bool(re.fullmatch(r'[A-Za-z0-9_-]{32,128}',cfg.webhook_secret)),
    }
    return {'local_configuration_ready':all(checks.values()),'checks':checks,
        'callback_urls':[cfg.public_origin+path for path in ('/auth/github/callback','/auth/github/connect/callback')]
            if cfg.public_origin else [],
        'database_kind':'postgresql' if cfg.database_target.startswith(('postgres://','postgresql://')) else 'local_sqlite',
        'database_roles_verified':False,'app_permissions_verified':False,'live_acceptance_verified':False,
        'production_ready':False,'customer_ingestion_ready':False,
        'open_release_gates':['worker_database_and_private_catalog_isolation','verified_runner_baseline',
            'live_provider_and_runner_acceptance','ingress_abuse_limits','secret_store_and_recovery',
            'isolated_patch_validation','independent_security_review']}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--env-file')
    args=parser.parse_args(argv)
    env=dict(os.environ)
    try:
        if args.env_file:env.update(read_env(args.env_file))
        result=inspect(Config.from_env(env))
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError):
        print(json.dumps({'local_configuration_ready':False,'production_ready':False,
                          'missing_environment':[name for name in ('GITHUB_APP_ID','GITHUB_OAUTH_CLIENT_ID',
                            'GITHUB_OAUTH_CLIENT_SECRET','GITHUB_PRIVATE_KEY_PATH') if not env.get(name)],
                          'error':'Invalid, incomplete or insufficiently protected setup; values are not printed.'}))
        return 2
    print(json.dumps(result,indent=2))
    return 0 if result['local_configuration_ready'] else 2


if __name__=='__main__':raise SystemExit(main())
