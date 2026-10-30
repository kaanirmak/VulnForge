"""Configuration is loaded at runtime, not at module import time."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import os
import re
import json
from urllib.parse import urlsplit

from .privacy import MetadataPolicy, PrivacyError


@dataclass(frozen=True)
class Config:
    environment: str = "development"
    vault: Any = None
    webhook_secret: str = ""
    admin_token: str = field(default='',repr=False)
    operator_credentials: tuple[tuple[str,str],...] = field(default=(),repr=False)
    app_id: str = ""
    private_key_path: str = ""
    database_path: str = "./data/vulnforge.db"
    database_url: str = field(default='',repr=False)
    customer_database_url: str = field(default='',repr=False)
    worker_database_url: str = field(default='',repr=False)
    database_auto_migrate: bool = True
    enable_auto_pr: bool = False
    enable_kev: bool = False
    enable_checks: bool = False
    scan_interval_seconds: int = 900
    github_api_url: str = "https://api.github.com"
    osv_api_url: str = "https://api.osv.dev"
    max_file_bytes: int = 300_000
    scan_mode: str = 'customer_runner'
    allow_managed_source_access: bool = False
    managed_scan_consent_id: str = ''
    intelligence_mode: str = 'disabled'
    allow_external_package_metadata: bool = False
    osv_allowed_packages: tuple[str, ...] = ()
    private_package_patterns: tuple[str, ...] = ()
    operator_report_token: str = field(default='',repr=False)
    github_oauth_client_id: str = ''
    github_oauth_client_secret: str = field(default='',repr=False)
    public_origin: str = ''
    allow_insecure_local_auth: bool = False
    customer_api_preview: bool = False
    github_connection_preview: bool = False
    runner_oidc_preview: bool = False
    runner_trusted_workflows: tuple[str,...] = ()

    def __post_init__(self):
        if self.environment not in ('development', 'staging', 'production'):
            raise ValueError(f"Invalid environment: {self.environment}. Must be one of: development, staging, production")

        if self.environment == 'production':
            if self.allow_insecure_local_auth:
                raise ValueError('Insecure local auth is strictly forbidden in production')
            if not self.database_url or not self.customer_database_url or not self.worker_database_url:
                raise ValueError('Production environment requires separated PostgreSQL database URLs for operator, customer, and worker')
            if not self.webhook_secret or len(self.webhook_secret) < 32:
                raise ValueError('Production environment requires a high-entropy webhook secret of at least 32 characters')
            if self.admin_token and len(self.admin_token) < 32:
                raise ValueError('Production admin token must be at least 32 characters')
            if self.public_origin and (self.public_origin.startswith('http://') or any(h in self.public_origin for h in ('localhost', '127.0.0.1', '::1'))):
                raise ValueError('Production public origin must use HTTPS and cannot be a loopback address')

        if not isinstance(self.operator_credentials,tuple): raise ValueError('Invalid operator credential configuration')
        operators=set();tokens=set()
        for item in self.operator_credentials:
            if (not isinstance(item,tuple) or len(item)!=2 or not all(isinstance(v,str) for v in item) or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{1,63}',item[0]) or
                not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',item[1]) or item[0] in operators or item[1] in tokens):
                raise ValueError('Invalid operator credential configuration')
            operators.add(item[0]);tokens.add(item[1])
        if self.operator_credentials and self.admin_token:
            raise ValueError('Named operator credentials replace the legacy admin token')
        if self.operator_report_token and self.operator_report_token in tokens:
            raise ValueError('Report intake requires an independent credential')
        for url in (self.database_url,self.customer_database_url,self.worker_database_url):
            if url:
                if not url.startswith(('postgresql://','postgres://')):
                    raise ValueError('Database URL must use a PostgreSQL connection URI')
                from .network import validate_database_network_isolation
                validate_database_network_isolation(url, self.environment)
        configured_urls=[url for url in (self.database_url,self.customer_database_url,self.worker_database_url) if url]
        if len(configured_urls)!=len(set(configured_urls)):
            raise ValueError('Operator, customer and worker database URLs must use distinct roles')
        for value in (self.allow_managed_source_access,self.allow_external_package_metadata,
                      self.enable_auto_pr,self.enable_checks,self.enable_kev,self.allow_insecure_local_auth,self.customer_api_preview,self.database_auto_migrate,self.runner_oidc_preview,self.github_connection_preview):
            if type(value) is not bool: raise ValueError('Consent and feature flags must be booleans')
        if self.scan_mode not in ('customer_runner','managed'):
            raise ValueError('Invalid SCAN_MODE')
        if self.scan_mode=='managed' and not self.source_access_allowed:
            raise ValueError('Managed scanning requires explicit source access and a consent reference')
        if self.enable_auto_pr and not self.source_access_allowed:
            raise ValueError('Automatic PRs require the separately enabled managed scan mode')
        if self.operator_report_token and self.operator_report_token==self.admin_token:
            raise ValueError('Operator report token must be independent of ADMIN_TOKEN')
        policy=self.metadata_policy()
        if policy.mode!='disabled': policy.require_endpoint(self.osv_api_url)
        if self.enable_kev and self.intelligence_mode!='public_osv':
            raise ValueError('Public KEV access requires explicitly enabled public intelligence mode')
        if any((self.github_oauth_client_id,self.github_oauth_client_secret,self.public_origin)):
            if not all((self.github_oauth_client_id,self.github_oauth_client_secret,self.public_origin)):
                raise ValueError('OAuth requires a client ID, client secret and fixed public origin')
            if not re.fullmatch(r'[A-Za-z0-9_.-]{3,100}',self.github_oauth_client_id):
                raise ValueError('Invalid OAuth client ID')
            origin=urlsplit(self.public_origin)
            try: origin.port
            except ValueError: raise ValueError('Invalid public origin') from None
            local=(self.allow_insecure_local_auth and origin.hostname in ('localhost','127.0.0.1','::1'))
            if (not origin.hostname or origin.username or origin.password or origin.path or
                origin.query or origin.fragment or (origin.scheme!='https' and not (local and origin.scheme=='http')) or
                any(c.isspace() for c in self.public_origin)):
                raise ValueError('OAuth requires a fixed HTTPS origin without a path or query')
        if self.customer_api_preview and (not self.oauth_enabled or not self.allow_insecure_local_auth or
            urlsplit(self.public_origin).hostname not in ('localhost','127.0.0.1','::1')):
            raise ValueError('Customer API preview requires explicitly enabled loopback development auth')
        if self.github_connection_preview and (not self.customer_api_preview or self.scan_mode!='customer_runner'):
            raise ValueError('GitHub connection preview requires loopback customer-runner mode')
        from .oidc import WORKFLOW
        if (not isinstance(self.runner_trusted_workflows,tuple) or len(self.runner_trusted_workflows)>20 or
            any(not isinstance(ref,str) or not WORKFLOW.fullmatch(ref) or '..' in ref
                for ref in self.runner_trusted_workflows) or
            len(set(self.runner_trusted_workflows))!=len(self.runner_trusted_workflows)):
            raise ValueError('Runner workflows must be exact commit-pinned reusable workflow references')
        if self.runner_oidc_preview and (not self.customer_api_preview or not self.runner_trusted_workflows or
            self.scan_mode!='customer_runner'):
            raise ValueError('Runner identity preview requires loopback customer-runner mode and trusted workflows')

    @property
    def is_production(self) -> bool:
        return self.environment == 'production'

    @property
    def is_staging(self) -> bool:
        return self.environment == 'staging'

    @property
    def is_development(self) -> bool:
        return self.environment == 'development'

    @property
    def oauth_enabled(self):
        return bool(self.github_oauth_client_id and self.github_oauth_client_secret and self.public_origin)

    @property
    def database_target(self):
        return self.database_url or self.database_path

    @property
    def source_access_allowed(self):
        return (self.scan_mode=='managed' and self.allow_managed_source_access is True and
                isinstance(self.managed_scan_consent_id,str) and
                bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}',self.managed_scan_consent_id)))

    def require_source_access(self):
        if not self.source_access_allowed:
            raise PrivacyError('Server source access is disabled; an approved customer runner report is required')

    def metadata_policy(self):
        return MetadataPolicy(self.intelligence_mode,self.allow_external_package_metadata,
                              self.osv_allowed_packages,self.private_package_patterns)

    @classmethod
    def from_env(cls,env=None):
        getenv=os.getenv if env is None else env.get
        def unique_credentials(pairs):
            result={}
            for key,value in pairs:
                if key in result: raise ValueError()
                result[key]=value
            return result
        try:
            raw=json.loads(getenv('OPERATOR_CREDENTIALS','{}'),object_pairs_hook=unique_credentials)
            if not isinstance(raw,dict): raise ValueError()
            credentials=tuple(raw.items())
        except (ValueError,TypeError): raise ValueError('Invalid OPERATOR_CREDENTIALS configuration') from None
        return cls(
            environment=getenv("VULNFORGE_ENV", getenv("ENVIRONMENT", "development")).lower(),
            webhook_secret=getenv("WEBHOOK_SECRET", ""),
            admin_token=getenv("ADMIN_TOKEN", ""),
            operator_credentials=credentials,
            app_id=getenv("GITHUB_APP_ID", ""),
            private_key_path=getenv("GITHUB_PRIVATE_KEY_PATH", ""),
            database_path=getenv("DATABASE_PATH", "./data/vulnforge.db"),
            database_url=getenv('DATABASE_URL',''),
            customer_database_url=getenv('CUSTOMER_DATABASE_URL',''),
            worker_database_url=getenv('WORKER_DATABASE_URL',''),
            database_auto_migrate=getenv('DATABASE_AUTO_MIGRATE','true').lower()=='true',
            enable_auto_pr=getenv("ENABLE_AUTO_PR", "false").lower() == "true",
            enable_kev=getenv("ENABLE_KEV", "false").lower() == "true",
            enable_checks=getenv("ENABLE_CHECKS", "false").lower() == "true",
            scan_interval_seconds=max(60, int(getenv("SCAN_INTERVAL_SECONDS", "900"))),
            github_api_url=getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
            osv_api_url=getenv("OSV_API_URL", "https://api.osv.dev").rstrip("/"),
            scan_mode=getenv('SCAN_MODE','customer_runner'),
            allow_managed_source_access=getenv('ALLOW_MANAGED_SOURCE_ACCESS','false').lower()=='true',
            managed_scan_consent_id=getenv('MANAGED_SCAN_CONSENT_ID',''),
            intelligence_mode=getenv('INTELLIGENCE_MODE','disabled'),
            allow_external_package_metadata=getenv('ALLOW_EXTERNAL_PACKAGE_METADATA','false').lower()=='true',
            osv_allowed_packages=tuple(v.strip() for v in getenv('OSV_ALLOWED_PACKAGES','').split(',') if v.strip()),
            private_package_patterns=tuple(v.strip() for v in getenv('PRIVATE_PACKAGE_PATTERNS','').split(',') if v.strip()),
            operator_report_token=getenv('OPERATOR_REPORT_TOKEN',''),
            github_oauth_client_id=getenv('GITHUB_OAUTH_CLIENT_ID',''),
            github_oauth_client_secret=getenv('GITHUB_OAUTH_CLIENT_SECRET',''),
            public_origin=getenv('PUBLIC_ORIGIN',''),
            allow_insecure_local_auth=getenv('ALLOW_INSECURE_LOCAL_AUTH','false').lower()=='true',
            customer_api_preview=getenv('CUSTOMER_API_PREVIEW','false').lower()=='true',
            github_connection_preview=getenv('GITHUB_CONNECTION_PREVIEW','false').lower()=='true',
            runner_oidc_preview=getenv('RUNNER_OIDC_PREVIEW','false').lower()=='true',
            runner_trusted_workflows=tuple(v.strip() for v in getenv('RUNNER_TRUSTED_WORKFLOWS','').split(',') if v.strip()),
        )

    def private_key(self) -> str:
        if self.vault:
            val = self.vault.get_secret('github_private_key')
            if val:
                return val
        if not self.private_key_path:
            raise ValueError("GITHUB_PRIVATE_KEY_PATH is not configured")
        return Path(self.private_key_path).read_text(encoding="utf-8")


def validate_cross_environment_isolation(configs: dict[str, 'Config']) -> None:
    """Ensure development, staging, and production environments do not share credentials, databases, or keys."""
    envs = list(configs.keys())
    for i in range(len(envs)):
        for j in range(i + 1, len(envs)):
            env1, env2 = envs[i], envs[j]
            c1, c2 = configs[env1], configs[env2]
            # Check database isolation
            if c1.database_url and c1.database_url == c2.database_url:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same database_url")
            if c1.customer_database_url and c1.customer_database_url == c2.customer_database_url:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same customer_database_url")
            if c1.worker_database_url and c1.worker_database_url == c2.worker_database_url:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same worker_database_url")
            # Check secret and key isolation
            if c1.webhook_secret and c1.webhook_secret == c2.webhook_secret:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same webhook_secret")
            if c1.admin_token and c1.admin_token == c2.admin_token:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same admin_token")
            if c1.github_oauth_client_id and c1.github_oauth_client_id == c2.github_oauth_client_id:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same github_oauth_client_id")
            if c1.github_oauth_client_secret and c1.github_oauth_client_secret == c2.github_oauth_client_secret:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same github_oauth_client_secret")
            if c1.operator_report_token and c1.operator_report_token == c2.operator_report_token:
                raise ValueError(f"Environment separation violation: {env1} and {env2} share the same operator_report_token")

