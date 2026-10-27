"""Configuration is loaded at runtime, not at module import time."""
from dataclasses import dataclass, field
from pathlib import Path
import os
import re
import json
from urllib.parse import urlsplit

from .privacy import MetadataPolicy, PrivacyError


@dataclass(frozen=True)
class Config:
    webhook_secret: str = ""
    admin_token: str = field(default='',repr=False)
    operator_credentials: tuple[tuple[str,str],...] = field(default=(),repr=False)
    app_id: str = ""
    private_key_path: str = ""
    database_path: str = "./data/vulnforge.db"
    database_url: str = field(default='',repr=False)
    customer_database_url: str = field(default='',repr=False)
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
    runner_oidc_preview: bool = False
    runner_trusted_workflows: tuple[str,...] = ()

    def __post_init__(self):
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
        for url in (self.database_url,self.customer_database_url):
            if url and not url.startswith(('postgresql://','postgres://')):
                raise ValueError('Database URL must use a PostgreSQL connection URI')
        for value in (self.allow_managed_source_access,self.allow_external_package_metadata,
                      self.enable_auto_pr,self.enable_checks,self.enable_kev,self.allow_insecure_local_auth,self.customer_api_preview,self.database_auto_migrate,self.runner_oidc_preview):
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
    def from_env(cls):
        def unique_credentials(pairs):
            result={}
            for key,value in pairs:
                if key in result: raise ValueError()
                result[key]=value
            return result
        try:
            raw=json.loads(os.getenv('OPERATOR_CREDENTIALS','{}'),object_pairs_hook=unique_credentials)
            if not isinstance(raw,dict): raise ValueError()
            credentials=tuple(raw.items())
        except (ValueError,TypeError): raise ValueError('Invalid OPERATOR_CREDENTIALS configuration') from None
        return cls(
            webhook_secret=os.getenv("WEBHOOK_SECRET", ""),
            admin_token=os.getenv("ADMIN_TOKEN", ""),
            operator_credentials=credentials,
            app_id=os.getenv("GITHUB_APP_ID", ""),
            private_key_path=os.getenv("GITHUB_PRIVATE_KEY_PATH", ""),
            database_path=os.getenv("DATABASE_PATH", "./data/vulnforge.db"),
            database_url=os.getenv('DATABASE_URL',''),
            customer_database_url=os.getenv('CUSTOMER_DATABASE_URL',''),
            database_auto_migrate=os.getenv('DATABASE_AUTO_MIGRATE','true').lower()=='true',
            enable_auto_pr=os.getenv("ENABLE_AUTO_PR", "false").lower() == "true",
            enable_kev=os.getenv("ENABLE_KEV", "false").lower() == "true",
            enable_checks=os.getenv("ENABLE_CHECKS", "false").lower() == "true",
            scan_interval_seconds=max(60, int(os.getenv("SCAN_INTERVAL_SECONDS", "900"))),
            github_api_url=os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
            osv_api_url=os.getenv("OSV_API_URL", "https://api.osv.dev").rstrip("/"),
            scan_mode=os.getenv('SCAN_MODE','customer_runner'),
            allow_managed_source_access=os.getenv('ALLOW_MANAGED_SOURCE_ACCESS','false').lower()=='true',
            managed_scan_consent_id=os.getenv('MANAGED_SCAN_CONSENT_ID',''),
            intelligence_mode=os.getenv('INTELLIGENCE_MODE','disabled'),
            allow_external_package_metadata=os.getenv('ALLOW_EXTERNAL_PACKAGE_METADATA','false').lower()=='true',
            osv_allowed_packages=tuple(v.strip() for v in os.getenv('OSV_ALLOWED_PACKAGES','').split(',') if v.strip()),
            private_package_patterns=tuple(v.strip() for v in os.getenv('PRIVATE_PACKAGE_PATTERNS','').split(',') if v.strip()),
            operator_report_token=os.getenv('OPERATOR_REPORT_TOKEN',''),
            github_oauth_client_id=os.getenv('GITHUB_OAUTH_CLIENT_ID',''),
            github_oauth_client_secret=os.getenv('GITHUB_OAUTH_CLIENT_SECRET',''),
            public_origin=os.getenv('PUBLIC_ORIGIN',''),
            allow_insecure_local_auth=os.getenv('ALLOW_INSECURE_LOCAL_AUTH','false').lower()=='true',
            customer_api_preview=os.getenv('CUSTOMER_API_PREVIEW','false').lower()=='true',
            runner_oidc_preview=os.getenv('RUNNER_OIDC_PREVIEW','false').lower()=='true',
            runner_trusted_workflows=tuple(v.strip() for v in os.getenv('RUNNER_TRUSTED_WORKFLOWS','').split(',') if v.strip()),
        )

    def private_key(self) -> str:
        if not self.private_key_path:
            raise ValueError("GITHUB_PRIVATE_KEY_PATH is not configured")
        return Path(self.private_key_path).read_text(encoding="utf-8")
