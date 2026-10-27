"""Privacy boundaries shared by runner reports and outbound intelligence queries."""
from dataclasses import dataclass
from fnmatch import fnmatchcase
import hashlib
import re
from urllib.parse import urlsplit

from .dependencies import Dependency
from .intelligence import package_key
from .scanner import SECRETS


class PrivacyError(RuntimeError):
    """A denied action; messages must never contain the rejected customer input."""


EXTRA_SECRETS = re.compile(
    r'\b(?:sk_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{20,}|'
    r'xox[baprs]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{30,}|'
    r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b'
)


def safe_metadata(value: str) -> str:
    if (any(ord(c) < 32 or ord(c) == 127 for c in value) or
        any(regex.search(value) for _, regex in SECRETS) or EXTRA_SECRETS.search(value)):
        raise ValueError('Sensitive or multiline metadata is forbidden')
    return value


def path_id(relative_path: str) -> str:
    """Stable relative-path pseudonym; a hash is not encryption or anonymization."""
    safe_metadata(relative_path)
    if (not relative_path or len(relative_path)>1024 or relative_path.startswith('/') or
        '\\' in relative_path or ':' in relative_path or
        any(part in ('','.','..') for part in relative_path.split('/'))):
        raise ValueError('A safe relative path is required')
    return 'sha256:'+hashlib.sha256(relative_path.encode()).hexdigest()


def package_identity(ecosystem, name):
    return f'{ecosystem}:{package_key(name,ecosystem)}'


@dataclass(frozen=True)
class MetadataPolicy:
    mode: str = 'disabled'
    external_consent: bool = False
    allowed_packages: tuple[str, ...] = ()
    private_packages: tuple[str, ...] = ()

    def __post_init__(self):
        if self.mode not in ('disabled','public_osv','private_osv'):
            raise ValueError('Invalid intelligence mode')
        if type(self.external_consent) is not bool:
            raise ValueError('Metadata consent must be an explicit boolean')
        if not isinstance(self.allowed_packages,tuple) or not isinstance(self.private_packages,tuple):
            raise ValueError('Package policy lists must be immutable tuples')
        normalized=[]
        for identity in self.allowed_packages:
            safe_metadata(identity)
            if ':' not in identity or any(c in identity for c in '*?[]'):
                raise ValueError('Public package approvals must be exact ecosystem:name identities')
            eco,_,name=identity.partition(':')
            if not name or eco not in ('PyPI','npm','Go','crates.io','Packagist') or ':' in name:
                raise ValueError('Invalid approved package identity')
            normalized.append(package_identity(eco,name))
        object.__setattr__(self,'allowed_packages',tuple(sorted(set(normalized))))
        normalized=[]
        for pattern in self.private_packages:
            safe_metadata(pattern)
            if ':' not in pattern:
                raise ValueError('Private package patterns require ecosystem:name')
            eco,_,name=pattern.partition(':')
            normalized.append(package_identity(eco,name))
        object.__setattr__(self,'private_packages',tuple(normalized))

    def require_endpoint(self, url):
        if self.mode == 'disabled':
            raise PrivacyError('Intelligence queries are disabled by privacy policy')
        parsed=urlsplit(url)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment):
            raise PrivacyError('An explicit HTTPS intelligence endpoint without credentials is required')
        if self.mode=='public_osv':
            if self.external_consent is not True:
                raise PrivacyError('External package metadata sharing requires explicit consent')
            if url.rstrip('/')!='https://api.osv.dev':
                raise PrivacyError('Public intelligence mode only permits the OSV API endpoint')
        elif parsed.hostname.lower() in ('api.osv.dev','osv.dev'):
            raise PrivacyError('Private intelligence mode requires an operator-managed endpoint')

    def require_packages(self, deps: list[Dependency], url):
        # Preflight the entire inventory before the first HTTP request, so a
        # denied package in a later batch cannot leak an earlier partial batch.
        self.require_endpoint(url)
        approved=set(self.allowed_packages)
        for dep in deps:
            identity=package_identity(dep.ecosystem,dep.name)
            safe_metadata(dep.name)
            safe_metadata(dep.version)
            if self.mode=='private_osv': continue
            if (identity not in approved or any(fnmatchcase(identity,pattern) for pattern in self.private_packages)):
                raise PrivacyError('Package metadata is not approved for this external provider')
