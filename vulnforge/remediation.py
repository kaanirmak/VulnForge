"""Conservative, opt-in automatic draft-PR builder (never merges)."""
import hashlib
import re
from packaging.version import Version, InvalidVersion
from .dependencies import Dependency
from .osv import fixed_version


# Only exact, unadorned requirement pins can be safely replaced here.
REQ_LINE = re.compile(r'^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>\s*==\s*)'
                      r'(?P<version>[A-Za-z0-9_.!+-]+)(?P<rest>\s*(?:#.*)?)$', re.MULTILINE)


def patched_requirement(source: str, dep: Dependency, target: str) -> str | None:
    if dep.file_path.rsplit('/',1)[-1]!='requirements.txt' or dep.ecosystem!='PyPI':
        return None
    try:
        if Version(target) <= Version(dep.version) or Version(target).is_prerelease:
            return None
    except InvalidVersion:
        return None
    matches=[m for m in REQ_LINE.finditer(source) if m['name'].lower().replace('_','-') == dep.name.lower().replace('_','-')
             and m['version']==dep.version]
    if len(matches)!=1:
        return None
    match=matches[0]
    return source[:match.start('version')]+target+source[match.end('version'):]


def candidate_version(dep: Dependency, advisories: list[dict]):
    """Choose a version that is >= every known fixed version for package."""
    versions=[]
    for a in advisories:
        v=fixed_version(dep,a)
        if not v:
            return None
        versions.append(Version(v))
    return str(max(versions)) if versions else None


def remediation_key(path: str, dep: Dependency, target: str):
    return hashlib.sha256(f'{path}:{dep.name}:{dep.version}->{target}'.encode()).hexdigest()[:24]


def branch_for(dep: Dependency, key: str):
    safe=re.sub(r'[^a-z0-9-]+','-',dep.name.lower())[:35].strip('-')
    return f'vulnforge/security/{safe}-{key[:10]}'
