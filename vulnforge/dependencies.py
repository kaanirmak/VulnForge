"""Parse exact locked versions only; intentionally skip ambiguous/unlocked packages."""
import json
import re
import tomllib
from dataclasses import dataclass
from packaging.version import Version, InvalidVersion


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    file_path: str


def parse_manifest(path: str, content: str) -> list[Dependency]:
    name = path.rsplit('/', 1)[-1]
    packages: list[Dependency] = []

    def add(pkg, ver, eco):
        if isinstance(pkg,str) and isinstance(ver,str) and pkg and ver:
            packages.append(Dependency(pkg,ver,eco,path))

    if name == 'requirements.txt':
        for line in content.splitlines():
            line = line.strip()
            m = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.!+-]+)(?:\s*(?:#.*)?)?$',line)
            if m: add(m[1],m[2],'PyPI')
    elif name == 'package-lock.json':
        obj = json.loads(content)
        # lockfile v2/v3: packages contains transitive resolved versions.
        for key, entry in obj.get('packages',{}).items():
            if not key or 'node_modules/' not in key or not isinstance(entry,dict):
                continue
            pkg = key.split('node_modules/')[-1]
            if entry.get('version') and not entry.get('link'):
                add(pkg,entry['version'],'npm')
        # Old lockfile v1: recursively walk dependency tree.
        if not obj.get('packages'):
            def walk(deps):
                for pkg, info in deps.items():
                    if isinstance(info,dict):
                        add(pkg,info.get('version'),'npm')
                        walk(info.get('dependencies',{}))
            walk(obj.get('dependencies',{}))
    elif name == 'poetry.lock':
        obj = tomllib.loads(content)
        for item in obj.get('package',[]):
            add(item.get('name'),item.get('version'),'PyPI')
    elif name == 'Cargo.lock':
        obj = tomllib.loads(content)
        for item in obj.get('package',[]):
            if item.get('source','').startswith('registry+'):
                add(item.get('name'),item.get('version'),'crates.io')
    elif name == 'composer.lock':
        obj = json.loads(content)
        for item in obj.get('packages',[])+obj.get('packages-dev',[]):
            add(item.get('name'),str(item.get('version','')).lstrip('v'),'Packagist')
    elif name == 'go.mod':
        in_block=False
        for line in content.splitlines():
            line=line.split('//',1)[0].strip()
            if line.startswith('require ('): in_block=True; continue
            if in_block and line==')': in_block=False; continue
            if line.startswith('require '): line=line[len('require '):]
            elif not in_block: continue
            m=re.match(r'^([^\s()]+)\s+(v[^\s]+)$',line)
            if m: add(m[1],m[2],'Go')
    return list(dict.fromkeys(packages))


@dataclass
class InventoryResult:
    dependencies: list[Dependency]
    issues: list[dict]


def inventory_manifest(path: str, content: str) -> InventoryResult:
    """Extract known versions while retaining every unsupported declaration as coverage debt."""
    issues = []
    name = path.rsplit('/', 1)[-1]
    deps = parse_manifest(path, content)
    valid=[]
    for dep in deps:
        exact=True
        if dep.ecosystem=='PyPI':
            try: Version(dep.version)
            except InvalidVersion: exact=False
        elif dep.ecosystem in ('npm','crates.io','Packagist'):
            exact=bool(re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?',dep.version))
        if exact: valid.append(dep)
        else: issues.append({'path':path,'reason':'non_exact_package_version'})
    deps=valid
    if name == 'requirements.txt':
        for n, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if not parse_manifest(path, line):
                issues.append({'path': path, 'line': n, 'reason': 'unresolved_requirement'})
        # Exact requirement pins do not establish the transitive dependency graph.
        issues.append({'path': path, 'reason': 'transitive_graph_unavailable'})
    elif name == 'go.mod':
        issues.append({'path': path, 'reason': 'declared_modules_only_no_resolved_build_list'})
    elif name == 'package-lock.json':
        obj = json.loads(content)
        if not isinstance(obj, dict) or not any(k in obj for k in ('packages', 'dependencies')):
            issues.append({'path': path, 'reason': 'missing_lockfile_inventory'})
        for key, item in obj.get('packages', {}).items():
            if key and (not isinstance(item, dict) or not item.get('version') or item.get('link')):
                issues.append({'path': path, 'reason': 'unresolved_or_local_package'})
            if key and 'node_modules/' not in key:
                issues.append({'path':path,'reason':'workspace_package_not_registry_resolved'})
        if not obj.get('packages'):
            def check_tree(tree):
                for item in tree.values():
                    if not isinstance(item,dict) or not item.get('version'):
                        issues.append({'path':path,'reason':'unresolved_or_local_package'})
                    elif item.get('dependencies'):
                        check_tree(item['dependencies'])
            check_tree(obj.get('dependencies',{}))
        if obj.get('lockfileVersion') not in (1, 2, 3):
            issues.append({'path': path, 'reason': 'unsupported_lockfile_version'})
    elif name in ('poetry.lock', 'Cargo.lock'):
        obj = tomllib.loads(content)
        if 'package' not in obj:
            issues.append({'path': path, 'reason': 'missing_package_inventory'})
        for item in obj.get('package', []):
            if not item.get('name') or not item.get('version'):
                issues.append({'path': path, 'reason': 'missing_package_identity'})
            if name == 'Cargo.lock' and not item.get('source', '').startswith('registry+'):
                issues.append({'path': path, 'reason': 'unresolved_local_or_git_package'})
            if name == 'poetry.lock' and item.get('source',{}).get('type') in ('git','directory','file','url'):
                issues.append({'path':path,'reason':'unresolved_local_or_git_package'})
    elif name == 'composer.lock':
        obj = json.loads(content)
        if 'packages' not in obj:
            issues.append({'path': path, 'reason': 'missing_package_inventory'})
        for item in obj.get('packages', []) + obj.get('packages-dev', []):
            if not item.get('name') or not item.get('version'):
                issues.append({'path': path, 'reason': 'missing_package_identity'})
    else:
        issues.append({'path': path, 'reason': 'unsupported_manifest'})
    return InventoryResult(deps, issues)
