"""Parse exact locked versions only; intentionally skip ambiguous/unlocked packages."""
import json
import re
import tomllib
from dataclasses import dataclass
from packaging.version import Version, InvalidVersion
from packaging.requirements import Requirement, InvalidRequirement


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    file_path: str


def join_continued_lines(content: str) -> list[tuple[int, str]]:
    raw_lines = content.splitlines()
    logical_lines = []
    curr = []
    start_lineno = 1
    for lineno, line in enumerate(raw_lines, 1):
        stripped = line.strip()
        if not curr:
            start_lineno = lineno
        if stripped.endswith('\\'):
            curr.append(stripped[:-1].strip())
        else:
            if curr:
                curr.append(stripped)
                logical_lines.append((start_lineno, ' '.join(curr)))
                curr = []
            else:
                logical_lines.append((lineno, stripped))
    if curr:
        logical_lines.append((start_lineno, ' '.join(curr)))
    return logical_lines


def parse_python_requirement_line(raw: str) -> tuple[str, str] | None:
    line = re.sub(r'#.*$', '', raw).strip()
    if not line:
        return None
    # Strip --hash and other pip options
    clean = re.sub(r'--hash=\S+', '', line)
    clean = re.sub(r'--hash\s+\S+', '', clean).strip()
    if not clean:
        return None
    try:
        req = Requirement(clean)
        if len(req.specifier) == 1:
            spec = next(iter(req.specifier))
            if spec.operator == '==':
                return req.name, spec.version
    except InvalidRequirement:
        pass
    m = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.!+-]+)', clean)
    if m:
        return m[1], m[2]
    return None


def parse_manifest(path: str, content: str, *, include_resolver=None, _visited=None) -> list[Dependency]:
    name = path.rsplit('/', 1)[-1]
    packages: list[Dependency] = []

    def add(pkg, ver, eco):
        if isinstance(pkg,str) and isinstance(ver,str) and pkg and ver:
            packages.append(Dependency(pkg,ver,eco,path))

    if name == 'requirements.txt' or name.endswith('.txt') or name.endswith('.in'):
        visited = set(_visited or ())
        visited.add(path)
        for _, line in join_continued_lines(content):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.startswith(('-r', '--requirement', '-c', '--constraint')):
                parts = stripped.split(None, 1)
                if len(parts) == 2 and include_resolver:
                    target = parts[1].strip()
                    parent = path.rsplit('/', 1)[0] if '/' in path else ''
                    target_path = f"{parent}/{target}" if parent and not target.startswith('/') else target
                    if target_path not in visited:
                        sub_content = include_resolver(target_path)
                        if sub_content is not None:
                            packages.extend(parse_manifest(target_path, sub_content,
                                                           include_resolver=include_resolver,
                                                           _visited=visited))
                continue
            parsed = parse_python_requirement_line(stripped)
            if parsed:
                add(parsed[0], parsed[1], 'PyPI')
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
    elif name == 'uv.lock':
        obj = tomllib.loads(content)
        for item in obj.get('package',[]):
            if item.get('name') and item.get('version'):
                add(item['name'], item['version'], 'PyPI')
    elif name == 'Pipfile.lock':
        obj = json.loads(content)
        for section in ('default', 'develop'):
            for pkg, info in obj.get(section, {}).items():
                ver = info.get('version', '')
                if ver.startswith('=='):
                    ver = ver[2:]
                if ver:
                    add(pkg, ver, 'PyPI')
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


def inventory_manifest(path: str, content: str, *, include_resolver=None) -> InventoryResult:
    """Extract known versions while retaining every unsupported declaration as coverage debt."""
    issues = []
    name = path.rsplit('/', 1)[-1]
    deps = parse_manifest(path, content, include_resolver=include_resolver)
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
    if name == 'requirements.txt' or (name.startswith('requirements') and name.endswith('.txt')):
        for lineno, raw in join_continued_lines(content):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith(('-r', '--requirement', '-c', '--constraint')):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    target = parts[1].strip()
                    parent = path.rsplit('/', 1)[0] if '/' in path else ''
                    target_path = f"{parent}/{target}" if parent and not target.startswith('/') else target
                    if not include_resolver or include_resolver(target_path) is None:
                        issues.append({'path': path, 'line': lineno, 'reason': 'unresolved_include', 'target': target})
                continue
            if not parse_manifest(path, line):
                issues.append({'path': path, 'line': lineno, 'reason': 'unresolved_requirement'})
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
    elif name in ('poetry.lock', 'Cargo.lock', 'uv.lock'):
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
            if name == 'uv.lock':
                src = item.get('source', {})
                if isinstance(src, dict):
                    if any(k in src for k in ('git', 'directory', 'path', 'editable')) or src.get('type') in ('git', 'directory', 'path', 'editable'):
                        issues.append({'path': path, 'reason': 'unresolved_local_or_git_package'})
    elif name == 'Pipfile.lock':
        obj = json.loads(content)
        if not any(k in obj for k in ('default', 'develop')):
            issues.append({'path': path, 'reason': 'missing_package_inventory'})
        for section in ('default', 'develop'):
            for pkg, info in obj.get(section, {}).items():
                if not isinstance(info, dict) or not info.get('version'):
                    issues.append({'path': path, 'reason': 'missing_package_identity'})
                elif not str(info['version']).startswith('=='):
                    issues.append({'path': path, 'reason': 'non_exact_package_version'})
                if isinstance(info, dict) and any(k in info for k in ('editable', 'file', 'path', 'git')):
                    issues.append({'path': path, 'reason': 'unresolved_local_or_git_package'})
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
