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


def parse_yarn_lock(path: str, content: str) -> tuple[list[Dependency], list[dict]]:
    deps: list[Dependency] = []
    issues: list[dict] = []
    seen: set[tuple[str, str]] = set()

    current_names: list[str] = []
    current_version: str | None = None
    current_resolution: str | None = None
    is_link_or_portal = False

    def finish_block():
        nonlocal current_names, current_version, current_resolution, is_link_or_portal
        if current_names:
            if is_link_or_portal:
                for name in current_names:
                    issues.append({'path': path, 'package': name, 'reason': 'unresolved_or_local_package'})
            elif current_version:
                for name in current_names:
                    real_name = name
                    if current_resolution and '@npm:' in current_resolution:
                        res_clean = current_resolution.strip('"\'')
                        res_pkg = res_clean.split('@npm:')[0].lstrip('/')
                        if res_pkg:
                            real_name = res_pkg
                    pair = (real_name, current_version)
                    if pair not in seen:
                        seen.add(pair)
                        deps.append(Dependency(real_name, current_version, 'npm', path))
        current_names = []
        current_version = None
        current_resolution = None
        is_link_or_portal = False

    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith('#'):
            continue
        if not line.startswith(' ') and not line.startswith('\t') and trimmed.endswith(':'):
            finish_block()
            header = trimmed.rstrip(':')
            if header in ('__metadata', 'version'):
                continue
            for raw_spec in header.split(','):
                spec = raw_spec.strip().strip('"\'')
                if not spec:
                    continue
                # Handle yarn berry alias: e.g. "alias-pkg@npm:target-pkg@^1.0.0"
                if '@npm:' in spec:
                    parts = spec.split('@npm:', 1)
                    target_part = parts[1]
                    if '@' in target_part:
                        pkg_name = target_part.rsplit('@', 1)[0]
                    else:
                        pkg_name = target_part
                elif spec.startswith('@'):
                    parts = spec[1:].split('@', 1)
                    pkg_name = '@' + parts[0]
                else:
                    pkg_name = spec.split('@', 1)[0]
                if pkg_name and pkg_name not in current_names:
                    current_names.append(pkg_name)
        else:
            if trimmed.startswith('version'):
                parts = trimmed.split(None, 1) if ' ' in trimmed else trimmed.split(':', 1)
                if len(parts) == 2:
                    val = parts[1].strip().strip('"\'')
                    if val.startswith(':'):
                        val = val[1:].strip().strip('"\'')
                    current_version = val
            elif trimmed.startswith('resolution:'):
                current_resolution = trimmed.split(':', 1)[1].strip().strip('"\'')
                if any(x in current_resolution for x in ('link:', 'portal:', 'file:')):
                    is_link_or_portal = True
            elif any(trimmed.startswith(k) for k in ('link:', 'portal:', 'file:')):
                is_link_or_portal = True

    finish_block()
    return deps, issues


def parse_pnpm_lock(path: str, content: str) -> tuple[list[Dependency], list[dict]]:
    deps: list[Dependency] = []
    issues: list[dict] = []
    seen: set[tuple[str, str]] = set()

    in_packages = False

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if not line.startswith(' ') and not line.startswith('\t'):
            if stripped.startswith('packages:'):
                in_packages = True
            else:
                in_packages = False
            continue

        if in_packages:
            indent = len(line) - len(line.lstrip())
            if indent == 2 and stripped.endswith(':'):
                key = stripped.rstrip(':').strip('\'"')
                key = key.lstrip('/')
                if 'link:' in key or 'file:' in key:
                    issues.append({'path': path, 'package': key, 'reason': 'unresolved_or_local_package'})
                    continue
                if '(' in key:
                    key = key.split('(', 1)[0]
                if '_' in key and '@' in key:
                    parts = key.split('_')
                    key = parts[0]
                if '@' in key:
                    if key.startswith('@'):
                        scope_parts = key[1:].rsplit('@', 1)
                        if len(scope_parts) == 2:
                            pkg_name = '@' + scope_parts[0]
                            version = scope_parts[1]
                        else:
                            pkg_name, version = key, ''
                    else:
                        pkg_name, version = key.rsplit('@', 1)
                    version = version.split('(')[0].strip()
                    if pkg_name and version:
                        pair = (pkg_name, version)
                        if pair not in seen:
                            seen.add(pair)
                            deps.append(Dependency(pkg_name, version, 'npm', path))

    return deps, issues


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
            if not key or not isinstance(entry,dict):
                continue
            if 'node_modules/' not in key and not entry.get('name'):
                continue
            pkg = entry.get('name') or key.split('node_modules/')[-1]
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
    elif name in ('pnpm-lock.yaml', 'pnpm-lock.yml'):
        p_deps, _ = parse_pnpm_lock(path, content)
        packages.extend(p_deps)
    elif name == 'yarn.lock':
        y_deps, _ = parse_yarn_lock(path, content)
        packages.extend(y_deps)
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
            if key and 'node_modules/' not in key and not item.get('name'):
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
    elif name in ('pnpm-lock.yaml', 'pnpm-lock.yml'):
        if 'lockfileVersion' not in content:
            issues.append({'path': path, 'reason': 'missing_lockfile_inventory'})
        p_deps, p_issues = parse_pnpm_lock(path, content)
        deps.extend(p_deps)
        issues.extend(p_issues)
        if not p_deps and not p_issues and content.strip():
            issues.append({'path': path, 'reason': 'missing_package_inventory'})
    elif name == 'yarn.lock':
        y_deps, y_issues = parse_yarn_lock(path, content)
        deps.extend(y_deps)
        issues.extend(y_issues)
        if not y_deps and not y_issues and content.strip():
            issues.append({'path': path, 'reason': 'missing_package_inventory'})
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
