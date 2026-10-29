"""Manifest and lockfile patch resolver for Python and npm ecosystems."""
import hashlib
import json
import re
from typing import Any
from packaging.version import Version, InvalidVersion
from .dependencies import Dependency

REQ_LINE = re.compile(
    r'^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>\s*==\s*)'
    r'(?P<version>[A-Za-z0-9_.!+-]+)(?P<rest>\s*(?:#.*)?)$',
    re.MULTILINE
)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def patch_python_requirements(source: str, dep: Dependency, target: str) -> str | None:
    try:
        if Version(target) <= Version(dep.version) or Version(target).is_prerelease:
            return None
    except InvalidVersion:
        return None

    matches = [
        m for m in REQ_LINE.finditer(source)
        if m['name'].lower().replace('_', '-') == dep.name.lower().replace('_', '-')
        and m['version'] == dep.version
    ]
    if len(matches) != 1:
        return None
    match = matches[0]
    return source[:match.start('version')] + target + source[match.end('version'):]


def patch_npm_package_json(source: str, dep: Dependency, target: str) -> str | None:
    try:
        if Version(target) <= Version(dep.version) or Version(target).is_prerelease:
            return None
    except InvalidVersion:
        return None

    try:
        data = json.loads(source)
    except Exception:
        return None

    changed = False
    pkg_name = dep.name

    for section in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
        if section in data and isinstance(data[section], dict) and pkg_name in data[section]:
            cur_spec = str(data[section][pkg_name]).strip()
            prefix = ''
            if cur_spec.startswith('^'):
                prefix = '^'
            elif cur_spec.startswith('~'):
                prefix = '~'
            elif cur_spec.startswith('>='):
                prefix = '>='
            data[section][pkg_name] = f"{prefix}{target}"
            changed = True

    if not changed:
        return None

    return json.dumps(data, indent=2) + "\n"


def patch_npm_package_lock(source: str, dep: Dependency, target: str) -> str | None:
    try:
        data = json.loads(source)
    except Exception:
        return None

    pkg_name = dep.name
    changed = False

    # 1. Update lockfile v2/v3 packages map
    packages = data.get('packages')
    if isinstance(packages, dict):
        # Root packages (node_modules/<name>)
        nm_key = f"node_modules/{pkg_name}"
        if nm_key in packages and isinstance(packages[nm_key], dict):
            packages[nm_key]['version'] = target
            resolved = packages[nm_key].get('resolved')
            if isinstance(resolved, str) and f"/{pkg_name}/-/{pkg_name}-" in resolved:
                packages[nm_key]['resolved'] = re.sub(
                    rf"/{re.escape(pkg_name)}/-/{re.escape(pkg_name)}-[^\s/]+\.tgz",
                    f"/{pkg_name}/-/{pkg_name}-{target}.tgz",
                    resolved
                )
            changed = True

        # Root manifest descriptor in packages[""]
        root_desc = packages.get("")
        if isinstance(root_desc, dict):
            for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                if section in root_desc and isinstance(root_desc[section], dict) and pkg_name in root_desc[section]:
                    cur = str(root_desc[section][pkg_name])
                    prefix = '^' if cur.startswith('^') else '~' if cur.startswith('~') else ''
                    root_desc[section][pkg_name] = f"{prefix}{target}"
                    changed = True

    # 2. Update lockfile v1 dependencies tree (and v2 backwards-compat tree)
    dependencies = data.get('dependencies')
    if isinstance(dependencies, dict):
        def _walk_deps(d: dict):
            nonlocal changed
            if pkg_name in d and isinstance(d[pkg_name], dict):
                d[pkg_name]['version'] = target
                resolved = d[pkg_name].get('resolved')
                if isinstance(resolved, str) and f"/{pkg_name}/-/{pkg_name}-" in resolved:
                    d[pkg_name]['resolved'] = re.sub(
                        rf"/{re.escape(pkg_name)}/-/{re.escape(pkg_name)}-[^\s/]+\.tgz",
                        f"/{pkg_name}/-/{pkg_name}-{target}.tgz",
                        resolved
                    )
                changed = True
            for k, v in d.items():
                if isinstance(v, dict) and 'dependencies' in v and isinstance(v['dependencies'], dict):
                    _walk_deps(v['dependencies'])

        _walk_deps(dependencies)

    if not changed:
        return None

    return json.dumps(data, indent=2) + "\n"


def patch_python_lockfile(source: str, dep: Dependency, target: str, filename: str) -> str | None:
    if filename.endswith('.lock') or filename == 'requirements.lock':
        # Similar line replacement for simple requirements.lock
        return patch_python_requirements(source, dep, target)
    if filename == 'Pipfile.lock':
        try:
            data = json.loads(source)
            pkg = dep.name.lower().replace('_', '-')
            for sec in ('default', 'develop'):
                if sec in data and isinstance(data[sec], dict):
                    for k in list(data[sec].keys()):
                        if k.lower().replace('_', '-') == pkg:
                            data[sec][k]['version'] = f"=={target}"
                            return json.dumps(data, indent=4) + "\n"
        except Exception:
            return None
    return None


def resolve_manifest_and_lockfile(
    files: dict[str, Any],
    dep: Dependency,
    target_version: str
) -> dict[str, Any]:
    """Re-resolve manifest and corresponding lockfile for Python and npm patches."""
    ecosystem = dep.ecosystem.lower()
    path = dep.file_path
    filename = path.rsplit('/', 1)[-1]
    dir_prefix = path.rsplit('/', 1)[0] + '/' if '/' in path else ''

    result = {
        'success': False,
        'manifest_path': path,
        'manifest_sha256': None,
        'updated_manifest': None,
        'updated_manifest_sha256': None,
        'lockfile_path': None,
        'lockfile_sha256': None,
        'updated_lockfile': None,
        'updated_lockfile_sha256': None,
        'modified_files': {},
        'diagnostics': []
    }

    file_entry = files.get(path) if isinstance(files, dict) else None
    if not file_entry or not isinstance(file_entry.get('text'), str):
        result['diagnostics'].append(f"Manifest file {path} not found in repository files")
        return result

    manifest_text = file_entry['text']
    result['manifest_sha256'] = _sha256(manifest_text)

    if ecosystem in ('pypi', 'python'):
        patched_manifest = patch_python_requirements(manifest_text, dep, target_version)
        if patched_manifest is None:
            result['diagnostics'].append(f"Failed to patch requirement pin in {path}")
            return result

        result['updated_manifest'] = patched_manifest
        result['updated_manifest_sha256'] = _sha256(patched_manifest)
        result['modified_files'][path] = patched_manifest

        # Check for associated lockfile
        for candidate_lock in ('requirements.lock', 'Pipfile.lock'):
            lock_path = f"{dir_prefix}{candidate_lock}"
            if lock_path in files and isinstance(files[lock_path].get('text'), str):
                orig_lock = files[lock_path]['text']
                patched_lock = patch_python_lockfile(orig_lock, dep, target_version, candidate_lock)
                if patched_lock:
                    result['lockfile_path'] = lock_path
                    result['lockfile_sha256'] = _sha256(orig_lock)
                    result['updated_lockfile'] = patched_lock
                    result['updated_lockfile_sha256'] = _sha256(patched_lock)
                    result['modified_files'][lock_path] = patched_lock
                break

        result['success'] = True
        return result

    elif ecosystem == 'npm':
        if filename == 'package.json':
            manifest_path = path
            lockfile_path = f"{dir_prefix}package-lock.json"
        elif filename == 'package-lock.json':
            lockfile_path = path
            manifest_path = f"{dir_prefix}package.json"
        else:
            result['diagnostics'].append(f"Unsupported npm manifest file {filename}")
            return result

        # Ensure package.json exists and is patched
        pkg_entry = files.get(manifest_path)
        if not pkg_entry or not isinstance(pkg_entry.get('text'), str):
            result['diagnostics'].append(f"package.json at {manifest_path} required for npm resolution")
            return result

        orig_manifest = pkg_entry['text']
        patched_manifest = patch_npm_package_json(orig_manifest, dep, target_version)
        if not patched_manifest:
            result['diagnostics'].append(f"Could not patch dependency {dep.name} in {manifest_path}")
            return result

        result['manifest_path'] = manifest_path
        result['manifest_sha256'] = _sha256(orig_manifest)
        result['updated_manifest'] = patched_manifest
        result['updated_manifest_sha256'] = _sha256(patched_manifest)
        result['modified_files'][manifest_path] = patched_manifest

        # Check and patch package-lock.json if present
        lock_entry = files.get(lockfile_path)
        if lock_entry and isinstance(lock_entry.get('text'), str):
            orig_lock = lock_entry['text']
            patched_lock = patch_npm_package_lock(orig_lock, dep, target_version)
            if patched_lock:
                result['lockfile_path'] = lockfile_path
                result['lockfile_sha256'] = _sha256(orig_lock)
                result['updated_lockfile'] = patched_lock
                result['updated_lockfile_sha256'] = _sha256(patched_lock)
                result['modified_files'][lockfile_path] = patched_lock

        result['success'] = True
        return result

    result['diagnostics'].append(f"Ecosystem {dep.ecosystem} not supported by patch resolver")
    return result
