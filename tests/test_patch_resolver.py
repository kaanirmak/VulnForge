import json
import pytest
from vulnforge.dependencies import Dependency
from vulnforge.patch_resolver import (
    patch_python_requirements,
    patch_npm_package_json,
    patch_npm_package_lock,
    resolve_manifest_and_lockfile,
)
from vulnforge.remediation import build_patch_plan


def test_patch_python_requirements():
    dep = Dependency('requests', '2.28.0', 'PyPI', 'requirements.txt')
    src = "flask==2.2.0\nrequests==2.28.0 # pinned\npytest==7.1.0\n"
    patched = patch_python_requirements(src, dep, '2.31.0')
    assert patched == "flask==2.2.0\nrequests==2.31.0 # pinned\npytest==7.1.0\n"

    # Downgrade or prerelease rejected
    assert patch_python_requirements(src, dep, '2.20.0') is None
    assert patch_python_requirements(src, dep, '2.32.0rc1') is None


def test_patch_npm_package_json():
    dep = Dependency('express', '4.17.1', 'npm', 'package.json')
    src = json.dumps({
        "name": "my-app",
        "dependencies": {
            "express": "^4.17.1",
            "lodash": "^4.17.21"
        }
    }, indent=2) + "\n"

    patched = patch_npm_package_json(src, dep, '4.21.0')
    assert patched is not None
    data = json.loads(patched)
    assert data["dependencies"]["express"] == "^4.21.0"
    assert data["dependencies"]["lodash"] == "^4.17.21"


def test_patch_npm_package_lock_v2():
    dep = Dependency('express', '4.17.1', 'npm', 'package-lock.json')
    lock_data = {
        "name": "my-app",
        "lockfileVersion": 2,
        "packages": {
            "": {
                "name": "my-app",
                "dependencies": {
                    "express": "^4.17.1"
                }
            },
            "node_modules/express": {
                "version": "4.17.1",
                "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                "integrity": "sha512-old"
            }
        },
        "dependencies": {
            "express": {
                "version": "4.17.1",
                "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
            }
        }
    }
    src = json.dumps(lock_data, indent=2) + "\n"

    patched = patch_npm_package_lock(src, dep, '4.21.0')
    assert patched is not None
    res = json.loads(patched)
    assert res["packages"]["node_modules/express"]["version"] == "4.21.0"
    assert "express-4.21.0.tgz" in res["packages"]["node_modules/express"]["resolved"]
    assert res["packages"][""]["dependencies"]["express"] == "^4.21.0"
    assert res["dependencies"]["express"]["version"] == "4.21.0"
    assert "express-4.21.0.tgz" in res["dependencies"]["express"]["resolved"]


def test_resolve_manifest_and_lockfile_python():
    dep = Dependency('urllib3', '1.26.4', 'PyPI', 'requirements.txt')
    files = {
        'requirements.txt': {'text': 'urllib3==1.26.4\n'},
        'requirements.lock': {'text': 'urllib3==1.26.4\n'}
    }
    result = resolve_manifest_and_lockfile(files, dep, '1.26.19')
    assert result['success'] is True
    assert 'urllib3==1.26.19\n' == result['updated_manifest']
    assert result['lockfile_path'] == 'requirements.lock'
    assert 'urllib3==1.26.19\n' == result['updated_lockfile']


def test_resolve_manifest_and_lockfile_npm():
    dep = Dependency('lodash', '4.17.20', 'npm', 'package.json')
    files = {
        'package.json': {'text': json.dumps({"dependencies": {"lodash": "4.17.20"}}, indent=2) + "\n"},
        'package-lock.json': {'text': json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}}, indent=2) + "\n"}
    }
    result = resolve_manifest_and_lockfile(files, dep, '4.17.21')
    assert result['success'] is True
    assert result['lockfile_path'] == 'package-lock.json'
    assert '4.17.21' in result['updated_manifest']
    assert '4.17.21' in result['updated_lockfile']


def test_patch_plan_with_npm():
    dep = Dependency('lodash', '4.17.20', 'npm', 'package.json')
    policy = {
        'enabled': True,
        'repo': 'my/repo',
        'connection_id': 'conn1',
        'organization_id': 'org1',
        'allowed_packages': ['lodash'],
        'allowed_files': ['package.json', 'package-lock.json']
    }
    files = {
        'package.json': {'text': json.dumps({"dependencies": {"lodash": "^4.17.20"}}, indent=2) + "\n"},
        'package-lock.json': {'text': json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}}, indent=2) + "\n"}
    }
    plan = build_patch_plan(
        'my/repo', 'main', 'a'*40, policy, files, dep,
        advisories=[{'id': 'GHSA-35jh-r3h4-6jhm'}],
        recommendation={'status': 'candidate_verified', 'recommended_version': '4.17.21'}
    )
    assert plan is not None
    assert plan['target_version'] == '4.17.21'
    assert plan['lockfile_path'] == 'package-lock.json'
    assert plan['patched_manifest_sha256'] is not None
    assert plan['patched_lockfile_sha256'] is not None
    assert 'lockfile_resolver_required' not in plan['blockers']
