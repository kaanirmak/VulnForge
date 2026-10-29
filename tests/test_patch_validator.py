import json
import pytest
from vulnforge.dependencies import Dependency
from vulnforge.db import Store
from vulnforge.patch_validator import validate_patch_plan


def test_validate_patch_plan_success(tmp_path):
    plan = {
        'plan_id': 'test-plan-1',
        'repo': 'my/repo',
        'package': 'requests',
        'target_version': '2.31.0',
        'baseline_sha': 'a' * 40,
        'file_path': 'requirements.txt',
        'patched_manifest_sha256': 'manifest-sha-123',
        'lockfile_path': None,
        'patched_lockfile_sha256': None,
    }
    original_files = {
        'requirements.txt': {'text': 'requests==2.27.0\npytest==7.0.0\n'}
    }
    patched_files = {
        'requirements.txt': 'requests==2.31.0\npytest==7.0.0\n'
    }

    evidence = validate_patch_plan(
        plan,
        original_files,
        patched_files,
        advisories_for_target=[]
    )

    assert evidence['plan_id'] == 'test-plan-1'
    assert evidence['all_checks_passed'] is True
    assert evidence['evidence_hash'] is not None

    checks = evidence['checks']
    assert checks['lockfile_resolution']['passed'] is True
    assert checks['isolated_build_and_test']['passed'] is True
    assert checks['post_patch_sast_sca_rescan']['passed'] is True
    assert checks['inventory_diff_verification']['passed'] is True
    assert 'requests' in checks['inventory_diff_verification']['upgraded_packages']

    # Test persistence in store
    store = Store(str(tmp_path / "test.db"))
    store.save_patch_validation('my/repo', 'test-plan-1', evidence)

    loaded = store.get_patch_validation('my/repo', 'test-plan-1')
    assert loaded is not None
    assert loaded['plan_id'] == 'test-plan-1'
    assert loaded['all_checks_passed'] is True
    assert loaded['evidence_hash'] == evidence['evidence_hash']


def test_validate_patch_plan_fails_when_target_has_advisories():
    plan = {
        'plan_id': 'test-plan-vuln',
        'repo': 'my/repo',
        'package': 'bad-lib',
        'target_version': '1.0.1',
        'baseline_sha': 'b' * 40,
        'file_path': 'requirements.txt',
        'patched_manifest_sha256': 'sha-xyz',
    }
    original_files = {
        'requirements.txt': {'text': 'bad-lib==1.0.0\n'}
    }
    patched_files = {
        'requirements.txt': 'bad-lib==1.0.1\n'
    }

    evidence = validate_patch_plan(
        plan,
        original_files,
        patched_files,
        advisories_for_target=[{'id': 'GHSA-new-cve'}]
    )

    assert evidence['all_checks_passed'] is False
    assert evidence['checks']['post_patch_sast_sca_rescan']['passed'] is False
    assert evidence['checks']['post_patch_sast_sca_rescan']['sca_advisories'] == ['GHSA-new-cve']


def test_validate_patch_plan_fails_when_test_command_fails():
    import sys
    plan = {
        'plan_id': 'test-plan-broken-test',
        'repo': 'my/repo',
        'package': 'foo',
        'target_version': '2.0.0',
        'baseline_sha': 'c' * 40,
        'file_path': 'requirements.txt',
        'patched_manifest_sha256': 'sha-foo',
    }
    original_files = {'requirements.txt': {'text': 'foo==1.0.0\n'}}
    patched_files = {'requirements.txt': 'foo==2.0.0\n'}

    evidence = validate_patch_plan(
        plan,
        original_files,
        patched_files,
        test_command=[sys.executable, '-c', 'import sys; sys.exit(1)']
    )

    assert evidence['all_checks_passed'] is False
    assert evidence['checks']['isolated_build_and_test']['passed'] is False
    assert evidence['checks']['isolated_build_and_test']['exit_code'] == 1
