import pytest
from vulnforge.remediation import format_draft_pr


def test_format_draft_pr():
    plan = {
        'plan_id': 'plan-test-draft',
        'repo': 'octocat/hello-world',
        'package': 'urllib3',
        'current_version': '1.26.4',
        'target_version': '1.26.19',
        'upgrade_class': 'patch',
        'file_path': 'requirements.txt',
        'baseline_sha': 'a' * 40,
    }
    advisories = [
        {
            'id': 'GHSA-v845-jxx5-vc9f',
            'summary': 'Cookie leak on redirect',
            'aliases': ['CVE-2023-43804'],
        }
    ]
    validation_evidence = {
        'plan_id': 'plan-test-draft',
        'all_checks_passed': True,
        'evidence_hash': 'sha256:abc123evidence',
        'checks': {
            'lockfile_resolution': {'passed': True},
            'isolated_build_and_test': {'passed': True, 'exit_code': 0, 'duration_seconds': 1.25},
            'post_patch_sast_sca_rescan': {'passed': True},
            'inventory_diff_verification': {'passed': True, 'upgraded_packages': ['urllib3 (1.26.4 -> 1.26.19)']}
        }
    }

    title, body = format_draft_pr(plan, advisories, validation_evidence)

    assert "urllib3 from 1.26.4 to 1.26.19 (Draft)" in title
    # Advisories section
    assert "GHSA-v845-jxx5-vc9f" in body
    assert "Cookie leak on redirect" in body
    assert "CVE-2023-43804" in body
    # Pre vs Post
    assert "Pre-patch baseline" in body
    assert "Post-patch target" in body
    assert "requirements.txt" in body
    # Evidence
    assert "**Isolated Ephemeral Tests**: Passed" in body
    assert "sha256:abc123evidence" in body
    # Risks
    assert "**Upgrade Class**: `patch`" in body
    assert "**Breaking Change Risk**: `low`" in body
    assert "Human Review Checklist" in body
    # Rollback
    assert "Rollback Runbook" in body
    assert "git revert" in body
