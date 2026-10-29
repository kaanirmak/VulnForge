import json
import pytest
from vulnforge.db import Store
from vulnforge.post_merge import (
    verify_post_merge_scan,
    build_rollback_pr_content,
    process_post_merge_scan,
)


class MockGitHub:
    def __init__(self):
        self.prs = []

    async def create_fix_pr(self, repo, installation_id, base, branch, path, old_sha, new_text, title, body):
        self.prs.append({'branch': branch, 'title': title, 'body': body})
        return f"https://github.com/{repo}/pull/101"


def test_verify_post_merge_scan_success():
    pre = [{'key': 'adv1', 'title': 'RCE', 'severity': 'high', 'details': {'advisory_id': 'GHSA-123'}}]
    post = []  # no findings in post-merge scan
    verif = verify_post_merge_scan(
        repo='org/repo',
        merge_sha='a' * 40,
        pre_findings=pre,
        post_findings=post,
        resolved_advisories=['GHSA-123']
    )
    assert verif['success'] is True
    assert verif['resolved_advisories'] == ['GHSA-123']
    assert len(verif['failures']) == 0


def test_verify_post_merge_scan_fails_when_unresolved():
    pre = [{'key': 'adv1', 'title': 'RCE', 'severity': 'high', 'details': {'advisory_id': 'GHSA-123'}}]
    post = [{'key': 'adv1', 'title': 'RCE', 'severity': 'high', 'details': {'advisory_id': 'GHSA-123'}}]
    verif = verify_post_merge_scan(
        repo='org/repo',
        merge_sha='a' * 40,
        pre_findings=pre,
        post_findings=post,
        resolved_advisories=['GHSA-123']
    )
    assert verif['success'] is False
    assert any('still present after merge' in f for f in verif['failures'])


def test_verify_post_merge_scan_fails_on_regression():
    pre = [{'key': 'adv1', 'title': 'RCE', 'severity': 'high', 'details': {'advisory_id': 'GHSA-123'}}]
    # Vulnerability closed, but a new critical SAST issue was introduced by the patch
    post = [{'key': 'sast-eval', 'title': 'Dynamic eval', 'severity': 'critical', 'details': {'rule': 'js-eval'}}]
    verif = verify_post_merge_scan(
        repo='org/repo',
        merge_sha='a' * 40,
        pre_findings=pre,
        post_findings=post,
        resolved_advisories=['GHSA-123']
    )
    assert verif['success'] is False
    assert any('New severe findings introduced' in f for f in verif['failures'])


def test_store_resolve_patch_findings_with_proof(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "org/repo"
    store.save_finding(
        repo=repo,
        key='finding-key-1',
        category='dependency',
        severity='high',
        title='Vulnerable Dep',
        file_path='requirements.txt',
        commit_sha='a' * 40,
        details={'advisory_id': 'GHSA-abc-123'}
    )

    findings = store.list_rows('findings', repo=repo)
    assert len(findings) == 1
    assert findings[0]['status'] == 'open'

    store.resolve_patch_findings_with_proof(
        repo=repo,
        merge_sha='b' * 40,
        pr_url='https://github.com/org/repo/pull/15',
        resolved_advisories=['GHSA-abc-123']
    )

    findings = store.list_rows('findings', repo=repo)
    assert len(findings) == 1
    f = findings[0]
    assert f['status'] == 'resolved'
    details = json.loads(f['details'])
    assert 'closure_proof' in details
    proof = details['closure_proof']
    assert proof['merge_sha'] == 'b' * 40
    assert proof['pr_url'] == 'https://github.com/org/repo/pull/15'
    assert proof['verification_passed'] is True


@pytest.mark.anyio
async def test_process_post_merge_scan_success(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "org/repo"
    store.save_finding(
        repo=repo,
        key='k1',
        category='dependency',
        severity='medium',
        title='Dep issue',
        file_path='requirements.txt',
        commit_sha='a'*40,
        details={'advisory_id': 'GHSA-test'}
    )
    gh = MockGitHub()

    res = await process_post_merge_scan(
        github_client=gh,
        store=store,
        repo=repo,
        installation_id=1,
        base_branch='main',
        pr_number=10,
        merge_sha='m'*40,
        pr_url='https://github.com/org/repo/pull/10',
        resolved_advisories=['GHSA-test'],
        pre_findings=[{'key': 'k1', 'details': {'advisory_id': 'GHSA-test'}}],
        post_findings=[]
    )

    assert res['status'] == 'verified_and_closed'
    assert res['rollback_created'] is False
    assert len(gh.prs) == 0
    f = store.list_rows('findings', repo=repo)[0]
    assert f['status'] == 'resolved'


@pytest.mark.anyio
async def test_process_post_merge_scan_failure_creates_rollback_pr(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "org/repo"
    gh = MockGitHub()

    res = await process_post_merge_scan(
        github_client=gh,
        store=store,
        repo=repo,
        installation_id=1,
        base_branch='main',
        pr_number=10,
        merge_sha='m'*40,
        pr_url='https://github.com/org/repo/pull/10',
        resolved_advisories=['GHSA-test'],
        pre_findings=[],
        post_findings=[{'key': 'new-crit', 'severity': 'critical', 'title': 'SQL injection'}],
        revert_files={'requirements.txt': 'old-requirements-content\n'}
    )

    assert res['status'] == 'verification_failed'
    assert res['rollback_created'] is True
    assert len(gh.prs) == 1
    assert "Security Rollback" in gh.prs[0]['title']
    assert "revert PR #10" in gh.prs[0]['title']
