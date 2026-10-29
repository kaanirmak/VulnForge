import pytest
from vulnforge.db import Store
from vulnforge.remediation import reconcile_and_publish_pr


class MockGitHub:
    def __init__(self):
        self.prs = []
        self.pulls_response = []
        self.ref_exists = False
        self.commits_response = []

    def repo_path(self, repo):
        return f"/repos/{repo}"

    async def request(self, method, path, install_id, json=None):
        if "pulls" in path:
            return self.pulls_response
        if "git/ref" in path:
            if self.ref_exists:
                return {'ref': path}
            raise Exception("404 Not Found")
        if "commits" in path:
            return self.commits_response
        return {}

    async def create_fix_pr(self, repo, installation_id, base, branch, path, old_sha, new_text, title, body):
        self.prs.append((branch, title))
        return f"https://github.com/{repo}/pull/99"


@pytest.mark.anyio
async def test_reconcile_existing_store_record(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    key = "rem-key-1"
    store.save_remediation(repo, key, "https://github.com/my/repo/pull/1")

    gh = MockGitHub()
    res = await reconcile_and_publish_pr(
        gh, store, repo, 123, "main", "vulnforge/fix-1", key,
        "requirements.txt", "oldsha", "newcontent", "Title", "Body"
    )

    assert res['status'] == 'reconciled_existing'
    assert res['pr_url'] == "https://github.com/my/repo/pull/1"
    assert len(gh.prs) == 0  # no new PR created


@pytest.mark.anyio
async def test_reconcile_existing_github_open_pr(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    key = "rem-key-2"
    gh = MockGitHub()
    gh.pulls_response = [{'html_url': 'https://github.com/my/repo/pull/42', 'state': 'open', 'merged_at': None}]

    res = await reconcile_and_publish_pr(
        gh, store, repo, 123, "main", "vulnforge/fix-2", key,
        "requirements.txt", "oldsha", "newcontent", "Title", "Body"
    )

    assert res['status'] == 'reconciled_existing'
    assert res['pr_url'] == 'https://github.com/my/repo/pull/42'
    assert store.has_remediation(repo, key) is True
    assert len(gh.prs) == 0


@pytest.mark.anyio
async def test_reconcile_already_merged(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    key = "rem-key-3"
    gh = MockGitHub()
    gh.pulls_response = [{'html_url': 'https://github.com/my/repo/pull/50', 'state': 'closed', 'merged_at': '2026-10-30T00:00:00Z'}]

    res = await reconcile_and_publish_pr(
        gh, store, repo, 123, "main", "vulnforge/fix-3", key,
        "requirements.txt", "oldsha", "newcontent", "Title", "Body"
    )

    assert res['status'] == 'already_merged'
    assert len(gh.prs) == 0


@pytest.mark.anyio
async def test_reconcile_preserves_human_commits(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    key = "rem-key-4"
    gh = MockGitHub()
    gh.ref_exists = True
    # Human engineer made a commit on the branch
    gh.commits_response = [{
        'author': {'login': 'alice-engineer'},
        'commit': {'committer': {'name': 'Alice Engineer'}}
    }]

    res = await reconcile_and_publish_pr(
        gh, store, repo, 123, "main", "vulnforge/fix-4", key,
        "requirements.txt", "oldsha", "newcontent", "Title", "Body"
    )

    assert res['status'] == 'human_changes_preserved'
    assert res['action_taken'] == 'aborted_to_avoid_overwriting_human_commits'
    assert len(gh.prs) == 0


@pytest.mark.anyio
async def test_clean_pr_creation(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    repo = "my/repo"
    key = "rem-key-new"
    gh = MockGitHub()

    res = await reconcile_and_publish_pr(
        gh, store, repo, 123, "main", "vulnforge/fix-new", key,
        "requirements.txt", "oldsha", "newcontent", "Title", "Body"
    )

    assert res['status'] == 'created'
    assert res['pr_url'] == f"https://github.com/{repo}/pull/99"
    assert len(gh.prs) == 1
    assert store.has_remediation(repo, key) is True
