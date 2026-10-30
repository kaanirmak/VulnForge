import pytest
from vulnforge.gitlab import GitLabAdapter


def test_gitlab_webhook_token_verification():
    secret = "gl-secret-token-xyz"
    adapter = GitLabAdapter(webhook_secret=secret)

    # Valid token
    assert adapter.verify_webhook_token(secret) is True
    assert adapter.verify_webhook_token(f"  {secret}  ") is True

    # Invalid token
    assert adapter.verify_webhook_token("wrong-secret") is False
    assert adapter.verify_webhook_token(None) is False
    assert adapter.verify_webhook_token("") is False


def test_gitlab_push_event_parsing():
    adapter = GitLabAdapter()
    payload = {
        "project": {"path_with_namespace": "gitlab-org/gitlab-runner", "default_branch": "main"},
        "ref": "refs/heads/main",
        "before": "0" * 40,
        "after": "a" * 40,
        "commits": [{"id": "a" * 40}],
    }
    job = adapter.parse_webhook_event("Push Hook", payload)
    assert job["provider"] == "gitlab"
    assert job["event"] == "push"
    assert job["repo"] == "gitlab-org/gitlab-runner"
    assert job["after"] == "a" * 40
    assert job["deleted"] is False


def test_gitlab_branch_deletion_parsing():
    adapter = GitLabAdapter()
    payload = {
        "project": {"path_with_namespace": "group/subproject", "default_branch": "main"},
        "ref": "refs/heads/feature-old",
        "before": "b" * 40,
        "after": "0" * 40,
        "commits": [],
    }
    job = adapter.parse_webhook_event("Push Hook", payload)
    assert job["deleted"] is True


def test_gitlab_merge_request_parsing():
    adapter = GitLabAdapter()
    payload = {
        "project": {"path_with_namespace": "team/backend-api", "default_branch": "main"},
        "object_attributes": {
            "action": "open",
            "iid": 42,
            "target_branch": "main",
            "last_commit": {"id": "c" * 40},
        },
    }
    job = adapter.parse_webhook_event("Merge Request Hook", payload)
    assert job["event"] == "merge_request"
    assert job["mr_iid"] == 42
    assert job["sha"] == "c" * 40
    assert job["target_branch"] == "main"


def test_gitlab_pipeline_hook_parsing():
    adapter = GitLabAdapter()
    payload = {
        "project": {"path_with_namespace": "corp/service", "default_branch": "main"},
        "object_attributes": {
            "id": 1050,
            "status": "success",
            "sha": "d" * 40,
        },
    }
    job = adapter.parse_webhook_event("Pipeline Hook", payload)
    assert job["event"] == "pipeline"
    assert job["pipeline_id"] == 1050
    assert job["status"] == "success"


def test_gitlab_oauth_url_and_mr_note_formatting():
    adapter = GitLabAdapter(
        gitlab_url="https://gitlab.example.com",
        oauth_client_id="test-gl-client-id",
    )
    url = adapter.build_oauth_authorize_url(
        redirect_uri="https://vf.example.com/auth/gitlab/callback",
        state="state123",
    )
    assert "https://gitlab.example.com/oauth/authorize" in url
    assert "client_id=test-gl-client-id" in url
    assert "state=state123" in url

    # Clean note
    clean_note = adapter.format_mr_vulnerability_note([])
    assert "No vulnerabilities detected" in clean_note

    # Findings note
    findings = [
        {"package": "lodash", "severity": "critical", "advisory_id": "CVE-2021-23337", "recommended_version": "4.17.21"}
    ]
    findings_note = adapter.format_mr_vulnerability_note(findings)
    assert "CRITICAL" in findings_note
    assert "`lodash`" in findings_note
    assert "CVE-2021-23337" in findings_note
