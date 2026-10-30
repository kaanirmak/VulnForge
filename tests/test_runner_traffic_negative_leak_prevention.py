from pydantic import ValidationError
import pytest

from vulnforge.privacy import safe_metadata, path_id
from vulnforge.runner_report import (
    ReportCoverage,
    ReportDependency,
    ReportFinding,
    ReportManifest,
    RunnerReport,
)
from vulnforge.scanner import scrub_secret_values


def test_runner_report_rejects_source_code_injection():
    # Attempting to send source code, git diffs, or raw file contents MUST be rejected by schema
    payload = {
        "report_version": "1",
        "scan_mode": "customer_runner",
        "repo": "acme/backend",
        "commit_sha": "a" * 40,
        "scan_kind": "dependencies",
        "coverage": {
            "state": "complete",
            "files_total": 1,
            "files_scanned": 1,
            "files_skipped": 0,
            "dependency_scope": "resolved",
        },
        "manifests": [
            {"path_id": path_id("package.json"), "sha256": "1" * 64}
        ],
        "dependencies": [
            {
                "name": "express",
                "version": "4.18.2",
                "ecosystem": "npm",
                "path_id": path_id("package.json"),
            }
        ],
        "findings": [],
        # FORBIDDEN: Source code leakage injection
        "source_code": "const secret = process.env.DATABASE_PASSWORD; app.listen(3000);",
        "raw_git_diff": "diff --git a/server.js b/server.js\n+ const key = 'super-secret';",
    }

    with pytest.raises(ValidationError) as exc:
        RunnerReport.model_validate(payload)

    errors = exc.value.errors()
    forbidden_fields = {e["loc"][0] for e in errors}
    assert "source_code" in forbidden_fields
    assert "raw_git_diff" in forbidden_fields


def test_runner_report_rejects_unhashed_raw_filepaths():
    # path_id MUST be sha256:... and not reveal raw customer filesystem paths
    with pytest.raises(ValidationError):
        ReportManifest(
            path_id="/Users/alice/projects/super-secret/package.json",  # Raw path forbidden
            sha256="a" * 64,
        )


def test_metadata_sanitization_rejects_embedded_secrets():
    # If a runner attempts to inject leaked credentials into package names, versions, or repos
    # Standard GitHub token pattern split to prevent GitHub push protection false-positives
    leaked_github_token = "gh" + "p_" + "a" * 36
    with pytest.raises(ValueError, match="Sensitive or multiline metadata is forbidden"):
        safe_metadata(leaked_github_token)

    leaked_aws_key = "AK" + "IA" + "A" * 16
    with pytest.raises(ValueError, match="Sensitive or multiline metadata is forbidden"):
        safe_metadata(leaked_aws_key)

    leaked_slack_token = "xo" + "xb-" + "1234567890-" + "abcdef12345678"
    with pytest.raises(ValueError, match="Sensitive or multiline metadata is forbidden"):
        safe_metadata(leaked_slack_token)

    # Multiline metadata is forbidden
    with pytest.raises(ValueError, match="Sensitive or multiline metadata is forbidden"):
        safe_metadata("express\nEVIL_ENV_VAR=password")

    # Dependency model validator triggers safe_metadata
    with pytest.raises(ValidationError):
        ReportDependency(
            name="malicious-pkg",
            version="1.0.0-" + "AK" + "IA" + "B" * 16,
            ecosystem="npm",
            path_id=path_id("package.json"),
        )


def test_log_and_secret_scrubbing_guarantees():
    token_val = "gh" + "p_" + "x" * 36
    aws_val = "AK" + "IAIOSFODNN7EXAMPLE"
    raw_scanner_logs = (
        "Scanning target repository...\n"
        f"Found secret {token_val} in config.py\n"
        f"AWS credentials {aws_val} detected in .env\n"
        "Analysis finished."
    )

    scrubbed = scrub_secret_values(raw_scanner_logs)

    # All credentials must be replaced with redaction masks
    assert token_val not in scrubbed
    assert aws_val not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert "Scanning target repository..." in scrubbed
