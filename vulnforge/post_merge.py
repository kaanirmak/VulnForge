"""Post-merge verification, finding closure proofs, and automated rollback PR generation."""
import json
import time
from typing import Any


def verify_post_merge_scan(
    repo: str,
    merge_sha: str,
    pre_findings: list[dict],
    post_findings: list[dict],
    resolved_advisories: list[str]
) -> dict[str, Any]:
    """Verify that post-merge scan closed expected advisories without introducing regressions."""
    failures = []
    resolved_set = set(resolved_advisories)

    # 1. Verify target advisories are no longer in post_findings
    post_advisories = set()
    for f in post_findings:
        det = f.get('details') or {}
        if isinstance(det, str):
            try: det = json.loads(det)
            except Exception: det = {}
        adv_id = det.get('advisory_id') or det.get('rule') or f.get('key')
        if adv_id:
            post_advisories.add(adv_id)

    still_open = resolved_set.intersection(post_advisories)
    if still_open:
        failures.append(f"Target advisories still present after merge: {sorted(still_open)}")

    # 2. Check for newly introduced high/critical findings (regressions)
    pre_keys = {f.get('key') for f in pre_findings}
    new_regressions = []
    for f in post_findings:
        if f.get('key') not in pre_keys and f.get('severity') in ('critical', 'high'):
            new_regressions.append(f"{f.get('severity')}:{f.get('title')}")

    if new_regressions:
        failures.append(f"New severe findings introduced by merge: {new_regressions}")

    success = len(failures) == 0
    return {
        'repo': repo,
        'merge_sha': merge_sha,
        'success': success,
        'failures': failures,
        'resolved_advisories': sorted(resolved_set - post_advisories),
        'timestamp': time.time()
    }


def build_rollback_pr_content(
    repo: str,
    pr_number: int,
    merge_sha: str,
    failures: list[str],
    revert_files: dict[str, str]
) -> tuple[str, str]:
    """Create title and markdown body for a rollback PR."""
    title = f"⚠️ Security Rollback: revert PR #{pr_number} due to post-merge verification failure"
    failure_bullets = "\n".join(f"- {fail}" for fail in failures)
    revert_list = "\n".join(f"- `{path}`" for path in sorted(revert_files.keys()))

    body = f"""## ⚠️ Automated Security Rollback Request
Post-merge verification of PR #{pr_number} at commit `{merge_sha}` failed automated security checks.

### ❌ Verification Failures Detected
{failure_bullets}

### 🔄 Restored Files
The following files are reverted to their pre-patch state:
{revert_list}

### 🛠️ Required Action
- [ ] Review regression findings
- [ ] Investigate why upstream patch introduced unexpected issues
- [ ] Merge this rollback PR if immediate remediation in production is required
"""
    return title, body


async def process_post_merge_scan(
    github_client: Any,
    store: Any,
    repo: str,
    installation_id: int,
    base_branch: str,
    pr_number: int,
    merge_sha: str,
    pr_url: str,
    resolved_advisories: list[str],
    pre_findings: list[dict],
    post_findings: list[dict],
    revert_files: dict[str, str] | None = None
) -> dict[str, Any]:
    """Process post-merge results: close verified findings or trigger rollback PR on failure."""
    verif = verify_post_merge_scan(
        repo=repo,
        merge_sha=merge_sha,
        pre_findings=pre_findings,
        post_findings=post_findings,
        resolved_advisories=resolved_advisories
    )

    if verif['success']:
        # Record finding closure proofs in store
        store.resolve_patch_findings_with_proof(
            repo=repo,
            merge_sha=merge_sha,
            pr_url=pr_url,
            resolved_advisories=resolved_advisories
        )
        store.audit_event(repo, None, 'system', 'post_merge_verification_passed', {
            'merge_sha': merge_sha,
            'pr_url': pr_url,
            'resolved_advisories': resolved_advisories
        })
        return {
            'status': 'verified_and_closed',
            'rollback_created': False,
            'verification': verif
        }

    # Verification failed: create automated rollback PR if revert files provided
    rollback_url = None
    if revert_files and github_client:
        title, body = build_rollback_pr_content(
            repo=repo,
            pr_number=pr_number,
            merge_sha=merge_sha,
            failures=verif['failures'],
            revert_files=revert_files
        )
        revert_branch = f"vulnforge/revert/pr-{pr_number}-{int(time.time())}"
        first_file = next(iter(revert_files.keys()))
        first_content = revert_files[first_file]
        try:
            rollback_url = await github_client.create_fix_pr(
                repo=repo,
                installation_id=installation_id,
                base=base_branch,
                branch=revert_branch,
                path=first_file,
                old_sha=merge_sha,
                new_text=first_content,
                title=title,
                body=body
            )
        except Exception:
            rollback_url = None

    store.audit_event(repo, None, 'system', 'post_merge_verification_failed', {
        'merge_sha': merge_sha,
        'pr_url': pr_url,
        'failures': verif['failures'],
        'rollback_pr_url': rollback_url
    })

    return {
        'status': 'verification_failed',
        'rollback_created': bool(rollback_url),
        'rollback_url': rollback_url,
        'verification': verif
    }
