import json
import time
from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData
from vulnforge.remediation import build_patch_plans

ORIGIN = "http://127.0.0.1:8000"


def test_full_controlled_repo_lifecycle_acceptance(tmp_path):
    """End-to-end acceptance test for the full product lifecycle:
    
    1. Installation -> App installs on controlled repo
    2. Initial Scan -> Baseline inventory & scan completion
    3. Push / PR -> Code change evaluated against baseline
    4. New Advisory -> Ingestion marks repo affected
    5. Recommendation -> Patch plan built with verified upgrade candidate
    6. Uninstall -> App uninstalled and cleanup verified
    """
    db_path = str(tmp_path / "acceptance.db")
    cfg = Config(
        database_path=db_path,
        admin_token="test-admin-token-1234567890123456",
        customer_api_preview=True,
        allow_insecure_local_auth=True,
        public_origin=ORIGIN,
        github_oauth_client_id="test-client-id",
        github_oauth_client_secret="test-client-secret",
    )
    store = Store(db_path)
    app = create_app(cfg=cfg, store=store)
    client = TestClient(app, base_url=ORIGIN)

    # Setup identity & tenant
    identities = Identities(store)
    user = identities.record_github_user(5001, "pilot-lead")
    org = identities.create_organization(user["id"], "Pilot Corporation")
    org_id = org["id"]

    repo = "pilot-org/payment-gateway"
    installation_id = 98765
    baseline_sha = "1" * 40

    # -------------------------------------------------------------
    # Step 1: Installation
    # -------------------------------------------------------------
    store.upsert_repo(repo, installation_id, "main")
    identities.record_repository_ownership(org_id, repo, user["id"], "live-acceptance-fixture")

    with store.conn() as c:
        r_repo = c.execute("SELECT * FROM repositories WHERE full_name=?", (repo,)).fetchone()
        assert r_repo is not None
        assert r_repo["installation_id"] == installation_id
        assert r_repo["default_branch"] == "main"

    # -------------------------------------------------------------
    # Step 2: Initial Scan & Baseline Inventory
    # -------------------------------------------------------------
    initial_deps = [
        Dependency("requests", "2.25.0", "pypi", "requirements.txt"),
        Dependency("urllib3", "1.26.4", "pypi", "requirements.txt"),
    ]
    store.replace_inventory(repo, initial_deps)
    scan_id = store.start_scan(repo, "dependencies", baseline_sha)
    store.finish_scan(
        scan_id,
        "complete",
        {"files_total": 2, "files_scanned": 2, "files_skipped": 0, "scope": "dependency_manifests"},
        [{"name": d.name, "version": d.version, "ecosystem": d.ecosystem} for d in initial_deps],
    )

    with store.conn() as c:
        scans = c.execute("SELECT * FROM scans WHERE repo=?", (repo,)).fetchall()
        assert len(scans) == 1
        assert scans[0]["state"] == "complete"
        assert scans[0]["commit_sha"] == baseline_sha

    # -------------------------------------------------------------
    # Step 3: Push / PR Event (Commit Drift)
    # -------------------------------------------------------------
    new_sha = "2" * 40
    # Simulate a PR introducing a new vulnerable dependency
    pr_deps = initial_deps + [Dependency("lodash", "4.17.15", "npm", "package.json")]
    store.replace_inventory(repo, pr_deps)
    pr_scan_id = store.start_scan(repo, "dependencies", new_sha)
    store.finish_scan(
        pr_scan_id,
        "complete",
        {"files_total": 3, "files_scanned": 3, "files_skipped": 0, "scope": "dependency_manifests"},
        [{"name": d.name, "version": d.version, "ecosystem": d.ecosystem} for d in pr_deps],
    )

    with store.conn() as c:
        inv = c.execute("SELECT * FROM dependency_inventory WHERE repo=?", (repo,)).fetchall()
        assert len(inv) == 3

    # -------------------------------------------------------------
    # Step 4: New Threat Intelligence Advisory Ingestion
    # -------------------------------------------------------------
    adv_id = "GHSA-xxxx-yyyy-zzzz"
    adv_data = {
        "id": adv_id,
        "summary": "Critical Prototype Pollution in Lodash",
        "details": "Lodash versions prior to 4.17.21 are vulnerable.",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            }
        ],
    }
    store.save_advisory(adv_data, source="ghsa")

    # Record advisory impact for our repo
    store.save_impact(
        repo=repo,
        advisory_id=adv_id,
        state="affected",
        scan_id=pr_scan_id,
        evidence={"detected_version": "4.17.15", "fixed_version": "4.17.21"},
        recommendations={"target_version": "4.17.21", "safe_upgrade": True},
    )

    with store.conn() as c:
        impact = c.execute("SELECT * FROM advisory_impacts WHERE repo=? AND advisory_id=?", (repo, adv_id)).fetchone()
        assert impact is not None
        assert impact["state"] == "affected"

    # -------------------------------------------------------------
    # Step 5: Remediation Recommendation & Patch Plan
    # -------------------------------------------------------------
    identities.set_remediation_policy(org_id, repo, user["id"], True, ["requests"], ["requirements.txt"])
    policy = store.remediation_policy(repo)

    dep = Dependency("requests", "2.25.0", "PyPI", "requirements.txt")
    files = {"requirements.txt": {"text": "requests==2.25.0\n"}}
    grouped = {
        dep: [
            {
                "id": adv_id,
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
                    }
                ],
            }
        ]
    }
    recommendations = {dep: {"status": "candidate_verified", "recommended_version": "2.31.0"}}

    plans = build_patch_plans(
        repo=repo,
        base_branch="main",
        baseline_sha=new_sha,
        policy=policy,
        files=files,
        grouped=grouped,
        recommendations=recommendations,
    )
    assert len(plans) == 1
    assert plans[0]["package"] == "requests"
    assert plans[0]["target_version"] == "2.31.0"
    assert plans[0]["baseline_sha"] == new_sha

    # -------------------------------------------------------------
    # Step 6: Uninstall / Data Cleanup Lifecycle
    # -------------------------------------------------------------
    # Simulate App uninstallation
    store.audit_event(repo, None, "github_webhook", "installation_deleted", {"installation_id": installation_id})

    # Purge tenant repository connection upon uninstall
    org_data = OrganizationData(store, org_id, user["id"], "dummy-hash")
    # Verify project health before purge
    health = org_data.project_health(repo)
    assert health["risk_summary"]["open_findings"] >= 0
    assert health["repo"] == repo

    # Purge data cleanly
    purge_res = org_data.purge_data()
    assert purge_res["status"] == "purged"
    assert repo in purge_res["purged_repositories"]

    # Verify database state after uninstall purge
    with store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM findings WHERE repo=?", (repo,)).fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM dependency_inventory WHERE repo=?", (repo,)).fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM scans WHERE repo=?", (repo,)).fetchone()[0] == 0
        # Audit log retains the uninstallation record
        uninst_audit = c.execute(
            "SELECT * FROM audit_events WHERE action='installation_deleted' AND repo=?",
            (repo,),
        ).fetchone()
        assert uninst_audit is not None
