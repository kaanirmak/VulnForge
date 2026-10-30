import pytest

from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.dr import execute_disaster_recovery_drill
from vulnforge.encryption import DataEncryptor, DecryptionError


def test_disaster_recovery_drill_lifecycle_and_verification(tmp_path):
    source_db = str(tmp_path / "production_source.db")
    backup_file = str(tmp_path / "backup_archive.enc")
    target_db = str(tmp_path / "standby_restored.db")
    encryption_key = DataEncryptor.generate_key()

    source_store = Store(source_db)
    repo = "disaster-recovery/mission-critical"
    source_store.upsert_repo(repo, 999, "main")

    # Seed meaningful operational state
    source_store.save_finding(
        repo=repo,
        key="vuln-core-001",
        category="sast",
        severity="critical",
        title="Remote Code Execution in Parser",
        file_path="src/parser.py",
        commit_sha="a" * 40,
        details={"cve": "CVE-2026-99999", "cisa_kev": True},
    )
    source_store.save_finding(
        repo=repo,
        key="vuln-core-002",
        category="dependency",
        severity="high",
        title="Denial of Service in Lodash",
        file_path="package-lock.json",
        commit_sha="a" * 40,
        details={"cve": "CVE-2026-88888"},
    )
    source_store.replace_inventory(
        repo,
        [
            Dependency("lodash", "4.17.20", "npm", "package.json"),
            Dependency("requests", "2.31.0", "pypi", "requirements.txt"),
        ],
    )
    scan_id = source_store.start_scan(repo, "dependencies", "a" * 40)
    source_store.finish_scan(scan_id, "complete", {"files_scanned": 10}, [])
    source_store.audit_event(repo, None, "system", "backup_drill_initiated", {"drill_id": "dr-1"})

    # Execute drill
    report = execute_disaster_recovery_drill(
        source_db=source_db,
        backup_file_path=backup_file,
        target_db_path=target_db,
        encryption_key=encryption_key,
        max_rto_allowed_seconds=1800.0,
    )

    assert report.success is True
    assert report.rto_seconds < 1800.0  # RTO <= 30 mins
    assert report.rpo_seconds < 900.0   # RPO <= 15 mins
    assert report.records_verified > 0
    assert report.details["status"] == "PASS"
    assert report.details["parity"]["findings"]["source"] == 2
    assert report.details["parity"]["findings"]["restored"] == 2

    # Verify directly on restored database
    restored_store = Store(target_db)
    with restored_store.conn() as c:
        f_row = c.execute("SELECT * FROM findings WHERE key='vuln-core-001'").fetchone()
        assert f_row is not None
        assert f_row["title"] == "Remote Code Execution in Parser"
        assert f_row["severity"] == "critical"

        inv = c.execute("SELECT * FROM dependency_inventory WHERE repo=?", (repo,)).fetchall()
        assert len(inv) == 2


def test_disaster_recovery_drill_with_wrong_key(tmp_path):
    source_db = str(tmp_path / "source.db")
    backup_file = str(tmp_path / "backup.enc")
    target_db = str(tmp_path / "target.db")
    source_store = Store(source_db)
    source_store.upsert_repo("org/repo", 1, "main")

    key1 = DataEncryptor.generate_key()
    key2 = DataEncryptor.generate_key()

    # If restore is attempted with wrong key, DecryptionError is raised
    with pytest.raises(DecryptionError):
        from vulnforge.encryption import create_encrypted_backup, restore_encrypted_backup
        create_encrypted_backup(source_db, backup_file, key1)
        restore_encrypted_backup(backup_file, target_db, key2)
