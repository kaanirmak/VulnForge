import json
from pathlib import Path
import pytest

from vulnforge.db import Store
from vulnforge.onprem import (
    AirgappedConfig,
    generate_onprem_compose,
    is_airgapped_safe_host,
    load_offline_advisories_bundle,
    validate_airgapped_isolation,
)


def test_airgapped_safe_host_resolution():
    # Internal & private safe hosts
    assert is_airgapped_safe_host("127.0.0.1") is True
    assert is_airgapped_safe_host("10.100.1.5") is True
    assert is_airgapped_safe_host("192.168.1.100") is True
    assert is_airgapped_safe_host("172.20.0.5") is True
    assert is_airgapped_safe_host("git.internal.corp") is True
    assert is_airgapped_safe_host("https://nexus.local:8443/repo") is True
    assert is_airgapped_safe_host("db.lan") is True

    # External internet hosts must be rejected
    assert is_airgapped_safe_host("api.osv.dev") is False
    assert is_airgapped_safe_host("https://github.com") is False
    assert is_airgapped_safe_host("8.8.8.8") is False
    assert is_airgapped_safe_host("1.1.1.1") is False


def test_validate_airgapped_isolation():
    cfg = AirgappedConfig(airgapped=True)

    # Valid internal endpoints
    assert validate_airgapped_isolation(cfg, ["https://git.corp", "10.0.0.5:5432"]) is True

    # External endpoint violation raises ValueError
    with pytest.raises(ValueError, match="Air-gapped isolation violation"):
        validate_airgapped_isolation(cfg, ["https://git.corp", "https://api.github.com"])


def test_load_offline_advisories_bundle(tmp_path):
    db_path = str(tmp_path / "onprem.db")
    store = Store(db_path)

    # Create dummy bundle file
    bundle_file = tmp_path / "advisories_bundle.json"
    bundle_data = [
        {
            "id": "GHSA-OFFLINE-001",
            "summary": "Offline Critical RCE",
            "vulnerabilities": [{"package": {"name": "offline-lib", "ecosystem": "pip"}}],
        },
        {
            "id": "CVE-2026-9999",
            "summary": "Offline High DoS",
            "vulnerabilities": [{"package": {"name": "secure-parser", "ecosystem": "npm"}}],
        },
    ]
    bundle_file.write_text(json.dumps(bundle_data), encoding="utf-8")

    imported = load_offline_advisories_bundle(store, str(bundle_file))
    assert imported == 2

    # Verify advisories saved in store
    with store.conn() as c:
        adv1 = c.execute("SELECT * FROM advisories WHERE id='GHSA-OFFLINE-001'").fetchone()
        assert adv1 is not None
        assert "Offline Critical RCE" in adv1["summary"]

        adv2 = c.execute("SELECT * FROM advisories WHERE id='CVE-2026-9999'").fetchone()
        assert adv2 is not None


def test_generate_onprem_compose():
    compose_yaml = generate_onprem_compose(db_password="test-secure-password", image_tag="0.3.0")
    assert "postgres:14-alpine" in compose_yaml
    assert "test-secure-password" in compose_yaml
    assert "vulnforge/server:0.3.0" in compose_yaml
    assert "AIRGAPPED: \"true\"" in compose_yaml
    assert "internal: true" in compose_yaml

