import sys
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import vulnforge
from scripts.build_package import build, verify_distribution


def test_package_version_consistency():
    # 1. vulnforge.__version__ matches pyproject.toml
    pyproject_text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'version\s*=\s*"([^"]+)"', pyproject_text)
    assert match is not None
    pyproject_version = match.group(1)

    assert vulnforge.__version__ == pyproject_version
    assert re.match(r"^\d+\.\d+\.\d+$", vulnforge.__version__)


def test_reproducible_build_and_distribution_verification(tmp_path):
    dist_dir = tmp_path / "dist"
    # Build package candidate
    manifest = build(dist_dir, allow_dirty=True)

    assert manifest["artifact"].startswith("vulnforge_mvp-")
    assert manifest["artifact"].endswith(".whl")
    assert len(manifest["sha256"]) == 64
    assert manifest["provenance"]["predicate_type"] == "https://slsa.dev/provenance/v1"

    # Verify distribution artifacts
    verified = verify_distribution(dist_dir)
    assert verified["verified"] is True
    assert verified["artifact"] == manifest["artifact"]
    assert verified["sha256"] == manifest["sha256"]
    assert len(manifest["provenance"]["materials"]) >= 4
    assert len(verified["dependency_lock_sha256"]) == 64
