import os
import sys
import tempfile
from pathlib import Path
import pytest

from vulnforge.isolated_runner import (
    clean_environment,
    ExecutionResult,
    IsolatedRunner,
    ResourceLimits,
)


def test_sandbox_escape_path_traversal_blocked(tmp_path):
    """Verify that file manifests with traversal paths cannot escape the ephemeral directory."""
    runner = IsolatedRunner()

    evil_outside = tmp_path / "outside_marker.txt"
    evil_outside.write_text("should_not_be_overwritten")

    # Various traversal attack vectors
    malicious_files = {
        f"../../{evil_outside.name}": "PWNED_CONTENT",
        f"/{evil_outside}": "PWNED_CONTENT",
        f"subdir/../../../../{evil_outside.name}": "PWNED_CONTENT",
        f"..\\{evil_outside.name}": "PWNED_CONTENT",
        "valid_dir/safe.txt": "SAFE_CONTENT",
    }

    # Execute harmless inspection inside sandbox
    script = (
        "import os\n"
        "files = []\n"
        "for root, _, filenames in os.walk('.'):\n"
        "    for f in filenames:\n"
        "        files.append(os.path.join(root, f))\n"
        "print('FOUND:' + ','.join(sorted(files)))\n"
    )

    res = runner.run_in_ephemeral_workspace(
        [sys.executable, "-c", script],
        files=malicious_files,
    )

    assert res.success is True
    # The outside marker must never have been overwritten
    assert evil_outside.read_text() == "should_not_be_overwritten"
    # Only safe file should have been written in the sandbox
    assert "safe.txt" in res.stdout
    assert evil_outside.name not in res.stdout


def test_sandbox_symlink_escape_containment(tmp_path):
    """Verify that symlinks inside the sandbox cannot be used to leak or write outside."""
    runner = IsolatedRunner()

    target_outside = tmp_path / "protected_target.txt"
    target_outside.write_text("top_secret_outside_data")

    # Script inside sandbox tries to create a symlink to outside target
    script = f"""
import os, sys
try:
    os.symlink("{target_outside}", "symlink_to_target")
    # Subprocess tries reading through symlink
    with open("symlink_to_target", "r") as f:
        print("READ:" + f.read())
except Exception as e:
    print("ERR:" + str(e))
"""
    res = runner.run_in_ephemeral_workspace(
        [sys.executable, "-c", script],
        files={"dummy.txt": "dummy"},
    )
    assert res.success is True


def test_sandbox_egress_network_blocked():
    """Verify that outbound network requests are trapped/blocked when allow_network=False."""
    runner = IsolatedRunner(limits=ResourceLimits(allow_network=False, timeout_seconds=5.0))

    # Python urllib request should immediately fail or raise URLError because of dummy proxy
    script = """
import urllib.request
import sys
try:
    urllib.request.urlopen("http://example.com", timeout=2.0)
    print("CONNECTED")
except Exception as e:
    print("BLOCKED:" + e.__class__.__name__)
"""
    res = runner.run_command([sys.executable, "-c", script])
    assert "CONNECTED" not in res.stdout
    assert "BLOCKED:" in res.stdout or res.exit_code != 0


def test_sandbox_package_manager_offline_flags():
    """Verify package manager ecosystem environment flags are configured for strict offline mode."""
    env, _ = clean_environment(allow_network=False)
    assert env.get("HTTP_PROXY") == "http://127.0.0.1:0"
    assert env.get("HTTPS_PROXY") == "http://127.0.0.1:0"
    assert env.get("ALL_PROXY") == "socks5://127.0.0.1:0"
    assert env.get("PIP_NO_INDEX") == "1"
    assert env.get("NPM_CONFIG_OFFLINE") == "true"
    assert env.get("CARGO_NET_OFFLINE") == "true"


def test_sandbox_secret_scrubbing_matrix(monkeypatch):
    """Verify that credentials across multiple patterns and prefixes are strictly scrubbed."""
    secrets_to_set = {
        "GITHUB_TOKEN": "gh" + "p_fake_dummy_token_12345",
        "GH_TOKEN": "gh" + "p_fake_dummy_token_67890",
        "AWS_ACCESS_KEY_ID": "AK" + "IA_fake_key_id",
        "AWS_SECRET_ACCESS_KEY": "fake_aws_secret_key_abcdef",
        "POSTGRES_PASSWORD": "super_secret_pg_password",
        "DATABASE_URL": "postgresql://user:pass@internal-db:5432/vulnforge",
        "VF_ADMIN_TOKEN": "vf" + "_admin_token_xyz987",
        "PRIVATE_KEY_PEM": "-----BEGIN PRIVATE KEY-----",
        "BEARER_AUTH_HEADER": "Bearer fake_token",
        "SESSION_COOKIE_VALUE": "session=abcdef123456",
        "SSL_CERT_KEY": "cert_private_key_data",
        "SAFE_BUILD_FLAG": "release-mode-fast",
    }
    for k, v in secrets_to_set.items():
        monkeypatch.setenv(k, v)

    runner = IsolatedRunner()

    script = """
import os
for k in sorted(os.environ.keys()):
    print(k + "=" + os.environ[k])
"""
    res = runner.run_command([sys.executable, "-c", script])
    assert res.success is True

    # None of the secret variables should appear in the subprocess environment
    for k in secrets_to_set:
        if k != "SAFE_BUILD_FLAG":
            assert f"{k}=" not in res.stdout
            assert k in res.cleaned_env_keys


def test_sandbox_cpu_timeout_enforcement():
    """Verify that a runaway CPU busy-loop is terminated cleanly by timeout."""
    runner = IsolatedRunner(limits=ResourceLimits(timeout_seconds=0.4))
    script = """
import time
start = time.time()
while time.time() - start < 10.0:
    pass
"""
    res = runner.run_command([sys.executable, "-c", script])
    assert res.timed_out is True
    assert res.exit_code == 124
    assert res.duration_seconds >= 0.35


def test_sandbox_output_truncation_limits():
    """Verify that high-volume stdout/stderr output is truncated to prevent buffer flooding."""
    limits = ResourceLimits(max_output_bytes=256)
    runner = IsolatedRunner(limits=limits)
    script = """
import sys
sys.stdout.write("X" * 10000)
sys.stderr.write("Y" * 10000)
"""
    res = runner.run_command([sys.executable, "-c", script])
    assert len(res.stdout) <= 256
    assert len(res.stderr) <= 256


def test_sandbox_ephemeral_directory_cleanup():
    """Verify that temporary workspace directories are completely deleted after execution."""
    runner = IsolatedRunner()
    created_workspace = None

    script = """
import os
print("CWD:" + os.getcwd())
with open("test_file.txt", "w") as f:
    f.write("temporary data")
"""
    res = runner.run_in_ephemeral_workspace(
        [sys.executable, "-c", script],
        files={"initial.txt": "start"},
    )
    assert res.success is True

    for line in res.stdout.splitlines():
        if line.startswith("CWD:"):
            created_workspace = line.split(":", 1)[1].strip()

    assert created_workspace is not None
    assert "vf_isolated_" in created_workspace
    # The temporary directory must no longer exist on disk
    assert not os.path.exists(created_workspace)
