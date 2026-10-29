import os
import sys
from pathlib import Path
import pytest
from vulnforge.isolated_runner import (
    clean_environment,
    ExecutionResult,
    IsolatedRunner,
    ResourceLimits,
)


def test_clean_environment_scrubbing(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'ghp_secret123')
    monkeypatch.setenv('DATABASE_URL', 'postgres://user:pass@localhost/db')
    monkeypatch.setenv('VF_SIGNING_KEY', 'my-super-secret')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'awssecret')
    monkeypatch.setenv('SAFE_CUSTOM_VAR', 'hello')

    env, scrubbed = clean_environment(allow_network=False)
    assert 'GITHUB_TOKEN' not in env
    assert 'DATABASE_URL' not in env
    assert 'VF_SIGNING_KEY' not in env
    assert 'AWS_SECRET_ACCESS_KEY' not in env
    assert 'GITHUB_TOKEN' in scrubbed
    assert 'DATABASE_URL' in scrubbed
    assert 'VF_SIGNING_KEY' in scrubbed

    # Offline flags
    assert env['HTTP_PROXY'] == 'http://127.0.0.1:0'
    assert env['PIP_NO_INDEX'] == '1'
    assert env['NPM_CONFIG_OFFLINE'] == 'true'


def test_run_command_success():
    runner = IsolatedRunner()
    res = runner.run_command([sys.executable, '-c', 'print("hello-isolated")'])
    assert res.success is True
    assert res.exit_code == 0
    assert 'hello-isolated' in res.stdout
    assert not res.timed_out


def test_run_command_timeout():
    limits = ResourceLimits(timeout_seconds=0.3)
    runner = IsolatedRunner(limits=limits)
    res = runner.run_command([sys.executable, '-c', 'import time; time.sleep(2.0)'])
    assert res.timed_out is True
    assert res.exit_code == 124


def test_output_truncation():
    limits = ResourceLimits(max_output_bytes=100)
    runner = IsolatedRunner(limits=limits)
    res = runner.run_command([sys.executable, '-c', 'print("A" * 500)'])
    assert len(res.stdout) <= 100


def test_ephemeral_workspace():
    runner = IsolatedRunner()
    files = {
        'src/main.py': 'print("ephemeral test")',
        'data/input.txt': 'sample payload'
    }
    res = runner.run_in_ephemeral_workspace(
        [sys.executable, 'src/main.py'],
        files=files
    )
    assert res.success is True
    assert 'ephemeral test' in res.stdout


def test_managed_scan_runner_error():
    import subprocess
    runner = IsolatedRunner()
    scan_fn = runner.managed_scan_runner()
    with pytest.raises(subprocess.CalledProcessError):
        scan_fn([sys.executable, '-c', 'import sys; sys.exit(2)'])
