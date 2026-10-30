"""Isolated, ephemeral execution runner with secret scrubbing and strict resource limits."""
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


SAFE_ENV_VARS = (
    'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TEMP', 'TMP',
    'HOME', 'USER', 'LOGNAME', 'TERM', 'SYSTEMROOT', 'COMSPEC'
)

SENSITIVE_KEY_PATTERN = re.compile(
    r'(?i)(token|key|secret|password|auth|credential|private|database|github|aws|postgres|pg_|ssh_|api_|vf_|bearer|cookie|cert)'
)


@dataclass(frozen=True)
class ResourceLimits:
    cpu_seconds: int = 60
    memory_bytes: int = 512 * 1024 * 1024  # 512 MB
    max_output_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_file_size_bytes: int = 25 * 1024 * 1024  # 25 MB
    timeout_seconds: float = 60.0
    allow_network: bool = False


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    resource_exceeded: bool = False
    cleaned_env_keys: list[str] = field(default_factory=list)
    workspace_path: str | None = None

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.resource_exceeded


def clean_environment(
    extra_env: dict[str, str] | None = None,
    allow_network: bool = False,
    isolated_home: str | None = None
) -> tuple[dict[str, str], list[str]]:
    """Return a sanitized environment dictionary stripped of all secrets and credentials."""
    scrubbed_keys = []
    env: dict[str, str] = {}

    for k, v in os.environ.items():
        if SENSITIVE_KEY_PATTERN.search(k):
            scrubbed_keys.append(k)
        elif k in SAFE_ENV_VARS:
            env[k] = v

    if isolated_home:
        env['HOME'] = isolated_home
        env['TMPDIR'] = isolated_home

    if not allow_network:
        # Strict network blocking indicators
        env['HTTP_PROXY'] = 'http://127.0.0.1:0'
        env['HTTPS_PROXY'] = 'http://127.0.0.1:0'
        env['ALL_PROXY'] = 'socks5://127.0.0.1:0'
        env['NO_PROXY'] = ''
        env['PIP_NO_INDEX'] = '1'
        env['NPM_CONFIG_OFFLINE'] = 'true'
        env['CARGO_NET_OFFLINE'] = 'true'

    if extra_env:
        for k, v in extra_env.items():
            if not SENSITIVE_KEY_PATTERN.search(k):
                env[k] = str(v)
            else:
                scrubbed_keys.append(k)

    return env, sorted(set(scrubbed_keys))


def _make_preexec(limits: ResourceLimits) -> Callable[[], None] | None:
    if os.name != 'posix':
        return None

    def _preexec():
        try:
            # Set CPU limit (soft and hard)
            if hasattr(resource, 'RLIMIT_CPU'):
                resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 5))
            # Set maximum file size created by process
            if hasattr(resource, 'RLIMIT_FSIZE'):
                resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_file_size_bytes, limits.max_file_size_bytes))
            # Set virtual memory limit where supported
            if hasattr(resource, 'RLIMIT_AS'):
                try:
                    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
                except (ValueError, OSError):
                    pass
            elif hasattr(resource, 'RLIMIT_DATA'):
                try:
                    resource.setrlimit(resource.RLIMIT_DATA, (limits.memory_bytes, limits.memory_bytes))
                except (ValueError, OSError):
                    pass
        except Exception:
            pass

    return _preexec


class IsolatedRunner:
    """Manages ephemeral, sandboxed process execution for scans and patch validations."""

    def __init__(self, limits: ResourceLimits | None = None):
        self.limits = limits or ResourceLimits()

    def run_command(
        self,
        cmd: list[str],
        *,
        cwd: str | Path | None = None,
        input_data: str | None = None,
        extra_env: dict[str, str] | None = None,
        limits: ResourceLimits | None = None
    ) -> ExecutionResult:
        lim = limits or self.limits
        working_dir = str(cwd) if cwd else None
        env, scrubbed = clean_environment(
            extra_env=extra_env,
            allow_network=lim.allow_network,
            isolated_home=working_dir
        )
        preexec = _make_preexec(lim)

        start_time = time.time()
        timed_out = False
        resource_exceeded = False
        stdout_str = ""
        stderr_str = ""
        exit_code = -1

        try:
            proc = subprocess.run(
                cmd,
                cwd=working_dir,
                env=env,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=lim.timeout_seconds,
                preexec_fn=preexec
            )
            exit_code = proc.returncode
            stdout_str = proc.stdout[:lim.max_output_bytes]
            stderr_str = proc.stderr[:lim.max_output_bytes]
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            stdout_str = (exc.stdout or "")[:lim.max_output_bytes] if isinstance(exc.stdout, str) else ""
            stderr_str = (exc.stderr or "Execution timed out")[:lim.max_output_bytes] if isinstance(exc.stderr, str) else "Execution timed out"
        except subprocess.SubprocessError as exc:
            resource_exceeded = True
            exit_code = 125
            stderr_str = str(exc)[:lim.max_output_bytes]

        duration = time.time() - start_time
        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_seconds=duration,
            timed_out=timed_out,
            resource_exceeded=resource_exceeded,
            cleaned_env_keys=scrubbed,
            workspace_path=working_dir
        )

    def run_in_ephemeral_workspace(
        self,
        cmd: list[str],
        files: dict[str, str],
        *,
        input_data: str | None = None,
        limits: ResourceLimits | None = None
    ) -> ExecutionResult:
        """Run command inside an isolated temporary directory that is automatically destroyed."""
        with tempfile.TemporaryDirectory(prefix="vf_isolated_") as tmpdir:
            base_dir = Path(tmpdir).resolve()
            # Materialize workspace files with strict containment
            for rel_path, content in files.items():
                if rel_path.startswith('/') or '\\' in rel_path or '..' in rel_path.split('/'):
                    continue
                try:
                    dest = (base_dir / rel_path).resolve()
                    if not dest.is_relative_to(base_dir):
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(content, encoding='utf-8')
                except Exception:
                    continue

            result = self.run_command(cmd, cwd=tmpdir, input_data=input_data, limits=limits)
            # Ephemeral workspace is safely deleted at context exit
            return result

    def managed_scan_runner(self, limits: ResourceLimits | None = None) -> Callable[[list[str]], str]:
        """Callable adapter runner for semgrep, gitleaks, or other scanner tools."""
        lim = limits or self.limits

        def _runner(cmd: list[str]) -> str:
            res = self.run_command(cmd, limits=lim)
            if not res.success:
                raise subprocess.CalledProcessError(
                    returncode=res.exit_code,
                    cmd=cmd,
                    output=res.stdout,
                    stderr=res.stderr
                )
            return res.stdout

        return _runner

