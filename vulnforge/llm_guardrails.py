"""Model-agnostic tool/policy gate, structured output validator, and prompt-injection/exfiltration guardrails."""
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class SecurityPolicyViolation(Exception):
    """Raised when an agent/model attempts an unauthorized tool call or violates policy."""


ALLOWED_TOOLS: Set[str] = {
    "read_manifest",
    "query_advisories",
    "propose_patch",
    "evaluate_semver",
}

FORBIDDEN_COMMAND_PATTERNS = (
    re.compile(r"(?i)\b(sh|bash|zsh|exec|eval|system|popen|subprocess)\b"),
    re.compile(r"(?i)\b(curl|wget|nc|ncat|netcat|telnet|socat)\b"),
    re.compile(r"(?i)\b(rm\s+-rf|chmod|chown|kill|pkill)\b"),
    re.compile(r"(?i)(environ|getenv|token|secret|password|credential)"),
)

PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)"),
    re.compile(r"(?i)you\s+are\s+now\s+(an?\s+unrestricted|a\s+different|in\s+developer\s+mode)"),
    re.compile(r"(?i)(system\s+prompt|prompt\s+override|disregard\s+safety)"),
    re.compile(r"(?i)print\s+(system\s+message|all\s+secret|hidden\s+instruction)"),
    re.compile(r"(?i)as\s+an\s+ai\s+without\s+restrictions"),
)

EXFILTRATION_PATTERNS = (
    re.compile(r"!\[.*?\]\((https?://[^\s)]+)\)"),  # Markdown image exfiltration
    re.compile(r"(?i)(curl|wget)\s+.*?(https?://|\$|token|key)"),  # Outbound HTTP exfiltration
    re.compile(r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>"),  # XSS script injection
)


class PolicyGate:
    """Enforces least-privilege boundary on agent/model tool invocations."""

    def __init__(self, allowed_tools: Optional[Set[str]] = None):
        self.allowed_tools = allowed_tools or ALLOWED_TOOLS

    def check_tool_invocation(self, tool_name: str, parameters: Dict[str, Any]) -> bool:
        """Validate whether the requested tool invocation is permitted."""
        if tool_name not in self.allowed_tools:
            raise SecurityPolicyViolation(f"Unauthorized tool invocation: '{tool_name}' is not in allowed tools.")

        # Check path parameter safety
        for param_key, param_val in parameters.items():
            if isinstance(param_val, str):
                # Path containment check
                if "path" in param_key.lower() or "file" in param_key.lower():
                    if param_val.startswith("/") or "\\" in param_val or ".." in param_val.split("/"):
                        raise SecurityPolicyViolation(
                            f"Path traversal detected in tool parameter '{param_key}': '{param_val}'"
                        )

                # Forbidden command execution patterns
                for pat in FORBIDDEN_COMMAND_PATTERNS:
                    if pat.search(param_val):
                        raise SecurityPolicyViolation(
                            f"Forbidden command/credential pattern detected in parameter '{param_key}'"
                        )

        return True


class StructuredOutputValidator:
    """Validates model responses against strict schemas to prevent hallucinations or schema poisoning."""

    REQUIRED_PATCH_KEYS = {
        "package",
        "target_version",
        "files_modified",
        "summary",
        "breaking_change_risk",
    }

    ALLOWED_PATCH_KEYS = REQUIRED_PATCH_KEYS | {"notes", "verified_locally"}

    @classmethod
    def validate_patch_proposal(cls, output_json: str) -> Dict[str, Any]:
        """Validate and sanitize structured patch proposal JSON."""
        try:
            data = json.loads(output_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Model output is not valid JSON: {str(exc)}") from exc

        if not isinstance(data, dict):
            raise ValueError("Model output must be a JSON object")

        missing = cls.REQUIRED_PATCH_KEYS - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields in model patch proposal: {sorted(missing)}")

        unauthorized = set(data.keys()) - cls.ALLOWED_PATCH_KEYS
        if unauthorized:
            raise ValueError(f"Unauthorized extraneous fields in model proposal: {sorted(unauthorized)}")

        if not isinstance(data["files_modified"], list) or not data["files_modified"]:
            raise ValueError("'files_modified' must be a non-empty list of paths")

        for f in data["files_modified"]:
            if not isinstance(f, str) or f.startswith("/") or ".." in f.split("/"):
                raise ValueError(f"Invalid file path in 'files_modified': {f}")

        if data["breaking_change_risk"] not in ("low", "medium", "high", "unknown"):
            raise ValueError(f"Invalid 'breaking_change_risk': {data['breaking_change_risk']}")

        return data


class InjectionExfiltrationDetector:
    """Detects prompt injection attempts in inputs and data exfiltration patterns in outputs."""

    @classmethod
    def scan_for_prompt_injection(cls, text: str) -> Tuple[bool, List[str]]:
        """Return (is_safe, detected_threat_descriptions)."""
        if not text or not isinstance(text, str):
            return True, []

        threats = []
        for pat in PROMPT_INJECTION_PATTERNS:
            if pat.search(text):
                threats.append(f"Prompt injection matched: '{pat.pattern}'")

        return len(threats) == 0, threats

    @classmethod
    def scan_for_exfiltration(cls, text: str) -> Tuple[bool, List[str]]:
        """Return (is_safe, detected_exfiltration_threats)."""
        if not text or not isinstance(text, str):
            return True, []

        threats = []
        for pat in EXFILTRATION_PATTERNS:
            match = pat.search(text)
            if match:
                threats.append(f"Exfiltration pattern detected: '{match.group(0)[:60]}'")

        return len(threats) == 0, threats

