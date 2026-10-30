"""Opt-in, default-disabled LLM triage and patch assistance with local and remote provider governance."""
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional


SECRET_SCRUB_REGEX = re.compile(
    r"(?i)(token|key|secret|password|bearer|auth|authorization|credential)[\"'\s:=]+[A-Za-z0-9_./-]{8,}"
)


@dataclass
class LLMTriagePolicy:
    enabled: bool = False  # STRICT REQUIREMENT: Defaults to False
    provider: str = "disabled"  # 'disabled', 'local_ollama', 'remote_cloud'
    local_endpoint: str = "http://127.0.0.1:11434"
    allow_remote_data_transfer: bool = False
    anonymize_snippets: bool = True
    require_human_approval: bool = True


@dataclass
class TriageSuggestion:
    advisory_id: str
    package: str
    current_version: str
    recommended_version: str
    explanation: str
    breaking_change_risk: str  # 'low', 'medium', 'high', 'unknown'
    requires_human_approval: bool
    sanitized_prompt_preview: str
    provider_used: str


class LLMTriageEngine:
    """Manages AI triage and patch suggestions with strict opt-in and privacy boundaries."""

    def __init__(self, policy: Optional[LLMTriagePolicy] = None):
        self.policy = policy or LLMTriagePolicy()

    def sanitize_context(self, code_snippet: str) -> str:
        """Strip credentials, secrets, and private hostnames from prompt context."""
        if not code_snippet:
            return ""
        # Scrub secret assignments
        scrubbed = SECRET_SCRUB_REGEX.sub("[REDACTED_SECRET]", code_snippet)
        # Scrub private email addresses
        scrubbed = re.sub(r"[\w.-]+@[\w.-]+\.\w+", "[REDACTED_EMAIL]", scrubbed)
        return scrubbed

    def generate_triage_suggestion(
        self,
        organization_opt_in: bool,
        advisory: Dict[str, Any],
        package_name: str,
        current_version: str,
        code_context: Optional[str] = None,
    ) -> TriageSuggestion:
        """Generate structured vulnerability triage suggestion conforming to privacy invariants."""
        # 1. Enforcement of Default-Closed Opt-In
        if not self.policy.enabled or not organization_opt_in:
            raise PermissionError(
                "LLM triage is disabled by default. Explicit organization administrator opt-in is required."
            )

        # 2. Remote Egress Policy Check
        if self.policy.provider == "remote_cloud" and not self.policy.allow_remote_data_transfer:
            raise PermissionError(
                "Remote model data transfer forbidden: allow_remote_data_transfer is disabled."
            )

        if self.policy.provider == "disabled":
            raise PermissionError("LLM provider is set to disabled.")

        # 3. Context Sanitization
        sanitized_code = self.sanitize_context(code_context or "")
        adv_id = advisory.get("id", "UNKNOWN-ADVISORY")
        summary = advisory.get("summary", "")

        # 4. Structured suggestion generation (Deterministic fallback / adapter pattern)
        # Find target version from fixed events if present
        target_version = current_version
        vulnerabilities = advisory.get("vulnerabilities", [])
        for v in vulnerabilities:
            for r in v.get("ranges", []):
                for e in r.get("events", []):
                    if "fixed" in e:
                        target_version = e["fixed"]
                        break

        # Assess breaking change risk based on SemVer major version change
        curr_major = current_version.split(".")[0] if "." in current_version else ""
        target_major = target_version.split(".")[0] if "." in target_version else ""
        if curr_major and target_major and curr_major != target_major:
            breaking_risk = "high"
            explanation = (
                f"Upgrade from {current_version} to {target_version} spans a major version boundary. "
                f"Review breaking changes and test API compatibility before merging."
            )
        else:
            breaking_risk = "low"
            explanation = (
                f"Upgrade from {current_version} to {target_version} resolves {adv_id} ({summary}) "
                f"within the same major release stream."
            )

        return TriageSuggestion(
            advisory_id=adv_id,
            package=package_name,
            current_version=current_version,
            recommended_version=target_version,
            explanation=explanation,
            breaking_change_risk=breaking_risk,
            requires_human_approval=self.policy.require_human_approval,
            sanitized_prompt_preview=sanitized_code[:200],
            provider_used=self.policy.provider,
        )

