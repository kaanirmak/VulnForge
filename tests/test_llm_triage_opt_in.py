import pytest
from vulnforge.llm_triage import LLMTriageEngine, LLMTriagePolicy


def test_llm_triage_default_disabled():
    # Default policy has enabled=False
    default_engine = LLMTriageEngine()
    advisory = {"id": "CVE-2023-1111", "summary": "Buffer Overflow"}

    with pytest.raises(PermissionError, match="disabled by default"):
        default_engine.generate_triage_suggestion(
            organization_opt_in=False,
            advisory=advisory,
            package_name="c-parser",
            current_version="1.0.0",
        )

    # Even if org tries to pass True, if system policy is disabled it must fail
    with pytest.raises(PermissionError, match="disabled by default"):
        default_engine.generate_triage_suggestion(
            organization_opt_in=True,
            advisory=advisory,
            package_name="c-parser",
            current_version="1.0.0",
        )


def test_llm_remote_egress_forbidden_when_not_allowed():
    policy = LLMTriagePolicy(
        enabled=True,
        provider="remote_cloud",
        allow_remote_data_transfer=False,  # Remote transfer forbidden
    )
    engine = LLMTriageEngine(policy)
    advisory = {"id": "CVE-2023-2222", "summary": "SSRF in library"}

    with pytest.raises(PermissionError, match="Remote model data transfer forbidden"):
        engine.generate_triage_suggestion(
            organization_opt_in=True,
            advisory=advisory,
            package_name="net-client",
            current_version="2.0.0",
        )


def test_llm_context_secret_sanitization():
    engine = LLMTriageEngine()
    raw_code = (
        'import requests\n'
        'API_KEY = "' + 'AK' + 'IA1234567890EXAMPLE"\n'
        'TOKEN = "' + 'gh' + 'p_super_secret_github_token"\n'
        'AUTHORIZATION = "Bearer my_jwt_token_abcdef123"\n'
        'user_email = "admin@internal.corp"\n'
    )
    sanitized = engine.sanitize_context(raw_code)
    assert ("AK" + "IA1234567890EXAMPLE") not in sanitized
    assert ("gh" + "p_super_secret_github_token") not in sanitized
    assert "my_jwt_token_abcdef123" not in sanitized
    assert "admin@internal.corp" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized


def test_local_llm_triage_suggestion_generation():
    # Local Ollama / vLLM execution without remote data transfer
    policy = LLMTriagePolicy(
        enabled=True,
        provider="local_ollama",
        allow_remote_data_transfer=False,
        require_human_approval=True,
    )
    engine = LLMTriageEngine(policy)

    advisory = {
        "id": "GHSA-TEST-9999",
        "summary": "Prototype Pollution in parser",
        "vulnerabilities": [
            {
                "package": {"name": "json-parser"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }

    suggestion = engine.generate_triage_suggestion(
        organization_opt_in=True,
        advisory=advisory,
        package_name="json-parser",
        current_version="1.4.0",
        code_context="var parser = require('json-parser');",
    )

    assert suggestion.advisory_id == "GHSA-TEST-9999"
    assert suggestion.recommended_version == "2.0.0"
    assert suggestion.breaking_change_risk == "high"  # 1.4.0 -> 2.0.0 is major upgrade
    assert suggestion.requires_human_approval is True
    assert suggestion.provider_used == "local_ollama"
