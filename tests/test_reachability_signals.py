import pytest
from vulnforge.reachability import analyze_reachability


def test_reachability_detected_in_source():
    files = {
        "app/service.py": """
import requests
from requests import get

def fetch_data(url):
    response = get(url)
    return response.text
""",
        "app/utils.py": "print('hello')",
    }
    assessment = analyze_reachability(
        files=files,
        package_name="requests",
        vulnerable_symbols=["get", "post"],
        base_severity="high",
    )
    assert assessment.status == "reachable"
    assert "get" in assessment.matched_symbols
    assert len(assessment.callsites) == 1
    assert assessment.callsites[0]["file"] == "app/service.py"
    assert assessment.is_runtime_exposed is False
    assert assessment.contextual_severity == "high"


def test_unreachable_when_package_never_imported():
    files = {
        "app/main.py": "import os\nprint(os.getcwd())",
    }
    assessment = analyze_reachability(
        files=files,
        package_name="urllib3",
        vulnerable_symbols=["poolmanager"],
        base_severity="critical",
    )
    assert assessment.status == "unreachable"
    assert assessment.confidence >= 0.9
    # Critical downgraded to low because package is dead code / never imported
    assert assessment.contextual_severity == "low"
    assert "never imported" in assessment.evidence_rationale


def test_unreachable_when_specific_symbol_not_used():
    files = {
        "app/main.py": """
import pyyaml
from pyyaml import safe_load

def load_config(text):
    return safe_load(text)
"""
    }
    # Vulnerable symbol is unsafe_load, but code uses safe_load
    assessment = analyze_reachability(
        files=files,
        package_name="pyyaml",
        vulnerable_symbols=["unsafe_load", "load"],
        base_severity="critical",
    )
    assert assessment.status == "unreachable"
    assert assessment.contextual_severity == "low"


def test_runtime_exposure_in_http_route():
    files = {
        "app/routes.py": """
from fastapi import APIRouter
from vulnerable_xml import parse_untrusted_xml

router = APIRouter()

@router.post("/api/upload")
def upload_endpoint(payload: str):
    data = parse_untrusted_xml(payload)
    return {"status": "ok", "data": data}
"""
    }
    assessment = analyze_reachability(
        files=files,
        package_name="vulnerable_xml",
        vulnerable_symbols=["parse_untrusted_xml"],
        base_severity="high",
    )
    assert assessment.status == "runtime_exposed"
    assert assessment.is_runtime_exposed is True
    # Upgraded/flagged with critical urgency due to route exposure
    assert assessment.contextual_severity == "critical"
    assert "public HTTP route handlers" in assessment.evidence_rationale

