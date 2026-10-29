import pytest
from vulnforge.dependencies import Dependency
from vulnforge.kev import VulnerabilityMetrics
from vulnforge.intelligence import evaluate_remediation_priority


def test_prioritization_separates_cvss_from_real_threat_and_exposure():
    finding = {'id': 'find-1', 'severity': 'critical', 'title': 'Test vuln'}

    # Scenario 1: Active exploitation in CISA KEV on a runtime dependency -> P0
    kev_metrics = VulnerabilityMetrics(
        cve_id='CVE-2024-0001',
        cvss_score=7.5,
        cvss_severity='HIGH',
        kev_date_added='2026-01-15',
        kev_ransomware=True
    )
    runtime_dep = Dependency('pkg-a', '1.0.0', 'npm', 'package-lock.json', direct=True, scope='runtime')
    p0_res = evaluate_remediation_priority(finding, metrics=kev_metrics, dependency=runtime_dep, environment='production')
    assert p0_res['priority'] == 'P0'
    assert p0_res['recommended_sla_hours'] == 24
    assert p0_res['in_kev'] is True
    assert p0_res['is_ransomware'] is True
    assert any('P0 Critical' in r for r in p0_res['rationale'])
    assert any('ransomware' in r for r in p0_res['rationale'])

    # Scenario 2: Active KEV on a development dependency -> downgraded from P0 to P1
    dev_dep = Dependency('pkg-a', '1.0.0', 'npm', 'package-lock.json', direct=True, scope='dev')
    p1_dev_res = evaluate_remediation_priority(finding, metrics=kev_metrics, dependency=dev_dep, environment='production')
    assert p1_dev_res['priority'] == 'P1'
    assert p1_dev_res['recommended_sla_hours'] == 72
    assert p1_dev_res['exposure_level'] == 'production_dev'

    # Scenario 3: High EPSS (35%) and high CVSS in runtime -> P1
    epss_metrics = VulnerabilityMetrics(
        cve_id='CVE-2024-0002',
        cvss_score=8.5,
        cvss_severity='HIGH',
        epss_score=0.35,
        epss_percentile=0.92
    )
    p1_epss_res = evaluate_remediation_priority(finding, metrics=epss_metrics, dependency=runtime_dep, environment='production')
    assert p1_epss_res['priority'] == 'P1'
    assert p1_epss_res['recommended_sla_hours'] == 72
    assert any('EPSS probability: 35.00%' in r for r in p1_epss_res['rationale'])

    # Scenario 4: Critical theoretical CVSS (9.8) but isolated in dev scope with 0 KEV and negligible EPSS
    # Under conventional tools this causes panic alarms; under VulnForge policy it is P2
    low_exposure_metrics = VulnerabilityMetrics(
        cve_id='CVE-2024-0003',
        cvss_score=9.8,
        cvss_severity='CRITICAL',
        epss_score=0.001,
        epss_percentile=0.1
    )
    p2_res = evaluate_remediation_priority(finding, metrics=low_exposure_metrics, dependency=dev_dep, environment='production')
    assert p2_res['priority'] == 'P2'
    assert p2_res['recommended_sla_hours'] == 336
    assert p2_res['base_severity'] == 'CRITICAL'  # Technical severity is honestly preserved

    # Scenario 5: Low CVSS (3.5) with no KEV and low EPSS -> P3
    low_metrics = VulnerabilityMetrics(
        cve_id='CVE-2024-0004',
        cvss_score=3.5,
        cvss_severity='LOW',
        epss_score=0.01,
        epss_percentile=0.2
    )
    p3_res = evaluate_remediation_priority(finding, metrics=low_metrics, dependency=runtime_dep, environment='production')
    assert p3_res['priority'] == 'P3'
    assert p3_res['recommended_sla_hours'] == 720

