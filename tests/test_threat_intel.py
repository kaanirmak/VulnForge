import json
import pytest
from vulnforge.db import Store
from vulnforge.kev import NVD, EPSS, KEV, enrich_advisory_metrics, VulnerabilityMetrics


def test_nvd_cvss_parsing_and_hash_evidence():
    nvd_sample = {
        'id': 'CVE-2024-1234',
        'metrics': {
            'cvssMetricV31': [
                {
                    'source': 'nvd@nist.gov',
                    'type': 'Primary',
                    'cvssData': {
                        'version': '3.1',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL'
                    }
                }
            ]
        }
    }
    parsed = NVD.parse_nvd_cve(nvd_sample)
    assert parsed['cve_id'] == 'CVE-2024-1234'
    assert parsed['cvss_score'] == 9.8
    assert parsed['cvss_severity'] == 'CRITICAL'
    assert parsed['cvss_vector'] == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    assert parsed['evidence']['source'] == 'NVD'
    assert len(parsed['evidence']['source_sha256']) == 64
    assert parsed['evidence']['observed_at'] > 0


def test_epss_parsing_and_hash_evidence():
    epss_sample = {
        'status': 'OK',
        'status-code': 200,
        'version': '1.0',
        'access': 'public',
        'total': 1,
        'offset': 0,
        'limit': 1,
        'data': [
            {
                'cve': 'CVE-2024-1234',
                'epss': '0.94231',
                'percentile': '0.99120',
                'date': '2026-10-29'
            }
        ]
    }
    parsed = EPSS.parse_epss_response(epss_sample)
    assert 'CVE-2024-1234' in parsed
    cve_data = parsed['CVE-2024-1234']
    assert cve_data['epss_score'] == 0.94231
    assert cve_data['epss_percentile'] == 0.99120
    assert cve_data['evidence']['source'] == 'EPSS'
    assert len(cve_data['evidence']['source_sha256']) == 64


def test_enrich_advisory_metrics_with_combined_evidence(tmp_path):
    advisory = {
        'id': 'GHSA-xxxx-yyyy-zzzz',
        'aliases': ['CVE-2024-1234'],
        'summary': 'Critical remote execution'
    }
    nvd_data = {
        'cve_id': 'CVE-2024-1234',
        'cvss_score': 9.8,
        'cvss_severity': 'CRITICAL',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'evidence': {'source': 'NVD', 'source_sha256': 'a' * 64, 'observed_at': 1700000000.0}
    }
    epss_data = {
        'cve_id': 'CVE-2024-1234',
        'epss_score': 0.85,
        'epss_percentile': 0.95,
        'evidence': {'source': 'EPSS', 'source_sha256': 'b' * 64, 'observed_at': 1700000000.0}
    }
    kev_data = {
        'cve': 'CVE-2024-1234',
        'date_added': '2026-05-01',
        'ransomware': True
    }

    metrics = enrich_advisory_metrics(advisory, nvd_data=nvd_data, epss_data=epss_data, kev_data=kev_data)
    assert metrics.cve_id == 'CVE-2024-1234'
    assert metrics.cvss_score == 9.8
    assert metrics.cvss_severity == 'CRITICAL'
    assert metrics.epss_score == 0.85
    assert metrics.kev_ransomware is True
    assert 'nvd' in metrics.evidence
    assert 'epss' in metrics.evidence
    assert 'kev' in metrics.evidence

    # Persistence to database
    store = Store(str(tmp_path / 'db'))
    store.save_vulnerability_metrics(metrics)

    saved = store.get_vulnerability_metrics('CVE-2024-1234')
    assert saved is not None
    assert saved['cvss_score'] == 9.8
    assert saved['epss_score'] == 0.85
    assert saved['kev_ransomware'] is True
    assert saved['evidence']['nvd']['source_sha256'] == 'a' * 64
    assert saved['evidence']['epss']['source_sha256'] == 'b' * 64

