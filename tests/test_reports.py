import uuid
import pytest
from vulnforge.reports import (
    sbom, sarif, spdx, vex, inventory_diff,
    validate_cyclonedx, validate_sarif, validate_spdx, validate_openvex
)


def sample_scan():
    return {
        'id': str(uuid.uuid4()).replace('-', ''),
        'repo': 'org/demo-repo',
        'commit_sha': '0123456789abcdef0123456789abcdef01234567',
        'state': 'complete',
        'started_at': 1700000000.0,
        'finished_at': 1700000010.0,
        'coverage': {'state': 'complete', 'files_scanned': 5},
        'evidence_status': {'complete': True},
        'dependencies': [
            {
                'name': 'requests',
                'version': '2.31.0',
                'ecosystem': 'PyPI',
                'scope': 'runtime',
                'digest': 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
            },
            {
                'name': 'pytest',
                'version': '8.3.3',
                'ecosystem': 'PyPI',
                'scope': 'dev',
                'digest': None
            }
        ],
        'findings': [
            {
                'key': 'find-1',
                'title': 'Vulnerable requests version',
                'severity': 'high',
                'category': 'dependency',
                'file_path': 'requirements.txt',
                'status': 'open',
                'details': {'osv_id': 'GHSA-j8r2-6x86-q33q', 'line': 2}
            },
            {
                'key': 'find-2',
                'title': 'Suppressed issue',
                'severity': 'medium',
                'category': 'code',
                'file_path': 'app.py',
                'status': 'suppressed',
                'details': {'rule': 'dynamic-execution', 'line': 42}
            }
        ]
    }


def test_cyclonedx_sbom_generation_and_validation():
    scan = sample_scan()
    doc = sbom(scan)
    assert doc['bomFormat'] == 'CycloneDX'
    assert doc['specVersion'] == '1.6'
    assert len(doc['components']) == 2
    assert validate_cyclonedx(doc) is True

    # Validate failure on broken document
    with pytest.raises(ValueError, match='bomFormat must be CycloneDX'):
        validate_cyclonedx({'bomFormat': 'Other', 'specVersion': '1.6'})


def test_sarif_generation_and_validation():
    scan = sample_scan()
    doc = sarif(scan)
    assert doc['version'] == '2.1.0'
    assert len(doc['runs']) == 1
    assert len(doc['runs'][0]['results']) == 2
    assert validate_sarif(doc) is True

    with pytest.raises(ValueError, match='SARIF version must be 2.1.0'):
        validate_sarif({'version': '1.0.0', '$schema': 'url', 'runs': []})


def test_spdx_sbom_generation_and_validation():
    scan = sample_scan()
    doc = spdx(scan)
    assert doc['spdxVersion'] == 'SPDX-2.3'
    assert doc['SPDXID'] == 'SPDXRef-DOCUMENT'
    assert len(doc['packages']) == 2
    assert len(doc['relationships']) == 2
    assert validate_spdx(doc) is True

    # Check purl and checksum
    req_pkg = next(p for p in doc['packages'] if p['name'] == 'requests')
    assert any(ref['referenceLocator'] == 'pkg:pypi/requests@2.31.0' for ref in req_pkg['externalRefs'])
    assert req_pkg['checksums'][0]['checksumValue'] == '1111111111111111111111111111111111111111111111111111111111111111'

    with pytest.raises(ValueError, match='SPDXID must be SPDXRef-DOCUMENT'):
        validate_spdx({'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'INVALID'})


def test_openvex_generation_and_validation():
    scan = sample_scan()
    doc = vex(scan)
    assert doc['@context'] == 'https://openvex.dev/ns/v0.2.0'
    assert len(doc['statements']) == 2
    assert validate_openvex(doc) is True

    # find-1 is open -> affected
    stmt_open = doc['statements'][0]
    assert stmt_open['vulnerability']['name'] == 'GHSA-j8r2-6x86-q33q'
    assert stmt_open['status'] == 'affected'
    assert 'action_statement' in stmt_open

    # find-2 is suppressed -> not_affected
    stmt_supp = doc['statements'][1]
    assert stmt_supp['vulnerability']['name'] == 'dynamic-execution'
    assert stmt_supp['status'] == 'not_affected'
    assert stmt_supp['justification'] == 'risk_accepted'

    with pytest.raises(ValueError, match='Invalid OpenVEX @context'):
        validate_openvex({'@context': 'invalid', 'author': 'me', 'timestamp': 'now', 'statements': []})


def test_inventory_diff():
    base_scan = {
        'dependencies': [
            {'ecosystem': 'PyPI', 'name': 'requests', 'version': '2.28.0'},
            {'ecosystem': 'PyPI', 'name': 'six', 'version': '1.16.0'},
            {'ecosystem': 'npm', 'name': 'lodash', 'version': '4.17.20'}
        ]
    }
    head_scan = {
        'dependencies': [
            {'ecosystem': 'PyPI', 'name': 'requests', 'version': '2.31.0'},  # upgraded
            {'ecosystem': 'PyPI', 'name': 'urllib3', 'version': '2.2.3'},   # added
            {'ecosystem': 'npm', 'name': 'lodash', 'version': '4.17.20'}     # unchanged
            # six removed
        ]
    }

    diff = inventory_diff(base_scan, head_scan)
    assert diff['summary']['added'] == 1
    assert diff['summary']['removed'] == 1
    assert diff['summary']['upgraded'] == 1
    assert diff['summary']['unchanged'] == 1

    assert diff['added'] == [{'ecosystem': 'PyPI', 'name': 'urllib3', 'version': '2.2.3'}]
    assert diff['removed'] == [{'ecosystem': 'PyPI', 'name': 'six', 'version': '1.16.0'}]
    assert diff['upgraded'] == [{'ecosystem': 'PyPI', 'name': 'requests', 'old_version': '2.28.0', 'new_version': '2.31.0'}]
    assert diff['unchanged'] == [{'ecosystem': 'npm', 'name': 'lodash', 'version': '4.17.20'}]

    # None base scan test
    empty_base_diff = inventory_diff(None, head_scan)
    assert empty_base_diff['summary']['added'] == 3
    assert empty_base_diff['summary']['removed'] == 0

