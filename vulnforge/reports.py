"""Snapshot exports. Coverage metadata always accompanies exported evidence."""
import re
import json
import uuid
from datetime import datetime, timezone
from urllib.parse import quote


def purl(dep):
    types = {'PyPI': 'pypi', 'npm': 'npm', 'Go': 'golang', 'crates.io': 'cargo', 'Packagist': 'composer'}
    name = dep['name']
    if dep['ecosystem'] == 'PyPI':
        name = re.sub(r'[-_.]+', '-', name).lower()
    return f"pkg:{types[dep['ecosystem']]}/{quote(name, safe='/')}@{quote(dep['version'], safe='')}"


def sbom(scan):
    components = {}
    for dep in scan['dependencies']:
        identity = purl(dep)
        components[identity] = {'type': 'library', 'bom-ref': identity, 'name': dep['name'],
                                'version': dep['version'], 'purl': identity}
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'serialNumber': f"urn:uuid:{uuid.UUID(scan['id'])}",
            'metadata': {'timestamp': datetime.fromtimestamp(scan['started_at'], timezone.utc).isoformat(),
                         'properties': [{'name': 'vulnforge:repository', 'value': scan['repo']},
                                        {'name': 'vulnforge:commit', 'value': scan['commit_sha'] or 'unknown'},
                                        {'name': 'vulnforge:scan', 'value': scan['id']},
                                        {'name': 'vulnforge:coverage', 'value': scan['state']},
                                        {'name': 'vulnforge:evidence_status', 'value': json.dumps(scan.get('evidence_status',{}),sort_keys=True)},
                                        {'name': 'vulnforge:evidence', 'value': json.dumps(scan['coverage'],sort_keys=True)}]},
            'components': list(components.values())}


def sarif(scan):
    rules, results = {}, []
    for f in scan['findings']:
        details = f['details']
        rule = details.get('rule', details.get('osv_id', f.get('category', 'coverage')))
        rules[rule] = {'id': rule, 'shortDescription': {'text': f['title']}}
        result = {'ruleId': rule, 'level': 'error' if f['severity'] in ('critical', 'high') else 'warning',
                  'message': {'text': f['title']}, 'partialFingerprints': {'vulnforge/v1': f['key']}}
        if f.get('file_path'):
            result['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': quote(f['file_path'], safe='/')},
                                    'region': {'startLine': max(1, details.get('line', 1))}}}]
        results.append(result)
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
            'runs': [{'tool': {'driver': {'name': 'VulnForge', 'version': '0.3.0', 'rules': list(rules.values())}},
                      'invocations': [{'executionSuccessful': scan['state'] == 'complete'}],
                      'properties': {'scan_id': scan['id'], 'commit_sha': scan['commit_sha'],
                                     'evidence_status':scan.get('evidence_status',{}),
                                     'coverage': scan['coverage'], 'analysis_state': scan['state']},
                      'results': results}]}
