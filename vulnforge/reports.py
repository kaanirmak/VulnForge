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
        comp = {'type': 'library', 'bom-ref': identity, 'name': dep['name'],
                'version': dep['version'], 'purl': identity}
        if dep.get('digest'):
            comp['hashes'] = [{'alg': 'SHA-256' if 'sha256' in dep['digest'].lower() else 'SHA-1',
                               'content': dep['digest'].split(':')[-1]}]
        if dep.get('scope') in ('dev', 'test', 'build'):
            comp['scope'] = 'optional'
        else:
            comp['scope'] = 'required'
        components[identity] = comp

    doc = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'serialNumber': f"urn:uuid:{uuid.UUID(scan['id'])}",
           'metadata': {'timestamp': datetime.fromtimestamp(scan['started_at'], timezone.utc).isoformat(),
                        'properties': [{'name': 'vulnforge:repository', 'value': scan['repo']},
                                       {'name': 'vulnforge:commit', 'value': scan['commit_sha'] or 'unknown'},
                                       {'name': 'vulnforge:scan', 'value': scan['id']},
                                       {'name': 'vulnforge:coverage', 'value': scan['state']},
                                       {'name': 'vulnforge:evidence_status', 'value': json.dumps(scan.get('evidence_status',{}),sort_keys=True)},
                                       {'name': 'vulnforge:evidence', 'value': json.dumps(scan['coverage'],sort_keys=True)}]},
           'components': list(components.values())}
    validate_cyclonedx(doc)
    return doc


def sarif(scan):
    from .scanner import scrub_secret_values
    rules, results = {}, []
    for f in scan['findings']:
        details = f['details']
        rule = details.get('rule', details.get('osv_id', f.get('category', 'coverage')))
        safe_title = scrub_secret_values(str(f['title']))
        rules[rule] = {'id': rule, 'shortDescription': {'text': safe_title}}
        result = {'ruleId': rule, 'level': 'error' if f['severity'] in ('critical', 'high') else 'warning',
                  'message': {'text': safe_title}, 'partialFingerprints': {'vulnforge/v1': f['key']}}
        if f.get('file_path'):
            result['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': quote(f['file_path'], safe='/')},
                                    'region': {'startLine': max(1, details.get('line', 1))}}}]
        results.append(result)
    doc = {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
           'runs': [{'tool': {'driver': {'name': 'VulnForge', 'version': '0.3.0', 'rules': list(rules.values())}},
                     'invocations': [{'executionSuccessful': scan['state'] == 'complete'}],
                     'properties': {'scan_id': scan['id'], 'commit_sha': scan['commit_sha'],
                                    'evidence_status':scan.get('evidence_status',{}),
                                    'coverage': scan['coverage'], 'analysis_state': scan['state']},
                     'results': results}]}
    validate_sarif(doc)
    return doc


def spdx(scan):
    packages = []
    relationships = []
    doc_id = 'SPDXRef-DOCUMENT'

    for dep in scan.get('dependencies', []):
        clean_name = re.sub(r'[^A-Za-z0-9.-]', '-', dep['name'])
        clean_ver = re.sub(r'[^A-Za-z0-9.-]', '-', dep['version'])
        pkg_id = f"SPDXRef-Package-{clean_name}-{clean_ver}"
        pkg = {
            'SPDXID': pkg_id,
            'name': dep['name'],
            'versionInfo': dep['version'],
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False,
            'externalRefs': [{
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': purl(dep)
            }]
        }
        if dep.get('digest'):
            pkg['checksums'] = [{
                'algorithm': 'SHA256' if 'sha256' in dep['digest'].lower() else 'SHA1',
                'checksumValue': dep['digest'].split(':')[-1]
            }]
        packages.append(pkg)
        relationships.append({
            'spdxElementId': doc_id,
            'relationshipType': 'DESCRIBES',
            'relatedSpdxElement': pkg_id
        })

    doc = {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': doc_id,
        'name': f"VulnForge-SBOM-{scan['repo'].replace('/', '-')}",
        'documentNamespace': f"https://vulnforge.dev/spdx/{scan['id']}",
        'creationInfo': {
            'created': datetime.fromtimestamp(scan['started_at'], timezone.utc).isoformat(),
            'creators': ['Tool: VulnForge-0.3.0']
        },
        'packages': packages,
        'relationships': relationships
    }
    validate_spdx(doc)
    return doc


def vex(scan):
    from .scanner import scrub_secret_values
    statements = []
    finished = scan.get('finished_at') or scan.get('started_at') or 0

    for f in scan.get('findings', []):
        details = f.get('details', {})
        vuln_id = details.get('osv_id') or details.get('rule') or f.get('category', 'unknown-vuln')
        status = f.get('status', 'open')

        # Map VulnForge finding status to OpenVEX status
        if status in ('suppressed', 'risk_accepted'):
            vex_status = 'not_affected'
            justification = 'risk_accepted'
            action = None
        elif status == 'resolved':
            vex_status = 'fixed'
            justification = None
            action = None
        else:
            vex_status = 'affected'
            justification = None
            action = 'Remediate vulnerability by upgrading to recommended package version.'

        product_id = f"repo:{scan['repo']}"
        if f.get('file_path'):
            product_id += f"#{f['file_path']}"

        stmt = {
            'vulnerability': {'name': str(vuln_id)},
            'products': [{'@id': product_id}],
            'status': vex_status
        }
        if justification:
            stmt['justification'] = justification
        if action:
            stmt['action_statement'] = action
        statements.append(stmt)

    doc = {
        '@context': 'https://openvex.dev/ns/v0.2.0',
        '@id': f"https://vulnforge.dev/vex/{scan['id']}",
        'author': 'VulnForge',
        'timestamp': datetime.fromtimestamp(finished, timezone.utc).isoformat(),
        'version': 1,
        'statements': statements
    }
    validate_openvex(doc)
    return doc


def inventory_diff(base_scan: dict | None, head_scan: dict) -> dict:
    base_dict = {}
    if base_scan and base_scan.get('dependencies'):
        for d in base_scan['dependencies']:
            base_dict[(d['ecosystem'], d['name'])] = d['version']

    head_dict = {}
    if head_scan and head_scan.get('dependencies'):
        for d in head_scan['dependencies']:
            head_dict[(d['ecosystem'], d['name'])] = d['version']

    added = []
    removed = []
    upgraded = []
    unchanged = []

    for (eco, name), head_ver in head_dict.items():
        if (eco, name) not in base_dict:
            added.append({'ecosystem': eco, 'name': name, 'version': head_ver})
        else:
            base_ver = base_dict[(eco, name)]
            if base_ver != head_ver:
                upgraded.append({'ecosystem': eco, 'name': name, 'old_version': base_ver, 'new_version': head_ver})
            else:
                unchanged.append({'ecosystem': eco, 'name': name, 'version': head_ver})

    for (eco, name), base_ver in base_dict.items():
        if (eco, name) not in head_dict:
            removed.append({'ecosystem': eco, 'name': name, 'version': base_ver})

    # Sort deterministically
    sort_key = lambda x: (x['ecosystem'], x['name'])
    added.sort(key=sort_key)
    removed.sort(key=sort_key)
    upgraded.sort(key=sort_key)
    unchanged.sort(key=sort_key)

    return {
        'added': added,
        'removed': removed,
        'upgraded': upgraded,
        'unchanged': unchanged,
        'summary': {
            'added': len(added),
            'removed': len(removed),
            'upgraded': len(upgraded),
            'unchanged': len(unchanged),
            'total_head': len(head_dict),
            'total_base': len(base_dict)
        }
    }


def validate_cyclonedx(doc: dict) -> bool:
    if not isinstance(doc, dict):
        raise ValueError('CycloneDX document must be a JSON object')
    if doc.get('bomFormat') != 'CycloneDX':
        raise ValueError('bomFormat must be CycloneDX')
    if doc.get('specVersion') not in ('1.4', '1.5', '1.6'):
        raise ValueError(f"Unsupported specVersion: {doc.get('specVersion')}")
    if not isinstance(doc.get('serialNumber'), str) or not doc['serialNumber'].startswith('urn:uuid:'):
        raise ValueError('serialNumber must be a valid urn:uuid')
    if not isinstance(doc.get('version'), int) or doc['version'] < 1:
        raise ValueError('version must be a positive integer')
    if 'metadata' not in doc or not isinstance(doc['metadata'], dict) or 'timestamp' not in doc['metadata']:
        raise ValueError('metadata with timestamp is required')
    if not isinstance(doc.get('components'), list):
        raise ValueError('components must be a list')
    for comp in doc['components']:
        if not comp.get('name') or not comp.get('version') or not comp.get('type'):
            raise ValueError('Component requires name, version and type')
    return True


def validate_sarif(doc: dict) -> bool:
    if not isinstance(doc, dict):
        raise ValueError('SARIF document must be a JSON object')
    if doc.get('version') != '2.1.0':
        raise ValueError('SARIF version must be 2.1.0')
    if not doc.get('$schema'):
        raise ValueError('SARIF $schema is required')
    runs = doc.get('runs')
    if not isinstance(runs, list) or not runs:
        raise ValueError('SARIF requires at least one run')
    for r in runs:
        driver = r.get('tool', {}).get('driver', {})
        if not driver.get('name'):
            raise ValueError('Tool driver name is required')
        if not isinstance(r.get('results'), list):
            raise ValueError('Run results must be a list')
        for res in r['results']:
            if not res.get('ruleId') or not res.get('message', {}).get('text'):
                raise ValueError('Result requires ruleId and message text')
    return True


def validate_spdx(doc: dict) -> bool:
    if not isinstance(doc, dict):
        raise ValueError('SPDX document must be a JSON object')
    if doc.get('spdxVersion') not in ('SPDX-2.2', 'SPDX-2.3'):
        raise ValueError('spdxVersion must be SPDX-2.2 or SPDX-2.3')
    if doc.get('dataLicense') != 'CC0-1.0':
        raise ValueError('dataLicense must be CC0-1.0')
    if doc.get('SPDXID') != 'SPDXRef-DOCUMENT':
        raise ValueError('SPDXID must be SPDXRef-DOCUMENT')
    if not doc.get('documentNamespace') or not doc.get('name'):
        raise ValueError('name and documentNamespace are required')
    if 'creationInfo' not in doc or not doc['creationInfo'].get('created'):
        raise ValueError('creationInfo with created timestamp is required')
    if not isinstance(doc.get('packages'), list):
        raise ValueError('packages must be a list')
    return True


def validate_openvex(doc: dict) -> bool:
    if not isinstance(doc, dict):
        raise ValueError('OpenVEX document must be a JSON object')
    if not str(doc.get('@context', '')).startswith('https://openvex.dev/ns/'):
        raise ValueError('Invalid OpenVEX @context')
    if not doc.get('author') or not doc.get('timestamp'):
        raise ValueError('author and timestamp are required')
    if not isinstance(doc.get('statements'), list):
        raise ValueError('statements must be a list')
    for stmt in doc['statements']:
        if not stmt.get('vulnerability', {}).get('name'):
            raise ValueError('Statement vulnerability name required')
        if stmt.get('status') not in ('not_affected', 'affected', 'fixed', 'under_investigation'):
            raise ValueError(f"Invalid statement status: {stmt.get('status')}")
    return True
