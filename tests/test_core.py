from vulnforge.scanner import (
    FINDING_SCHEMA_VERSION,
    compute_fingerprint,
    normalize_finding,
    normalize_severity,
    runner_fingerprint,
    scan_code,
    to_runner_finding,
)
from vulnforge.dependencies import parse_manifest, Dependency
from vulnforge.remediation import patched_requirement, candidate_version, branch_for
from vulnforge.db import Store


def test_scanner_keeps_secret_out_of_evidence():
    secret='ghp_'+'A'*36
    results=scan_code('client.py',f'api_token="{secret}"\neval(user_data)\n')
    assert len(results)==2
    assert all(secret not in str(item) for item in results)
    assert results[0]['details']['evidence'].startswith('[REDACTED')
    assert results[0]['schema_version']==FINDING_SCHEMA_VERSION
    assert results[0]['details']['schema_version']==FINDING_SCHEMA_VERSION
    assert len(results[0]['fingerprint'])==64


def test_finding_normalization_and_common_fingerprint_schema():
    import pytest
    assert normalize_severity('ERROR')=='high'
    assert normalize_severity('warning')=='medium'
    assert normalize_severity('note')=='info'
    with pytest.raises(ValueError):
        normalize_severity('unknown')

    code_item=normalize_finding(
        category='code',
        severity='ERROR',
        title='Semgrep rule match',
        file_path='src/app.py',
        line=42,
        rule='dynamic-execution',
        snippet='eval(x)',
        scanner='semgrep',
    )
    assert code_item['severity']=='high'
    assert code_item['scanner']=='semgrep'
    assert code_item['key'].startswith('code:')
    assert code_item['details']['path_id'].startswith('sha256:')
    runner_item=to_runner_finding(code_item)
    assert runner_item['rule_id']=='dynamic-execution'
    assert runner_item['line']==42
    assert runner_item['fingerprint']==runner_fingerprint(code_item['details']['path_id'],42,'dynamic-execution')

    dep_item=normalize_finding(
        category='dependency',
        severity='high',
        title='requests@2.27.0 affected by GHSA-xxxx',
        file_path='requirements.txt',
        ecosystem='PyPI',
        package='requests',
        version='2.27.0',
        advisory_id='GHSA-xxxx',
        scanner='osv',
    )
    assert dep_item['key'].startswith('dep:')
    assert dep_item['details']['fingerprint']==dep_item['fingerprint']
    assert dep_item['details']['path_id'].startswith('sha256:')

    cov_item=normalize_finding(
        category='coverage',
        severity='info',
        title='File not analyzed',
        file_path='src/blob.bin',
        sha='a'*40,
        scanner='coverage',
    )
    assert cov_item['key'].startswith('coverage:')
    assert compute_fingerprint('coverage',file_path='src/blob.bin',sha='a'*40)==(cov_item['key'],cov_item['fingerprint'])


def test_ast_rule_and_no_eval_in_comment():
    results=scan_code('x.py','# eval(user)\nimport subprocess\nsubprocess.run(cmd, shell=True)\n')
    assert len(results)==1 and results[0]['details']['rule']=='subprocess-shell'


def test_parse_multiple_formats():
    deps=parse_manifest('requirements.txt','Flask==2.0.0\nrequests>=2\n# comment\n')
    assert deps==[Dependency('Flask','2.0.0','PyPI','requirements.txt')]
    js='{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.18"}}}'
    assert parse_manifest('package-lock.json',js)==[Dependency('lodash','4.17.18','npm','package-lock.json')]
    poetry='[[package]]\nname = "requests"\nversion = "2.22.0"\n'
    assert parse_manifest('backend/poetry.lock',poetry)==[Dependency('requests','2.22.0','PyPI','backend/poetry.lock')]
    assert parse_manifest('go.mod','module hi\nrequire (\n github.com/pkg/errors v0.8.0\n)')[0].name=='github.com/pkg/errors'


def test_patch_exact_pin_only():
    dep=Dependency('requests','2.27.0','PyPI','app/requirements.txt')
    original='# keep\nrequests==2.27.0  # pinned\nfastapi==0.115.0\n'
    assert patched_requirement(original,dep,'2.31.0')=='# keep\nrequests==2.31.0  # pinned\nfastapi==0.115.0\n'
    assert patched_requirement('requests>=2.27.0\n',dep,'2.31.0') is None
    assert patched_requirement('requests==2.27.0\nrequests==2.27.0\n',dep,'2.31.0') is None
    assert patched_requirement(original,dep,'2.0.0') is None


def test_fixed_version_candidate():
    dep=Dependency('requests','2.27.0','PyPI','requirements.txt')
    advisory={'affected':[{'package':{'name':'requests','ecosystem':'PyPI'},
                           'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.31.0'}]}]}]}
    from vulnforge.osv import fixed_version
    assert fixed_version(dep,advisory)=='2.31.0'
    assert candidate_version(dep,[advisory])=='2.31.0'
    assert branch_for(dep,'0123456789abcdef').startswith('vulnforge/security/requests-')


def test_queue_is_durable_and_retries(tmp_path):
    store=Store(str(tmp_path/'a.db'))
    store.upsert_repo('o/r',1,'main')
    assert store.enqueue('commit_scan','o/r',{'sha':'a'*40},'job1')
    assert not store.enqueue('commit_scan','o/r',{'sha':'a'*40},'job1')
    claimed=store.claim()
    assert claimed['kind']=='commit_scan'
    store.finish(claimed)
    assert store.claim() is None
    store.save_finding('o/r','dep:key','dependency','high','foo','requirements.txt','a'*40,{})
    assert store.list_rows('findings')[0]['status']=='open'
    store.resolve_missing_dependencies('o/r',set())
    assert store.list_rows('findings')[0]['status']=='resolved'
