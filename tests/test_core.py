from vulnforge.scanner import scan_code
from vulnforge.dependencies import parse_manifest, Dependency
from vulnforge.remediation import patched_requirement, candidate_version, branch_for
from vulnforge.db import Store


def test_scanner_keeps_secret_out_of_evidence():
    secret='ghp_'+'A'*36
    results=scan_code('client.py',f'api_token="{secret}"\neval(user_data)\n')
    assert len(results)==2
    assert all(secret not in str(item) for item in results)
    assert results[0]['details']['evidence'].startswith('[REDACTED')


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
