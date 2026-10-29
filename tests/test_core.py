from vulnforge.scanner import (
    FINDING_SCHEMA_VERSION,
    GITLEAKS_CONFIG_CONTENT,
    GITLEAKS_CONFIG_ID,
    GITLEAKS_CONFIG_SHA256,
    PINNED_GITLEAKS_VERSION,
    PINNED_SEMGREP_VERSION,
    SEMGREP_RULEPACK_CONTENT,
    SEMGREP_RULEPACK_ID,
    SEMGREP_RULEPACK_SHA256,
    compute_fingerprint,
    normalize_finding,
    normalize_severity,
    parse_gitleaks_json,
    parse_semgrep_json,
    run_gitleaks_adapter,
    run_semgrep_adapter,
    runner_fingerprint,
    scan_code,
    scrub_secret_values,
    to_runner_finding,
    verify_gitleaks_contract,
    verify_semgrep_contract,
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


def test_semgrep_adapter_pins_rulepack_and_tool_version_and_strips_source(tmp_path):
    import json, pytest
    checkout=tmp_path/'checkout';checkout.mkdir()
    rulepack=tmp_path/'rulepack.json'
    rulepack.write_text(SEMGREP_RULEPACK_CONTENT,encoding='utf-8')
    contract=verify_semgrep_contract(f'semgrep {PINNED_SEMGREP_VERSION}\n',rulepack_path=rulepack)
    assert contract['version']==PINNED_SEMGREP_VERSION
    assert contract['rulepack_id']==SEMGREP_RULEPACK_ID
    assert contract['rulepack_sha256']==SEMGREP_RULEPACK_SHA256

    with pytest.raises(ValueError):
        verify_semgrep_contract('semgrep 1.95.0',rulepack_path=rulepack)
    with pytest.raises(ValueError):
        verify_semgrep_contract(PINNED_SEMGREP_VERSION,rulepack_path='p/default')
    bad_pack=tmp_path/'bad.json';bad_pack.write_text('{}',encoding='utf-8')
    with pytest.raises(ValueError):
        verify_semgrep_contract(PINNED_SEMGREP_VERSION,rulepack_path=bad_pack)

    commands=[]
    def fake_runner(cmd):
        commands.append(cmd)
        if '--version' in cmd:
            return PINNED_SEMGREP_VERSION
        return json.dumps({
            'version':PINNED_SEMGREP_VERSION,
            'results':[
                {
                    'check_id':'rules.vulnforge.python.dynamic-execution',
                    'path':'src/handler.py',
                    'start':{'line':19},
                    'extra':{
                        'severity':'ERROR',
                        'message':'Dynamic Python evaluation can execute attacker-controlled input',
                        'lines':'eval(super_secret_source_code_snippet)',
                    },
                },
                {
                    'check_id':'vulnforge.javascript.inner-html',
                    'path':'web/ui.js',
                    'start':{'line':7},
                    'extra':{
                        'severity':'WARNING',
                        'message':'HTML sink; verify input escaping/sanitization',
                        'lines':'el.innerHTML = untrusted_html',
                    },
                },
            ],
        })
    findings=run_semgrep_adapter(checkout,semgrep_bin='/opt/semgrep/bin/semgrep',
                                 rulepack_path=rulepack,runner=fake_runner)
    assert len(findings)==2
    assert '--metrics=off' in commands[1] and '--disable-version-check' in commands[1]
    assert findings[0]['scanner']=='semgrep'
    assert findings[0]['severity']=='high'
    assert findings[0]['details']['rule']=='dynamic-execution'
    assert findings[0]['details']['tool_version']==PINNED_SEMGREP_VERSION
    assert findings[0]['details']['rulepack_sha256']==SEMGREP_RULEPACK_SHA256
    assert 'super_secret_source_code_snippet' not in json.dumps(findings)
    runner_f=to_runner_finding(findings[0])
    assert runner_f['rule_id']=='dynamic-execution' and runner_f['line']==19

    with pytest.raises(ValueError):
        parse_semgrep_json({'version':'0.99.0','results':[]})
    with pytest.raises(ValueError):
        run_semgrep_adapter(checkout,semgrep_bin=checkout/'bin/semgrep',rulepack_path=rulepack,runner=fake_runner)


def test_gitleaks_adapter_strips_secrets_from_findings_logs_and_exports(tmp_path):
    import json, subprocess, pytest
    from vulnforge.reports import sarif
    checkout=tmp_path/'checkout';checkout.mkdir()
    config_file=tmp_path/'gitleaks.toml'
    config_file.write_text(GITLEAKS_CONFIG_CONTENT,encoding='utf-8')
    contract=verify_gitleaks_contract(f'v{PINNED_GITLEAKS_VERSION}\n',config_path=config_file)
    assert contract['version']==PINNED_GITLEAKS_VERSION
    assert contract['config_id']==GITLEAKS_CONFIG_ID
    assert contract['config_sha256']==GITLEAKS_CONFIG_SHA256

    with pytest.raises(ValueError):
        verify_gitleaks_contract('8.20.0',config_path=config_file)
    bad_cfg=tmp_path/'bad.toml';bad_cfg.write_text('title = "bad"',encoding='utf-8')
    with pytest.raises(ValueError):
        verify_gitleaks_contract(PINNED_GITLEAKS_VERSION,config_path=bad_cfg)

    raw_token='ghp_'+'Z'*36
    raw_aws='AKIAIOSFODNN7EXAMPLE'
    commands=[]
    def fake_runner(cmd):
        commands.append(cmd)
        if 'version' in cmd:
            return PINNED_GITLEAKS_VERSION
        return json.dumps([
            {
                'RuleID':'github-pat',
                'Description':f'GitHub Personal Access Token {raw_token}',
                'StartLine':14,
                'File':'src/config.py',
                'Secret':raw_token,
                'Match':f'GITHUB_TOKEN = "{raw_token}"',
            },
            {
                'RuleID':'aws-access-token',
                'Description':'AWS Access Key ID',
                'StartLine':28,
                'File':'src/aws.py',
                'Secret':raw_aws,
                'Match':f'aws_key = "{raw_aws}"',
            },
        ])
    findings=run_gitleaks_adapter(checkout,gitleaks_bin='/opt/gitleaks/bin/gitleaks',
                                  config_path=config_file,runner=fake_runner)
    assert len(findings)==2
    assert '--redact' in commands[1] and '--no-banner' in commands[1]
    encoded_findings=json.dumps(findings)
    assert raw_token not in encoded_findings and raw_aws not in encoded_findings
    assert findings[0]['scanner']=='gitleaks'
    assert findings[0]['details']['rule']=='hardcoded-secret'
    assert findings[0]['details']['gitleaks_rule_id']=='github-pat'
    assert findings[0]['details']['evidence']=='[REDACTED: possible secret]'
    runner_f=to_runner_finding(findings[0])
    assert runner_f['rule_id']=='hardcoded-secret' and runner_f['line']==14

    # Verify SARIF export and error log scrubbing never leak secret values
    scan_doc={
        'id':'11111111-2222-3333-4444-555555555555',
        'state':'complete',
        'commit_sha':'a'*40,
        'coverage':{'scope':'commit_files'},
        'findings':findings,
    }
    sarif_json=json.dumps(sarif(scan_doc))
    assert raw_token not in sarif_json and raw_aws not in sarif_json

    def failing_runner(cmd):
        if 'version' in cmd:
            return PINNED_GITLEAKS_VERSION
        raise subprocess.CalledProcessError(2,cmd,stderr=f'fatal error while scanning {raw_token}')
    with pytest.raises(RuntimeError) as exc_info:
        run_gitleaks_adapter(checkout,gitleaks_bin='/opt/gitleaks/bin/gitleaks',
                             config_path=config_file,runner=failing_runner)
    assert raw_token not in str(exc_info.value) and '[REDACTED]' in str(exc_info.value)
    assert raw_token not in scrub_secret_values(f'leak: {raw_token}')
