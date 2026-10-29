import json
import os
from pathlib import Path

from vulnforge.cli import scan,main,write_report
from vulnforge.runner_report import parse_report

SHA='a'*40


def test_code_report_omits_source_secrets_and_paths(tmp_path):
    root=tmp_path/'source';root.mkdir()
    token='ghp_'+'A'*36
    (root/'private-name.py').write_text(f'credential = "{token}"\neval(user_input)\n')
    result=scan(root,'org/project',SHA)
    encoded=result.model_dump_json()
    assert len(result.findings)==2 and result.coverage.state=='complete'
    assert token not in encoded and 'private-name' not in encoded and 'user_input' not in encoded
    assert {f.rule_id for f in result.findings}=={'hardcoded-secret','dynamic-execution'}
    assert parse_report(encoded.encode())==result


def test_repository_code_is_never_executed(tmp_path):
    marker=tmp_path/'executed'
    (tmp_path/'setup.py').write_text(f'open({str(marker)!r},"w").write("bad")\n')
    (tmp_path/'conftest.py').write_text('raise RuntimeError("must not import")\n')
    (tmp_path/'package.json').write_text('{"scripts":{"install":"touch executed"}}')
    result=scan(tmp_path,'org/project',SHA)
    assert result.coverage.files_scanned==3 and not marker.exists()


def test_manifest_dependency_scope_is_honest(tmp_path):
    (tmp_path/'requirements.txt').write_text('requests==2.27.0\nprivate-package>=1\n')
    report=scan(tmp_path,'org/project',SHA,'dependencies')
    assert report.coverage.state=='incomplete' and report.coverage.dependency_scope=='declared'
    assert report.coverage.reasons['unresolved_dependency']
    assert report.coverage.reasons['transitive_graph_unavailable']
    assert len(report.dependencies)==1 and len(report.manifests)==1


def test_resolved_package_lock_and_empty_inventory(tmp_path):
    empty=scan(tmp_path,'org/project',SHA,'dependencies')
    assert empty.coverage.state=='incomplete'
    (tmp_path/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{
        '':{'name':'project'},'node_modules/demo':{'version':'1.2.3'}}}))
    report=scan(tmp_path,'org/project',SHA,'dependencies')
    assert report.coverage.state=='complete' and report.coverage.dependency_scope=='resolved'
    assert report.dependencies[0].name=='demo'


def test_symlinks_submodules_and_vendored_trees_are_not_followed(tmp_path):
    root=tmp_path/'source';root.mkdir()
    outside=tmp_path/'outside';outside.mkdir();(outside/'secret.py').write_text('eval(secret)')
    (root/'linked').symlink_to(outside,target_is_directory=True)
    (root/'linked.py').symlink_to(outside/'secret.py')
    git=root/'.git';git.mkdir();(git/'ignored.py').write_text('eval(secret)')
    # Git submodule checkouts have a .git file rather than a .git directory.
    module=root/'submodule';module.mkdir();(module/'.git').write_text('gitdir: outside')
    (module/'source.py').write_text('eval(secret)')
    report=scan(root,'org/project',SHA)
    assert report.coverage.state=='incomplete' and not report.findings
    assert report.coverage.files_skipped>=2


def test_limits_binary_parse_errors_and_invalid_manifest(tmp_path,monkeypatch):
    from vulnforge import cli
    (tmp_path/'big.py').write_text('x'*300001)
    (tmp_path/'binary.py').write_bytes(b'\xff\x00')
    (tmp_path/'broken.py').write_text('def f(:')
    report=scan(tmp_path,'org/project',SHA)
    assert report.coverage.files_skipped==2 and report.coverage.files_scanned==1
    assert report.coverage.reasons['parse_error']==1 and report.coverage.state=='incomplete'
    monkeypatch.setattr(cli,'MAX_ENTRIES',1)
    limited=scan(tmp_path,'org/project',SHA)
    assert limited.coverage.state=='incomplete' and limited.coverage.reasons['scanner_limit']


def test_atomic_private_output_and_exit_codes(tmp_path,capsys):
    root=tmp_path/'source';root.mkdir();(root/'code.py').write_text('eval(value)')
    output=tmp_path/'report.json'
    args=['--root',str(root),'--repo','org/project','--sha',SHA,'--output',str(output)]
    assert main(args+['--fail-on','high'])==1
    assert output.stat().st_mode&0o777==0o600
    assert not list(tmp_path.glob('.vf-report-*'))
    assert 'code.py' not in capsys.readouterr().out
    assert main(args+['--kind','dependencies','--require-complete'])==3
    assert main(args+['--sha','invalid'])==2
    assert 'invalid' not in capsys.readouterr().err


def test_symlink_root_is_rejected(tmp_path):
    root=tmp_path/'source';root.mkdir();link=tmp_path/'link';link.symlink_to(root,target_is_directory=True)
    assert main(['--root',str(link),'--repo','org/project','--sha',SHA,'--output',str(tmp_path/'out')])==2


def test_cli_profiles_push_pr_default_branch_and_scheduled(tmp_path,capsys):
    base=tmp_path/'base';base.mkdir()
    head=tmp_path/'head';head.mkdir()
    (base/'existing.py').write_text('eval(old_value)\n')
    (head/'existing.py').write_text('# comment line\neval(old_value)\n')
    out=tmp_path/'report.json'
    # PR profile with base-root ignores pre-existing finding when gating on --fail-on high
    code=main(['--root',str(head),'--base-root',str(base),'--profile','pull_request',
               '--repo','org/project','--sha',SHA,'--output',str(out),'--fail-on','high'])
    assert code==0
    summary=json.loads(capsys.readouterr().out)
    assert summary['profile']=='pull_request' and summary['diff_status']=='compared'
    assert summary['new_findings']==0 and summary['pre_existing_findings']==1

    # Introducing a new finding in head fails the PR gate
    (head/'added.py').write_text('eval(new_value)\n')
    code2=main(['--root',str(head),'--base-root',str(base),'--profile','pull_request',
                '--repo','org/project','--sha',SHA,'--output',str(out),'--fail-on','high'])
    assert code2==1
    summary2=json.loads(capsys.readouterr().out)
    assert summary2['new_findings']==1 and summary2['pre_existing_findings']==1

    # Scheduled profile requires complete coverage automatically
    sched=main(['--root',str(head),'--profile','scheduled','--kind','dependencies',
                '--repo','org/project','--sha',SHA,'--output',str(out)])
    assert sched==3
    capsys.readouterr()

    # --base-root with non-PR profile is rejected
    assert main(['--root',str(head),'--base-root',str(base),'--profile','push',
                 '--repo','org/project','--sha',SHA,'--output',str(out)])==2
