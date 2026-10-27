import os
from pathlib import Path
import subprocess
import sys

import pytest

from vulnforge.github_app import registration
from vulnforge.runner_cleanup import cleanup


def test_registration_separates_source_and_write_permissions():
    runner=registration('https://security.example.com')
    assert runner['permissions']=={'metadata':'read'} and not runner['events']
    managed=registration('https://security.example.com','managed_read')
    assert managed['permissions']['contents']=='read' and 'checks' not in managed['permissions']
    patch=registration('https://security.example.com','remediation_write',checks=True)
    assert patch['permissions']['contents']=='write' and patch['permissions']['checks']=='write'
    assert not patch['live_verified'] and not patch['public']
    with pytest.raises(ValueError): registration('https://security.example.com',checks=True)


@pytest.mark.parametrize('origin',['http://example.com','https://localhost','https://127.0.0.1',
    'https://[::1]','https://192.168.1.2','https://user:secret@example.com','https://example.com/path',
    'https://example.com?query=1','https://example.com:999999','https://example.com/#fragment'])
def test_registration_rejects_unusable_origins(origin):
    with pytest.raises(ValueError): registration(origin)


def environment(tmp_path):
    root=tmp_path/'checkout';root.mkdir()
    temp=tmp_path/'runner';temp.mkdir()
    output=tmp_path/'outputs'
    env={**os.environ,'VF_ROOT':str(root),'VF_REPOSITORY':'org/project','VF_SHA':'a'*40,
         'VF_FAIL_ON':'none','RUNNER_TEMP':str(temp),'GITHUB_OUTPUT':str(output)}
    return root,temp,output,env


def test_composite_entrypoint_uses_isolated_imports_and_metadata_only(tmp_path):
    root,temp,output,env=environment(tmp_path)
    (root/'code.py').write_text('eval(private_source_value)')
    (root/'vulnforge.py').write_text('raise RuntimeError("untrusted shadow module")')
    script=Path(__file__).resolve().parents[1]/'scripts/action_scan.py'
    result=subprocess.run([sys.executable,'-I',str(script)],cwd=root,env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    values=dict(line.split('=',1) for line in output.read_text().splitlines())
    content=Path(values['code-report']).read_text()
    assert 'private_source_value' not in content and 'code.py' not in content
    assert 'shadow module' not in result.stderr
    cleanup(values['code-report'],temp)
    assert not list(temp.iterdir())


def test_interrupt_and_error_cleanup(tmp_path,monkeypatch):
    from scripts import action_scan
    _,temp,_,env=environment(tmp_path)
    for name,value in env.items(): monkeypatch.setenv(name,value)
    def interrupt(*args): raise KeyboardInterrupt()
    monkeypatch.setattr(action_scan,'scan',interrupt)
    assert action_scan.main()==2
    assert not list(temp.iterdir())


def test_cleanup_refuses_checkout_symlinks_or_unexpected_files(tmp_path):
    root,temp,_,_=environment(tmp_path)
    (root/'source.py').write_text('must remain')
    with pytest.raises(ValueError): cleanup(root/'source.py',temp)
    directory=temp/'vulnforge-fixture';directory.mkdir()
    (directory/'other-file').write_text('must remain')
    with pytest.raises(ValueError): cleanup(directory/'code.json',temp)
    (directory/'other-file').unlink();(directory/'code.json').symlink_to(root/'source.py')
    with pytest.raises(ValueError): cleanup(directory/'code.json',temp)
    assert (root/'source.py').read_text()=='must remain'
