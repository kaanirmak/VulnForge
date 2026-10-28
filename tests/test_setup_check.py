"""Preflight must never execute .env, write a database or echo credentials."""
from dataclasses import replace
import json

import pytest

from test_runner_oidc import signing_key
from test_github_metadata import configuration
from vulnforge.config import Config
from vulnforge.setup_check import inspect,main,read_env,ENV_KEYS


def test_unconfigured_preflight_stays_closed_and_does_not_create_database(tmp_path,monkeypatch,capsys):
    monkeypatch.chdir(tmp_path)
    for key in ENV_KEYS:monkeypatch.delenv(key,raising=False)
    assert main([])==2
    result=json.loads(capsys.readouterr().out)
    assert not result['production_ready'] and not result['customer_ingestion_ready']
    assert not (tmp_path/'data').exists()


def test_valid_local_config_is_never_a_live_or_production_acceptance(signing_key,tmp_path):
    key=tmp_path/'private.pem';key.write_text(configuration(signing_key).private_key());key.chmod(0o600)
    cfg=Config(app_id='123',github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='secret-fixture-only-12345',
        private_key_path=str(key),public_origin='http://127.0.0.1:8000',allow_insecure_local_auth=True,
        customer_api_preview=True,github_connection_preview=True,webhook_secret='w'*48,
        operator_credentials=(('operator','a'*48),))
    result=inspect(cfg)
    assert result['local_configuration_ready']
    for field in ('app_permissions_verified','live_acceptance_verified','production_ready','database_roles_verified'):
        assert result[field] is False
    encoded=json.dumps(result)
    for secret in (cfg.github_oauth_client_secret,'a'*48,'w'*48,str(key),'BEGIN PRIVATE'):
        assert secret not in encoded
    assert not inspect(replace(cfg,private_key_path=str(tmp_path/'absent')))['checks']['private_rsa_key']


@pytest.mark.parametrize('body',[
    'PATH=/tmp/evil','PYTHONPATH=/tmp/evil','PUBLIC_ORIGIN=$(touch /tmp/no)',
    'ADMIN_TOKEN=one\nADMIN_TOKEN=two','not-an-assignment','ADMIN_TOKEN="unclosed',
])
def test_env_file_is_literal_restricted_and_duplicate_free(tmp_path,body):
    file=tmp_path/'.env';file.write_text(body);file.chmod(0o600)
    with pytest.raises((ValueError,OSError)):read_env(str(file))


def test_quoted_json_operator_credentials_and_no_interpolation(tmp_path):
    file=tmp_path/'.env';file.write_text('# local\nOPERATOR_CREDENTIALS={"admin":"'+'a'*48+'"}\nSCAN_MODE=\'customer_runner\'\n')
    file.chmod(0o600)
    values=read_env(str(file));cfg=Config.from_env(values)
    assert cfg.operator_credentials==(('admin','a'*48),) and cfg.scan_mode=='customer_runner'


@pytest.mark.parametrize('kind',['public_permissions','symlink','large','invalid_config'])
def test_bad_env_files_fail_without_printing_values(tmp_path,capsys,kind):
    target=tmp_path/'target';target.write_text('ADMIN_TOKEN=do-not-echo-this-secret');target.chmod(0o600)
    path=target
    if kind=='public_permissions':target.chmod(0o644)
    elif kind=='symlink':path=tmp_path/'link';path.symlink_to(target)
    elif kind=='large':target.write_text('x'*32769)
    else:target.write_text('PUBLIC_ORIGIN=https://example.com\nGITHUB_OAUTH_CLIENT_SECRET=do-not-echo-this-secret')
    assert main(['--env-file',str(path)])==2
    output=capsys.readouterr().out
    assert 'do-not-echo-this-secret' not in output and str(path) not in output
    assert json.loads(output)['production_ready'] is False
