import json

import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.db import Store

KEY='operator_a_'+'X'*40
OTHER='operator_b_'+'Y'*40


def test_named_operator_credentials_are_distinct_audited_and_hidden(tmp_path):
    cfg=Config(operator_credentials=(('alice',KEY),('bob',OTHER)))
    assert KEY not in repr(cfg) and OTHER not in repr(cfg)
    store=Store(str(tmp_path/'db'))
    with TestClient(create_app(cfg,store)) as client:
        assert client.get('/api/findings').status_code==401
        assert client.get('/api/findings',headers={'Authorization':'Bearer unknown'}).status_code==401
        for name,key in (('alice',KEY),('bob',OTHER)):
            response=client.get('/api/findings?repo=private-query-marker',headers={'Authorization':'Bearer '+key})
            assert response.status_code==200
        audits=store.list_rows('audit_events')
        assert {a['actor'] for a in audits}=={'alice','bob'}
        assert all(a['action']=='operator_access' for a in audits)
        encoded=json.dumps(audits)
        assert KEY not in encoded and OTHER not in encoded and 'private-query-marker' not in encoded


def test_home_is_customer_sign_in_and_operator_console_is_separate(tmp_path):
    store=Store(str(tmp_path/'db'))
    with TestClient(create_app(Config(),store)) as client:
        home=client.get('/',follow_redirects=False)
        assert home.status_code==303 and home.headers['location']=='/account'
        assert 'id="token"' not in client.get('/account').text
        assert 'Operatör konsolu' in client.get('/operator').text
        assert client.get('/api/findings').status_code==503


@pytest.mark.parametrize('kwargs',[
    {'operator_credentials':(('alice','short'),)},
    {'operator_credentials':(('alice',KEY),('alice',OTHER))},
    {'operator_credentials':(('alice',KEY),('bob',KEY))},
    {'operator_credentials':(('alice',KEY),),'admin_token':'legacy'},
    {'operator_credentials':(('alice',KEY),),'operator_report_token':KEY},
    {'operator_credentials':(('invalid/name',KEY),)},
])
def test_invalid_or_shared_operator_settings_are_rejected(kwargs):
    with pytest.raises(ValueError): Config(**kwargs)


def test_operator_key_rotation_invalidates_old_key(tmp_path):
    store=Store(str(tmp_path/'db'))
    cfg=Config(operator_credentials=(('alice',OTHER),))
    with TestClient(create_app(cfg,store)) as client:
        assert client.get('/api/findings',headers={'Authorization':'Bearer '+KEY}).status_code==401
        assert client.get('/api/findings',headers={'Authorization':'Bearer '+OTHER}).status_code==200


def test_environment_configuration_and_validation(monkeypatch):
    monkeypatch.delenv('ADMIN_TOKEN',raising=False)
    monkeypatch.setenv('OPERATOR_CREDENTIALS',json.dumps({'alice':KEY}))
    assert Config.from_env().operator_credentials==(('alice',KEY),)
    monkeypatch.setenv('OPERATOR_CREDENTIALS','not-json')
    with pytest.raises(ValueError,match='Invalid OPERATOR_CREDENTIALS'): Config.from_env()


def test_duplicate_environment_operator_ids_are_rejected(monkeypatch):
    monkeypatch.setenv('OPERATOR_CREDENTIALS','{"alice":"'+KEY+'","alice":"'+OTHER+'"}')
    with pytest.raises(ValueError,match='Invalid OPERATOR_CREDENTIALS'): Config.from_env()
