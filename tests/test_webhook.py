import hashlib
import hmac
import uuid

from fastapi.testclient import TestClient
from vulnforge.api import create_app, signature_ok
from support import managed_config as Config
from vulnforge.db import Store


def setup(tmp_path):
    cfg=Config(webhook_secret='test-webhook-secret',admin_token='test-admin',
               database_path=str(tmp_path/'test.db'))
    store=Store(cfg.database_path)
    return TestClient(create_app(cfg,store)),store


def signed(event, body, secret='test-webhook-secret', delivery=None):
    return {'X-GitHub-Event':event, 'X-GitHub-Delivery':delivery or str(uuid.uuid4()),
            'X-Hub-Signature-256':'sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest(),
            'Content-Type':'application/json'}


def test_github_documented_vector():
    assert signature_ok(b'Hello, World!',
        'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17',
        "It's a Secret to Everybody")
    assert not signature_ok(b'Hello World!',
        'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17',
        "It's a Secret to Everybody")


def test_signature_required_and_dedup(tmp_path):
    client,store=setup(tmp_path)
    body=( '{"repository":{"full_name":"test/backend","default_branch":"main"},'
          '"installation":{"id":123},"ref":"refs/heads/main",'
          '"before":"'+('a'*40)+'","after":"'+('b'*40)+'","commits":[]}' ).encode()
    delivery='1111-AAAA'
    assert client.post('/github/webhook',content=body,headers=signed('push',body,delivery=delivery)).status_code==202
    assert client.post('/github/webhook',content=body,headers=signed('push',body,delivery=delivery)).json()['duplicate']
    assert len(store.list_rows('jobs'))==1
    assert store.list_rows('repositories')[0]['full_name']=='test/backend'
    assert client.post('/github/webhook',content=body+b' ',headers=signed('push',body)).status_code==403
    assert client.post('/github/webhook',content=body).status_code==403


def test_admin_is_protected(tmp_path):
    client,_=setup(tmp_path)
    assert client.get('/health').json()['status']=='ok'
    assert client.get('/api/findings').status_code==401
    assert client.get('/api/findings',headers={'Authorization':'Bearer wrong'}).status_code==401
    assert client.get('/api/findings',headers={'Authorization':'Bearer test-admin'}).json()==[]
    assert client.post('/api/rescan?repo=missing/repo',headers={'Authorization':'Bearer test-admin'}).status_code==404


def test_dependabot_alert_triggers_audit(tmp_path):
    client,store=setup(tmp_path)
    body=b'{"repository":{"full_name":"test/backend","default_branch":"main"},"installation":{"id":123},"action":"created"}'
    res=client.post('/github/webhook',content=body,headers=signed('dependabot_alert',body))
    assert res.status_code==202
    assert store.list_rows('jobs')[0]['kind']=='dependency_audit'


def test_installation_adds_repos(tmp_path):
    client,store=setup(tmp_path)
    body=b'{"repositories_added":[{"full_name":"org/api","default_branch":"develop"}],"installation":{"id":3},"action":"added"}'
    res=client.post('/github/webhook',content=body,headers=signed('installation_repositories',body))
    assert res.status_code==202
    assert store.list_rows('repositories')[0]['default_branch']=='develop'


def test_new_global_advisory_targets_only_matching_projects(tmp_path):
    from vulnforge.dependencies import Dependency
    client,store=setup(tmp_path)
    store.upsert_repo('org/affected',12,'main')
    store.upsert_repo('org/unrelated',14,'main')
    store.replace_inventory('org/affected',[Dependency('Requests','2.27.0','PyPI','requirements.txt')])
    store.replace_inventory('org/unrelated',[Dependency('django','4.1.0','PyPI','requirements.txt')])
    body=b'{"action":"published","security_advisory":{"ghsa_id":"GHSA-FAKE",' \
         b'"vulnerabilities":[{"package":{"ecosystem":"pip","name":"requests"}}]}}'
    res=client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    assert res.status_code==202 and res.json()['matching_repositories']==1
    jobs=store.list_rows('jobs')
    assert len(jobs)==1 and jobs[0]['repo']=='org/affected'
