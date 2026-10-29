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


def test_deleted_branch_and_reconciled_push_worker_flow(tmp_path):
    import asyncio, json
    from vulnforge.worker import Agent
    client,store=setup(tmp_path)
    s1,s2,s3='1'*40,'2'*40,'3'*40
    deleted_default=json.dumps({
        'repository':{'full_name':'test/backend','default_branch':'main'},
        'installation':{'id':123},
        'ref':'refs/heads/main',
        'before':s1,
        'after':'0'*40,
        'deleted':True,
        'commits':[],
    }).encode()
    res=client.post('/github/webhook',content=deleted_default,headers=signed('push',deleted_default))
    assert res.status_code==202 and res.json()['queued']==0
    events=store.list_rows('audit_events',repo='test/backend')
    assert any(e['action']=='default_branch_deleted_observed' for e in events)
    assert store.repository('test/backend')['evidence_invalidated_at'] is not None

    deleted_feature=json.dumps({
        'repository':{'full_name':'test/backend','default_branch':'main'},
        'installation':{'id':123},
        'ref':'refs/heads/feature/x',
        'before':s1,
        'after':'0'*40,
        'deleted':True,
        'commits':[],
    }).encode()
    res=client.post('/github/webhook',content=deleted_feature,headers=signed('push',deleted_feature))
    assert res.status_code==202 and res.json()['queued']==0
    events=store.list_rows('audit_events',repo='test/backend')
    assert any(e['action']=='branch_deleted_observed' for e in events)

    store.record_branch_head('test/backend',s1)
    force_push=json.dumps({
        'repository':{'full_name':'test/backend','default_branch':'main'},
        'installation':{'id':123},
        'ref':'refs/heads/main',
        'before':s2,
        'after':s3,
        'forced':True,
        'commits':[{'id':s3}],
    }).encode()
    res=client.post('/github/webhook',content=force_push,headers=signed('push',force_push))
    assert res.status_code==202 and res.json()['queued']==1
    job=store.claim()
    assert job is not None and json.loads(job['payload'])['forced'] is True

    class FakeGitHub:
        async def reconcile_push(self, repo, install, before, after, fallback, *, forced=False, last_sha=None, max_backfill=250):
            assert forced is True and last_sha==s1
            return {'shas':[s2,s3],'mode':'force_push_backfill','truncated':False,'base_sha':s1}
    class FakeOSV:
        pass
    agent=Agent(Config(),store,FakeGitHub(),FakeOSV())
    asyncio.run(agent.process(job))
    store.finish(job)
    assert store.repository('test/backend')['last_sha']==s3
    queued=store.list_rows('jobs',repo='test/backend')
    kinds=[j['kind'] for j in queued if j['state']=='pending']
    assert kinds.count('commit_scan')==2 and 'dependency_audit' in kinds
    events=store.list_rows('audit_events',repo='test/backend')
    reconciled=[ json.loads(e['details']) for e in events if e['action']=='push_reconciled' ]
    assert reconciled and reconciled[0]['mode']=='force_push_backfill' and reconciled[0]['base_sha']==s1


def test_installation_lifecycle_repo_add_remove_suspend_unsuspend_and_permissions(tmp_path):
    import json, time
    from vulnforge.config import Config as CustomerConfig
    from vulnforge.identity import Identities
    client,store=setup(tmp_path)
    ident=Identities(store)
    admin=ident.record_github_user(701,'install-admin')
    org=ident.create_organization(admin['id'],'Install Org')

    add_body=json.dumps({
        'action':'added',
        'installation':{'id':77},
        'repositories_added':[
            {'full_name':'org/one','default_branch':'main'},
            {'full_name':'org/two','default_branch':'develop'},
        ],
    }).encode()
    res=client.post('/github/webhook',content=add_body,headers=signed('installation_repositories',add_body))
    assert res.status_code==202 and res.json()['queued']==2
    ident.record_repository_ownership(org['id'],'org/one',admin['id'],'verify:org-one')
    ident.record_repository_ownership(org['id'],'org/two',admin['id'],'verify:org-two')
    assert any(e['action']=='repository_added_to_installation' for e in store.list_rows('audit_events',repo='org/one'))

    rem_body=json.dumps({
        'action':'removed',
        'installation':{'id':77},
        'repositories_removed':[{'full_name':'org/two'}],
    }).encode()
    res=client.post('/github/webhook',content=rem_body,headers=signed('installation_repositories',rem_body))
    assert res.status_code==202
    assert store.repository('org/two') is None
    org_events=store.list_rows('audit_events',repo='organization:'+org['id'])
    assert any(e['action']=='repository_removed_from_installation' and json.loads(e['details'])['repo']=='org/two'
               for e in org_events)

    susp_body=json.dumps({'action':'suspend','installation':{'id':77}}).encode()
    res=client.post('/github/webhook',content=susp_body,headers=signed('installation',susp_body))
    assert res.status_code==202 and store.repository('org/one') is None
    org_events=store.list_rows('audit_events',repo='organization:'+org['id'])
    assert any(e['action']=='installation_suspended' and json.loads(e['details'])['repo']=='org/one'
               for e in org_events)

    unsusp_body=json.dumps({
        'action':'unsuspend',
        'installation':{'id':77},
        'repositories':[{'full_name':'org/one','default_branch':'main'}],
    }).encode()
    res=client.post('/github/webhook',content=unsusp_body,headers=signed('installation',unsusp_body))
    assert res.status_code==202 and res.json()['queued']==1
    assert store.repository('org/one') is not None
    assert any(e['action']=='installation_unsuspended' for e in store.list_rows('audit_events',repo='org/one'))

    perm_body=json.dumps({
        'action':'new_permissions_accepted',
        'installation':{'id':77,'permissions':{'metadata':'read','contents':'read'}},
    }).encode()
    res=client.post('/github/webhook',content=perm_body,headers=signed('installation',perm_body))
    assert res.status_code==202 and res.json()['reconciled_repositories']==1 and res.json()['queued']==1
    perm_events=[json.loads(e['details']) for e in store.list_rows('audit_events',repo='org/one')
                 if e['action']=='installation_permissions_changed']
    assert perm_events and perm_events[-1]['permissions']=={'metadata':'read','contents':'read'}

    # Customer-runner mode disables active runner_policies if installation permissions widen beyond metadata:read
    cust_cfg=CustomerConfig(webhook_secret='test-webhook-secret',admin_token='test-admin',
                            database_path=str(tmp_path/'cust.db'))
    cust_store=Store(cust_cfg.database_path)
    cust_client=TestClient(create_app(cust_cfg,cust_store))
    cust_ident=Identities(cust_store)
    c_admin=cust_ident.record_github_user(702,'cust-admin')
    c_org=cust_ident.create_organization(c_admin['id'],'Cust Org')
    cust_store.upsert_repo('cust/app',88,'main')
    cust_ident.record_repository_ownership(c_org['id'],'cust/app',c_admin['id'],'verify:cust-app')
    conn_id=cust_store.repository('cust/app')['connection_id']
    with cust_store.transaction(), cust_store.conn() as c:
        c.execute('INSERT INTO runner_policies VALUES(?,?,?,?,?,?,?,?,?,1)',
                  ('cust/app',conn_id,c_org['id'],500,600,'org/sec/.github/workflows/scan.yml@' + 'a'*40,
                   'refs/heads/main',c_admin['id'],time.time()))
    widen_body=json.dumps({
        'action':'new_permissions_accepted',
        'installation':{'id':88,'permissions':{'metadata':'read','contents':'write'}},
    }).encode()
    res=cust_client.post('/github/webhook',content=widen_body,headers=signed('installation',widen_body))
    assert res.status_code==202 and res.json()['queued']==0 and res.json()['reconciled_repositories']==1
    with cust_store.conn() as c:
        enabled=c.execute('SELECT enabled FROM runner_policies WHERE repo=?',('cust/app',)).fetchone()['enabled']
    assert enabled==0
