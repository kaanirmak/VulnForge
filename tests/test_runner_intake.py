import asyncio
from dataclasses import replace
import json
import time

import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.runner_intake import RunnerIntake,RunnerDenied,RunnerConflict
from vulnforge.runner_report import RunnerReport
from test_database import pg_store,pg_customer,pg_operator
from test_job_scope import queue,own
from test_organization import config,client_for,ROOT,ORIGIN
from test_privacy import report_fixture
from test_runner_oidc import signing_key,claims,signed,verifier,WORKFLOW


class Metadata:
    def __init__(self): self.calls=[];self.callback=None;self.result={'repository_id':201,'owner_id':101,'default_branch':'main'}
    async def repository(self,repo,installation):
        self.calls.append((repo,installation))
        if self.callback: self.callback()
        return dict(self.result)


def report(**overrides): return RunnerReport.model_validate({**report_fixture(),'repo':'alpha/project',**overrides})


def configure(store):
    org=own(store);cfg=replace(config(store),runner_oidc_preview=True,runner_trusted_workflows=(WORKFLOW,))
    with store.conn() as c: actor=c.execute('SELECT id FROM users WHERE github_id=100').fetchone()[0]
    metadata=Metadata();intake=RunnerIntake(store,cfg,metadata)
    asyncio.run(intake.configure(org,'alpha/project',actor,WORKFLOW))
    # Model a policy installed before the workflow started, rather than sleeping.
    with store.conn() as c: c.execute('UPDATE runner_policies SET verified_at=?',(time.time()-10,))
    return org,actor,cfg,metadata,intake


@pytest.fixture
def setup(queue,signing_key):
    org,actor,cfg,metadata,intake=configure(queue)
    async def identity(**change):
        oidc=verifier(signing_key)
        try: return await oidc.verify(signed(signing_key,claims(**change)))
        finally: await oidc.client.aclose()
    return queue,org,actor,cfg,metadata,intake,identity


def test_identity_verified_reports_remain_quarantined_and_idempotent(setup):
    store,org,actor,cfg,metadata,intake,identity=setup
    async def run():
        token=await identity()
        first=await intake.accept(token,report())
        duplicate=await intake.accept(token,report())
        refreshed=await intake.accept(await identity(jti='fresh-jti'),report())
        assert not first['duplicate'] and duplicate['duplicate'] and refreshed['duplicate']
        assert first['trust_state']=='identity_verified_quarantined' and not first['baseline_ready']
        assert first['receipt_id']==duplicate['receipt_id']==refreshed['receipt_id']
    asyncio.run(run())
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM runner_token_uses').fetchone()[0]==2
        assert c.execute('SELECT COUNT(*) FROM dependency_inventory').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]==0
        assert 'fixture-jti-1' not in str([dict(r) for r in c.execute('SELECT * FROM runner_token_uses')])


@pytest.mark.parametrize('change',[
    {'repository_id':'999'},{'repository_owner_id':'999'},
    {'sha':'d'*40},{'ref':'refs/heads/other','workflow_ref':'alpha/project/.github/workflows/customer.yml@refs/heads/other'},
    {'job_workflow_ref':'other/platform/.github/workflows/scan.yml@'+'b'*40},
])
def test_wrong_project_sha_branch_or_workflow_cannot_upload(setup,change):
    store,_,_,_,_,intake,identity=setup
    async def run():
        with pytest.raises(RunnerDenied): await intake.accept(await identity(**change),report())
    asyncio.run(run())
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==0


def test_changed_report_or_reused_token_cannot_overwrite_evidence(setup):
    store,_,_,_,_,intake,identity=setup
    async def run():
        token=await identity();first=await intake.accept(token,report())
        changed=report_fixture();changed['repo']='alpha/project';changed['dependencies'][0]['version']='9.9.9'
        with pytest.raises(RunnerConflict): await intake.accept(token,RunnerReport.model_validate(changed))
        with pytest.raises(RunnerConflict):
            await intake.accept(await identity(jti='new-jti'),RunnerReport.model_validate(changed))
        code=RunnerReport.model_validate({'report_version':'1','scan_mode':'customer_runner','repo':'alpha/project',
            'commit_sha':'a'*40,'scan_kind':'code','coverage':{'state':'complete','files_total':0,'files_scanned':0,'files_skipped':0}})
        with pytest.raises(RunnerConflict): await intake.accept(token,code)
        assert not (await intake.accept(await identity(jti='code-jti'),code))['duplicate']
    asyncio.run(run())
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==2


@pytest.mark.parametrize('change',['uninstall','reinstall','branch','disable','admin_role','metadata','policy_update'])
def test_access_loss_or_policy_change_during_provider_wait_rejects_write(setup,change):
    store,org,actor,cfg,metadata,intake,identity=setup
    def revoke():
        independent=Store(store.path,migrate=False)
        if change in ('uninstall','reinstall'):
            independent.remove_repo('alpha/project')
            if change=='reinstall': independent.upsert_repo('alpha/project',11,'main')
        elif change=='branch': independent.upsert_repo('alpha/project',11,'other')
        elif change=='disable': intake.disable(org,'alpha/project',actor)
        elif change=='admin_role':
            with independent.conn() as c:
                c.execute("UPDATE memberships SET role='viewer' WHERE organization_id=? AND user_id=?",(org,actor))
        elif change=='policy_update':
            with independent.conn() as c: c.execute('UPDATE runner_policies SET verified_at=?',(time.time(),))
        else: metadata.result['owner_id']=999
    metadata.callback=revoke
    async def run():
        with pytest.raises(RunnerDenied): await intake.accept(await identity(),report())
    asyncio.run(run())
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==0


def test_token_issued_before_policy_was_installed_is_rejected(setup):
    _,_,_,_,_,intake,identity=setup
    async def run():
        with pytest.raises(RunnerDenied):
            await intake.accept(await identity(iat=int(time.time())-30,nbf=int(time.time())-30),report())
    asyncio.run(run())


def test_runner_api_uses_real_signature_check_and_never_accepts_operator_token(tmp_path,signing_key):
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main')
    _,_,cfg,metadata,intake=configure(store)
    app=create_app(cfg,store);app.state.github_metadata=metadata;app.state.runner_oidc=verifier(signing_key)
    with TestClient(app,base_url=ORIGIN) as client:
        url='/api/v1/runner/reports';headers={'Authorization':'Bearer '+signed(signing_key)}
        assert client.post(url,json=report().model_dump()).status_code==401
        assert client.post(url,json=report().model_dump(),headers={'Authorization':'Bearer operator-only'}).status_code==401
        accepted=client.post(url,json=report().model_dump(),headers=headers)
        assert accepted.status_code==202 and not accepted.json()['baseline_ready']
        assert accepted.headers['cache-control']=='no-store'
        assert client.post(url,json=report().model_dump(),headers=headers).json()['duplicate']
        assert client.post(url+'?token=private-marker',json={},headers=headers).status_code==400
        assert client.post(url+'/?token=private-marker',json={},headers=headers,follow_redirects=False).status_code==400
        assert client.post(url,json={**report().model_dump(),'source':'private-marker'},headers=headers).status_code==422
        assert client.post(url,content=b'x'*1000001,headers={**headers,'Content-Type':'application/json'}).status_code==413
        assert client.post(url,json={},headers={**headers,'Content-Encoding':'gzip'}).status_code==415
        assert client.post(url,json=report().model_dump(),headers={**headers,'Host':'attacker.example'}).status_code==400
    asyncio.run(app.state.runner_oidc.client.aclose())


def test_policy_route_requires_admin_csrf_and_platform_workflow_allowlist(tmp_path):
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main')
    org,actor,cfg,metadata,_=configure(store);app=create_app(cfg,store);app.state.github_metadata=metadata
    user={'id':actor};client,headers=client_for(app,store,cfg,user)
    url=ROOT+'/'+org+'/runner-policy';body={'repo':'alpha/project','workflow_ref':WORKFLOW}
    assert client.put(url,json=body).status_code==403
    assert client.put(url,json={**body,'workflow_ref':'attacker/scan.yml@main'},headers=headers).status_code==403
    assert client.put(url,json=body,headers=headers).status_code==200
    assert client.delete(url,params={'repo':'alpha/project'},headers=headers).status_code==204
    assert client.post('/api/v1/runner/reports',json={}).status_code==401


def test_ingestion_is_default_closed_and_public_host_cannot_enable_preview(tmp_path):
    from vulnforge.config import Config
    store=Store(str(tmp_path/'db'))
    with TestClient(create_app(Config(),store)) as client:
        assert client.post('/api/v1/runner/reports',json={}).status_code==503
    with pytest.raises(ValueError): Config(runner_oidc_preview=True,runner_trusted_workflows=(WORKFLOW,))
    with pytest.raises(ValueError): replace(config(store),runner_trusted_workflows=('org/repo/.github/workflows/scan.yml@main',))
    with pytest.raises(ValueError):
        replace(config(store),runner_oidc_preview=True,runner_trusted_workflows=(WORKFLOW,),scan_mode='managed',
                allow_managed_source_access=True,managed_scan_consent_id='test-managed-consent')


def test_parallel_redelivery_creates_one_receipt(setup):
    from concurrent.futures import ThreadPoolExecutor
    store,_,_,_,_,intake,identity=setup
    verified=asyncio.run(identity())
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:asyncio.run(intake.accept(verified,report())),range(3)))
    assert len({r['receipt_id'] for r in results})==1
    assert sum(not r['duplicate'] for r in results)==1


def test_non_owner_operator_can_intake_but_customer_cannot_read_proofs(pg_store,pg_customer,pg_operator,signing_key):
    from vulnforge.database import DatabaseError
    pg_store.upsert_repo('alpha/project',11,'main')
    org,actor,cfg,metadata,_=configure(pg_store)
    cfg=replace(cfg,database_url=pg_operator.path,customer_database_url=pg_customer.path,database_auto_migrate=False)
    app=create_app(cfg,pg_operator);app.state.github_metadata=metadata;app.state.runner_oidc=verifier(signing_key)
    with TestClient(app,base_url=ORIGIN) as client:
        accepted=client.post('/api/v1/runner/reports',json=report().model_dump(),
                             headers={'Authorization':'Bearer '+signed(signing_key)})
        assert accepted.status_code==202
    for table in ('runner_policies','runner_receipts','runner_token_uses'):
        with pg_customer.conn() as c:
            with pytest.raises(DatabaseError): c.execute('SELECT * FROM '+table)
    asyncio.run(app.state.runner_oidc.client.aclose())


def test_runner_receipts_and_token_barrier_survive_verified_database_import(tmp_path,pg_store,signing_key):
    from vulnforge.migrate import import_sqlite
    source=Store(str(tmp_path/'source.db'));source.upsert_repo('alpha/project',11,'main')
    _,_,_,_,intake=configure(source)
    async def run():
        oidc=verifier(signing_key)
        try: return await intake.accept(await oidc.verify(signed(signing_key)),report())
        finally: await oidc.client.aclose()
    receipt=asyncio.run(run())
    result=import_sqlite(source.path,pg_store.path)
    assert result['verified']
    for table in ('runner_policies','runner_receipts','runner_token_uses'):
        assert result['tables'][table]==1
        with source.conn() as a,pg_store.conn() as b:
            assert [dict(r) for r in a.execute('SELECT * FROM '+table)]==[dict(r) for r in b.execute('SELECT * FROM '+table)]


def test_cli_to_oidc_upload_is_metadata_only_end_to_end(tmp_path,signing_key):
    import httpx
    from vulnforge.cli import scan,write_report
    from vulnforge.runner_upload import upload
    from test_runner_upload import ENV
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main')
    _,_,cfg,metadata,_=configure(store);app=create_app(cfg,store)
    app.state.github_metadata=metadata;app.state.runner_oidc=verifier(signing_key)
    checkout=tmp_path/'checkout';checkout.mkdir()
    source_secret='ghp_'+'A'*36
    (checkout/'private-file-name.py').write_text(f'token="{source_secret}"\neval(private_source)\n')
    report_path=tmp_path/'code.json';write_report(scan(checkout,'alpha/project','a'*40),report_path)
    sent=[]
    class RoutedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self,request):
            if request.url.host=='pipelines.actions.githubusercontent.com':
                assert request.headers['authorization']=='Bearer fixture-runtime-token'
                return httpx.Response(200,json={'value':signed(signing_key)})
            assert request.url.host=='127.0.0.1'
            sent.append(request.content.decode())
            return await httpx.ASGITransport(app=app).handle_async_request(request)
    async def run():
        async with httpx.AsyncClient(transport=RoutedTransport()) as client:
            result=await upload(report_path,ORIGIN,consent=True,allow_loopback=True,client=client,environ=ENV)
            assert result['trust_state']=='identity_verified_quarantined'
        await app.state.runner_oidc.client.aclose()
    asyncio.run(run())
    assert len(sent)==1
    assert all(value not in sent[0] for value in (source_secret,'private-file-name','private_source','fixture-runtime-token'))
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]==0


def test_provider_failure_or_duplicate_authorization_never_creates_receipt(tmp_path,signing_key):
    from vulnforge.github_metadata import MetadataError
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main')
    _,_,cfg,metadata,_=configure(store);app=create_app(cfg,store)
    class Unavailable:
        async def repository(self,*args): raise MetadataError('private-provider-marker')
    app.state.github_metadata=Unavailable();app.state.runner_oidc=verifier(signing_key)
    token='Bearer '+signed(signing_key)
    with TestClient(app,base_url=ORIGIN) as client:
        response=client.post('/api/v1/runner/reports',json=report().model_dump(),headers={'Authorization':token})
        assert response.status_code==503 and 'private-provider-marker' not in response.text
        assert client.post('/api/v1/runner/reports',json=report().model_dump(),
            headers=[('Authorization',token),('Authorization',token)]).status_code==401
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM runner_receipts').fetchone()[0]==0
    asyncio.run(app.state.runner_oidc.client.aclose())


def test_json_object_key_order_does_not_change_receipt_identity(setup):
    _,_,_,_,_,intake,identity=setup
    data=report().model_dump()
    data['coverage'].update(state='incomplete',dependency_scope='declared',unresolved_dependencies=1,
        reasons={'unresolved_dependency':1,'transitive_graph_unavailable':1})
    reordered=json.loads(json.dumps(data))
    reordered['coverage']['reasons']={'transitive_graph_unavailable':1,'unresolved_dependency':1}
    async def run():
        token=await identity()
        first=await intake.accept(token,RunnerReport.model_validate(data))
        again=await intake.accept(token,RunnerReport.model_validate(reordered))
        assert again['duplicate'] and first['receipt_id']==again['receipt_id']
    asyncio.run(run())
