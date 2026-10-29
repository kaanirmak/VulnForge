"""Connection revocation and lease fencing on SQLite and real PostgreSQL."""
import asyncio
import time

import pytest

from vulnforge.db import Store,StaleJob
from vulnforge.identity import Identities
from vulnforge.job import JobStore
from vulnforge.worker import Agent,execute_job
from support import managed_config
from test_agent import FakeGitHub,FakeOSV
from test_database import pg_store  # isolated temporary database fixture


@pytest.fixture(params=['sqlite','postgresql'])
def queue(request,tmp_path):
    store=(Store(str(tmp_path/'jobs.db')) if request.param=='sqlite'
           else request.getfixturevalue('pg_store'))
    store.upsert_repo('alpha/project',11,'main')
    store.upsert_repo('bravo/project',22,'main')
    return store


def claim(store,repo='alpha/project',key='audit'):
    store.enqueue('dependency_audit',repo,{},key)
    return store.claim()


def own(store,repo='alpha/project'):
    ids=Identities(store)
    user=ids.record_github_user(100,'owner')
    org=ids.create_organization(user['id'],'Alpha')
    ids.record_repository_ownership(org['id'],repo,user['id'],'fixture-verification')
    return org['id']


def test_scope_is_server_derived_and_connection_dedup_is_stable(queue):
    organization=own(queue)
    queue.enqueue('dependency_audit','alpha/project',
                  {'organization_id':'forged','installation_id':999},'same')
    job=queue.claim()
    assert job['organization_id']==organization and job['installation_id']==11
    queue.upsert_repo('alpha/project',11,'renamed-default')
    queue.check_job(job)
    assert not queue.enqueue('dependency_audit','alpha/project',{},'same')
    queue.finish(job)
    with pytest.raises(StaleJob): queue.finish(job)


@pytest.mark.parametrize('revoke',['remove','reinstall','installation','ownership','lease'])
def test_revoked_jobs_cannot_write_finish_or_enqueue_children(queue,revoke):
    job=claim(queue)
    if revoke in ('remove','reinstall'):
        queue.remove_repo(job['repo'])
        if revoke=='reinstall': queue.upsert_repo(job['repo'],11,'main')
    elif revoke=='installation': queue.upsert_repo(job['repo'],77,'main')
    elif revoke=='ownership': own(queue)
    else:
        with queue.conn() as c: c.execute('UPDATE jobs SET lease_until=? WHERE id=?',(time.time()-1,job['id']))
    with pytest.raises(StaleJob):
        with queue.job_scope(job):
            queue.save_finding(job['repo'],'forbidden','code','high','Old result',None,None,{})
    with pytest.raises(StaleJob): queue.finish(job)
    assert not queue.list_rows('findings')
    if revoke!='remove':
        assert queue.enqueue('dependency_audit',job['repo'],{},'new')


def test_reclaimed_lease_rejects_old_completion_and_old_discard(queue):
    old=claim(queue)
    with queue.conn() as c: c.execute('UPDATE jobs SET lease_until=? WHERE id=?',(time.time()-1,old['id']))
    new=queue.claim()
    assert new['id']==old['id'] and new['claim_token']!=old['claim_token']
    with pytest.raises(StaleJob): queue.finish(old,'old error')
    queue.discard_job(old)
    queue.check_job(new)
    queue.finish(new)


def test_worker_api_blocks_foreign_repository_scan_and_global_access(queue):
    foreign=queue.start_scan('bravo/project','dependencies')
    job=claim(queue)
    with queue.job_scope(job):
        scoped=JobStore(queue,job)
        with pytest.raises(PermissionError): scoped.repository('bravo/project')
        with pytest.raises(PermissionError): scoped.enqueue('dependency_audit','bravo/project',{},'child')
        with pytest.raises(PermissionError): scoped.finish_scan(foreign,'complete',{})
        with pytest.raises(PermissionError): scoped.upsert_repo('alpha/project',22,'main')
        with pytest.raises(PermissionError): scoped.list_rows('findings')
        with pytest.raises(PermissionError): scoped.conn()
        local=scoped.start_scan(job['repo'],'dependencies')
        scoped.finish_scan(local,'complete',{})
    assert queue.scan(foreign)['state']=='running'
    assert queue.scan(local)['state']=='complete'


def test_revoke_during_provider_await_leaves_no_resurrected_rows(queue):
    job=claim(queue)
    class RevokingGitHub(FakeGitHub):
        async def get_file(self,*args):
            # Simulate an independent uninstall transaction while HTTP is pending.
            other=Store(queue.path,migrate=False)
            other.remove_repo(job['repo'])
            other.upsert_repo(job['repo'],11,'main')
            return await super().get_file(*args)
    agent=Agent(managed_config(),queue,RevokingGitHub(),FakeOSV())
    with pytest.raises(StaleJob): asyncio.run(agent.process(job))
    assert not queue.list_rows('findings') and not queue.list_rows('scans')
    assert agent.store is queue
    # The context must reset even after revocation; independent jobs still work.
    fresh=claim(queue,key='fresh')
    queue.check_job(fresh)
    queue.finish(fresh)


def test_ownership_delete_and_reassignment_never_revives_old_claim(queue):
    organization=own(queue)
    job=claim(queue)
    with queue.transaction(),queue.conn() as c:
        old=dict(c.execute('SELECT * FROM repository_ownership WHERE repo=?',(job['repo'],)).fetchone())
        c.execute('DELETE FROM repository_ownership WHERE repo=?',(job['repo'],))
        c.execute('INSERT INTO repository_ownership VALUES(?,?,?,?,?)',
                  tuple(old[k] for k in ('repo','organization_id','granted_by','verification_reference','created_at')))
    assert queue.repository(job['repo'])['connection_id']!=job['connection_id']
    with pytest.raises(StaleJob): queue.check_job(job)
    fresh=claim(queue,key='fresh')
    assert fresh['organization_id']==organization


def test_unknown_repository_cannot_be_enqueued(queue):
    with pytest.raises(LookupError): queue.enqueue('dependency_audit','unknown/repo',{},'unknown')


def test_execute_job_uses_fresh_clients_and_clears_them(tmp_path,monkeypatch):
    from vulnforge import worker
    store=Store(str(tmp_path/'jobs.db'));store.upsert_repo('alpha/project',11,'main')
    created=[]
    class GitHub(FakeGitHub):
        def __init__(self,cfg): super().__init__();self.closed=False;created.append(self)
        def bind_job(self,job,guard): self.bound=job['connection_id'];guard()
        async def close(self): self.closed=True
    class OSV(FakeOSV):
        def __init__(self,*args,**kwargs): self.closed=False;created.append(self)
        async def close(self): self.closed=True
    monkeypatch.setattr(worker,'GitHub',GitHub);monkeypatch.setattr(worker,'OSV',OSV)
    async def run():
        await execute_job(managed_config(),store,claim(store,key='first'))
        await execute_job(managed_config(),store,claim(store,key='second'))
    asyncio.run(run())
    assert len(created)==4 and all(c.closed for c in created)
    assert all(j['state']=='done' for j in store.list_rows('jobs'))


def test_job_errors_do_not_store_or_log_provider_secrets(tmp_path,monkeypatch,caplog):
    from vulnforge import worker
    store=Store(str(tmp_path/'jobs.db'));store.upsert_repo('alpha/project',11,'main')
    async def fail(self,job): raise RuntimeError('private-package ghp_do-not-log')
    monkeypatch.setattr(worker.Agent,'process',fail)
    asyncio.run(execute_job(managed_config(),store,claim(store)))
    assert 'ghp_' not in caplog.text and 'private-package' not in caplog.text
    assert store.list_rows('jobs')[0]['last_error']=='RuntimeError'


def test_github_token_is_repository_limited_and_revalidated(tmp_path,monkeypatch):
    import httpx
    from vulnforge.github import GitHub,GitHubError
    store=Store(str(tmp_path/'jobs.db'));store.upsert_repo('alpha/project',11,'main')
    job=claim(store);requests=[]
    def handler(request):
        import json
        requests.append(request)
        assert json.loads(request.content)['repositories']==['project']
        return httpx.Response(201,json={'token':'fixture-token',
                                       'expires_at':'2099-01-01T00:00:00Z'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            github=GitHub(managed_config(),client)
            monkeypatch.setattr(github,'app_jwt',lambda:'fixture-jwt')
            github.bind_job(job,lambda:store.check_job(job))
            assert await github.token(11)=='fixture-token'
            assert await github.token(11)=='fixture-token'
            with pytest.raises(GitHubError): await github.token(22)
            with pytest.raises(GitHubError): await github.request('GET','/repos/bravo/project',11)
            store.remove_repo(job['repo'])
            with pytest.raises(StaleJob): await github.token(11)
            await github.close()
            assert not github.tokens and not client.cookies
    asyncio.run(run())
    assert len(requests)==1


def test_client_close_clears_advisory_and_cookie_caches():
    import httpx
    from vulnforge.osv import OSV
    from vulnforge.kev import KEV
    async def run():
        async with httpx.AsyncClient() as client:
            osv=OSV(client=client);kev=KEV(client=client)
            osv.cache['private-id']={'summary':'private'}
            kev._entries={'CVE-2099-12345':{}}
            client.cookies.set('session','fixture-cookie')
            await osv.close();await kev.close()
            assert not osv.cache and kev._entries is None and not client.cookies
    asyncio.run(run())


def test_old_unscoped_jobs_are_cancelled_on_upgrade(tmp_path):
    import sqlite3
    from vulnforge.db import SCHEMA
    path=tmp_path/'legacy.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        c.execute('INSERT INTO repositories(full_name,installation_id,default_branch,updated_at) VALUES(?,?,?,?)',
                  ('alpha/project',11,'main',time.time()))
        c.execute('''INSERT INTO jobs(unique_key,kind,repo,payload,available_at,created_at)
                     VALUES(?,?,?,?,?,?)''',('legacy','dependency_audit','alpha/project','{}',0,0))
    store=Store(str(path))
    assert store.claim() is None
    assert store.list_rows('jobs')[0]['state']=='cancelled'
    assert store.enqueue('dependency_audit','alpha/project',{},'legacy')
    store.check_job(store.claim())


def test_private_catalog_queue_is_blocked_until_namespaced(tmp_path):
    from vulnforge.privacy import PrivacyError
    store=Store(str(tmp_path/'jobs.db'));store.upsert_repo('alpha/project',11,'main')
    cfg=managed_config(intelligence_mode='private_osv',osv_api_url='https://osv.internal.example')
    agent=Agent(cfg,store,FakeGitHub(),FakeOSV())
    with pytest.raises(PrivacyError,match='namespaced'):
        asyncio.run(agent.process(claim(store)))
    assert not store.list_rows('scans')


def test_private_osv_catalog_is_namespaced_per_organization_and_isolated(queue):
    ids=Identities(queue)
    alpha_owner=ids.record_github_user(100,'alpha-owner')
    bravo_owner=ids.record_github_user(200,'bravo-owner')
    alpha_org=ids.create_organization(alpha_owner['id'],'Alpha')['id']
    bravo_org=ids.create_organization(bravo_owner['id'],'Bravo')['id']
    ids.record_repository_ownership(alpha_org,'alpha/project',alpha_owner['id'],'fixture-alpha')
    ids.record_repository_ownership(bravo_org,'bravo/project',bravo_owner['id'],'fixture-bravo')
    cfg=managed_config(intelligence_mode='private_osv',osv_api_url='https://osv.internal.example')
    agent=Agent(cfg,queue,FakeGitHub(),FakeOSV())
    alpha_job=claim(queue,'alpha/project','alpha-audit')
    asyncio.run(agent.process(alpha_job))
    queue.finish(alpha_job)
    with queue.conn() as c:
        adv=c.execute('SELECT id,source,catalog_scope FROM advisories').fetchone()
        assert adv['id']==f'org:{alpha_org}:GHSA-TEST'
        assert adv['source']=='Private OSV' and adv['catalog_scope']==f'org:{alpha_org}'
    assert not queue.list_advisories()
    assert len(queue.list_advisories(organization_id=alpha_org))==1
    assert not queue.list_advisories(organization_id=bravo_org)
    if queue.backend=='sqlite':
        from vulnforge.organization import OrganizationData
        alpha_view=OrganizationData(queue,alpha_org,alpha_owner['id'])
        bravo_view=OrganizationData(queue,bravo_org,bravo_owner['id'])
        assert len(alpha_view.advisories())==1
        assert not bravo_view.advisories()


def test_legacy_non_public_advisories_are_quarantined_on_upgrade(tmp_path):
    import sqlite3
    from vulnforge.db import SCHEMA
    path=tmp_path/'legacy_advisories.db'
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        now=time.time()
        c.execute('''INSERT INTO advisories(id,aliases,summary,source,data,source_sha256,withdrawn,first_seen_at,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?)''',
                  ('PRIV-LEGACY-1','[]','Legacy unnamespaced entry','Custom Feed','{}','0'*64,0,now,now))
        c.execute('INSERT INTO advisory_aliases(alias,advisory_id) VALUES(?,?)',
                  ('CVE-2099-99999','PRIV-LEGACY-1'))
    store=Store(str(path))
    with store.conn() as c:
        assert c.execute("SELECT catalog_scope FROM advisories WHERE id='PRIV-LEGACY-1'").fetchone()[0]=='quarantined_legacy'
        assert c.execute("SELECT catalog_scope FROM advisory_aliases WHERE alias='CVE-2099-99999'").fetchone()[0]=='quarantined_legacy'
    assert not store.list_advisories()
    assert store.advisory('PRIV-LEGACY-1') is None


def test_new_installation_cannot_inherit_old_owner_or_private_results(queue):
    own(queue)
    job=claim(queue)
    queue.save_finding(job['repo'],'private','code','high','Old private result',None,None,{})
    queue.upsert_repo(job['repo'],77,'main')
    assert not queue.list_rows('findings',repo=job['repo'])
    with queue.conn() as c:
        assert c.execute('SELECT 1 FROM repository_ownership WHERE repo=?',(job['repo'],)).fetchone() is None
    fresh=claim(queue,key='new-installation')
    assert fresh['organization_id'] is None and fresh['installation_id']==77
    with pytest.raises(StaleJob): queue.check_job(job)


def test_bound_worker_never_gets_repository_write_token_while_publication_gate_is_closed(tmp_path,monkeypatch):
    import httpx,json
    from vulnforge.github import GitHub,GitHubError
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main');job=claim(store)
    def handler(request):
        permissions=json.loads(request.content)['permissions']
        assert permissions['contents']=='read' and permissions['pull_requests']=='read'
        return httpx.Response(201,json={'token':'fixture-token','expires_at':'2099-01-01T00:00:00Z'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            github=GitHub(managed_config(enable_auto_pr=True),client)
            monkeypatch.setattr(github,'app_jwt',lambda:'fixture-jwt')
            github.bind_job(job,lambda:store.check_job(job))
            assert await github.token(11)=='fixture-token'
            with pytest.raises(GitHubError):
                await github.request('POST','/repos/alpha/project/pulls',11,json={'draft':True})
    asyncio.run(run())
