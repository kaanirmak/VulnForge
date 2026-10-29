"""Acceptance regressions for the technical document's evidence and safety gates."""
import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from support import managed_config as Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency, inventory_manifest
from vulnforge.github import GitHub, GitHubError
from support import fixture_osv as OSV
from vulnforge.worker import Agent
from test_agent import FakeGitHub, FakeOSV
from test_webhook import setup, signed


AUTH={'Authorization':'Bearer test-admin'}


def test_intake_rolls_back_delivery_and_repo_when_enqueue_fails(tmp_path, monkeypatch):
    client,store=setup(tmp_path)
    body=json.dumps({'installation':{'id':1},'action':'created','repositories':[{'full_name':'o/r'}]}).encode()
    original=store.enqueue
    def fail(*args,**kwargs): raise RuntimeError('simulated outage')
    monkeypatch.setattr(store,'enqueue',fail)
    with pytest.raises(RuntimeError):
        client.post('/github/webhook',content=body,headers=signed('installation',body,delivery='retry-me'))
    assert store.list_rows('repositories')==[]
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM deliveries').fetchone()[0]==0
    monkeypatch.setattr(store,'enqueue',original)
    response=client.post('/github/webhook',content=body,headers=signed('installation',body,delivery='retry-me'))
    assert response.json()['queued']==1


def test_uninstall_without_repo_list_removes_all_installation_data(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    store.upsert_repo('o/other',2,'main')
    store.enqueue('dependency_audit','o/r',{},'pending')
    scan=store.start_scan('o/r','dependencies','a'*40)
    store.finish_scan(scan,'complete',{})
    body=b'{"installation":{"id":1},"action":"deleted"}'
    assert client.post('/github/webhook',content=body,headers=signed('installation',body)).status_code==202
    assert [r['full_name'] for r in store.list_rows('repositories')]==['o/other']
    assert store.list_rows('jobs')==[]
    assert store.scan(scan) is None


def test_pr_event_queues_once_per_head(tmp_path):
    client,store=setup(tmp_path)
    body=json.dumps({'installation':{'id':1},'repository':{'full_name':'o/r'},'action':'synchronize',
                     'number':7,'pull_request':{'head':{'sha':'a'*40}}}).encode()
    for _ in range(2):
        assert client.post('/github/webhook',content=body,headers=signed('pull_request',body)).status_code==202
    jobs=store.list_rows('jobs')
    assert len(jobs)==1 and jobs[0]['kind']=='pull_request_scan'
    assert json.loads(jobs[0]['payload'])=={'sha':'a'*40,'number':7}


@pytest.mark.parametrize('path,content,reason',[
    ('requirements.txt','requests>=2\n-r hidden.txt','unresolved_requirement'),
    ('requirements.txt','requests==2.27.0','transitive_graph_unavailable'),
    ('go.mod','module m\nrequire example.org/m v1.0.0','declared_modules_only_no_resolved_build_list'),
    ('package-lock.json','{}','missing_lockfile_inventory'),
    ('poetry.lock','[metadata]\nversion="1"','missing_package_inventory'),
    ('package-lock.json','{"lockfileVersion":3,"packages":{"node_modules/local":{"link":true}}}','unresolved_or_local_package'),
])
def test_unsupported_inventory_is_never_clean(path,content,reason):
    result=inventory_manifest(path,content)
    assert any(i['reason']==reason for i in result.issues)


class LockGitHub(FakeGitHub):
    def __init__(self, text=None):
        super().__init__()
        self.text=text or '{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}'
    async def manifest_paths(self,*args): return ['package-lock.json']
    async def get_file(self,repo,install,path,ref):
        return {'sha':'c'*40,'path':path,'text':self.text}


class CleanOSV:
    async def check(self,deps): return []


def test_complete_snapshot_has_digest_and_resolves_old_findings(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db'))
        store.upsert_repo('o/r',1,'main')
        store.save_finding('o/r','old','dependency','high','Old','package-lock.json','a'*40,{})
        agent=Agent(Config(),store,LockGitHub(),CleanOSV())
        await agent.audit('o/r',1,'main')
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='complete'
        assert scan['commit_sha']=='b'*40
        assert len(scan['coverage']['manifests'][0]['sha256'])==64
        assert scan['dependencies'][0]['version']=='1.0.0'
        assert store.list_rows('findings')[0]['status']=='resolved'
        assert store.list_rows('dependency_inventory')[0]['version']=='1.0.0'
    asyncio.run(run())


def test_python_extras_markers_continuations_and_includes():
    from vulnforge.dependencies import parse_manifest, inventory_manifest, Dependency
    content = (
        '# Base requirements\n'
        'requests[security,socks]==2.31.0 \\\n'
        '    --hash=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n'
        'urllib3==2.2.3 ; python_version >= "3.11" and sys_platform == "linux"\n'
        '-r nested/extra.txt\n'
    )
    nested_content = (
        'certifi==2024.7.4\n'
        'charset-normalizer[unicode]==3.3.2\n'
    )
    def resolver(rel_path):
        if rel_path in ('nested/extra.txt', 'app/nested/extra.txt'):
            return nested_content
        return None

    # Parse with include resolver
    deps = parse_manifest('app/requirements.txt', content, include_resolver=resolver)
    names = {d.name: d.version for d in deps}
    assert names['requests'] == '2.31.0'
    assert names['urllib3'] == '2.2.3'
    assert names['certifi'] == '2024.7.4'
    assert names['charset-normalizer'] == '3.3.2'

    # Inventory without resolver reports unresolved_include
    result_no_resolver = inventory_manifest('app/requirements.txt', content)
    assert any(i.get('reason') == 'unresolved_include' and i.get('target') == 'nested/extra.txt'
               for i in result_no_resolver.issues)

    # Inventory with resolver includes all resolved packages
    result_with_resolver = inventory_manifest('app/requirements.txt', content, include_resolver=resolver)
    res_names = {d.name: d.version for d in result_with_resolver.dependencies}
    assert res_names['requests'] == '2.31.0'
    assert res_names['certifi'] == '2024.7.4'


def test_uv_lock_and_pipfile_lock_resolved_inventories():
    from vulnforge.dependencies import parse_manifest, inventory_manifest
    uv_content = (
        'version = 1\n'
        'revision = 1\n\n'
        '[[package]]\n'
        'name = "fastapi"\n'
        'version = "0.115.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'dependencies = [{ name = "pydantic" }]\n\n'
        '[[package]]\n'
        'name = "pydantic"\n'
        'version = "2.9.2"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    uv_deps = parse_manifest('uv.lock', uv_content)
    assert len(uv_deps) == 2
    uv_inv = inventory_manifest('uv.lock', uv_content)
    assert len(uv_inv.dependencies) == 2
    assert uv_inv.issues == []

    pipfile_content = json.dumps({
        '_meta': {'hash': {'sha256': '1234'}},
        'default': {
            'requests': {'version': '==2.31.0', 'hashes': ['sha256:1111']}
        },
        'develop': {
            'pytest': {'version': '==8.3.3', 'hashes': ['sha256:2222']}
        }
    })
    pf_deps = parse_manifest('Pipfile.lock', pipfile_content)
    assert len(pf_deps) == 2
    pf_inv = inventory_manifest('Pipfile.lock', pipfile_content)
    assert len(pf_inv.dependencies) == 2
    assert pf_inv.issues == []

    # Local/git package in uv.lock is caught
    bad_uv = uv_content + '\n[[package]]\nname = "local-pkg"\nversion = "0.1.0"\nsource = { path = "../local" }\n'
    bad_uv_inv = inventory_manifest('uv.lock', bad_uv)
    assert any(i.get('reason') == 'unresolved_local_or_git_package' for i in bad_uv_inv.issues)


def test_incomplete_audit_cannot_resolve_old_findings_or_replace_inventory(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db'))
        store.upsert_repo('o/r',1,'main')
        store.save_finding('o/r','old','dependency','high','Old','requirements.txt','a'*40,{})
        store.replace_inventory('o/r',[Dependency('old','1','PyPI','requirements.txt')])
        await Agent(Config(),store,FakeGitHub(),CleanOSV()).audit('o/r',1,'main')
        assert store.list_rows('findings')[0]['status']=='open'
        assert store.list_rows('dependency_inventory')[0]['package_name']=='old'
        assert store.repos_using_packages([('npm','new-advisory')])=={'o/r'}
    asyncio.run(run())


def test_failed_feed_records_failed_scan_and_preserves_old_findings(tmp_path):
    class FailingOSV:
        async def check(self,deps): raise RuntimeError('timeout')
    async def run():
        store=Store(str(tmp_path/'db'))
        store.save_finding('o/r','old','dependency','high','Old',None,'a'*40,{})
        with pytest.raises(RuntimeError):
            await Agent(Config(),store,LockGitHub(),FailingOSV()).audit('o/r',1,'main')
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='failed' and scan['commit_sha']=='b'*40
        assert scan['dependencies'][0]['version']=='1.0.0'
        assert store.list_rows('findings')[0]['status']=='open'
    asyncio.run(run())


def test_pr_inventory_does_not_change_default_branch_state(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db'))
        store.replace_inventory('o/r',[Dependency('baseline','2','npm','package-lock.json')])
        store.save_finding('o/r','old','dependency','high','Old',None,'b'*40,{})
        await Agent(Config(),store,LockGitHub(),CleanOSV()).audit('o/r',1,'main',snapshot_sha='a'*40)
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['kind']=='pr_dependencies' and scan['commit_sha']=='a'*40
        assert store.list_rows('dependency_inventory')[0]['package_name']=='baseline'
        assert store.list_rows('findings')[0]['status']=='open'
    asyncio.run(run())


def test_code_coverage_and_snapshot_results(tmp_path):
    class Sources(FakeGitHub):
        async def changed_files(self,*args):
            return [{'filename':p} for p in ('a.py','binary.py','README.md')]
        async def get_file(self,repo,install,path,ref):
            return None if path=='binary.py' else {'text':'eval(user)\n','sha':'c'*40}
    async def run():
        store=Store(str(tmp_path/'db'))
        await Agent(Config(),store,Sources(),CleanOSV()).scan_commit('o/r',1,'a'*40)
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='incomplete'
        assert scan['coverage']['files_total']==3
        assert scan['coverage']['files_scanned']==1 and scan['coverage']['files_skipped']==2
        assert len(scan['findings'])==2
    asyncio.run(run())


def test_suppression_survives_rescan_then_expires_with_audit(tmp_path):
    client,store=setup(tmp_path)
    store.save_finding('o/r','k','code','high','Test','x.py','a'*40,{})
    id_=store.list_rows('findings')[0]['id']
    url=f'/api/v1/findings/{id_}/triage'
    assert client.patch(url,json={'status':'suppressed','reason':'confirmed exception'},headers=AUTH).status_code==422
    assert client.patch(url,json={'status':'suppressed','reason':'confirmed exception','expires_at':time.time()+60},headers=AUTH).status_code==200
    store.save_finding('o/r','k','code','critical','Test','x.py','b'*40,{})
    assert store.list_rows('findings')[0]['status']=='suppressed'
    with store.conn() as c: c.execute('UPDATE suppressions SET expires_at=0')
    assert client.get('/api/findings',headers=AUTH).json()[0]['status']=='open'
    events=client.get('/api/v1/audit/events',headers=AUTH).json()
    assert any(e['action']=='suppression_expired' for e in events)
    assert any(e['action']=='triage' for e in events)


def test_snapshot_exports_auth_and_coverage(tmp_path):
    client,store=setup(tmp_path)
    scan_id=store.start_scan('o/r','dependencies','a'*40)
    store.finish_scan(scan_id,'incomplete',{'issues':[{'reason':'partial'}],'manifests':[]},
                      [{'name':'@scope/demo','version':'1.2.3','ecosystem':'npm','file_path':'package-lock.json'}])
    for path in (f'/api/v1/sbom/{scan_id}',f'/api/v1/scans/{scan_id}/sarif',f'/api/v1/scans/{scan_id}'):
        assert client.get(path).status_code==401
        assert client.get(path,headers=AUTH).status_code==200
    bom=client.get(f'/api/v1/sbom/{scan_id}',headers=AUTH).json()
    assert bom['bomFormat']=='CycloneDX'
    assert bom['components'][0]['purl']=='pkg:npm/%40scope/demo@1.2.3'
    assert any(p['value']=='incomplete' for p in bom['metadata']['properties'])
    report=client.get(f'/api/v1/scans/{scan_id}/sarif',headers=AUTH).json()
    assert not report['runs'][0]['invocations'][0]['executionSuccessful']
    assert client.get('/api/v1/sbom/missing',headers=AUTH).status_code==404


def test_findings_cursor_and_filters(tmp_path):
    client,store=setup(tmp_path)
    for i in range(3): store.save_finding('o/r',str(i),'code','high','Title',None,'a'*40,{})
    first=client.get('/api/v1/findings?limit=2&severity=high',headers=AUTH).json()
    assert len(first['items'])==2 and first['next_cursor']
    last=client.get('/api/v1/findings',params={'cursor':first['next_cursor']},headers=AUTH).json()
    assert len(last['items'])==1 and last['next_cursor'] is None
    assert client.get('/api/v1/findings?limit=101',headers=AUTH).status_code==422
    assert client.get('/api/v1/findings?repo=other/repo',headers=AUTH).json()['items']==[]


def test_osv_pagination_refresh_and_withdrawal():
    withdrawn=False
    def handler(req):
        if req.url.path=='/v1/querybatch':
            return httpx.Response(200,json={'results':[{'vulns':[{'id':'TEST-A'}],'next_page_token':'page2'}]})
        if req.url.path=='/v1/query':
            assert json.loads(req.content)['page_token']=='page2'
            return httpx.Response(200,json={'vulns':[{'id':'TEST-B'}]})
        return httpx.Response(200,json={'id':req.url.path.split('/')[-1],**({'withdrawn':'2026-01-01'} if withdrawn else {})})
    async def run():
        nonlocal withdrawn
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            osv=OSV(client=client)
            deps=[Dependency('test','1','PyPI','requirements.txt')]
            assert len(await osv.check(deps))==2
            withdrawn=True
            assert await osv.check(deps)==[]
    asyncio.run(run())


def test_osv_repeated_page_token_fails_closed():
    def handler(req):
        if req.url.path=='/v1/querybatch':
            return httpx.Response(200,json={'results':[{'next_page_token':'same'}]})
        return httpx.Response(200,json={'next_page_token':'same'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(RuntimeError,match='pagination'):
                await OSV(client=client).check([Dependency('demo','1','npm','package-lock.json')])
    asyncio.run(run())


def test_checks_incomplete_is_not_success_and_annotations_paginate():
    calls=[]
    def handler(req):
        calls.append((req.method,json.loads(req.content)))
        return httpx.Response(200,json={'id':17})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(Config(enable_checks=True),client)
            async def token(_): return 'dummy'
            gh.token=token
            await gh.publish_check('o/r',1,{'id':'scan','kind':'commit','commit_sha':'a'*40,'state':'incomplete',
                'findings':[{'file_path':'x.py','severity':'high','title':'Rule','details':{'line':n+1}} for n in range(123)]})
    asyncio.run(run())
    assert [len(c[1]['output']['annotations']) for c in calls if 'output' in c[1]]==[50,50,23]
    assert calls[-1][1]['conclusion']=='action_required'


def test_pull_files_refuses_changed_head():
    calls=0
    def handler(req):
        nonlocal calls
        if req.url.path.endswith('/files'): return httpx.Response(200,json=[])
        calls+=1
        return httpx.Response(200,json={'head':{'sha':('a' if calls==1 else 'b')*40},'changed_files':0})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(Config(),client)
            async def token(_): return 'dummy'
            gh.token=token
            with pytest.raises(GitHubError,match='HEAD changed'):
                await gh.pull_files('o/r',1,7,'a'*40)
    asyncio.run(run())


def test_initial_push_enumerates_history_instead_of_trusting_webhook_subset():
    def handler(req):
        assert req.url.path.endswith('/commits')
        return httpx.Response(200,json=[{'sha':'b'*40},{'sha':'a'*40}])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(Config(),client)
            async def token(_): return 'dummy'
            gh.token=token
            assert await gh.commit_shas('o/r',1,'0'*40,'b'*40,['b'*40])==['a'*40,'b'*40]
    asyncio.run(run())


def test_nested_workspace_lock_packages_are_not_silently_lost():
    content=json.dumps({'lockfileVersion':3,'packages':{
        'apps/api/node_modules/demo':{'version':'1.2.3'},
        'apps/api':{'version':'1.0.0'},
        'node_modules/local':{'link':True}}})
    result=inventory_manifest('package-lock.json',content)
    assert Dependency('demo','1.2.3','npm','package-lock.json') in result.dependencies
    assert result.issues


def test_invalid_resolved_version_is_not_sent_to_osv_as_safe_package():
    content='{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"file:../demo"}}}'
    result=inventory_manifest('package-lock.json',content)
    assert result.dependencies==[]
    assert any(i['reason']=='non_exact_package_version' for i in result.issues)


def test_corrupt_manifest_is_incomplete_not_empty_clean_inventory(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db'))
        await Agent(Config(),store,LockGitHub('{broken'),CleanOSV()).audit('o/r',1,'main')
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='incomplete'
        assert scan['coverage']['files_skipped']==1
        assert scan['coverage']['issues'][0]['reason']=='manifest_parse_error'
    asyncio.run(run())


def test_branch_moving_during_audit_prevents_baseline_resolution(tmp_path):
    class MovingGitHub(LockGitHub):
        def __init__(self): super().__init__(); self.calls=0
        async def branch_head(self,*args):
            self.calls+=1
            return ('a' if self.calls==1 else 'b')*40
    async def run():
        store=Store(str(tmp_path/'db'))
        store.save_finding('o/r','old','dependency','high','Old',None,'a'*40,{})
        await Agent(Config(),store,MovingGitHub(),CleanOSV()).audit('o/r',1,'main')
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='incomplete' and scan['commit_sha']=='a'*40
        assert store.list_rows('findings')[0]['status']=='open'
    asyncio.run(run())


def test_withdrawn_advisory_without_packages_rechecks_registered_repositories(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    body=b'{"action":"withdrawn","security_advisory":{"ghsa_id":"TEST"}}'
    response=client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    assert response.json()['queued']==1


def test_baseline_changes_roll_back_when_snapshot_persistence_fails(tmp_path,monkeypatch):
    async def run():
        store=Store(str(tmp_path/'db'))
        store.replace_inventory('o/r',[Dependency('previous','0.1.0','npm','package-lock.json')])
        store.save_finding('o/r','old','dependency','high','Old',None,'a'*40,{})
        original=store.finish_scan
        def fail_complete(scan_id,state,*args,**kwargs):
            if state=='complete': raise RuntimeError('simulated disk failure')
            return original(scan_id,state,*args,**kwargs)
        monkeypatch.setattr(store,'finish_scan',fail_complete)
        with pytest.raises(RuntimeError):
            await Agent(Config(),store,LockGitHub(),CleanOSV()).audit('o/r',1,'main')
        assert store.list_rows('dependency_inventory')[0]['package_name']=='previous'
        assert store.list_rows('findings')[0]['status']=='open'
        assert store.list_rows('scans')[0]['state']=='failed'
    asyncio.run(run())


def test_scan_list_uses_time_not_random_identifier(tmp_path):
    store=Store(str(tmp_path/'db'))
    old=store.start_scan('o/r','dependencies','a'*40)
    new=store.start_scan('o/r','dependencies','b'*40)
    with store.conn() as c:
        c.execute('UPDATE scans SET started_at=1 WHERE id=?',(old,))
        c.execute('UPDATE scans SET started_at=2 WHERE id=?',(new,))
    assert store.list_rows('scans')[0]['id']==new


def test_unsupported_and_unlocked_manifests_are_visible():
    def handler(req):
        if '/git/commits/' in req.url.path: return httpx.Response(200,json={'tree':{'sha':'c'*40}})
        return httpx.Response(200,json={'tree':[{'path':p,'type':'blob'} for p in (
            'frontend/package-lock.json','frontend/package.json','other/package.json',
            'backend/uv.lock','service/pom.xml')]})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(Config(),client)
            async def token(_): return 'dummy'
            gh.token=token
            paths=await gh.manifest_paths('o/r',1,'a'*40)
            assert 'frontend/package.json' not in paths
            assert set(paths)=={'frontend/package-lock.json','other/package.json','backend/uv.lock','service/pom.xml'}
    asyncio.run(run())


def test_pr_base_head_comparison_separates_new_and_pre_existing_findings(tmp_path):
    base_sha='1'*40
    head_sha='2'*40
    client,store=setup(tmp_path)
    body=json.dumps({
        'installation':{'id':1},
        'repository':{'full_name':'o/r','default_branch':'main'},
        'action':'synchronize',
        'number':12,
        'pull_request':{'base':{'sha':base_sha},'head':{'sha':head_sha}},
    }).encode()
    res=client.post('/github/webhook',content=body,headers=signed('pull_request',body))
    assert res.status_code==202 and res.json()['queued']==1
    job=store.claim()
    assert json.loads(job['payload'])=={'sha':head_sha,'number':12,'base_sha':base_sha}

    published_checks=[]
    class PRGitHub(FakeGitHub):
        async def default_branch(self,repo,install): return 'main'
        async def pull_files(self,repo,install,number,expected_sha):
            return [
                {'filename':'app.py','status':'modified'},
                {'filename':'new_mod.py','status':'added'},
            ]
        async def manifest_paths(self,repo,install,sha):
            return ['package-lock.json']
        async def get_file(self,repo,install,path,ref):
            if path=='app.py' and ref==base_sha:
                return {'sha':'c'*40,'path':path,'text':'x = 1\neval(user_data)\n'}
            if path=='app.py' and ref==head_sha:
                # Shifted eval(user_data) by 2 lines + added subprocess.run(..., shell=True)
                return {'sha':'d'*40,'path':path,'text':'# header\n# comment\nx = 1\neval(user_data)\nimport subprocess\nsubprocess.run(cmd, shell=True)\n'}
            if path=='new_mod.py' and ref==head_sha:
                return {'sha':'e'*40,'path':path,'text':'eval(other_input)\n'}
            if path=='package-lock.json' and ref==base_sha:
                return {'sha':'f'*40,'path':path,'text':json.dumps({
                    'lockfileVersion':3,
                    'packages':{'node_modules/legacy-pkg':{'version':'1.0.0'}}
                })}
            if path=='package-lock.json' and ref==head_sha:
                return {'sha':'0'*40,'path':path,'text':json.dumps({
                    'lockfileVersion':3,
                    'packages':{
                        'node_modules/legacy-pkg':{'version':'1.0.0'},
                        'node_modules/new-vuln':{'version':'2.0.0'},
                    }
                })}
            return None
        async def publish_check(self,repo,install,scan):
            published_checks.append(scan)

    class PROSV:
        async def check(self,deps):
            out=[]
            for dep in deps:
                if dep.name=='legacy-pkg':
                    out.append((dep,{'id':'GHSA-legacy','aliases':['CVE-2025-0001'],'severity':[{'type':'CVSS_V3','score':'HIGH'}],'summary':'Legacy issue'}))
                elif dep.name=='new-vuln':
                    out.append((dep,{'id':'GHSA-new','aliases':['CVE-2025-0002'],'severity':[{'type':'CVSS_V3','score':'HIGH'}],'summary':'New issue'}))
            return out

    async def run():
        agent=Agent(Config(enable_checks=True),store,PRGitHub(),PROSV())
        await agent.process(job)
        store.finish(job)
    asyncio.run(run())

    assert len(published_checks)==2
    code_scan=next(s for s in published_checks if s['kind']=='pull_request')
    dep_scan=next(s for s in published_checks if s['kind']=='pr_dependencies')

    assert code_scan['coverage']['base_sha']==base_sha
    assert code_scan['coverage']['base_comparison']=='complete'
    assert code_scan['coverage']['findings_pre_existing']==1
    assert code_scan['coverage']['findings_new']==2
    by_file_rule={(f['file_path'],f['details']['rule']):f['details'] for f in code_scan['findings']}
    assert by_file_rule[('app.py','dynamic-execution')]['diff_status']=='pre_existing'
    assert by_file_rule[('app.py','dynamic-execution')]['base_line']==2
    assert by_file_rule[('app.py','subprocess-shell')]['diff_status']=='new'
    assert by_file_rule[('new_mod.py','dynamic-execution')]['diff_status']=='new'

    assert dep_scan['coverage']['base_sha']==base_sha
    assert dep_scan['coverage']['base_comparison']=='complete'
    assert dep_scan['coverage']['findings_pre_existing']==1
    assert dep_scan['coverage']['findings_new']==1
    by_pkg={f['details']['package']:f['details']['diff_status'] for f in dep_scan['findings']}
    assert by_pkg=={'legacy-pkg':'pre_existing','new-vuln':'new'}

    # Verify GitHub check conclusion treats pre-existing-only PR scan as success with notice annotation
    check_calls=[]
    def handler(req):
        check_calls.append(json.loads(req.content))
        return httpx.Response(200,json={'id':99})
    async def run_check():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            gh=GitHub(Config(enable_checks=True),http)
            async def token(_): return 'dummy'
            gh.token=token
            pre_only={
                'id':'scan-pre','kind':'pull_request','commit_sha':head_sha,'state':'complete',
                'coverage':{'base_comparison':'complete','findings_new':0,'findings_pre_existing':1},
                'findings':[{'file_path':'app.py','severity':'high','title':'Old eval','details':{'line':4,'diff_status':'pre_existing'}}],
            }
            await gh.publish_check('o/r',1,pre_only)
    asyncio.run(run_check())
    assert check_calls[0]['output']['annotations'][0]['annotation_level']=='notice'
    assert check_calls[0]['output']['annotations'][0]['message'].startswith('[PRE-EXISTING] ')
    assert check_calls[-1]['conclusion']=='success'
