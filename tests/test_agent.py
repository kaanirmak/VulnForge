import asyncio
import json
import httpx

from support import managed_config as Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.github import GitHub
from support import fixture_osv as OSV
from vulnforge.worker import Agent


def test_osv_batch_and_fetch_details():
    calls=[]
    def handler(req):
        calls.append(str(req.url))
        if req.url.path=='/v1/querybatch':
            data=json.loads(req.content)
            assert data['queries'][0]['package']['name']=='requests'
            return httpx.Response(200,json={'results':[{'vulns':[{'id':'GHSA-TEST'}]}]})
        if req.url.path=='/v1/vulns/GHSA-TEST':
            return httpx.Response(200,json={'id':'GHSA-TEST','summary':'test','affected':[]})
        raise AssertionError(req.url)
    async def run():
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        osv=OSV('https://api.osv.dev',client)
        found=await osv.check([Dependency('requests','2.0','PyPI','requirements.txt')])
        assert found[0][1]['id']=='GHSA-TEST'
        await client.aclose()
    asyncio.run(run())
    assert len(calls)==2


class FakeGitHub:
    def __init__(self): self.prs=[]
    async def default_branch(self,*args): return 'main'
    async def branch_head(self,*args): return 'b'*40
    async def manifest_paths(self,*args): return ['requirements.txt']
    async def get_file(self,repo,install,path,ref):
        return {'sha':'fileblob123','path':path,'text':'requests==2.27.0\n'}
    async def create_fix_pr(self,repo,install,base,branch,path,old_sha,new_text,title,body):
        self.prs.append((repo,branch,new_text,title,body))
        return 'https://github.com/o/r/pull/1'
    async def commit_shas(self,repo,install,before,after,commits):
        return ['a'*40,'b'*40]
    async def changed_files(self,repo,install,sha):
        return [{'filename':'script.py','status':'modified'}]


class FakeOSV:
    async def check(self,deps):
        dep=deps[0] if deps else None
        if dep and dep.version=='2.31.0':
            return []
        if dep and dep.name=='requests':
            return [(dep,{'id':'GHSA-TEST','summary':'fictional sample advisory',
                'affected':[{'package':{'name':'requests','ecosystem':'PyPI'},
                             'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.31.0'}]}]}]})]
        return []


def test_agent_blocks_draft_pr_for_incomplete_inventory(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db.sqlite'))
        store.upsert_repo('o/r',123,'main')
        gh=FakeGitHub()
        cfg=Config(enable_auto_pr=True)
        agent=Agent(cfg,store,gh,FakeOSV())
        await agent.audit('o/r',123,'main')
        assert len(store.list_rows('findings'))==1
        assert len(gh.prs)==0
        scan=store.scan(store.list_rows('scans')[0]['id'])
        assert scan['state']=='incomplete'
        assert scan['dependencies'][0]['version']=='2.27.0'
        assert 'transitive_graph_unavailable' in str(scan['coverage'])
        assert any(e['action']=='remediation_blocked' for e in store.list_rows('audit_events'))
        await agent.audit('o/r',123,'main')
        assert len(gh.prs)==0
    asyncio.run(run())


def test_push_enqueues_every_commit(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db.sqlite'))
        store.upsert_repo('o/r',123,'main')
        agent=Agent(Config(),store,FakeGitHub(),FakeOSV())
        await agent.push('o/r',123,'main',{
            'before':'a'*40,'after':'b'*40,'commits':[],'ref':'refs/heads/main'})
        assert [j['kind'] for j in store.list_rows('jobs')].count('commit_scan')==2
        assert [j['kind'] for j in store.list_rows('jobs')].count('dependency_audit')==1
    asyncio.run(run())
