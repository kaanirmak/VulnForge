import asyncio
import base64
import json
import httpx
import pytest

from vulnforge.github import GitHub, GitHubError
from support import managed_config as Config


def test_content_fetch_and_tree_sha():
    visited=[]
    def handler(req):
        visited.append(req.url.path)
        path=req.url.path
        if '/git/commits/' in path:
            return httpx.Response(200,json={'tree':{'sha':'c'*40}})
        if '/git/trees/' in path:
            assert path.endswith('c'*40)
            return httpx.Response(200,json={'truncated':False,'tree':[
                {'path':'package-lock.json','type':'blob'},
                {'path':'src/x.py','type':'blob'},
                {'path':'deps/requirements.txt','type':'blob'}]})
        if '/contents/' in path:
            return httpx.Response(200,json={'type':'file','encoding':'base64','size':15,
                'sha':'file123','content':base64.b64encode(b'hello, world!').decode()})
        raise AssertionError(path)
    async def run():
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        github=GitHub(Config(),client)
        async def token(id): return 'mock-token'
        github.token=token
        paths=await github.manifest_paths('owner/repo',7,'a'*40)
        assert paths==['package-lock.json','deps/requirements.txt']
        file=await github.get_file('owner/repo',7,'src/x.py','a'*40)
        assert file['text']=='hello, world!'
        await client.aclose()
    asyncio.run(run())
    assert len(visited)==3


def test_reject_untrusted_paths():
    async def run():
        github=GitHub(Config())
        with pytest.raises(ValueError):
            await github.get_file('owner/repo',7,'../secret.pem','a'*40)
        with pytest.raises(ValueError):
            await github.manifest_paths('owner/repo',7,'malformed')
        await github.close()
    asyncio.run(run())


def test_git_comparison_pagination():
    calls=[]
    def handler(req):
        page=int(req.url.params['page'])
        calls.append(page)
        if page==1:
            shas=[{'sha':format(i,'040x')} for i in range(1,101)]
        else:
            shas=[{'sha':'b'*40}]
        return httpx.Response(200,json={'status':'ahead','commits':shas})
    async def run():
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        github=GitHub(Config(),client)
        async def token(id): return 'mock-token'
        github.token=token
        result=await github.commit_shas('org/r',7,'a'*40,'b'*40,[])
        assert len(result)==101
        assert result[-1]=='b'*40
        await client.aclose()
    asyncio.run(run())
    assert calls==[1,2]


def test_reconcile_push_handles_initial_branch_force_push_large_push_and_missed_delivery():
    s0,s1,s2,s3,s4,s9=('0'*40,'1'*40,'2'*40,'3'*40,'4'*40,'9'*40)
    def handler(req):
        path=req.url.path
        if '/compare/' in path:
            if f'{s1}...{s3}' in path:
                return httpx.Response(200,json={'status':'ahead','commits':[{'sha':s2},{'sha':s3}]})
            if f'{s9}...{s3}' in path:
                return httpx.Response(200,json={'status':'diverged','commits':[]})
            if f'{s1}...{s4}' in path:
                return httpx.Response(200,json={'status':'ahead','commits':[{'sha':format(i,'040x')} for i in range(1,10)]})
            raise AssertionError(path)
        if path.endswith('/commits'):
            page=int(req.url.params['page'])
            sha=req.url.params['sha']
            if sha==s3:
                return httpx.Response(200,json=[{'sha':s3},{'sha':s2},{'sha':s1}] if page==1 else [])
            if sha==s4:
                return httpx.Response(200,json=[{'sha':format(10-i,'040x')} for i in range(5)] if page==1 else [])
        raise AssertionError(path)
    async def run():
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        github=GitHub(Config(),client)
        async def token(id): return 'mock-token'
        github.token=token
        initial=await github.reconcile_push('org/r',7,s0,s3,[s3],max_backfill=5)
        assert initial=={'shas':[s1,s2,s3],'mode':'initial_branch','truncated':False,'base_sha':s0}

        missed=await github.reconcile_push('org/r',7,s2,s3,[s3],last_sha=s1,max_backfill=5)
        assert missed=={'shas':[s2,s3],'mode':'missed_delivery_backfill','truncated':False,'base_sha':s1}

        forced=await github.reconcile_push('org/r',7,s9,s3,[s3],forced=True,last_sha=s9,max_backfill=2)
        assert forced=={'shas':[s2,s3],'mode':'force_push_backfill','truncated':True,'base_sha':s9}

        large=await github.reconcile_push('org/r',7,s1,s4,[],last_sha=s1,max_backfill=3)
        assert large['mode']=='large_push_backfill'
        assert large['truncated'] is True
        assert len(large['shas'])==3
        await client.aclose()
    asyncio.run(run())
