import asyncio
import json
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from vulnforge.github_metadata import GitHubMetadata,MetadataError,API
from test_runner_oidc import signing_key


def configuration(key):
    pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    return SimpleNamespace(app_id='123',private_key=lambda:pem)


def handler_for(key,change=None):
    calls=[]
    def handler(request):
        calls.append(request)
        assert str(request.url).startswith(API+'/')
        if request.url.path=='/app/installations/11':
            token=request.headers['authorization'].split(' ',1)[1]
            assert jwt.decode(token,key.public_key(),algorithms=['RS256'],issuer='123')['iss']=='123'
            result={'id':11,'app_id':123,'suspended_at':None,'account':{'id':101},'permissions':{'metadata':'read'}}
            if change=='suspended': result['suspended_at']='2099-01-01'
            if change=='wrong_app': result['app_id']=999
            if change=='installation_owner': result['account']['id']=999
            if change=='wide_app': result['permissions']['contents']='read'
            return httpx.Response(200,json=result)
        if request.url.path=='/app/installations/11/access_tokens':
            assert json.loads(request.content)=={'repositories':['project'],'permissions':{'metadata':'read'}}
            permissions={'metadata':'read'}
            if change=='wide_token': permissions['contents']='read'
            return httpx.Response(201,json={'token':'fixture-metadata-token','permissions':permissions})
        if request.url.path=='/repos/alpha/project':
            assert request.headers['authorization']=='Bearer fixture-metadata-token'
            if change=='redirect': return httpx.Response(302,headers={'Location':'https://attacker.example'})
            if change=='large': return httpx.Response(200,content=b'x'*65537)
            result={'id':201,'full_name':'alpha/project','owner':{'id':101},'default_branch':'main'}
            if change=='name': result['full_name']='bravo/project'
            if change=='repo_id': result['id']=True
            if change=='owner': result['owner']['id']=999
            if change=='branch': result['default_branch']='../main'
            if change=='archived': result['archived']=True
            return httpx.Response(200,json=result)
        raise AssertionError('No contents, diff, branch, code or arbitrary API endpoint is allowed')
    return handler,calls


def test_installation_and_repository_are_verified_with_metadata_only_token(signing_key):
    handler,calls=handler_for(signing_key)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            assert await GitHubMetadata(configuration(signing_key),client).repository('alpha/project',11)=={
                'repository_id':201,'owner_id':101,'default_branch':'main'}
    asyncio.run(run())
    assert len(calls)==3


@pytest.mark.parametrize('change',['suspended','wrong_app','installation_owner','wide_app','wide_token','redirect',
                                   'large','name','repo_id','owner','branch','archived'])
def test_metadata_mismatch_redirect_or_permissions_fail_closed(signing_key,change):
    handler,_=handler_for(signing_key,change)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(MetadataError,match='Repository installation could not be verified'):
                await GitHubMetadata(configuration(signing_key),client).repository('alpha/project',11)
    asyncio.run(run())
