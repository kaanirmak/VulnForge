"""No source access, guessed installations, account swaps or cross-org onboarding."""
import asyncio
from dataclasses import replace
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs,urlsplit

from fastapi.testclient import TestClient
import httpx
import pytest

from test_database import pg_store,pg_customer,pg_operator
from test_github_metadata import configuration,handler_for
from test_runner_oidc import signing_key
from test_organization import seed,config,client_for,ROOT,ORIGIN
from vulnforge.api import create_app
from vulnforge.auth import AuthError,AuthSessions,digest
from vulnforge.connections import (CALLBACK,ConnectionFlows,ConnectionDenied,ConnectionConflict,
                                   GitHubConnectionVerifier,VerifiedConnection)
from vulnforge.db import Store
from vulnforge.identity import Identities


def provider(key,change=None):
    metadata,metadata_calls=handler_for(key);calls=[]
    def handler(request):
        calls.append(request)
        if change=='redirect': return httpx.Response(302,headers={'Location':'https://invalid.example'})
        if request.url.host=='github.com':
            assert request.url.path=='/login/oauth/access_token'
            assert parse_qs(request.content.decode())['redirect_uri']==[ORIGIN+CALLBACK]
            return httpx.Response(200,json={'access_token':'ghu_memory_only_fixture','token_type':'bearer',
                                           'refresh_token':'ghr_never_persist_fixture'})
        if request.url.path=='/user':
            return httpx.Response(200,json={'id':999 if change=='account' else 100,'login':'fixture-owner'})
        assert request.url.host=='api.github.com'
        if request.url.path.startswith('/user/installations'):
            assert request.headers['authorization']=='Bearer ghu_memory_only_fixture'
        if request.url.path=='/user/installations':
            install={'id':11,'app_id':123,'permissions':{'metadata':'read'},'suspended_at':None,
                     'account':{'id':101,'login':'alpha'}}
            if change=='app':install['app_id']=456
            if change=='wide':install['permissions']['contents']='read'
            if change=='suspend':install['suspended_at']='2026-01-01'
            data={'total_count':1,'installations':[install]}
            if change=='bad_count':data['total_count']=True
            if change=='over_count':data['total_count']=501
            if change=='duplicate':data['installations']=[install,install];data['total_count']=2
            if change=='empty_page':data['installations']=[]
            return httpx.Response(200,json=data)
        if request.url.path=='/user/installations/11/repositories':
            row={'id':201,'full_name':'alpha/project','owner':{'id':101},'default_branch':'main',
                 'permissions':{'admin':True,'push':True,'pull':True}}
            if change=='read_only':row['permissions']['admin']=False
            if change=='numeric_admin':row['permissions']['admin']=1
            if change=='renamed':row['full_name']='alpha/other'
            if change=='repository_id':row['id']=999
            if change=='owner':row['owner']['id']=999
            if change=='branch':row['default_branch']='old'
            return httpx.Response(200,json={'total_count':1,'repositories':[row]})
        return metadata(request)
    return handler,calls


def test_real_exchange_user_access_and_app_metadata_both_verify_without_persisting_token(signing_key,monkeypatch):
    handler,calls=provider(signing_key)
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-client-secret',public_origin=ORIGIN)
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    proof=asyncio.run(GitHubConnectionVerifier(cfg).verify('code','verifier','alpha/project',100))
    assert proof==VerifiedConnection(100,'alpha/project',11,201,101,'main')
    assert len(calls)==7
    assert not any('/contents' in str(r.url) or '/commits' in str(r.url) for r in calls)
    assert 'ghu_' not in repr(proof) and 'secret' not in repr(proof)


def test_paginated_user_installations_and_repositories_are_completed(signing_key,monkeypatch):
    original,calls=provider(signing_key)
    def handler(request):
        result=original(request)
        if request.url.path=='/user/installations':
            data=result.json();last=data['installations'][0]
            page=int(request.url.params['page'])
            data['total_count']=101
            data['installations']=([{**last,'id':1000+n,'account':{'id':5000+n,'login':'other'+str(n)}}
                for n in range(100)] if page==1 else [last])
            return httpx.Response(200,json=data,headers={'Link':'<https://invalid.example/steal>; rel="next"'})
        if request.url.path=='/user/installations/11/repositories':
            data=result.json();last=data['repositories'][0];page=int(request.url.params['page'])
            data['total_count']=101
            data['repositories']=([{**last,'id':3000+n,'full_name':'alpha/other'+str(n)}
                for n in range(100)] if page==1 else [last])
            return httpx.Response(200,json=data)
        return result
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret',public_origin=ORIGIN)
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    assert asyncio.run(GitHubConnectionVerifier(cfg).verify('code','verifier','alpha/project',100)).repository_id==201
    assert len(calls)==9 and all(r.url.host in ('github.com','api.github.com') for r in calls)


@pytest.mark.parametrize('change',['redirect','account','app','wide','suspend','bad_count','over_count',
    'duplicate','empty_page','read_only','numeric_admin','renamed','repository_id','owner','branch'])
def test_provider_permission_identity_and_listing_mismatches_fail_closed(signing_key,monkeypatch,change):
    handler,calls=provider(signing_key,change)
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret',public_origin=ORIGIN)
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    with pytest.raises(AuthError):asyncio.run(GitHubConnectionVerifier(cfg).verify('code','verifier','alpha/project',100))
    assert all(r.url.host in ('github.com','api.github.com') for r in calls)


@pytest.fixture
def onboarding(tmp_path):
    store=Store(str(tmp_path/'db'));data=seed(store)
    cfg=replace(config(store),github_connection_preview=True,app_id='123')
    app=create_app(cfg,store)
    return store,data,cfg,app


def actor(onboarding,label='alpha',role='org_admin'):
    store,(members,orgs,repos,scans,findings),cfg,app=onboarding
    client,headers=client_for(app,store,cfg,members[label+'_'+role])
    return client,headers,ROOT+'/'+orgs[label]


def start(onboarding,repo='alpha/new-project',label='alpha',role='org_admin'):
    client,headers,root=actor(onboarding,label,role)
    response=client.post(root+'/connections/begin',json={'repo':repo,'consent':True,'consent_version':'metadata-v1'},headers=headers)
    assert response.status_code==200,response.text
    query=parse_qs(urlsplit(response.json()['authorization_url']).query)
    return client,headers,query['state'][0]


class FixtureVerifier:
    def __init__(self,operation=None):self.calls=[];self.operation=operation
    async def verify(self,code,verifier,repo,github_id):
        self.calls.append((code,repo,github_id))
        if self.operation:self.operation()
        return VerifiedConnection(github_id,repo,1,201,101,'main')


def test_preview_cannot_mix_managed_mode_or_become_public(onboarding):
    store,data,cfg,app=onboarding
    with pytest.raises(ValueError):replace(cfg,customer_api_preview=False)
    with pytest.raises(ValueError):replace(cfg,public_origin='https://public.example')
    with pytest.raises(ValueError):replace(cfg,scan_mode='managed',allow_managed_source_access=True,managed_scan_consent_id='fixture')


@pytest.mark.parametrize('role',['maintainer','analyst','viewer','auditor'])
def test_only_org_admin_can_start_connection(onboarding,role):
    client,headers,root=actor(onboarding,role=role)
    assert client.post(root+'/connections/begin',headers=headers,json={
        'repo':'alpha/new-project','consent':True,'consent_version':'metadata-v1'}).status_code==403


@pytest.mark.parametrize('change',[{'consent':False},{'consent':1},{'consent_version':'other'},
    {'repo':'alpha/../project'},{'installation_id':1},{'user_id':'injected'},{'source_access':True}])
def test_consent_and_fixed_identity_fields_cannot_be_overridden(onboarding,change):
    client,headers,root=actor(onboarding)
    body={'repo':'alpha/new-project','consent':True,'consent_version':'metadata-v1',**change}
    assert client.post(root+'/connections/begin',headers=headers,json=body).status_code==422


def test_csrf_and_foreign_org_rejected_before_flow_creation(onboarding):
    client,headers,root=actor(onboarding)
    body={'repo':'alpha/new-project','consent':True,'consent_version':'metadata-v1'}
    assert client.post(root+'/connections/begin',json=body).status_code==403
    foreign=ROOT+'/'+onboarding[1][1]['bravo']
    assert client.post(foreign+'/connections/begin',headers=headers,json=body).status_code==403
    assert client.post(root+'/connections/begin',headers=headers,json={**body,'repo':'bravo/private-project'}).status_code==403
    with onboarding[0].conn() as c:assert c.execute('SELECT COUNT(*) FROM connection_intents').fetchone()[0]==0


@pytest.mark.parametrize('issuer',[None,'https://github.com/login/oauth'])
def test_complete_connection_records_consent_without_source_job_or_inventory(onboarding,issuer):
    client,headers,state=start(onboarding)
    store,data,cfg,app=onboarding;verifier=FixtureVerifier();app.state.connection_verifier=verifier
    params={'state':state,'code':'fixture-code'}
    if issuer is not None:params['iss']=issuer
    response=client.get(CALLBACK,params=params,follow_redirects=False)
    assert response.status_code==303 and response.headers['location']=='/account?connection=connected'
    assert client.cookies.get('vf_local_connect') is None
    assert verifier.calls==[('fixture-code','alpha/new-project',100)]
    with store.conn() as c:
        assert c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',('alpha/new-project',)).fetchone()[0]==data[1]['alpha']
        assert c.execute('SELECT COUNT(*) FROM connection_intents').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM auth_states').fetchone()[0]==0
    assert store.list_rows('jobs')==[]
    assert store.list_rows('dependency_inventory',repo='alpha/new-project')==[]
    assert store.list_rows('scans',repo='alpha/new-project')==[]
    replay=client.get(CALLBACK,params={'state':state,'code':'fixture-code'},follow_redirects=False)
    assert replay.headers['location'].endswith('failed') and len(verifier.calls)==1


def test_browser_session_to_real_mock_provider_to_ownership_has_no_saved_oauth_credentials(onboarding,signing_key,monkeypatch):
    from vulnforge.config import Config
    handler,calls=provider(signing_key);real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    pem=configuration(signing_key).private_key()
    monkeypatch.setattr(Config,'private_key',lambda self:pem)
    client,headers,state=start(onboarding,'alpha/project')
    verifier=client.cookies.get('vf_local_connect')
    response=client.get(CALLBACK,params={'state':state,'code':'fixture-ephemeral-code'},follow_redirects=False)
    assert response.headers['location']=='/account?connection=connected'
    store=onboarding[0]
    assert store.repository('alpha/project')['installation_id']==11
    with store.conn() as c:
        dump='\n'.join(c.iterdump())
        assert c.execute('SELECT COUNT(*) FROM connection_intents').fetchone()[0]==0
    for secret in ('ghu_memory_only_fixture','ghr_never_persist_fixture','fixture-ephemeral-code',verifier):
        assert secret not in dump and secret not in response.text


def test_flow_is_bound_to_same_browser_and_same_session(onboarding):
    client,headers,state=start(onboarding)
    other,_,_=actor(onboarding)
    other.cookies.set('vf_local_connect',client.cookies.get('vf_local_connect'))
    app=onboarding[3];verifier=FixtureVerifier();app.state.connection_verifier=verifier
    response=other.get(CALLBACK,params={'state':state,'code':'fixture-code'},follow_redirects=False)
    assert response.headers['location'].endswith('failed') and not verifier.calls
    assert client.get(CALLBACK,params={'state':state,'code':'fixture-code'},follow_redirects=False).headers['location'].endswith('connected')


@pytest.mark.parametrize('operation',['logout','remove_admin','connection_change','other_owner'])
def test_access_or_connection_change_during_provider_wait_prevents_write(onboarding,operation):
    repo='alpha/private-project' if operation=='connection_change' else 'alpha/new-project'
    client,headers,state=start(onboarding,repo)
    store,(members,orgs,repos,scans,findings),cfg,app=onboarding
    def change():
        if operation=='logout':
            with store.conn() as c:c.execute('DELETE FROM user_sessions WHERE user_id=?',(members['alpha_org_admin']['id'],))
        elif operation=='remove_admin':
            with store.conn() as c:c.execute("UPDATE memberships SET role='viewer' WHERE user_id=? AND organization_id=?",
                (members['alpha_org_admin']['id'],orgs['alpha']))
        elif operation=='connection_change':store.remove_repo(repo);store.upsert_repo(repo,1,'main')
        else:
            store.upsert_repo(repo,1,'main')
            Identities(store).record_repository_ownership(orgs['bravo'],repo,members['bravo_org_admin']['id'],'verified-fixture')
    app.state.connection_verifier=FixtureVerifier(change)
    response=client.get(CALLBACK,params={'state':state,'code':'fixture-code'},follow_redirects=False)
    assert response.headers['location'].endswith('failed')
    with store.conn() as c:
        owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(repo,)).fetchone()
        assert owner is None or owner[0]!=orgs['alpha']


def test_restarting_flow_invalidates_previous_choice_and_expired_flow_is_rejected(onboarding):
    client,headers,state=start(onboarding)
    root=ROOT+'/'+onboarding[1][1]['alpha']
    response=client.post(root+'/connections/begin',headers=headers,json={
        'repo':'alpha/second-project','consent':True,'consent_version':'metadata-v1'})
    new=parse_qs(urlsplit(response.json()['authorization_url']).query)['state'][0]
    assert new!=state
    store=onboarding[0]
    with store.conn() as c:c.execute('UPDATE auth_states SET expires_at=?',(time.time()-1,))
    verifier=FixtureVerifier();onboarding[3].state.connection_verifier=verifier
    assert client.get(CALLBACK,params={'state':new,'code':'code'},follow_redirects=False).headers['location'].endswith('failed')
    assert not verifier.calls


def test_callback_unknown_parameters_and_slashes_never_reach_provider(onboarding):
    client,_,state=start(onboarding);verifier=FixtureVerifier();onboarding[3].state.connection_verifier=verifier
    for params in ({'state':state,'code':'code','installation_id':'1'},
        {'state':state,'code':'code','iss':'https://evil.example'},
        {'state':state,'code':'code','iss':''},
        [('state',state),('code','code'),('iss','https://github.com/login/oauth'),
         ('iss','https://github.com/login/oauth')],
        [('state',state),('state',state),('code','code')],{'state':state,'code':'code','error':'denied'}):
        assert client.get(CALLBACK,params=params,follow_redirects=False).status_code==400
    assert client.get(CALLBACK+'/',params={'state':state,'code':'code'}).status_code==400
    assert not verifier.calls


def test_authenticated_user_can_create_an_organization_without_an_operator_token(onboarding):
    client,headers,_=actor(onboarding,role='viewer')
    response=client.post(ROOT,headers=headers,json={'name':'My new team'})
    assert response.status_code==201
    own=next(row for row in client.get(ROOT).json()['items'] if row['id']==response.json()['id'])
    assert own['role']=='org_admin'
    assert client.post(ROOT,json={'name':'No CSRF'}).status_code==403
    assert client.post(ROOT,headers=headers,json={'name':'No spoof','created_by':'other'}).status_code==422


def test_postgres_non_owner_operator_and_customer_proof_separation(pg_store,pg_customer,pg_operator):
    data=seed(pg_store);members,orgs,repos,scans,findings=data
    cfg=replace(config(pg_store),github_connection_preview=True,app_id='123',database_url=pg_operator.path,
                customer_database_url=pg_customer.path,database_auto_migrate=False)
    app=create_app(cfg,pg_operator);app.state.connection_verifier=FixtureVerifier()
    client,headers=client_for(app,pg_operator,cfg,members['alpha_org_admin'])
    response=client.post(ROOT+'/'+orgs['alpha']+'/connections/begin',headers=headers,json={
        'repo':'alpha/new-project','consent':True,'consent_version':'metadata-v1'})
    state=parse_qs(urlsplit(response.json()['authorization_url']).query)['state'][0]
    assert client.get(CALLBACK,params={'state':state,'code':'code'},follow_redirects=False).headers['location'].endswith('connected')
    with pg_customer.conn() as c:
        from vulnforge.database import DatabaseError
        with pytest.raises(DatabaseError):c.execute('SELECT * FROM connection_intents')
    items=client.get(ROOT+'/'+orgs['alpha']+'/repositories').json()['items']
    assert 'alpha/new-project' in [r['full_name'] for r in items]
    assert all(r['full_name'].startswith('alpha/') for r in items)


def test_pending_consent_intent_transfers_without_exposing_provider_credentials(pg_store,tmp_path):
    from vulnforge.migrate import import_sqlite
    source=Store(str(tmp_path/'db'));members,orgs,repos,scans,findings=seed(source)
    cfg=replace(config(source),github_connection_preview=True,app_id='123')
    token,_=AuthSessions(source,cfg).create(members['alpha_org_admin']['id']);session=digest(token)
    location,verifier=ConnectionFlows(source,cfg).begin(orgs['alpha'],session,'alpha/new-project','metadata-v1',True)
    state=parse_qs(urlsplit(location).query)['state'][0]
    assert import_sqlite(source.path,pg_store.path)['tables']['connection_intents']==1
    flow=ConnectionFlows(pg_store,cfg);intent=flow.consume(state,verifier,session)
    result=flow.complete(intent,VerifiedConnection(100,'alpha/new-project',1,201,101,'main'))
    assert result['state']=='awaiting_runner' and not result['baseline_ready']
