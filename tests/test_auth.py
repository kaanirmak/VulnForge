"""OAuth protocol negative cases; all provider requests use a fixed-host mock."""
import base64
import hashlib
import json
from urllib.parse import parse_qs,urlsplit

from fastapi.testclient import TestClient
import httpx
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions,digest
from vulnforge.config import Config
from vulnforge.db import Store

ORIGIN='https://vulnforge.example'
PREFIX='__Host-vf_'


@pytest.fixture
def auth_app(tmp_path,monkeypatch):
    cfg=Config(database_path=str(tmp_path/'db'),admin_token='operator-admin',operator_report_token='report-operator',
               github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret-do-not-echo',public_origin=ORIGIN)
    store=Store(cfg.database_path);app=create_app(cfg,store)
    client=TestClient(app,base_url=ORIGIN,follow_redirects=False)
    calls=[];behavior={'token':{'access_token':'ghu_fixtureonlytoken','token_type':'bearer','refresh_token':'ghr_fixtureonly'},
                       'user':{'id':50,'login':'fixture-user','email':'not-stored@example.com'}}
    def handler(request):
        calls.append(request)
        key='token' if request.url.host=='github.com' else 'user'
        result=behavior[key]
        if isinstance(result,httpx.Response): return result
        if isinstance(result,Exception): raise result
        return httpx.Response(200,json=result)
    original=httpx.AsyncClient
    def factory(**kwargs):
        assert kwargs['follow_redirects'] is False
        return original(transport=httpx.MockTransport(handler),**kwargs)
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',factory)
    return client,store,cfg,calls,behavior


def start(client):
    response=client.get('/auth/github/login')
    assert response.status_code==303
    return response,parse_qs(urlsplit(response.headers['location']).query)


def finish(client,params,**extra):
    return client.get('/auth/github/callback',params={'state':params['state'][0],'code':'fixture-code',**extra})


def signed_in(auth_app):
    client,store,cfg,calls,behavior=auth_app
    _,params=start(client)
    assert finish(client,params).status_code==303
    return auth_app


def test_oauth_default_is_closed(tmp_path):
    client=TestClient(create_app(Config(),Store(str(tmp_path/'db'))))
    assert client.get('/auth/status').json()=={'github_login_configured':False,'customer_access_ready':False}
    assert client.get('/auth/github/login').status_code==503
    assert client.get('/api/v1/me').status_code==503


@pytest.mark.parametrize('origin',['http://public.example','https://u:p@host','https://host/path',
                                  'https://host?next=bad','https://host#fragment','https://host:invalid','https://host/'])
def test_auth_configuration_rejects_unsafe_or_ambiguous_origin(origin):
    with pytest.raises(ValueError):
        Config(github_oauth_client_id='fixture',github_oauth_client_secret='secret',public_origin=origin)


def test_oauth_configuration_requires_all_fields_and_explicit_local_exception():
    with pytest.raises(ValueError): Config(github_oauth_client_id='fixture')
    with pytest.raises(ValueError):
        Config(github_oauth_client_id='fixture',github_oauth_client_secret='secret',public_origin='http://localhost:8000')
    cfg=Config(github_oauth_client_id='fixture',github_oauth_client_secret='secret',public_origin='http://localhost:8000',
               allow_insecure_local_auth=True)
    assert not AuthSessions(None,cfg).secure and AuthSessions(None,cfg).cookie_prefix=='vf_local_'


def test_oauth_pkce_fixed_callback_and_cookie_policy(auth_app):
    client,store,cfg,calls,_=auth_app
    response,params=start(client)
    verifier=client.cookies.get(PREFIX+'oauth')
    expected=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    assert params['code_challenge']==[expected] and params['code_challenge_method']==['S256']
    assert params['redirect_uri']==[ORIGIN+'/auth/github/callback']
    assert 'scope' not in params and 'client_secret' not in params
    assert all(value in response.headers['set-cookie'] for value in ('HttpOnly','Secure','SameSite=lax','Path=/'))
    assert 'Domain=' not in response.headers['set-cookie']
    with store.conn() as c:
        row=dict(c.execute('SELECT * FROM auth_states').fetchone())
        assert row['state_hash']==digest(params['state'][0]) and row['browser_hash']==digest(verifier)
    assert not calls


def test_callback_verifies_provider_then_stores_minimal_identity_and_hashed_session(auth_app):
    client,store,cfg,calls,_=auth_app
    _,params=start(client);verifier=client.cookies.get(PREFIX+'oauth')
    response=finish(client,params)
    assert response.status_code==303 and response.headers['location']=='/account'
    assert client.cookies.get(PREFIX+'oauth') is None
    assert [str(req.url) for req in calls]==['https://github.com/login/oauth/access_token','https://api.github.com/user']
    payload=parse_qs(calls[0].content.decode())
    assert payload['code_verifier']==[verifier] and payload['client_secret']==[cfg.github_oauth_client_secret]
    assert not calls[0].url.query
    assert calls[1].headers['authorization']=='Bearer ghu_fixtureonlytoken'
    user=client.get('/api/v1/me').json()
    assert user['login']=='fixture-user' and user['customer_access_ready'] is False
    assert 'csrf_hash' not in user
    token=client.cookies.get(PREFIX+'session');csrf=client.cookies.get(PREFIX+'csrf')
    with store.conn() as c:
        row=dict(c.execute('SELECT * FROM user_sessions').fetchone())
        assert row['token_hash']==digest(token) and row['csrf_hash']==digest(csrf)
        data=' '.join(str(dict(row)) for table in ('user_sessions','users','auth_states','audit_events') for row in c.execute(f'SELECT * FROM {table}'))
    assert all(secret not in data for secret in (token,csrf,verifier,'fixture-code','ghu_fixtureonlytoken','ghr_fixtureonly','not-stored@example.com'))
    assert finish(client,params).status_code==401 and len(calls)==2


def test_stolen_state_is_bound_to_the_starting_browser(auth_app):
    client,store,cfg,calls,_=auth_app
    _,params=start(client)
    other=TestClient(client.app,base_url=ORIGIN,follow_redirects=False)
    assert finish(other,params).status_code==401 and not calls
    assert finish(client,params).status_code==303


@pytest.mark.parametrize('query',[{'state':'invalid','code':'fixture'},
                                 {'state':'x'*43,'code':'fixture'},
                                 {'code':'fixture'},
                                 {'state':'x'*43,'code':'fixture','next':'https://evil.example'},
                                 {'state':'x'*43,'code':'fixture','installation_id':'77'},
                                 [('state','x'*43),('state','x'*43),('code','fixture')]])
def test_invalid_callback_never_contacts_provider(auth_app,query):
    client,_,_,calls,_=auth_app;start(client)
    response=client.get('/auth/github/callback',params=query)
    assert response.status_code in (400,401) and not calls


def test_expired_state_is_consumed_without_contacting_provider(auth_app):
    client,store,_,calls,_=auth_app;_,params=start(client)
    with store.conn() as c: c.execute('UPDATE auth_states SET expires_at=0')
    assert finish(client,params).status_code==401 and not calls
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM auth_states').fetchone()[0]==0


def test_denied_callback_does_not_echo_provider_text_or_allow_replay(auth_app):
    client,store,_,calls,_=auth_app;_,params=start(client)
    response=client.get('/auth/github/callback',params={'state':params['state'][0],'error':'access_denied',
                                                       'error_description':'credential-do-not-echo'})
    assert response.status_code==401 and 'credential' not in response.text and not calls
    assert finish(client,params).status_code==401


@pytest.mark.parametrize('key,result',[
    ('token',{'error':'secret-detail','access_token':'ghu_fixtureonlytoken','token_type':'bearer'}),
    ('token',{'access_token':'contains whitespace','token_type':'bearer'}),
    ('token',{'access_token':'ghu_fixtureonlytoken','token_type':True}),
    ('token',httpx.Response(302,headers={'Location':'https://evil.example/steal'})),
    ('token',httpx.Response(200,content=b'{"access_token":"first","access_token":"second"}')),
    ('token',httpx.Response(200,content=b'invalid-secret-json')),
    ('token',httpx.Response(200,content=b'x'*65537)),
    ('user',httpx.Response(302,headers={'Location':'https://evil.example/steal'})),
    ('user',{'id':'50','login':'fixture'}),
    ('user',{'id':True,'login':'fixture'}),
    ('user',{'id':50,'login':'invalid/login'}),
    ('user',httpx.ReadTimeout('secret-error-do-not-echo')),
])
def test_provider_failures_are_sanitized_and_cannot_establish_session(auth_app,key,result):
    client,store,_,calls,behavior=auth_app;_,params=start(client);behavior[key]=result
    response=finish(client,params)
    assert response.status_code==502 and 'secret' not in response.text
    assert all(request.url.host in ('github.com','api.github.com') for request in calls)
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
        assert c.execute('SELECT COUNT(*) FROM user_sessions').fetchone()[0]==0
    assert client.cookies.get(PREFIX+'session') is None
    assert finish(client,params).status_code==401


def test_customer_session_is_never_an_operator_credential(auth_app):
    client,_,_,_,_=signed_in(auth_app)
    for path in ('/api/repositories','/api/findings','/api/v1/privacy'):
        assert client.get(path).status_code==401
        assert client.get(path,headers={'Authorization':'Bearer '+client.cookies.get(PREFIX+'session')}).status_code==401
    assert client.post('/api/v1/operator/runner-reports',json={}).status_code==401


@pytest.mark.parametrize('column',['expires_at','last_seen_at'])
def test_absolute_and_idle_expiry_revoke_session(auth_app,column):
    client,store,_,_,_=signed_in(auth_app)
    with store.conn() as c: c.execute(f'UPDATE user_sessions SET {column}=0')
    assert client.get('/api/v1/me').status_code==401
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM user_sessions').fetchone()[0]==0


def test_logout_requires_same_origin_and_matching_csrf_then_revokes_session(auth_app):
    client,store,_,_,_=signed_in(auth_app)
    csrf=client.cookies.get(PREFIX+'csrf');token=client.cookies.get(PREFIX+'session')
    for headers in ({},{'Origin':'https://evil.example','X-CSRF-Token':csrf},
                    {'Origin':ORIGIN,'X-CSRF-Token':'wrong'}, {'Origin':ORIGIN}):
        assert client.post('/auth/logout',headers=headers).status_code==403
        assert client.get('/api/v1/me').status_code==200
    response=client.post('/auth/logout',headers={'Origin':ORIGIN,'X-CSRF-Token':csrf})
    assert response.status_code==204
    assert client.get('/api/v1/me').status_code==401
    assert client.cookies.get(PREFIX+'session') is None
    assert AuthSessions(store,Config()).current(token) is None


def test_reauthentication_rotates_browser_session(auth_app):
    client,store,cfg,_,_=signed_in(auth_app)
    old=client.cookies.get(PREFIX+'session')
    _,params=start(client);assert finish(client,params).status_code==303
    assert client.cookies.get(PREFIX+'session')!=old
    assert AuthSessions(store,cfg).current(old) is None


def test_callback_and_session_survive_application_restart(auth_app):
    client,store,cfg,_,_=auth_app;_,params=start(client)
    second=TestClient(create_app(cfg,Store(store.path)),base_url=ORIGIN,follow_redirects=False)
    second.cookies.update(client.cookies)
    assert finish(second,params).status_code==303
    third=TestClient(create_app(cfg,Store(store.path)),base_url=ORIGIN)
    third.cookies.update(second.cookies)
    assert third.get('/api/v1/me').json()['login']=='fixture-user'


def test_auth_origin_is_fixed_and_ignores_forwarded_host(auth_app):
    client,_,_,calls,_=auth_app
    assert client.get('/auth/github/login',headers={'Host':'evil.example','X-Forwarded-Host':'vulnforge.example'}).status_code==400
    assert not calls


def test_auth_pages_use_no_store_and_callback_query_is_removed_from_scope(auth_app):
    client,_,_,_,_=auth_app
    for path in ('/account','/auth/status','/api/v1/me','/auth/github/callback?code=secret-code&state=secret-state'):
        response=client.get(path)
        assert response.headers['cache-control']=='no-store'
        assert response.headers['referrer-policy']=='no-referrer'
        assert response.headers['x-frame-options']=='DENY'
    captured=[]
    class Capture:
        async def __call__(self,scope,receive,send):
            await client.app(scope,receive,send)
            if scope['type']=='http': captured.append(scope['query_string'])
    wrapper=TestClient(Capture(),base_url=ORIGIN)
    wrapper.get('/auth/github/callback?code=secret-code&state=secret-state')
    assert captured==[b'']
