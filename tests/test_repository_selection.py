import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs,urlsplit

import httpx
import pytest

from test_connections import onboarding,actor,provider,FixtureVerifier
from test_runner_oidc import signing_key
from test_github_metadata import configuration
from vulnforge.auth import AuthError,digest
from vulnforge.connections import CALLBACK,GitHubConnectionVerifier
from vulnforge.repository_choices import RepositoryChoices


def discover(onboarding):
    client,headers,root=actor(onboarding)
    response=client.post(root+'/connections/discover',headers=headers,json={})
    assert response.status_code==200
    state=parse_qs(urlsplit(response.json()['authorization_url']).query)['state'][0]
    return client,headers,root,state


class DiscoveryVerifier(FixtureVerifier):
    async def discover(self,code,verifier,github_id):
        self.calls.append((code,github_id))
        if self.operation:self.operation()
        return [{'full_name':'alpha/project'}]


def test_discovery_is_session_scoped_and_does_not_connect_or_persist_credentials(onboarding):
    client,headers,root,state=discover(onboarding)
    app=onboarding[3];app.state.connection_verifier=DiscoveryVerifier()
    before=onboarding[0].list_rows('repositories')
    response=client.get(CALLBACK,params={'state':state,'code':'one-time-code',
        'iss':'https://github.com/login/oauth'},follow_redirects=False)
    assert response.headers['location']=='/account?connection=choose'
    choices=client.get(root+'/connections/choices')
    assert choices.headers['cache-control']=='no-store'
    assert choices.json()['items']==[{'full_name':'alpha/project'}]
    assert onboarding[0].list_rows('repositories')==before
    other,_,_=actor(onboarding)
    assert other.get(root+'/connections/choices').json()['requires_refresh'] is True
    assert client.get(CALLBACK,params={'state':state,'code':'replay'},follow_redirects=False).headers['location'].endswith('failed')
    assert len(app.state.connection_verifier.calls)==1
    with onboarding[0].conn() as c:
        assert 'one-time-code' not in '\n'.join(c.iterdump())


@pytest.mark.parametrize('role',['viewer','maintainer','analyst','auditor'])
def test_discovery_and_choices_require_org_admin(onboarding,role):
    client,headers,root=actor(onboarding,role=role)
    assert client.post(root+'/connections/discover',headers=headers,json={}).status_code==403
    assert client.get(root+'/connections/choices').status_code==403


def test_discovery_requires_csrf_and_rechecks_authority_after_provider(onboarding):
    client,headers,root=actor(onboarding)
    assert client.post(root+'/connections/discover',json={}).status_code==403
    client,headers,root,state=discover(onboarding)
    store=onboarding[0]
    def revoke():
        with store.conn() as c:c.execute('DELETE FROM user_sessions')
    onboarding[3].state.connection_verifier=DiscoveryVerifier(revoke)
    response=client.get(CALLBACK,params={'state':state,'code':'code'},follow_redirects=False)
    assert response.headers['location'].endswith('failed')
    assert not onboarding[3].state.repository_choices.entries


def test_logout_removes_repository_choices(onboarding):
    client,headers,root,state=discover(onboarding)
    onboarding[3].state.connection_verifier=DiscoveryVerifier()
    client.get(CALLBACK,params={'state':state,'code':'code'},follow_redirects=False)
    assert onboarding[3].state.repository_choices.entries
    assert client.post('/auth/logout',headers=headers).status_code==204
    assert not onboarding[3].state.repository_choices.entries


def test_repository_choices_expire_and_do_not_cross_orgs(monkeypatch):
    now=[0];monkeypatch.setattr('vulnforge.repository_choices.time.monotonic',lambda:now[0])
    cache=RepositoryChoices();cache.put('session','org',[{'full_name':'owner/repo'}])
    assert cache.get('other','org')['requires_refresh']
    assert cache.get('session','other')['requires_refresh']
    now[0]=301
    assert cache.get('session','org')['requires_refresh']
    assert not cache.entries


def test_real_discovery_uses_user_installations_without_source_or_app_tokens(signing_key,monkeypatch):
    handler,calls=provider(signing_key)
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret',public_origin='http://127.0.0.1:8000')
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    items=asyncio.run(GitHubConnectionVerifier(cfg).discover('code','verifier',100))
    assert items==[{'full_name':'alpha/project'}]
    assert len(calls)==4
    assert not any('/contents' in str(r.url) or '/access_tokens' in str(r.url) for r in calls)


@pytest.mark.parametrize('change',['account','wide','app','duplicate','bad_count','over_count','empty_page'])
def test_discovery_rejects_ambiguous_or_wrong_provider_identity(signing_key,monkeypatch,change):
    handler,_=provider(signing_key,change)
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret',public_origin='http://127.0.0.1:8000')
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    with pytest.raises(AuthError):asyncio.run(GitHubConnectionVerifier(cfg).discover('code','verifier',100))


def test_read_only_repositories_are_not_offered(signing_key,monkeypatch):
    handler,_=provider(signing_key,'read_only')
    cfg=SimpleNamespace(**vars(configuration(signing_key)),oauth_enabled=True,
        github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-secret',public_origin='http://127.0.0.1:8000')
    real=httpx.AsyncClient
    monkeypatch.setattr('vulnforge.auth.httpx.AsyncClient',lambda **kwargs:real(transport=httpx.MockTransport(handler),**kwargs))
    assert asyncio.run(GitHubConnectionVerifier(cfg).discover('code','verifier',100))==[]
