import asyncio
import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.dependencies import Dependency
from vulnforge.identity import Identities
from vulnforge.worker import Agent
from support import managed_config
from test_agent import FakeGitHub,FakeOSV
from test_job_scope import queue,own
from test_database import pg_store
from test_organization import seed,config,client_for,ROOT


def test_opt_in_is_connection_and_current_admin_bound(queue):
    org=own(queue);ids=Identities(queue)
    with queue.conn() as c: admin=c.execute('SELECT id FROM users WHERE github_id=100').fetchone()[0]
    assert queue.remediation_policy('alpha/project') is None
    result=ids.set_remediation_policy(org,'alpha/project',admin,True,['Requests'],['requirements.txt'])
    assert not result['automerge'] and not result['publication_ready']
    assert queue.remediation_policy('alpha/project')['allowed_packages']==['requests']
    ids.set_remediation_policy(org,'alpha/project',admin,False,['requests'],['requirements.txt'])
    assert queue.remediation_policy('alpha/project') is None
    ids.set_remediation_policy(org,'alpha/project',admin,True,['requests'],['requirements.txt'])
    queue.upsert_repo('alpha/project',999,'main')
    assert queue.remediation_policy('alpha/project') is None


@pytest.mark.parametrize('path',['.github/requirements.txt','../requirements.txt','requirements.in','src/../requirements.txt'])
def test_dangerous_patch_targets_are_rejected(queue,path):
    org=own(queue)
    with queue.conn() as c: admin=c.execute('SELECT id FROM users WHERE github_id=100').fetchone()[0]
    with pytest.raises(ValueError):
        Identities(queue).set_remediation_policy(org,'alpha/project',admin,True,['requests'],[path])


def test_even_opt_in_cannot_bypass_missing_validation_or_human_approval(queue):
    org=own(queue)
    with queue.conn() as c: admin=c.execute('SELECT id FROM users WHERE github_id=100').fetchone()[0]
    Identities(queue).set_remediation_policy(org,'alpha/project',admin,True,['requests'],['requirements.txt'])
    github=FakeGitHub();agent=Agent(managed_config(enable_auto_pr=True),queue,github,FakeOSV())
    dep=Dependency('requests','2.27.0','PyPI','requirements.txt')
    asyncio.run(agent.maybe_propose_patches('alpha/project',11,'main','a'*40,{}, {dep:[]}))
    assert not github.prs
    assert any('isolated_validation_and_bound_approval_required' in a['details'] for a in queue.list_rows('audit_events'))


def test_github_client_refuses_merge_and_non_draft_writes_even_when_enabled():
    import httpx
    from vulnforge.github import GitHub,GitHubError
    async def run():
        def forbidden(request): raise AssertionError('No request may leave the client')
        async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
            github=GitHub(managed_config(enable_auto_pr=True,enable_checks=True),client)
            for method,path,body in (
                ('PUT','/repos/alpha/project/pulls/1/merge',{}),
                ('POST','/repos/alpha/project/pulls',{'draft':False}),
                ('PUT','/repos/alpha/project/contents/.github/workflows/ci.yml',{'branch':'main'}),
                ('DELETE','/repos/alpha/project/git/refs/heads/main',{}),
            ):
                with pytest.raises(GitHubError): await github.request(method,path,11,json=body)
    asyncio.run(run())


def test_policy_api_requires_org_admin_and_csrf(tmp_path):
    from vulnforge.db import Store
    store=Store(str(tmp_path/'db'));members,orgs,repos,*_=seed(store);cfg=config(store);app=create_app(cfg,store)
    admin,headers=client_for(app,store,cfg,members['alpha_org_admin'])
    viewer,vheaders=client_for(app,store,cfg,members['alpha_viewer'])
    url=ROOT+'/'+orgs['alpha']+'/remediation-policy'
    body={'repo':repos['alpha'],'enabled':True,'packages':['requests'],'paths':['requirements.txt']}
    assert admin.put(url,json=body).status_code==403
    assert viewer.put(url,json=body,headers=vheaders).status_code==403
    assert admin.put(url,json={**body,'repo':repos['bravo']},headers=headers).status_code==404
    response=admin.put(url,json=body,headers=headers)
    assert response.status_code==200 and not response.json()['publication_ready']
    assert store.remediation_policy(repos['alpha']) is not None
