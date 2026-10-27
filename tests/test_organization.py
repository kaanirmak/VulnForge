"""Two independent dummy orgs across every customer data/export/triage route."""
from dataclasses import replace
import time

from fastapi.testclient import TestClient
import pytest

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData,ResourceNotFound,RoleDenied
from vulnforge.permissions import permits

ORIGIN='http://127.0.0.1:8000'
ROOT='/api/v1/organizations'


def seed(store):
    identity=Identities(store);members={};orgs={};repos={};scans={};findings={}
    for index,label in enumerate(('alpha','bravo')):
        owner=identity.record_github_user(100+index,label+'-owner')
        members[label+'_org_admin']=owner
        org=identity.create_organization(owner['id'],label+' organization');orgs[label]=org['id']
        for n,role in enumerate(('maintainer','analyst','viewer','auditor')):
            user=identity.record_github_user(1000+index*100+n,label+'-'+role)
            identity.set_membership(org['id'],user['id'],role,owner['id'])
            members[label+'_'+role]=user
        repo=label+'/private-project';repos[label]=repo
        store.upsert_repo(repo,index+1,'main')
        identity.record_repository_ownership(org['id'],repo,owner['id'],'verified-server-fixture')
        store.save_finding(repo,label+'-key','dependency','high',label+'-sensitive-finding','lock','a'*40,{'marker':label})
        with store.conn() as c: findings[label]=c.execute('SELECT id FROM findings WHERE repo=?',(repo,)).fetchone()[0]
        store.replace_inventory(repo,[Dependency(label+'-private-package','1.0.0','PyPI','lock')])
        scan=store.start_scan(repo,'dependencies','a'*40);scans[label]=scan
        finding={'key':label,'title':label+'-sensitive-finding','severity':'high','category':'dependency','file_path':'lock','details':{}}
        store.record_scan_finding(scan,finding)
        store.finish_scan(scan,'complete',{'files_total':1},[{'name':label+'-private-package','version':'1.0.0','ecosystem':'PyPI','file_path':'lock'}])
        store.save_remediation(repo,label+'-fix','https://github.com/'+repo+'/pull/1')
        advisory=store.save_advisory({'id':'GHSA-COMMON','summary':'Shared public issue','aliases':['CVE-2099-11111']})
        store.save_impact(repo,advisory,'affected',scan,{'marker':label},[{'package':label+'-private-package'}])
    # An unowned repo must never fall back into a customer's scope.
    store.upsert_repo('unassigned/private-project',3,'main')
    return members,orgs,repos,scans,findings


def config(store):
    return Config(database_path=store.path,admin_token='operator-only',operator_report_token='separate-report-operator',
                  github_oauth_client_id='Iv1.fixture',github_oauth_client_secret='fixture-only',public_origin=ORIGIN,
                  allow_insecure_local_auth=True,customer_api_preview=True)


def client_for(app,store,cfg,user):
    client=TestClient(app,base_url=ORIGIN)
    token,csrf=AuthSessions(store,cfg).create(user['id'])
    client.cookies.set('vf_local_session',token)
    client.cookies.set('vf_local_csrf',csrf)
    return client,{'Origin':ORIGIN,'X-CSRF-Token':csrf}


@pytest.fixture
def organizations(tmp_path):
    store=Store(str(tmp_path/'db'));fixtures=seed(store);cfg=config(store)
    return store,fixtures,cfg,create_app(cfg,store)


def actor(organizations,label='alpha',role='org_admin'):
    store,(members,orgs,repos,scans,findings),cfg,app=organizations
    client,headers=client_for(app,store,cfg,members[label+'_'+role])
    return client,headers,ROOT+'/'+orgs[label]


def test_preview_defaults_closed_and_cannot_be_enabled_for_public_origin(organizations):
    store,_,cfg,_=organizations
    closed=TestClient(create_app(replace(cfg,customer_api_preview=False),store),base_url=ORIGIN)
    assert closed.get(ROOT).status_code==503
    with pytest.raises(ValueError): replace(cfg,public_origin='https://public.example')
    with pytest.raises(ValueError): replace(cfg,allow_insecure_local_auth=False)
    assert Config().customer_api_preview is False


@pytest.mark.parametrize('role',['org_admin','maintainer','analyst','viewer','auditor'])
def test_all_read_roles_are_scoped_to_their_organization(organizations,role):
    client,_,root=actor(organizations,role=role)
    store,(members,orgs,repos,scans,findings),cfg,app=organizations
    mine=client.get(ROOT).json()['items']
    assert [row['id'] for row in mine]==[orgs['alpha']]
    for path in ('/overview','/repositories','/findings','/dependencies','/remediations','/scans','/impacts','/advisories',
                 '/scans/'+scans['alpha'],'/scans/'+scans['alpha']+'/sarif','/scans/'+scans['alpha']+'/sbom'):
        response=client.get(root+path)
        assert response.status_code==200,(path,response.text)
        assert 'bravo' not in response.text and 'unassigned' not in response.text
        assert response.headers['cache-control']=='no-store'
    assert client.get(root+'/overview').json()=={'repositories':1,'open_findings':1,'remediations':1,'affected_projects':1}
    assert client.get(root+'/advisories').json()['items'][0]['affected_projects']==1


@pytest.mark.parametrize('path',['/overview','/repositories','/findings','/dependencies','/remediations','/scans','/impacts','/advisories','/audit/events'])
def test_foreign_org_path_is_indistinguishable_from_missing_org(organizations,path):
    client,_,_=actor(organizations)
    orgs=organizations[1][1]
    denied=client.get(ROOT+'/'+orgs['bravo']+path)
    missing=client.get(ROOT+'/'+'0'*32+path)
    assert denied.status_code==missing.status_code==404
    assert denied.json()==missing.json()=={'detail':'Resource not found'}


@pytest.mark.parametrize('path',['/findings','/dependencies','/remediations','/scans','/impacts','/audit/events'])
def test_repo_filter_cannot_select_another_tenant_or_unowned_repo(organizations,path):
    client,_,root=actor(organizations)
    for repo in ('bravo/private-project','unassigned/private-project',"alpha/private-project' OR 1=1 --",''):
        response=client.get(root+path,params={'repo':repo})
        assert response.status_code==404
        assert 'bravo' not in response.text


@pytest.mark.parametrize('suffix',['','/sarif','/sbom'])
def test_foreign_scan_id_and_export_are_rejected_even_with_my_org_path(organizations,suffix):
    client,_,root=actor(organizations);scans=organizations[1][3]
    response=client.get(root+'/scans/'+scans['bravo']+suffix)
    assert response.status_code==404 and response.json()=={'detail':'Resource not found'}


@pytest.mark.parametrize('role,status,expected',[
    ('org_admin','resolved',200),('org_admin','suppressed',200),
    ('maintainer','resolved',200),('maintainer','suppressed',200),
    ('analyst','resolved',200),('analyst','suppressed',403),
    ('viewer','resolved',403),('viewer','suppressed',403),
    ('auditor','resolved',403),('auditor','suppressed',403),
])
def test_role_matrix_for_triage_and_risk_acceptance(organizations,role,status,expected):
    client,headers,root=actor(organizations,role=role)
    store,(members,orgs,repos,scans,findings),_,_=organizations
    change={'status':status,'reason':'Fixture reviewed'}
    if status=='suppressed': change['expires_at']=time.time()+300
    response=client.patch(root+f'/findings/{findings["alpha"]}/triage',json=change,headers=headers)
    assert response.status_code==expected,response.text
    with store.conn() as c:
        assert c.execute('SELECT status FROM findings WHERE id=?',(findings['bravo'],)).fetchone()[0]=='open'
        if expected==200:
            event=c.execute("SELECT actor,details FROM audit_events WHERE finding_id=? AND action='triage'",(findings['alpha'],)).fetchone()
            assert event['actor']==members['alpha_'+role]['id'] and orgs['alpha'] in event['details']
        else:
            assert c.execute('SELECT status FROM findings WHERE id=?',(findings['alpha'],)).fetchone()[0]=='open'


def test_foreign_finding_id_cannot_be_changed(organizations):
    client,headers,root=actor(organizations);finding=organizations[1][4]['bravo']
    response=client.patch(root+f'/findings/{finding}/triage',json={'status':'resolved','reason':'Reviewed fixture'},headers=headers)
    assert response.status_code==404


def test_csrf_requires_cookie_header_origin_and_server_hash(organizations):
    client,headers,root=actor(organizations);finding=organizations[1][4]['alpha']
    path=root+f'/findings/{finding}/triage';body={'status':'resolved','reason':'Reviewed fixture'}
    for forged in ({},{'Origin':'https://evil.example','X-CSRF-Token':headers['X-CSRF-Token']},
                   {'Origin':ORIGIN,'X-CSRF-Token':'forged'}):
        assert client.patch(path,json=body,headers=forged).status_code==403
    client.cookies.set('vf_local_csrf','forged')
    assert client.patch(path,json=body,headers={'Origin':ORIGIN,'X-CSRF-Token':'forged'}).status_code==403


@pytest.mark.parametrize('role,expected',[('org_admin',200),('maintainer',403),('analyst',403),('viewer',403),('auditor',200)])
def test_audit_access_is_explicit_and_scoped(organizations,role,expected):
    client,_,root=actor(organizations,role=role)
    response=client.get(root+'/audit/events')
    assert response.status_code==expected
    assert 'bravo' not in response.text


def test_role_changes_revoke_old_session_and_recheck_new_session(organizations):
    client,headers,root=actor(organizations,role='maintainer')
    store,(members,orgs,_,_,findings),cfg,app=organizations
    Identities(store).set_membership(orgs['alpha'],members['alpha_maintainer']['id'],'viewer',members['alpha_org_admin']['id'])
    assert client.patch(root+f'/findings/{findings["alpha"]}/triage',json={'status':'resolved','reason':'Reviewed fixture'},headers=headers).status_code==401
    client,headers=client_for(app,store,cfg,members['alpha_maintainer'])
    assert client.patch(root+f'/findings/{findings["alpha"]}/triage',json={'status':'resolved','reason':'Reviewed fixture'},headers=headers).status_code==403
    with store.conn() as c:
        c.execute('DELETE FROM memberships WHERE organization_id=? AND user_id=?',(orgs['alpha'],members['alpha_maintainer']['id']))
    assert client.get(root+'/findings').status_code==404


def test_bearer_cannot_replace_customer_session_and_customer_cookie_cannot_replace_operator(organizations):
    store,_,cfg,app=organizations
    client=TestClient(app,base_url=ORIGIN)
    assert client.get(ROOT,headers={'Authorization':'Bearer operator-only'}).status_code==401
    customer,_,_=actor(organizations)
    for path in ('/api/findings','/api/v1/overview','/api/v1/advisories','/api/v1/audit/events'):
        assert customer.get(path).status_code==401


def test_client_headers_and_query_cannot_override_session_identity_or_role(organizations):
    client,_,root=actor(organizations,role='viewer')
    store,(members,orgs,_,_,findings),_,_=organizations
    response=client.get(root+'/findings',params={'organization_id':orgs['bravo'],'user_id':members['bravo_org_admin']['id']},
                        headers={'X-Organization-ID':orgs['bravo'],'X-Role':'org_admin'})
    assert response.status_code==200 and 'bravo' not in response.text


def test_findings_cursor_filter_and_non_paginated_truncation(organizations):
    client,_,root=actor(organizations);store=organizations[0]
    store.save_finding('alpha/private-project','second','code','low','Second',None,'b'*40,{})
    first=client.get(root+'/findings',params={'limit':1}).json()
    assert first['truncated'] and first['next_cursor'] is not None
    second=client.get(root+'/findings',params={'limit':1,'cursor':first['next_cursor']}).json()
    assert first['items'][0]['id']!=second['items'][0]['id'] and second['next_cursor'] is None
    assert len(client.get(root+'/findings',params={'severity':'high'}).json()['items'])==1
    assert client.get(root+'/impacts',params={'advisory_id':'CVE-2099-11111'}).json()['items'][0]['repo']=='alpha/private-project'


def test_invalid_json_fields_sensitive_reason_and_size_never_echo_input(organizations):
    client,headers,root=actor(organizations);finding=organizations[1][4]['alpha']
    path=root+f'/findings/{finding}/triage'
    for body in ({'status':'resolved','reason':'Reviewed','source_code':'private-marker'},
                 {'status':'resolved','reason':'ghp_'+'x'*36},
                 {'status':'resolved','reason':'Reviewed','expires_at':True},
                 {'status':'suppressed','reason':'Reviewed','expires_at':0}):
        response=client.patch(path,json=body,headers=headers)
        assert response.status_code==422 and 'private-marker' not in response.text and 'ghp_' not in response.text
    response=client.patch(path,content=b'x'*4097,headers=headers)
    assert response.status_code==413


def test_suppression_expiry_never_changes_another_organization(organizations):
    client,_,root=actor(organizations);store=organizations[0];findings=organizations[1][4]
    for finding in findings.values(): store.triage(finding,'suppressed','Fixture reason',time.time()+30)
    with store.conn() as c: c.execute('UPDATE suppressions SET expires_at=0')
    assert client.get(root+'/overview').json()['open_findings']==1
    with store.conn() as c:
        assert c.execute('SELECT status FROM findings WHERE id=?',(findings['bravo'],)).fetchone()[0]=='suppressed'


def test_unknown_role_or_permission_is_denied_by_default():
    assert not permits('superuser','finding.read')
    assert not permits('org_admin','arbitrary.unlisted.action')


def test_internal_scope_requires_a_current_membership(organizations):
    store,(members,orgs,_,_,_),_,_=organizations
    data=OrganizationData(store,orgs['bravo'],members['alpha_org_admin']['id'])
    with pytest.raises(ResourceNotFound): data.rows('findings')
