import time

import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.auth import AuthSessions
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.identity import Identities
from test_job_scope import queue
from test_database import pg_store
from test_organization import seed,config,client_for,ROOT,ORIGIN


@pytest.fixture
def identities(queue):
    ids=Identities(queue)
    admin=ids.record_github_user(100,'admin')
    target=ids.record_github_user(200,'target')
    stranger=ids.record_github_user(300,'stranger')
    org=ids.create_organization(admin['id'],'Organization')
    return queue,ids,admin,target,stranger,org['id']


def test_invitation_is_recipient_bound_hashed_single_use_and_audited(identities):
    store,ids,admin,target,stranger,org=identities
    invitation=ids.invite(org,200,'maintainer',admin['id'])
    with store.conn() as c:
        row=dict(c.execute('SELECT * FROM invitations').fetchone())
        assert invitation['token'] not in str(row)
    with pytest.raises(LookupError): ids.accept_invitation(invitation['token'],stranger['id'])
    assert ids.accept_invitation(invitation['token'],target['id'])=={'organization_id':org,'role':'maintainer'}
    with pytest.raises(LookupError): ids.accept_invitation(invitation['token'],target['id'])
    with store.conn() as c:
        audit=str([dict(r) for r in c.execute('SELECT * FROM audit_events')])
    assert invitation['token'] not in audit


@pytest.mark.parametrize('condition',['expired','revoked','replaced','inviter_removed'])
def test_expired_revoked_replaced_or_stale_invites_cannot_grant_access(identities,condition):
    store,ids,admin,target,stranger,org=identities
    invitation=ids.invite(org,200,'viewer',admin['id'])
    if condition=='expired':
        with store.conn() as c: c.execute('UPDATE invitations SET expires_at=?',(time.time()-1,))
    elif condition=='revoked': ids.revoke_invitation(org,invitation['id'],admin['id'])
    elif condition=='replaced': ids.invite(org,200,'analyst',admin['id'])
    else:
        ids.set_membership(org,stranger['id'],'org_admin',admin['id'])
        ids.remove_membership(org,admin['id'],stranger['id'])
    with pytest.raises((LookupError,PermissionError)): ids.accept_invitation(invitation['token'],target['id'])
    assert not ids.list_organizations(target['id'])


def test_remove_member_revokes_sessions_and_keeps_last_admin(identities):
    store,ids,admin,target,stranger,org=identities
    ids.set_membership(org,target['id'],'maintainer',admin['id'])
    auth=AuthSessions(store,Config());token,_=auth.create(target['id'])
    with pytest.raises(PermissionError): ids.invite(org,300,'org_admin',target['id'])
    with pytest.raises(PermissionError): ids.remove_membership(org,admin['id'],admin['id'])
    ids.remove_membership(org,target['id'],admin['id'])
    assert auth.current(token) is None and not ids.list_organizations(target['id'])


def test_membership_routes_require_session_csrf_and_admin(tmp_path):
    store=Store(str(tmp_path/'db'));members,orgs,*_=seed(store);cfg=config(store);app=create_app(cfg,store)
    admin,headers=client_for(app,store,cfg,members['alpha_org_admin'])
    viewer,vheaders=client_for(app,store,cfg,members['alpha_viewer'])
    url=ROOT+'/'+orgs['alpha']+'/invitations'
    assert admin.post(url,json={'github_id':9999,'role':'viewer'}).status_code==403
    assert viewer.post(url,json={'github_id':9999,'role':'org_admin'},headers=vheaders).status_code==403
    assert admin.post(ROOT+'/'+orgs['bravo']+'/invitations',json={'github_id':9999,'role':'viewer'},headers=headers).status_code==403
    response=admin.post(url,json={'github_id':9999,'role':'viewer'},headers=headers)
    assert response.status_code==201 and response.headers['cache-control']=='no-store'
    invitation=response.json()
    user=Identities(store).record_github_user(9999,'invitee')
    invitee,iheaders=client_for(app,store,cfg,user)
    accepted=invitee.post(ROOT+'/invitations/accept',json={'token':invitation['token']},headers=iheaders)
    assert accepted.status_code==200 and accepted.json()['organization_id']==orgs['alpha']
    assert invitee.post(ROOT+'/invitations/accept',json={'token':invitation['token']},headers=iheaders).status_code==404
    remove=ROOT+'/'+orgs['alpha']+'/memberships/'+user['id']
    assert admin.delete(remove,headers=headers).status_code==204
    assert invitee.get(ROOT).status_code==401
