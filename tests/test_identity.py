"""Identity model acceptance. OAuth/tenant HTTP boundaries are deliberately not exposed yet."""
import pytest

from vulnforge.db import Store
from vulnforge.identity import Identities


@pytest.fixture
def identities(tmp_path):
    store=Store(str(tmp_path/'db'))
    return Identities(store)


def users_and_org(service):
    owner=service.record_github_user(100,'owner')
    other=service.record_github_user(200,'other')
    org=service.create_organization(owner['id'],'Fixture organization')
    return owner,other,org


def test_github_id_remains_stable_when_login_changes(identities):
    initial=identities.record_github_user(100,'old-login')
    updated=identities.record_github_user(100,'new-login')
    assert initial['id']==updated['id'] and updated['login']=='new-login'
    assert updated['created_at']==initial['created_at']


@pytest.mark.parametrize('id_,login',[(True,'user'),(0,'user'),(-1,'user'),(2**63,'user'),(1,'bad\nlogin'),(1,'a/b')])
def test_invalid_verified_identity_is_rejected(identities,id_,login):
    with pytest.raises(ValueError): identities.record_github_user(id_,login)


def test_organization_creation_requires_an_existing_identity(identities):
    with pytest.raises(PermissionError): identities.create_organization('not-a-user','Fixture')
    assert identities.list_organizations('not-a-user')==[]


def test_creator_becomes_admin_and_other_user_cannot_see_membership(identities):
    owner,other,org=users_and_org(identities)
    assert identities.list_organizations(owner['id'])==[{'id':org['id'],'name':'Fixture organization','role':'org_admin'}]
    assert identities.list_organizations(other['id'])==[]


def test_only_admin_can_grant_membership_and_role_is_validated(identities):
    owner,other,org=users_and_org(identities)
    with pytest.raises(PermissionError): identities.set_membership(org['id'],other['id'],'org_admin',other['id'])
    with pytest.raises(ValueError): identities.set_membership(org['id'],other['id'],'platform_operator',owner['id'])
    identities.set_membership(org['id'],other['id'],'analyst',owner['id'])
    assert identities.list_organizations(other['id'])[0]['role']=='analyst'
    with pytest.raises(PermissionError): identities.set_membership(org['id'],other['id'],'org_admin',other['id'])


def test_last_administrator_cannot_be_demoted(identities):
    owner,other,org=users_and_org(identities)
    with pytest.raises(PermissionError): identities.set_membership(org['id'],owner['id'],'viewer',owner['id'])
    identities.set_membership(org['id'],other['id'],'org_admin',owner['id'])
    identities.set_membership(org['id'],owner['id'],'viewer',owner['id'])
    assert identities.list_organizations(owner['id'])[0]['role']=='viewer'
    assert identities.list_organizations(other['id'])[0]['role']=='org_admin'


def test_repository_ownership_is_recorded_only_for_registered_repo_and_admin(identities):
    owner,other,org=users_and_org(identities)
    with pytest.raises(ValueError): identities.record_repository_ownership(org['id'],'fixture/repo',owner['id'],'verified-fixture')
    identities.store.upsert_repo('fixture/repo',1,'main')
    with pytest.raises(PermissionError): identities.record_repository_ownership(org['id'],'fixture/repo',other['id'],'verified-fixture')
    with pytest.raises(ValueError): identities.record_repository_ownership(org['id'],'fixture/repo',owner['id'],'')
    result=identities.record_repository_ownership(org['id'],'fixture/repo',owner['id'],'verified-fixture')
    assert result['organization_id']==org['id']


def test_repo_cannot_be_stolen_by_another_organization_even_for_same_user(identities):
    owner,_,first=users_and_org(identities)
    second=identities.create_organization(owner['id'],'Second')
    identities.store.upsert_repo('fixture/repo',1,'main')
    identities.record_repository_ownership(first['id'],'fixture/repo',owner['id'],'verified-fixture')
    with pytest.raises(PermissionError):
        identities.record_repository_ownership(second['id'],'fixture/repo',owner['id'],'verified-other')
    with identities.store.conn() as c:
        assert c.execute('SELECT organization_id FROM repository_ownership').fetchone()[0]==first['id']


def test_uninstall_cascades_ownership_but_keeps_user_organization(identities):
    owner,_,org=users_and_org(identities)
    identities.store.upsert_repo('fixture/repo',1,'main')
    identities.record_repository_ownership(org['id'],'fixture/repo',owner['id'],'verified-fixture')
    identities.store.remove_repo('fixture/repo')
    with identities.store.conn() as c: assert c.execute('SELECT COUNT(*) FROM repository_ownership').fetchone()[0]==0
    assert identities.list_organizations(owner['id'])[0]['id']==org['id']
