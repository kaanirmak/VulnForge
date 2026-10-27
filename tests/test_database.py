"""Versioned schema and real PostgreSQL parity. No shared/remote database is accepted."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import sqlite3
import time
import uuid
from urllib.parse import parse_qs, urlsplit
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.database import DatabaseError, Record, qmark_to_postgres
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.migrate import import_sqlite, TABLES
from vulnforge.runner_report import RunnerReport
from test_privacy import report_fixture


def test_sql_parameters_preserve_quoted_markers_and_data():
    assert qmark_to_postgres("SELECT '?', ?, '100%', \"?\"")=="SELECT '?', %s, '100%%', \"?\""
    assert qmark_to_postgres("SELECT 'it''s ?', ?")=="SELECT 'it''s ?', %s"
    row=Record(['name','id'],['fixture',7])
    assert row[0]=='fixture' and row['id']==7 and dict(row)=={'name':'fixture','id':7}


def test_existing_sqlite_schema_is_upgraded_without_deleting_records(tmp_path):
    path=tmp_path/'existing.db'
    from vulnforge.db import SCHEMA
    with sqlite3.connect(path) as c:
        c.executescript(SCHEMA)
        c.execute('INSERT INTO repositories(full_name,installation_id,default_branch,updated_at) VALUES(?,?,?,?)',
                  ('fixture/repo',1,'main',time.time()))
    upgraded=Store(str(path))
    assert upgraded.list_rows('repositories')[0]['full_name']=='fixture/repo'
    with upgraded.conn() as c: assert c.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==8


def test_applied_migration_drift_is_rejected(tmp_path):
    path=str(tmp_path/'db');store=Store(path)
    with store.conn() as c: c.execute("UPDATE schema_migrations SET checksum='tampered'")
    with pytest.raises(DatabaseError,match='checksum'): Store(path)


def test_database_url_has_explicit_precedence():
    cfg=Config(database_path='unused.db',database_url='postgresql://fixture@localhost/example')
    assert cfg.database_target==cfg.database_url
    with pytest.raises(ValueError): Config(database_url='https://unexpected.example/db')


@pytest.fixture
def pg_store():
    url=os.getenv('VULNFORGE_TEST_PG_URL')
    if not url: pytest.skip('Requires an explicitly provisioned temporary local PostgreSQL cluster')
    psycopg=pytest.importorskip('psycopg')
    from psycopg import sql
    parsed=urlsplit(url);params=parse_qs(parsed.query)
    host=params.get('host',[''])[0]
    # Refuse to create/drop any DB on a production/shared server or TCP socket.
    if (parsed.scheme!='postgresql' or parsed.hostname or parsed.username!='vulnforge_test' or
        parsed.path!='/postgres' or not host.startswith(('/private/tmp/vulnforge-pg.','/tmp/vulnforge-pg.')) or
        set(params)-{'host','port'}):
        pytest.fail('PostgreSQL tests require the isolated VF temporary Unix-socket cluster')
    dbname='vf_test_'+uuid.uuid4().hex
    with psycopg.connect(url,autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(dbname)))
    target=url.replace('/postgres?',f'/{dbname}?',1)
    try: yield Store(target)
    finally:
        with psycopg.connect(url,autocommit=True) as admin:
            admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(dbname)))


@pytest.fixture
def pg_customer(pg_store):
    from vulnforge.rls import CustomerStore,provision_customer,identifier
    role='vf_customer_'+uuid.uuid4().hex
    with pg_store.conn() as c:
        c.execute(f'CREATE ROLE {identifier(role)} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
    try:
        with pg_store.transaction(),pg_store.conn() as c: provision_customer(c,role)
        url=urlsplit(pg_store.path)._replace(netloc=role+'@').geturl()
        yield CustomerStore(url)
    finally:
        with pg_store.conn() as c:
            c.execute('DELETE FROM vf_security.runtime_roles WHERE role_name=?',(role,))
            c.execute(f'DROP OWNED BY {identifier(role)} CASCADE')
            c.execute(f'DROP ROLE {identifier(role)}')


@pytest.fixture
def pg_operator(pg_store):
    from vulnforge.rls import provision_operator,identifier
    role='vf_operator_'+uuid.uuid4().hex
    with pg_store.conn() as c:
        c.execute(f'CREATE ROLE {identifier(role)} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
    try:
        with pg_store.transaction(),pg_store.conn() as c: provision_operator(c,role)
        url=urlsplit(pg_store.path)._replace(netloc=role+'@').geturl()
        yield Store(url,migrate=False)
    finally:
        with pg_store.conn() as c:
            c.execute('DELETE FROM vf_security.runtime_roles WHERE role_name=?',(role,))
            c.execute(f'DROP OWNED BY {identifier(role)} CASCADE')
            c.execute(f'DROP ROLE {identifier(role)}')


def test_postgres_migrations_upserts_scans_and_triage(pg_store):
    store=pg_store;store.upsert_repo('org/service',2**40,'main')
    store.save_finding('org/service','key','dependency','high','Fixture','lock','a'*40,{})
    id_=store.list_rows('findings')[0]['id']
    store.triage(id_,'suppressed','fixture exception',time.time()+100)
    store.save_finding('org/service','key','dependency','critical','Fixture','lock','b'*40,{})
    assert store.list_rows('findings')[0]['status']=='suppressed'
    with store.conn() as c: c.execute('UPDATE suppressions SET expires_at=0')
    store.expire_suppressions()
    assert store.list_rows('findings')[0]['status']=='open'
    scan=store.start_scan('org/service','dependencies','b'*40)
    f={'key':'code:fixture','details':{'line':1},'title':'Fixture','severity':'high','file_path':'x.py'}
    store.record_scan_finding(scan,f);store.record_scan_finding(scan,{**f,'severity':'medium'})
    store.finish_scan(scan,'complete',{'files_total':1},[])
    assert store.scan(scan)['findings'][0]['severity']=='medium'
    assert Store(store.path).list_rows('repositories')[0]['installation_id']==2**40


def test_postgres_intelligence_and_quarantined_report(pg_store):
    store=pg_store;store.upsert_repo('org/service',1,'main')
    id_=store.save_advisory({'id':'GHSA-FIXTURE','aliases':['CVE-2099-11111']})
    store.save_impact('org/service',id_,'affected',None,{'version_affected':True},[])
    assert store.list_impacts(advisory_id='CVE-2099-11111')['items'][0]['repo']=='org/service'
    assert store.list_advisories()[0]['affected_projects']==1
    report=RunnerReport.model_validate(report_fixture())
    store.quarantine_runner_report(report)
    assert store.quarantine_runner_report(report)['duplicate']
    store.replace_inventory('org/service',[Dependency('Demo','1.0','PyPI','requirements.txt')])
    assert 'org/service' in store.repos_using_packages([('PyPI','demo')])
    store.remove_installation(1)
    with store.conn() as c:
        for table in ('repositories','runner_reports','advisory_impacts'):
            assert c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]==0


def test_postgres_transactions_and_queue_claims_are_atomic(pg_store):
    store=pg_store
    store.upsert_repo('o/r',1,'main')
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.add_delivery('rolled-back');store.enqueue('dependency_audit','o/r',{},'rollback')
            raise RuntimeError('fixture rollback')
    assert store.add_delivery('rolled-back')
    for n in range(20): store.enqueue('dependency_audit','o/r',{},str(n))
    with ThreadPoolExecutor(max_workers=5) as pool:
        claimed=list(pool.map(lambda _:store.claim(),range(25)))
    ids=[row['id'] for row in claimed if row]
    assert len(ids)==len(set(ids))==20
    for row in claimed:
        if row: store.finish(row)
    assert all(row['state']=='done' for row in store.list_rows('jobs'))


def test_postgres_api_round_trip(pg_store):
    store=pg_store;store.upsert_repo('org/service',1,'main')
    client=TestClient(create_app(Config(admin_token='fixture-admin'),store))
    auth={'Authorization':'Bearer fixture-admin'}
    assert client.get('/api/v1/overview',headers=auth).json()['repositories']==1
    assert client.post('/api/v1/intelligence/refresh',headers=auth).json()['queued']==1
    assert client.get('/api/repositories',headers=auth).json()[0]['full_name']=='org/service'
    assert client.get('/api/v1/impacts',headers=auth).json()['items']==[]


def test_postgres_uses_the_migration_namespace_despite_connection_default(pg_store):
    store=Store(pg_store.path+'&options=-csearch_path%3Dpg_catalog')
    store.upsert_repo('org/service',1,'main')
    with store.conn() as c:
        assert c.execute('SHOW search_path').fetchone()[0]=='public'
    assert store.list_rows('repositories')[0]['full_name']=='org/service'


def seed_sqlite(path):
    store=Store(str(path));store.upsert_repo('org/service',1,'main')
    store.add_delivery('fixture-delivery');store.enqueue('dependency_audit','org/service',{},'fixture-job')
    store.save_finding('org/service','dep:fixture','dependency','high','Fixture','requirements.txt','a'*40,{'package':'demo'})
    finding=store.list_rows('findings')[0]['id'];store.triage(finding,'suppressed','fixture reason',time.time()+500)
    store.save_remediation('org/service','fixture-remediation','https://github.com/org/service/pull/1')
    store.replace_inventory('org/service',[Dependency('demo','1.0.0','PyPI','requirements.txt')])
    id_=store.save_advisory({'id':'GHSA-FIXTURE','aliases':['CVE-2099-11111']})
    scan=store.start_scan('org/service','dependencies','a'*40)
    store.record_scan_finding(scan,{'key':'fixture','details':{}});store.finish_scan(scan,'complete',{},[])
    store.save_impact('org/service',id_,'affected',scan,{},[])
    store.quarantine_runner_report(RunnerReport.model_validate(report_fixture()))
    from vulnforge.identity import Identities
    identity=Identities(store)
    user=identity.record_github_user(999,'fixture-owner')
    org=identity.create_organization(user['id'],'Fixture workspace')
    identity.record_repository_ownership(org['id'],'org/service',user['id'],'server-verified-fixture')
    identity.invite(org['id'],10001,'viewer',user['id'])
    identity.set_remediation_policy(org['id'],'org/service',user['id'],True,['demo'],['requirements.txt'])
    from vulnforge.auth import AuthSessions
    sessions=AuthSessions(store,Config())
    sessions.begin();sessions.create(user['id'])
    return store


def test_sqlite_to_postgres_preserves_all_records_and_sequence_high_watermark(tmp_path,pg_store):
    source=seed_sqlite(tmp_path/'source.db')
    with source.conn() as c:
        c.execute('UPDATE sqlite_sequence SET seq=900 WHERE name=?',('findings',))
        expected={table:[dict(row) for row in c.execute(f'SELECT * FROM {table}')] for table in TABLES}
    result=import_sqlite(source.path,pg_store.path)
    assert result['verified'] and result['source_modified'] is False
    with pg_store.conn() as c:
        for table in TABLES:
            actual=[dict(row) for row in c.execute(f'SELECT * FROM {table}')]
            sort=lambda rows:sorted(json.dumps(row,sort_keys=True) for row in rows)
            assert sort(actual)==sort(expected[table]),table
    pg_store.save_finding('org/service','new','code','high','New',None,'b'*40,{})
    assert next(r for r in pg_store.list_rows('findings') if r['key']=='new')['id']>900
    assert len(source.list_rows('findings'))==1


def test_migration_refuses_nonempty_target_without_overwriting(tmp_path,pg_store):
    source=seed_sqlite(tmp_path/'source.db');pg_store.upsert_repo('existing/repo',9,'main')
    with pytest.raises(ValueError,match='empty'): import_sqlite(source.path,pg_store.path)
    assert pg_store.list_rows('repositories')[0]['full_name']=='existing/repo'


def test_migration_error_rolls_back_all_imported_tables(tmp_path,pg_store):
    source=seed_sqlite(tmp_path/'source.db')
    with source.conn() as c: c.execute('ALTER TABLE findings ADD COLUMN unexpected TEXT')
    with pytest.raises(ValueError,match='schema'): import_sqlite(source.path,pg_store.path)
    with pg_store.conn() as c:
        for table in TABLES: assert c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]==0


def test_postgres_identity_and_concurrent_last_admin_guard(pg_store):
    from vulnforge.identity import Identities
    service=Identities(pg_store)
    owner=service.record_github_user(100,'owner');other=service.record_github_user(200,'other')
    org=service.create_organization(owner['id'],'Fixture')
    service.set_membership(org['id'],other['id'],'org_admin',owner['id'])
    def demote(user):
        try:
            service.set_membership(org['id'],user['id'],'viewer',user['id'])
            return True
        except PermissionError: return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(demote,[owner,other]))
    assert sorted(results)==[False,True]
    with pg_store.conn() as c:
        assert c.execute("SELECT COUNT(*) FROM memberships WHERE role='org_admin'").fetchone()[0]==1


def test_postgres_auth_state_is_consumed_once_and_session_revokes(pg_store):
    from vulnforge.auth import AuthSessions,AuthError
    from vulnforge.identity import Identities
    service=AuthSessions(pg_store,Config())
    location,verifier=service.begin()
    state=parse_qs(urlsplit(location).query)['state'][0]
    def consume(_):
        try:
            service.consume(state,verifier)
            return True
        except AuthError: return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume,range(2)))==[False,True]
    user=Identities(pg_store).record_github_user(123,'fixture')
    token,csrf=service.create(user['id'])
    assert service.current(token)['id']==user['id']
    service.logout(token,csrf)
    assert service.current(token) is None


def test_postgres_organization_api_scopes_every_read_and_export(pg_store,pg_customer,pg_operator):
    from test_organization import seed,config,client_for,ROOT
    members,orgs,repos,scans,findings=seed(pg_store);cfg=replace(config(pg_store),customer_database_url=pg_customer.path,
        database_url=pg_operator.path,database_auto_migrate=False)
    client,headers=client_for(create_app(cfg,pg_operator),pg_operator,cfg,members['alpha_org_admin'])
    root=ROOT+'/'+orgs['alpha']
    for path in ('/overview','/repositories','/findings','/dependencies','/remediations','/scans','/impacts','/advisories','/audit/events',
                 '/scans/'+scans['alpha'],'/scans/'+scans['alpha']+'/sarif','/scans/'+scans['alpha']+'/sbom'):
        response=client.get(root+path)
        assert response.status_code==200,(path,response.text)
        assert 'bravo' not in response.text and 'unassigned' not in response.text
    assert client.get(root+'/advisories').json()['items'][0]['affected_projects']==1
    assert client.get(root+'/scans/'+scans['bravo']+'/sarif').status_code==404
    assert client.get(ROOT+'/'+orgs['bravo']+'/findings').status_code==404
    assert client.patch(root+f'/findings/{findings["bravo"]}/triage',headers=headers,
                        json={'status':'resolved','reason':'Reviewed fixture'}).status_code==404


def test_postgres_customer_role_and_membership_are_rechecked_with_existing_session(pg_store,pg_customer,pg_operator):
    from test_organization import seed,config,client_for,ROOT
    from vulnforge.identity import Identities
    members,orgs,repos,scans,findings=seed(pg_store);cfg=replace(config(pg_store),customer_database_url=pg_customer.path,
        database_url=pg_operator.path,database_auto_migrate=False)
    client,headers=client_for(create_app(cfg,pg_operator),pg_operator,cfg,members['alpha_maintainer'])
    root=ROOT+'/'+orgs['alpha'];path=root+f'/findings/{findings["alpha"]}/triage'
    change={'status':'suppressed','reason':'Reviewed fixture','expires_at':time.time()+300}
    assert client.patch(path,headers=headers,json=change).status_code==200
    Identities(pg_store).set_membership(orgs['alpha'],members['alpha_maintainer']['id'],'viewer',members['alpha_org_admin']['id'])
    assert client.patch(path,headers=headers,json=change).status_code==401
    client,headers=client_for(create_app(cfg,pg_operator),pg_operator,cfg,members['alpha_maintainer'])
    assert client.patch(path,headers=headers,json=change).status_code==403
    with pg_store.conn() as c:
        c.execute('DELETE FROM memberships WHERE organization_id=? AND user_id=?',(orgs['alpha'],members['alpha_maintainer']['id']))
    assert client.get(root+'/findings').status_code==404
