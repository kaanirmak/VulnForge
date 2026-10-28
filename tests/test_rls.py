"""Raw SQL must remain scoped with no application WHERE clause or role claims."""
from dataclasses import replace
import time

from fastapi.testclient import TestClient
import pytest

from test_database import pg_store,pg_customer,pg_operator
from test_organization import seed,config,client_for,ROOT
from vulnforge.api import create_app
from vulnforge.auth import AuthSessions,digest
from vulnforge.database import DatabaseError,split_sql
from vulnforge.db import Store
from vulnforge.identity import Identities
from vulnforge.organization import OrganizationData
from vulnforge.permissions import PERMISSIONS
from vulnforge.rls import CustomerStore,identifier,validate_role


def test_migration_splitter_keeps_function_bodies_and_quoted_semicolons():
    script="""-- comment ;
    CREATE FUNCTION f() RETURNS text AS $body$ SELECT 'one;two'; $body$ LANGUAGE sql;
    /* outer ; /* nested ; */ done */ SELECT 'it''s;quoted', "semi;colon";
    SELECT 1 -- trailing ;
    ;"""
    statements=split_sql(script)
    assert len(statements)==3 and "SELECT 'one;two';" in statements[0]
    assert "'it''s;quoted'" in statements[1] and statements[2].strip()=='SELECT 1'
    for invalid in ("SELECT 'unclosed",'/* unclosed','SELECT $body$ unclosed'):
        with pytest.raises(DatabaseError): split_sql(invalid)


@pytest.fixture
def scoped(pg_store,pg_customer):
    fixture=seed(pg_store);cfg=replace(config(pg_store),customer_database_url=pg_customer.path)
    members,orgs,repos,scans,findings=fixture
    def scope(label='alpha',role='org_admin'):
        user=members[label+'_'+role]
        token,_=AuthSessions(pg_store,cfg).create(user['id'])
        return pg_customer.organization_scope(orgs[label],user['id'],digest(token))
    return pg_store,pg_customer,fixture,cfg,scope


def test_raw_select_without_application_filters_is_organization_scoped(scoped):
    operator,customer,(members,orgs,repos,scans,findings),cfg,scope=scoped
    with scope(),customer.conn() as c:
        for table in ('repositories','findings','dependency_inventory','remediations','scans','advisory_impacts','audit_events','repository_ownership'):
            rows=c.execute(f'SELECT * FROM public.{table}').fetchall()
            assert rows and 'bravo' not in str([dict(row) for row in rows]),table
        assert len(c.execute('SELECT * FROM public.scan_findings').fetchall())==1
        assert len(c.execute('SELECT * FROM public.memberships').fetchall())==1
        assert len(c.execute('SELECT * FROM public.organizations').fetchall())==1
        # Same advisory affects two orgs, but the customer sees only one impact.
        assert c.execute('SELECT COUNT(*) FROM public.advisory_impacts').fetchone()[0]==1
    with customer.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM public.findings').fetchone()[0]==0


def test_organization_and_user_role_guc_forgery_does_not_change_actor(scoped):
    _,customer,(members,orgs,_,_,_),_,scope=scoped
    with scope(),customer.conn() as c:
        c.execute("SELECT set_config('vulnforge.organization_id',?,true)",(orgs['bravo'],))
        c.execute("SELECT set_config('vulnforge.user_id',?,true)",(members['bravo_org_admin']['id'],))
        c.execute("SELECT set_config('vulnforge.role','org_admin',true)")
        c.execute("SELECT set_config('vulnforge.internal','true',true)")
        assert c.execute('SELECT vf_security.actor_id()').fetchone()[0]==members['alpha_org_admin']['id']
        assert c.execute('SELECT COUNT(*) FROM public.findings').fetchone()[0]==0
        assert not c.execute("SELECT vf_security.permits('finding.suppress')").fetchone()[0]


@pytest.mark.parametrize('table',['user_sessions','auth_states','jobs','deliveries','runner_reports','schema_migrations','invitations','remediation_policies','runner_policies','runner_receipts','runner_token_uses','connection_intents'])
def test_customer_role_cannot_read_privileged_tables_even_with_session(scoped,table):
    _,customer,_,_,scope=scoped
    with pytest.raises(DatabaseError,match='42501'):
        with scope(),customer.conn() as c: c.execute(f'SELECT * FROM public.{table}')


@pytest.mark.parametrize('sql',[
    'SELECT * FROM vf_security.runtime_roles',
    'SET ROLE vulnforge_test',
    'SET SESSION AUTHORIZATION vulnforge_test',
    'ALTER TABLE public.findings DISABLE ROW LEVEL SECURITY',
    'TRUNCATE public.findings',
    'CREATE TABLE public.escape(id integer)',
    'CREATE TEMP TABLE findings(id integer)',
    "UPDATE public.repository_ownership SET organization_id='forged'",
    "UPDATE public.memberships SET role='org_admin'",
    "UPDATE public.findings SET repo='bravo/private-project'",
    "UPDATE public.findings SET title='forged'",
    'DELETE FROM public.audit_events',
])
def test_customer_connection_cannot_bypass_or_modify_authority(scoped,sql):
    _,customer,_,_,scope=scoped
    with pytest.raises(DatabaseError):
        with scope(),customer.conn() as c: c.execute(sql)


def test_row_security_off_raises_instead_of_exposing_rows(scoped):
    _,customer,_,_,scope=scoped
    with pytest.raises(DatabaseError,match='42501'):
        with scope(),customer.conn() as c:
            c.execute('SET LOCAL row_security=off')
            c.execute('SELECT * FROM public.findings')


def test_cross_org_update_has_no_effect_without_application_filter(scoped):
    operator,customer,(_,_,_,_,findings),_,scope=scoped
    with scope(),customer.conn() as c:
        assert c.execute("UPDATE public.findings SET status='resolved' WHERE id=?",(findings['bravo'],)).rowcount==0
    with operator.conn() as c:
        assert c.execute('SELECT status FROM findings WHERE id=?',(findings['bravo'],)).fetchone()[0]=='open'


def test_raw_sql_viewer_cannot_triage_and_analyst_cannot_accept_risk(scoped):
    _,customer,(_,_,_,_,findings),_,scope=scoped
    with scope(role='viewer'),customer.conn() as c:
        assert c.execute("UPDATE public.findings SET status='resolved' WHERE id=?",(findings['alpha'],)).rowcount==0
    with pytest.raises(DatabaseError,match='42501'):
        with scope(role='analyst'),customer.conn() as c:
            c.execute('INSERT INTO public.suppressions VALUES(?,?,?)',(findings['alpha'],'Fixture accepted',time.time()+60))


def test_database_role_matrix_matches_application_policy(scoped):
    _,customer,_,_,scope=scoped
    for role,allowed in PERMISSIONS.items():
        with scope(role=role),customer.conn() as c:
            for action in ('project.read','finding.read','scan.read','impact.read','export.read','finding.triage','finding.suppress','audit.read','unknown'):
                assert c.execute('SELECT vf_security.permits(?)',(action,)).fetchone()[0]==(action in allowed),(role,action)


def test_raw_sql_audit_reader_and_forger_are_restricted(scoped):
    _,customer,(members,orgs,repos,_,_),_,scope=scoped
    with scope(role='viewer'),customer.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM public.audit_events').fetchone()[0]==0
    with scope(role='auditor'),customer.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM public.audit_events').fetchone()[0]>0
    with pytest.raises(DatabaseError,match='42501'):
        with scope(),customer.conn() as c:
            c.execute('INSERT INTO public.audit_events(repo,actor,action,details,created_at) VALUES(?,?,?,?,?)',
                      (repos['bravo'],members['bravo_org_admin']['id'],'triage','{}',time.time()))


def test_expired_or_revoked_proof_and_scope_reset_fail_closed(scoped):
    operator,customer,(members,orgs,_,_,_),cfg,_=scoped
    user=members['alpha_org_admin'];sessions=AuthSessions(operator,cfg)
    token,csrf=sessions.create(user['id']);proof=digest(token)
    with customer.organization_scope(orgs['alpha'],user['id'],proof),customer.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]==1
    sessions.logout(token,csrf)
    with pytest.raises(DatabaseError,match='invalid or expired'):
        with customer.organization_scope(orgs['alpha'],user['id'],proof): pass
    with customer.conn() as c:
        c.execute("SELECT set_config('vulnforge.organization_id',?,false)",(orgs['alpha'],))
        c.execute("SELECT set_config('vulnforge.session_hash',?,false)",(proof,))
        assert c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]==0
    with pytest.raises(DatabaseError):
        with customer.organization_scope(orgs['alpha'],user['id'],'0'*64): pass


def test_invalid_nested_scope_and_mismatched_principal_are_rejected(scoped):
    _,customer,(members,orgs,_,_,_),_,scope=scoped
    with scope():
        with pytest.raises(DatabaseError,match='nested'):
            with scope(): pass
    with pytest.raises(DatabaseError):
        with customer.organization_scope(orgs['alpha'],members['alpha_org_admin']['id'],None): pass


def test_privileged_or_misgranted_runtime_configuration_is_rejected(pg_store,pg_customer):
    with pytest.raises(DatabaseError): CustomerStore(pg_store.path)
    with pg_store.conn() as c:
        role=c.execute('SELECT role_name FROM vf_security.runtime_roles WHERE mode=\'customer\'').fetchone()[0]
        c.execute(f'GRANT SELECT(token_hash) ON public.user_sessions TO {identifier(role)}')
    with pytest.raises(DatabaseError,match='column grant'): CustomerStore(pg_customer.path)


def test_missing_rls_and_inherited_role_are_rejected(pg_store,pg_customer):
    with pg_store.conn() as c: c.execute('ALTER TABLE public.findings NO FORCE ROW LEVEL SECURITY')
    with pytest.raises(DatabaseError,match='row security'): CustomerStore(pg_customer.path)
    with pg_store.conn() as c:
        c.execute('ALTER TABLE public.findings FORCE ROW LEVEL SECURITY')
        role=c.execute('SELECT role_name FROM vf_security.runtime_roles WHERE mode=\'customer\'').fetchone()[0]
        c.execute(f'ALTER ROLE {identifier(role)} INHERIT')
    with pytest.raises(DatabaseError,match='attributes'): CustomerStore(pg_customer.path)


def test_pg_customer_api_has_no_operator_fallback(pg_store):
    with pytest.raises(ValueError,match='separate restricted'):
        create_app(config(pg_store),pg_store)
    with pytest.raises(RuntimeError,match='restricted'):
        OrganizationData(pg_store,'any','any').overview()


def test_runtime_store_can_verify_without_migration_privileges(pg_store):
    assert Store(pg_store.path,migrate=False).backend=='postgresql'


@pytest.mark.parametrize('role',['org_admin','maintainer','analyst','viewer','auditor'])
def test_full_customer_api_roles_use_unprivileged_connections(pg_store,pg_customer,pg_operator,role):
    members,orgs,repos,scans,findings=seed(pg_store)
    cfg=replace(config(pg_store),customer_database_url=pg_customer.path,database_url=pg_operator.path,database_auto_migrate=False)
    app=create_app(cfg,pg_operator)
    client,headers=client_for(app,pg_operator,cfg,members['alpha_'+role]);root=ROOT+'/'+orgs['alpha']
    response=client.get(ROOT)
    assert response.status_code==200 and [r['id'] for r in response.json()['items']]==[orgs['alpha']]
    for path in ('/overview','/findings','/scans','/impacts','/advisories','/scans/'+scans['alpha']+'/sarif','/scans/'+scans['alpha']+'/sbom'):
        response=client.get(root+path)
        assert response.status_code==200,(role,path,response.text)
        assert 'bravo' not in response.text
    body={'status':'resolved','reason':'Reviewed fixture'}
    assert client.patch(root+f'/findings/{findings["alpha"]}/triage',json=body,headers=headers).status_code==(200 if role in ('org_admin','maintainer','analyst') else 403)
    assert client.get(root+'/audit/events').status_code==(200 if role in ('org_admin','auditor') else 403)


def test_rls_allows_only_scoped_system_expiry_for_read_only_user(pg_store,pg_customer,pg_operator):
    members,orgs,repos,scans,findings=seed(pg_store)
    for finding in findings.values(): pg_store.triage(finding,'suppressed','Fixture accepted',time.time()+60)
    with pg_store.conn() as c: c.execute('UPDATE suppressions SET expires_at=0')
    cfg=replace(config(pg_store),customer_database_url=pg_customer.path,database_url=pg_operator.path,database_auto_migrate=False)
    client,_=client_for(create_app(cfg,pg_operator),pg_operator,cfg,members['alpha_viewer'])
    response=client.get(ROOT+'/'+orgs['alpha']+'/overview')
    assert response.status_code==200 and response.json()['open_findings']==1
    with pg_store.conn() as c:
        assert c.execute('SELECT status FROM findings WHERE id=?',(findings['bravo'],)).fetchone()[0]=='suppressed'


def test_set_local_proof_resets_on_same_connection_after_commit_and_rollback(scoped):
    operator,customer,(members,orgs,_,_,_),cfg,_=scoped
    token,_=AuthSessions(operator,cfg).create(members['alpha_org_admin']['id'])
    with customer.conn() as c:
        for ending in ('COMMIT','ROLLBACK'):
            c.execute('BEGIN')
            c.execute("SELECT set_config('vulnforge.session_hash',?,true)",(digest(token),))
            c.execute("SELECT set_config('vulnforge.organization_id',?,true)",(orgs['alpha'],))
            assert c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]==1
            c.execute(ending)
            assert c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]==0


def test_untrusted_security_definer_or_group_membership_is_rejected(pg_store,pg_customer):
    with pg_store.conn() as c:
        c.execute("CREATE FUNCTION public.fixture_privileged() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'")
    with pytest.raises(DatabaseError,match='privileged function'): CustomerStore(pg_customer.path)
    with pg_store.conn() as c:
        c.execute('DROP FUNCTION public.fixture_privileged()')
        role=c.execute("SELECT role_name FROM vf_security.runtime_roles WHERE mode='customer'").fetchone()[0]
        c.execute(f'GRANT pg_read_all_data TO {identifier(role)}')
    with pytest.raises(DatabaseError,match='belong'): CustomerStore(pg_customer.path)


def test_customer_api_rejects_schema_owner_and_superuser_operator(pg_store,pg_customer):
    cfg=replace(config(pg_store),customer_database_url=pg_customer.path)
    with pytest.raises(DatabaseError): create_app(cfg,pg_store)


def test_operator_runtime_has_no_ddl_or_security_registry_write(pg_operator):
    from vulnforge.rls import verify_operator
    verify_operator(pg_operator)
    for sql in ('CREATE TABLE public.fixture_escape(id int)',
                "UPDATE vf_security.runtime_roles SET mode='operator'",'TRUNCATE public.findings'):
        with pytest.raises(DatabaseError):
            with pg_operator.transaction(),pg_operator.conn() as c: c.execute(sql)


def test_non_system_schema_with_pg_letters_cannot_hide_excess_grants(pg_store,pg_customer):
    with pg_store.conn() as c:
        c.execute('CREATE SCHEMA pgx_fixture')
        c.execute('CREATE TABLE pgx_fixture.fixture_secret(id int)')
        c.execute('GRANT USAGE ON SCHEMA pgx_fixture TO PUBLIC')
        c.execute('GRANT SELECT ON pgx_fixture.fixture_secret TO PUBLIC')
    with pytest.raises(DatabaseError,match='table grant'): CustomerStore(pg_customer.path)


def test_policies_work_when_functions_and_tables_have_a_non_superuser_owner(pg_store,pg_customer,pg_operator):
    import uuid
    role='vf_migration_'+uuid.uuid4().hex
    members,orgs,repos,scans,findings=seed(pg_store)
    with pg_store.conn() as c:
        original=c.execute('SELECT session_user').fetchone()[0]
        c.execute(f'CREATE ROLE {identifier(role)} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS')
    def transfer(owner):
        quoted=identifier(owner)
        with pg_store.conn() as c:
            for schema in ('public','vf_security'): c.execute(f'ALTER SCHEMA {schema} OWNER TO {quoted}')
            tables=c.execute("SELECT n.nspname,x.relname FROM pg_class x JOIN pg_namespace n ON n.oid=x.relnamespace WHERE n.nspname IN ('public','vf_security') AND x.relkind='r'").fetchall()
            for table in tables:
                c.execute(f'ALTER TABLE {identifier(table["nspname"])}.{identifier(table["relname"])} OWNER TO {quoted}')
            functions=c.execute("SELECT p.proname,pg_get_function_identity_arguments(p.oid) AS args FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='vf_security'").fetchall()
            for function in functions:
                c.execute(f'ALTER FUNCTION vf_security.{identifier(function["proname"])}({function["args"]}) OWNER TO {quoted}')
    try:
        transfer(role)
        cfg=replace(config(pg_store),customer_database_url=pg_customer.path,database_url=pg_operator.path,database_auto_migrate=False)
        client,_=client_for(create_app(cfg,pg_operator),pg_operator,cfg,members['alpha_org_admin'])
        for path in ('/findings','/scans/'+scans['alpha']+'/sarif','/advisories'):
            response=client.get(ROOT+'/'+orgs['alpha']+path)
            assert response.status_code==200 and 'bravo' not in response.text
    finally:
        transfer(original)
        with pg_store.conn() as c:
            c.execute(f'DROP OWNED BY {identifier(role)}')
            c.execute(f'DROP ROLE {identifier(role)}')
