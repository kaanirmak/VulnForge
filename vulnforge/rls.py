"""Provision and verify a separate, unprivileged PostgreSQL customer connection.

Run provisioning with the migration account, never with customer credentials.
No roles/passwords are created here; the DBA creates the login independently.
"""
import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import os
import re

from .database import DatabaseError,verify_migrations
from .db import Store,StaleJob

READ_TABLES=('organizations','memberships','repository_ownership','repositories','findings','dependency_inventory',
             'remediations','scans','scan_findings','advisory_impacts','advisories','advisory_aliases','suppressions','audit_events')
RLS_TABLES=(*READ_TABLES,'users','jobs','deliveries','runner_reports','invitations','remediation_policies','runner_policies','runner_receipts','runner_token_uses','connection_intents')
PRIVATE_TABLES=('users','jobs','deliveries','runner_reports','auth_states','user_sessions','schema_migrations','invitations','remediation_policies','runner_policies','runner_receipts','runner_token_uses','connection_intents')
SEQUENCES=('jobs_id_seq','findings_id_seq','remediations_id_seq','audit_events_id_seq','advisory_impacts_id_seq')
INSERT_COLUMNS={'suppressions':{'finding_id','reason','expires_at'},
                'audit_events':{'repo','finding_id','actor','action','details','created_at'}}
WORKER_SELECT_TABLES=('repositories','repository_ownership','remediation_policies','memberships','jobs','findings',
                      'suppressions','dependency_inventory','scans','scan_findings','advisory_impacts','advisories','advisory_aliases','remediations')
WORKER_INSERT_TABLES=('jobs','findings','dependency_inventory','scans','scan_findings','advisory_impacts','advisories','advisory_aliases','remediations')
WORKER_UPDATE_TABLES=('findings','dependency_inventory','scans','scan_findings','advisory_impacts','advisories','advisory_aliases')
WORKER_DELETE_TABLES=('dependency_inventory',)
WORKER_COLUMN_INSERTS={'audit_events':{'repo','finding_id','actor','action','details','created_at'}}
WORKER_COLUMN_UPDATES={'repositories':{'default_branch','evidence_invalidated_at','updated_at'},
                       'jobs':{'lease_until'}}


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}',value):
        raise DatabaseError('A simple lowercase PostgreSQL role name is required')
    return '"'+value+'"'


def validate_role(c,role,complete=True):
    row=c.execute('SELECT oid,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=?',(role,)).fetchone()
    if (row is None or not row['rolcanlogin'] or any(row[key] for key in
        ('rolsuper','rolinherit','rolcreaterole','rolcreatedb','rolreplication','rolbypassrls'))):
        raise DatabaseError('Customer database role has unsafe attributes')
    oid=row['oid']
    if c.execute('SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=?',(oid,)).fetchone():
        raise DatabaseError('Customer database role must not belong to another database role')
    for query in ('SELECT 1 FROM pg_catalog.pg_class WHERE relowner=?',
                  'SELECT 1 FROM pg_catalog.pg_proc WHERE proowner=?',
                  'SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner=?',
                  'SELECT 1 FROM pg_catalog.pg_database WHERE datdba=?'):
        if c.execute(query,(oid,)).fetchone(): raise DatabaseError('Customer database role must not own database objects')
    if not complete: return
    validate_no_creation(c,oid)
    # Reject unexpected table, column and sequence grants, including PUBLIC grants.
    rows=c.execute("""SELECT x.oid,n.nspname,x.relname,x.relkind FROM pg_catalog.pg_class x
        JOIN pg_catalog.pg_namespace n ON n.oid=x.relnamespace
        WHERE pg_catalog.left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
        AND x.relkind IN ('r','p','v','m','f','S')""").fetchall()
    for obj in rows:
        table=obj['relname'];public=obj['nspname']=='public'
        if obj['relkind']=='S':
            for permission in ('USAGE','SELECT','UPDATE'):
                allowed=public and table=='audit_events_id_seq' and permission=='USAGE'
                actual=c.execute('SELECT pg_catalog.has_sequence_privilege(?,?,?)',(oid,obj['oid'],permission)).fetchone()[0]
                if actual!=allowed: raise DatabaseError('Customer role has an unexpected sequence grant')
            continue
        for permission in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'):
            allowed=public and ((table in READ_TABLES and permission=='SELECT') or (table=='suppressions' and permission=='DELETE'))
            actual=c.execute('SELECT pg_catalog.has_table_privilege(?,?,?)',(oid,obj['oid'],permission)).fetchone()[0]
            if actual!=allowed: raise DatabaseError('Customer role has an unexpected table grant')
        columns=c.execute('SELECT attname,attnum FROM pg_catalog.pg_attribute WHERE attrelid=? AND attnum>0 AND NOT attisdropped',(obj['oid'],)).fetchall()
        for column in columns:
            for permission in ('SELECT','INSERT','UPDATE','REFERENCES'):
                allowed=public and ((permission=='SELECT' and table in READ_TABLES) or
                                    (permission=='INSERT' and column['attname'] in INSERT_COLUMNS.get(table,set())) or
                                    (permission=='UPDATE' and table=='findings' and column['attname']=='status'))
                actual=c.execute('SELECT pg_catalog.has_column_privilege(?,?,?,?)',(oid,obj['oid'],column['attnum'],permission)).fetchone()[0]
                if actual!=allowed: raise DatabaseError('Customer role has an unexpected column grant')
    if c.execute("""SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema','vf_security')
        AND pg_catalog.has_function_privilege(?,p.oid,'EXECUTE')""",(oid,)).fetchone():
        raise DatabaseError('Customer role can call an unreviewed privileged function')


def validate_no_creation(c,oid):
    if any(c.execute('SELECT pg_catalog.has_database_privilege(?,pg_catalog.current_database(),?)',(oid,permission)).fetchone()[0]
           for permission in ('CREATE','TEMP')):
        raise DatabaseError('Runtime role must not create database or temporary objects')
    if c.execute("SELECT 1 FROM pg_catalog.pg_namespace WHERE pg_catalog.left(nspname,3)<>'pg_' AND nspname<>'information_schema' AND pg_catalog.has_schema_privilege(?,oid,'CREATE')",(oid,)).fetchone():
        raise DatabaseError('Runtime role has an unsafe schema grant')


def provision_customer(c,role):
    quoted=identifier(role)
    validate_role(c,role,complete=False)
    existing=c.execute('SELECT mode FROM vf_security.runtime_roles WHERE role_name=?',(role,)).fetchone()
    if existing and existing['mode']!='customer': raise DatabaseError('An operator role cannot become a customer role')
    dbname=c.execute('SELECT pg_catalog.current_database()').fetchone()[0]
    dbquote='"'+dbname.replace('"','""')+'"'
    # Dedicated application database: remove PostgreSQL 14's PUBLIC temp default.
    c.execute(f'REVOKE TEMPORARY ON DATABASE {dbquote} FROM PUBLIC')
    c.execute(f'REVOKE CREATE,TEMPORARY ON DATABASE {dbquote} FROM {quoted}')
    c.execute(f'GRANT CONNECT ON DATABASE {dbquote} TO {quoted}')
    c.execute(f'REVOKE ALL ON SCHEMA public,vf_security FROM {quoted}')
    c.execute(f'GRANT USAGE ON SCHEMA public,vf_security TO {quoted}')
    for table in set(READ_TABLES)|set(PRIVATE_TABLES):
        # REVOKE table-level privileges alone does not remove old column grants.
        c.execute(f'REVOKE ALL ON public.{table} FROM {quoted}')
        columns=c.execute("SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=?::regclass AND attnum>0 AND NOT attisdropped",('public.'+table,)).fetchall()
        names=','.join('"'+row['attname']+'"' for row in columns)
        c.execute(f'REVOKE INSERT({names}),UPDATE({names}),REFERENCES({names}),SELECT({names}) ON public.{table} FROM {quoted}')
    for sequence in SEQUENCES:
        c.execute(f'REVOKE ALL ON public.{sequence} FROM PUBLIC')
        c.execute(f'REVOKE ALL ON public.{sequence} FROM {quoted}')
    c.execute(f'GRANT SELECT ON '+','.join('public.'+table for table in READ_TABLES)+f' TO {quoted}')
    c.execute(f'GRANT UPDATE(status) ON public.findings TO {quoted}')
    c.execute(f'GRANT DELETE ON public.suppressions TO {quoted}')
    for table,columns in INSERT_COLUMNS.items():
        c.execute(f'GRANT INSERT('+','.join(sorted(columns))+f') ON public.{table} TO {quoted}')
    c.execute(f'GRANT USAGE ON SEQUENCE public.audit_events_id_seq TO {quoted}')
    c.execute(f'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vf_security TO {quoted}')
    c.execute("INSERT INTO vf_security.runtime_roles VALUES(?,'customer') ON CONFLICT(role_name) DO NOTHING",(role,))
    validate_role(c,role)


def provision_operator(c,role):
    quoted=identifier(role)
    validate_role(c,role,complete=False)
    existing=c.execute('SELECT mode FROM vf_security.runtime_roles WHERE role_name=?',(role,)).fetchone()
    if existing and existing['mode']!='operator': raise DatabaseError('Customer role cannot become an operator')
    dbname=c.execute('SELECT pg_catalog.current_database()').fetchone()[0]
    dbquote='"'+dbname.replace('"','""')+'"'
    c.execute(f'REVOKE TEMPORARY ON DATABASE {dbquote} FROM PUBLIC')
    c.execute(f'REVOKE CREATE,TEMPORARY ON DATABASE {dbquote} FROM {quoted}')
    c.execute(f'REVOKE ALL ON SCHEMA public,vf_security FROM {quoted}')
    c.execute(f'GRANT CONNECT ON DATABASE {dbquote} TO {quoted}')
    c.execute(f'GRANT USAGE ON SCHEMA public,vf_security TO {quoted}')
    tables=(set(READ_TABLES)|set(PRIVATE_TABLES))-{'schema_migrations'}
    c.execute('GRANT SELECT,INSERT,UPDATE,DELETE ON '+','.join('public.'+name for name in sorted(tables))+f' TO {quoted}')
    c.execute(f'GRANT SELECT ON public.schema_migrations TO {quoted}')
    c.execute('GRANT USAGE ON SEQUENCE '+','.join('public.'+name for name in SEQUENCES)+f' TO {quoted}')
    c.execute(f'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vf_security TO {quoted}')
    c.execute("INSERT INTO vf_security.runtime_roles VALUES(?,'operator') ON CONFLICT(role_name) DO NOTHING",(role,))
    oid=c.execute('SELECT oid FROM pg_catalog.pg_roles WHERE rolname=?',(role,)).fetchone()[0]
    validate_no_creation(c,oid)
    validate_operator_grants(c,oid)


def verify_operator(store):
    with store.conn() as c:
        row=c.execute('SELECT current_user AS current,session_user AS session').fetchone()
        if row['current']!=row['session']: raise DatabaseError('Runtime connection must use its own login')
        validate_role(c,row['session'],complete=False)
        oid=c.execute('SELECT oid FROM pg_catalog.pg_roles WHERE rolname=?',(row['session'],)).fetchone()[0]
        validate_no_creation(c,oid)
        validate_operator_grants(c,oid)
        if not c.execute('SELECT vf_security.is_internal() AND NOT vf_security.is_customer() AND NOT vf_security.is_worker()').fetchone()[0]:
            raise DatabaseError('Operator runtime role must be separately registered')


def validate_worker(c,role,complete=True):
    validate_role(c,role,complete=False)
    oid=c.execute('SELECT oid FROM pg_catalog.pg_roles WHERE rolname=?',(role,)).fetchone()[0]
    if not complete: return
    validate_no_creation(c,oid)
    rows=c.execute("""SELECT x.oid,n.nspname,x.relname,x.relkind FROM pg_catalog.pg_class x
        JOIN pg_catalog.pg_namespace n ON n.oid=x.relnamespace
        WHERE pg_catalog.left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
        AND x.relkind IN ('r','p','v','m','f','S')""").fetchall()
    for obj in rows:
        table=obj['relname'];public=obj['nspname']=='public'
        if obj['relkind']=='S':
            for permission in ('USAGE','SELECT','UPDATE'):
                allowed=public and table in SEQUENCES and permission=='USAGE'
                actual=c.execute('SELECT pg_catalog.has_sequence_privilege(?,?,?)',(oid,obj['oid'],permission)).fetchone()[0]
                if actual!=allowed: raise DatabaseError('Worker role has an unexpected sequence grant')
            continue
        for permission in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'):
            allowed=public and ((permission=='SELECT' and table in WORKER_SELECT_TABLES) or
                                (permission=='INSERT' and table in WORKER_INSERT_TABLES) or
                                (permission=='UPDATE' and table in WORKER_UPDATE_TABLES) or
                                (permission=='DELETE' and table in WORKER_DELETE_TABLES))
            actual=c.execute('SELECT pg_catalog.has_table_privilege(?,?,?)',(oid,obj['oid'],permission)).fetchone()[0]
            if actual!=allowed: raise DatabaseError('Worker role has an unexpected table grant')
        columns=c.execute('SELECT attname,attnum FROM pg_catalog.pg_attribute WHERE attrelid=? AND attnum>0 AND NOT attisdropped',(obj['oid'],)).fetchall()
        for column in columns:
            for permission in ('SELECT','INSERT','UPDATE','REFERENCES'):
                allowed=public and ((permission=='SELECT' and table in WORKER_SELECT_TABLES) or
                                    (permission=='INSERT' and (table in WORKER_INSERT_TABLES or column['attname'] in WORKER_COLUMN_INSERTS.get(table,set()))) or
                                    (permission=='UPDATE' and (table in WORKER_UPDATE_TABLES or column['attname'] in WORKER_COLUMN_UPDATES.get(table,set()))))
                actual=c.execute('SELECT pg_catalog.has_column_privilege(?,?,?,?)',(oid,obj['oid'],column['attnum'],permission)).fetchone()[0]
                if actual!=allowed: raise DatabaseError('Worker role has an unexpected column grant')
    if c.execute("""SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema','vf_security')
        AND pg_catalog.has_function_privilege(?,p.oid,'EXECUTE')""",(oid,)).fetchone():
        raise DatabaseError('Worker role can call an unreviewed privileged function')


def provision_worker(c,role):
    quoted=identifier(role)
    validate_worker(c,role,complete=False)
    existing=c.execute('SELECT mode FROM vf_security.runtime_roles WHERE role_name=?',(role,)).fetchone()
    if existing and existing['mode']!='worker': raise DatabaseError('Runtime role mode cannot be converted')
    dbname=c.execute('SELECT pg_catalog.current_database()').fetchone()[0]
    dbquote='"'+dbname.replace('"','""')+'"'
    c.execute(f'REVOKE TEMPORARY ON DATABASE {dbquote} FROM PUBLIC')
    c.execute(f'REVOKE CREATE,TEMPORARY ON DATABASE {dbquote} FROM {quoted}')
    c.execute(f'REVOKE ALL ON SCHEMA public,vf_security FROM {quoted}')
    c.execute(f'GRANT CONNECT ON DATABASE {dbquote} TO {quoted}')
    c.execute(f'GRANT USAGE ON SCHEMA public,vf_security TO {quoted}')
    for table in set(READ_TABLES)|set(PRIVATE_TABLES):
        c.execute(f'REVOKE ALL ON public.{table} FROM {quoted}')
        columns=c.execute("SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=?::regclass AND attnum>0 AND NOT attisdropped",('public.'+table,)).fetchall()
        names=','.join('"'+row['attname']+'"' for row in columns)
        c.execute(f'REVOKE INSERT({names}),UPDATE({names}),REFERENCES({names}),SELECT({names}) ON public.{table} FROM {quoted}')
    for sequence in SEQUENCES:
        c.execute(f'REVOKE ALL ON public.{sequence} FROM PUBLIC')
        c.execute(f'REVOKE ALL ON public.{sequence} FROM {quoted}')
    c.execute('GRANT SELECT ON '+','.join('public.'+table for table in WORKER_SELECT_TABLES)+f' TO {quoted}')
    c.execute('GRANT INSERT ON '+','.join('public.'+table for table in WORKER_INSERT_TABLES)+f' TO {quoted}')
    c.execute('GRANT UPDATE ON '+','.join('public.'+table for table in WORKER_UPDATE_TABLES)+f' TO {quoted}')
    c.execute('GRANT DELETE ON '+','.join('public.'+table for table in WORKER_DELETE_TABLES)+f' TO {quoted}')
    for table,columns in WORKER_COLUMN_INSERTS.items():
        c.execute(f'GRANT INSERT('+','.join(sorted(columns))+f') ON public.{table} TO {quoted}')
    for table,columns in WORKER_COLUMN_UPDATES.items():
        c.execute(f'GRANT UPDATE('+','.join(sorted(columns))+f') ON public.{table} TO {quoted}')
    c.execute('GRANT USAGE ON SEQUENCE '+','.join('public.'+name for name in SEQUENCES)+f' TO {quoted}')
    c.execute(f'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vf_security TO {quoted}')
    c.execute("INSERT INTO vf_security.runtime_roles VALUES(?,'worker') ON CONFLICT(role_name) DO NOTHING",(role,))
    validate_worker(c,role)


def validate_operator_grants(c,oid):
    for table in set(READ_TABLES)|set(PRIVATE_TABLES):
        for permission in ('TRUNCATE','REFERENCES','TRIGGER'):
            if c.execute('SELECT pg_catalog.has_table_privilege(?,?,?)',(oid,'public.'+table,permission)).fetchone()[0]:
                raise DatabaseError('Operator runtime role has unnecessary object privileges')
    for table in ('vf_security.runtime_roles','public.schema_migrations'):
        for permission in ('INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES'):
            if c.execute('SELECT pg_catalog.has_table_privilege(?,?,?)',(oid,table,permission)).fetchone()[0]:
                raise DatabaseError('Runtime role must not modify security or migration metadata')
        for permission in ('INSERT','UPDATE','REFERENCES'):
            if c.execute('SELECT pg_catalog.has_any_column_privilege(?,?,?)',(oid,table,permission)).fetchone()[0]:
                raise DatabaseError('Runtime role must not modify security or migration columns')
    if c.execute("""SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema','vf_security')
        AND pg_catalog.has_function_privilege(?,p.oid,'EXECUTE')""",(oid,)).fetchone():
        raise DatabaseError('Runtime role can call an unreviewed privileged function')


class CustomerStore(Store):
    def __init__(self,path):
        self._job=ContextVar('customer_store_job',default=None)
        if not path.startswith(('postgresql://','postgres://')): raise DatabaseError('Customer RLS requires PostgreSQL')
        self.path=path;self.backend='postgresql';self._active=ContextVar('customer_transaction',default=None)
        with self.conn() as c:
            row=c.execute('SELECT current_user AS current,session_user AS session').fetchone()
            if row['current']!=row['session']: raise DatabaseError('Customer connection must use its own login')
            validate_role(c,row['session'])
            if not c.execute('SELECT vf_security.is_customer() AND NOT vf_security.is_internal() AND NOT vf_security.is_worker()').fetchone()[0]:
                raise DatabaseError('Customer database role is not registered')
            if c.execute("SELECT pg_catalog.current_setting('row_security')").fetchone()[0]!='on':
                raise DatabaseError('Customer row security must be enabled')
            rows=c.execute("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace").fetchall()
            enabled={row['relname'] for row in rows if row['relrowsecurity'] and row['relforcerowsecurity']}
            if not set(RLS_TABLES)<=enabled: raise DatabaseError('Required row security policy is missing')
            verify_migrations(c,'postgresql',security=True)

    @contextmanager
    def organization_scope(self,organization_id,user_id,session_hash):
        if self._active.get() is not None: raise DatabaseError('Customer scope cannot be nested or changed')
        if not isinstance(session_hash,str) or not re.fullmatch(r'[a-f0-9]{64}',session_hash):
            raise DatabaseError('Verified customer session proof is required')
        with self.transaction(),self.conn() as c:
            c.execute("SELECT pg_catalog.set_config('vulnforge.session_hash',?,true)",(session_hash,))
            c.execute("SELECT pg_catalog.set_config('vulnforge.organization_id',?,true)",(organization_id,))
            actor=c.execute('SELECT vf_security.actor_id()').fetchone()[0]
            if actor is None or actor!=user_id: raise DatabaseError('Customer session is invalid or expired')
            yield


class WorkerStore(Store):
    def __init__(self,path):
        self._job=ContextVar('worker_store_job',default=None)
        if not path.startswith(('postgresql://','postgres://')): raise DatabaseError('Worker RLS requires PostgreSQL')
        self.path=path;self.backend='postgresql';self._active=ContextVar('worker_transaction',default=None)
        with self.conn() as c:
            row=c.execute('SELECT current_user AS current,session_user AS session').fetchone()
            if row['current']!=row['session']: raise DatabaseError('Worker connection must use its own login')
            validate_worker(c,row['session'])
            if not c.execute('SELECT vf_security.is_worker() AND NOT vf_security.is_internal() AND NOT vf_security.is_customer()').fetchone()[0]:
                raise DatabaseError('Worker database role is not registered')
            if c.execute("SELECT pg_catalog.current_setting('row_security')").fetchone()[0]!='on':
                raise DatabaseError('Worker row security must be enabled')
            rows=c.execute("SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace").fetchall()
            enabled={row['relname'] for row in rows if row['relrowsecurity'] and row['relforcerowsecurity']}
            if not set(RLS_TABLES)<=enabled: raise DatabaseError('Required row security policy is missing')
            verify_migrations(c,'postgresql',security=True)

    def _apply_job_context(self,c,job):
        if (type(job.get('id')) is not int or job['id']<1 or
            not isinstance(job.get('claim_token'),str) or not re.fullmatch(r'[a-f0-9]{32}',job['claim_token']) or
            not isinstance(job.get('connection_id'),str) or not job['connection_id']):
            raise StaleJob('Job authorization expired')
        mode=job.get('catalog_scope_mode','public')
        if mode not in ('public','private_osv'):
            raise StaleJob('Job authorization expired')
        c.execute("SELECT pg_catalog.set_config('vulnforge.job_id',?,true)",(str(job['id']),))
        c.execute("SELECT pg_catalog.set_config('vulnforge.claim_token',?,true)",(job['claim_token'],))
        c.execute("SELECT pg_catalog.set_config('vulnforge.connection_id',?,true)",(job['connection_id'],))
        c.execute("SELECT pg_catalog.set_config('vulnforge.organization_id',?,true)",(job.get('organization_id') or '',))
        c.execute("SELECT pg_catalog.set_config('vulnforge.catalog_scope',?,true)",(mode,))


def main():
    parser=argparse.ArgumentParser(description='Provision an existing runtime DB login; dedicated database only')
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--customer-role')
    group.add_argument('--operator-role')
    group.add_argument('--worker-role')
    args=parser.parse_args()
    try:
        url=os.getenv('DATABASE_URL','')
        if not url.startswith(('postgresql://','postgres://')): raise DatabaseError('PostgreSQL migration connection required')
        store=Store(url)
        with store.transaction(),store.conn() as c:
            if args.customer_role: provision_customer(c,args.customer_role)
            elif args.operator_role: provision_operator(c,args.operator_role)
            else: provision_worker(c,args.worker_role)
    except (DatabaseError,ValueError):
        parser.exit(2,'Runtime role provisioning failed; credentials and server details are not printed. Check the RLS runbook.\n')
    print('Runtime database role provisioned; no customer access was enabled.')


if __name__=='__main__': main()
