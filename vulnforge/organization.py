"""Organization-scoped customer data access; never use the operator's global lists.

Principals must come from a verified server-side session. Membership is read from
the DB for each operation. App-level scoping does not replace RLS/worker isolation.
"""
from contextlib import contextmanager
import json
import time

from .identity import Identities
from .permissions import permits
from .privacy import safe_metadata


class ResourceNotFound(LookupError):
    pass


class RoleDenied(PermissionError):
    pass


# All identifiers in generated SQL come exclusively from this static map.
TABLES={
    'repositories':('full_name',()),
    'findings':('repo',('details',)),
    'dependency_inventory':('repo',()),
    'remediations':('repo',()),
    'scans':('repo',('coverage','dependencies')),
    'advisory_impacts':('repo',('evidence','recommendations')),
}


class OrganizationData:
    def __init__(self,store,organization_id,user_id,session_hash=None):
        self.store=store;self.organization_id=organization_id;self.user_id=user_id
        self.session_hash=session_hash

    @contextmanager
    def access(self,permission):
        from .rls import CustomerStore
        if self.store.backend=='postgresql' and not isinstance(self.store,CustomerStore):
            raise RuntimeError('Customer PostgreSQL access requires the restricted database connection')
        scope=(self.store.organization_scope(self.organization_id,self.user_id,self.session_hash)
               if isinstance(self.store,CustomerStore) else self.store.transaction())
        with scope,self.store.conn() as c:
            # Serialize role/ownership updates with the complete data operation.
            Identities(self.store)._lock_organization(c,self.organization_id)
            row=c.execute('SELECT role FROM memberships WHERE organization_id=? AND user_id=?',
                          (self.organization_id,self.user_id)).fetchone()
            if row is None: raise ResourceNotFound('Organization not found')
            if not permits(row['role'],permission): raise RoleDenied('Organization role does not allow this action')
            yield c

    def query(self,table,columns='x.*'):
        repo_column=TABLES[table][0]
        sql=f'''SELECT {columns} FROM {table} x JOIN repository_ownership o ON o.repo=x.{repo_column}
            WHERE o.organization_id=? AND EXISTS (SELECT 1 FROM memberships m
                WHERE m.organization_id=o.organization_id AND m.user_id=?)'''
        return sql,[self.organization_id,self.user_id]

    @staticmethod
    def decode(rows,fields):
        items=[dict(row) for row in rows]
        for item in items:
            for key in fields: item[key]=json.loads(item[key])
        return items

    def _repo(self,c,repo):
        if repo is None: return
        sql,args=self.query('repositories','x.full_name')
        if c.execute(sql+' AND x.full_name=?',args+[repo]).fetchone() is None:
            raise ResourceNotFound('Repository not found')

    def _expire_suppressions(self,c):
        sql,args=self.query('findings','x.id,x.repo')
        rows=c.execute(sql+''' AND x.status='suppressed' AND EXISTS (SELECT 1 FROM suppressions s
            WHERE s.finding_id=x.id AND s.expires_at<=?)''',args+[time.time()]).fetchall()
        for row in rows:
            c.execute("UPDATE findings SET status='open' WHERE id=? AND repo=?",(row['id'],row['repo']))
            self.store.audit_event(row['repo'],row['id'],'system','suppression_expired',
                                   {'organization_id':self.organization_id})

    def overview(self):
        with self.access('project.read') as c:
            self._expire_suppressions(c)
            result={}
            for name,table,condition in (
                ('repositories','repositories',''),('open_findings','findings'," AND x.status='open'"),
                ('remediations','remediations',''),('affected_projects','advisory_impacts'," AND x.state='affected'")):
                column='COUNT(DISTINCT x.repo)' if table=='advisory_impacts' else 'COUNT(*)'
                sql,args=self.query(table,column)
                result[name]=c.execute(sql+condition,args).fetchone()[0]
            return result

    def rows(self,table,repo=None,limit=50,cursor=0,status=None,severity=None):
        permission={'findings':'finding.read','scans':'scan.read'}.get(table,'project.read')
        if table not in TABLES or table=='advisory_impacts': raise ValueError('Unsupported customer table')
        if type(limit) is not int or not 1<=limit<=100: raise ValueError('Invalid page limit')
        if type(cursor) is not int or cursor<0: raise ValueError('Invalid cursor')
        with self.access(permission) as c:
            self._repo(c,repo)
            if table=='findings': self._expire_suppressions(c)
            columns=('x.full_name,x.default_branch,x.last_sha,x.updated_at' if table=='repositories' else 'x.*')
            sql,args=self.query(table,columns)
            if repo is not None: sql+=f' AND x.{TABLES[table][0]}=?';args.append(repo)
            if table in ('findings','remediations'):
                sql+=' AND x.id>?';args.append(cursor)
            elif cursor: raise ValueError('Cursor is unsupported for this list')
            if table=='findings':
                for column,value in (('status',status),('severity',severity)):
                    if value is not None: sql+=' AND x.'+column+'=?';args.append(value)
            order={'repositories':'x.full_name','findings':'x.id','remediations':'x.id',
                   'scans':'x.started_at DESC,x.id','dependency_inventory':'x.file_path,x.ecosystem,x.normalized_name,x.version'}[table]
            rows=c.execute(sql+' ORDER BY '+order+' LIMIT ?',args+[limit+1]).fetchall()
            items=self.decode(rows[:limit],TABLES[table][1])
            # Non-numeric lists are explicitly bounded, never advertised as full.
            return {'items':items,'truncated':len(rows)>limit,
                    'next_cursor':items[-1]['id'] if len(rows)>limit and table in ('findings','remediations') else None}

    def scan(self,scan_id,export=False):
        with self.access('export.read' if export else 'scan.read') as c:
            sql,args=self.query('scans')
            row=c.execute(sql+' AND x.id=?',args+[scan_id]).fetchone()
            if row is None: raise ResourceNotFound('Scan not found')
            scan=self.decode([row],('coverage','dependencies'))[0]
            scan['findings']=[json.loads(row['data']) for row in c.execute(
                'SELECT data FROM scan_findings WHERE scan_id=? ORDER BY finding_key',(scan_id,))]
            if export:
                self.store.audit_event(scan['repo'],None,self.user_id,'scan_export_requested',
                    {'organization_id':self.organization_id,'scan_id':scan_id})
            return scan

    def impacts(self,repo=None,advisory_id=None,state=None,cursor=0,limit=50):
        with self.access('impact.read') as c:
            self._repo(c,repo)
            sql,args=self.query('advisory_impacts')
            sql+=' AND x.id>?';args.append(cursor)
            for column,value in (('repo',repo),('state',state)):
                if value is not None: sql+=' AND x.'+column+'=?';args.append(value)
            if advisory_id is not None:
                sql+=' AND EXISTS (SELECT 1 FROM advisory_aliases a WHERE a.advisory_id=x.advisory_id AND a.alias=?)'
                args.append(advisory_id)
            rows=c.execute(sql+' ORDER BY x.id LIMIT ?',args+[limit+1]).fetchall()
            items=self.decode(rows[:limit],('evidence','recommendations'))
            return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None}

    def advisories(self,limit=50):
        with self.access('impact.read') as c:
            # Count only this org's projects, never reuse global advisory counters.
            rows=c.execute('''SELECT a.id,a.aliases,a.summary,a.source,a.withdrawn,a.first_seen_at,a.updated_at,
                SUM(CASE WHEN i.state='affected' THEN 1 ELSE 0 END) AS affected_projects,
                SUM(CASE WHEN i.state='under_investigation' THEN 1 ELSE 0 END) AS pending_projects
                FROM advisories a JOIN advisory_impacts i ON i.advisory_id=a.id
                JOIN repository_ownership o ON o.repo=i.repo WHERE o.organization_id=?
                AND EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=o.organization_id AND m.user_id=?)
                GROUP BY a.id,a.aliases,a.summary,a.source,a.withdrawn,a.first_seen_at,a.updated_at
                ORDER BY a.updated_at DESC,a.id LIMIT ?''',(self.organization_id,self.user_id,limit)).fetchall()
            return self.decode(rows,('aliases',))

    def triage(self,finding_id,status,reason,expires_at=None):
        if status not in ('open','resolved','suppressed'): raise ValueError('Invalid triage state')
        if not isinstance(reason,str) or not 5<=len(reason)<=2000: raise ValueError('Triage reason required')
        safe_metadata(reason)
        if status=='suppressed' and (type(expires_at) not in (int,float) or not time.time()<expires_at<=time.time()+366*86400):
            raise ValueError('Suppression expiry must be within the next year')
        if status!='suppressed' and expires_at is not None: raise ValueError('Expiry applies only to suppression')
        with self.access('finding.suppress' if status=='suppressed' else 'finding.triage') as c:
            sql,args=self.query('findings','x.id,x.repo')
            row=c.execute(sql+' AND x.id=?',args+[finding_id]).fetchone()
            if row is None: raise ResourceNotFound('Finding not found')
            return self.store.triage(finding_id,status,reason,expires_at,
                                    actor=self.user_id,organization_id=self.organization_id)

    def audit(self,repo=None,cursor=0,limit=50):
        with self.access('audit.read') as c:
            self._repo(c,repo)
            sql='''SELECT x.* FROM audit_events x WHERE x.id>? AND EXISTS (
                SELECT 1 FROM memberships m WHERE m.organization_id=? AND m.user_id=?)
                AND (x.repo=? OR EXISTS (SELECT 1 FROM repository_ownership o
                    WHERE o.repo=x.repo AND o.organization_id=?))'''
            args=[cursor,self.organization_id,self.user_id,'organization:'+self.organization_id,self.organization_id]
            if repo is not None: sql+=' AND x.repo=?';args.append(repo)
            rows=c.execute(sql+' ORDER BY x.id LIMIT ?',args+[limit+1]).fetchall()
            items=self.decode(rows[:limit],('details',))
            return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None}
