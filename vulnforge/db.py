"""SQLite/PostgreSQL durable queue, repo inventory and findings store."""
import json
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from importlib.resources import files


from .database import connect_database, migrate_database, verify_migrations

SCHEMA = files('vulnforge').joinpath('migrations/001_initial.sqlite.sql').read_text(encoding='utf-8')


class StaleJob(PermissionError):
    """The connection or exclusive lease that authorized a job no longer exists."""


class Store:
    def __init__(self, path: str, *, migrate=True):
        self.path = path
        self._active = ContextVar('store_transaction', default=None)
        self._job = ContextVar('store_job', default=None)
        self.backend='postgresql' if path.startswith(('postgresql://','postgres://')) else 'sqlite'
        if self.backend=='sqlite': Path(path).parent.mkdir(parents=True,exist_ok=True)
        with self.conn() as c:
            if migrate: migrate_database(c,self.backend)
            else: verify_migrations(c,self.backend)

    @contextmanager
    def conn(self):
        if self._active.get() is not None:
            yield self._active.get()
            return
        c = connect_database(self.path,self.backend)
        try:
            # Never keep this transaction open across a provider await. Each
            # local operation locks and revalidates the live connection/lease.
            if self._job.get() is not None:
                self.begin(c)
                self._check_job(c,self._job.get(),lock=True)
                token=self._active.set(c)
                try:
                    yield c
                    c.execute('COMMIT')
                except BaseException:
                    c.execute('ROLLBACK')
                    raise
                finally:
                    self._active.reset(token)
                return
            yield c
        finally:
            c.close()

    def begin(self,c):
        c.execute('BEGIN' if self.backend=='postgresql' else 'BEGIN IMMEDIATE')

    def _check_job(self,c,job,*,lock=False):
        row=c.execute('SELECT * FROM repositories WHERE full_name=?'+
                      (' FOR UPDATE' if lock and self.backend=='postgresql' else ''),
                      (job['repo'],)).fetchone()
        owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',
                        (job['repo'],)).fetchone()
        lease=c.execute('SELECT * FROM jobs WHERE id=?'+
                        (' FOR UPDATE' if lock and self.backend=='postgresql' else ''),
                        (job['id'],)).fetchone()
        if (row is None or lease is None or not job.get('claim_token') or
            row['connection_id']!=job.get('connection_id') or
            row['installation_id']!=job.get('installation_id') or
            (owner['organization_id'] if owner else None)!=job.get('organization_id') or
            lease['claim_token']!=job['claim_token'] or lease['state']!='running' or
            lease['connection_id']!=job.get('connection_id') or lease['repo']!=job['repo'] or
            lease['organization_id']!=job.get('organization_id') or
            lease['installation_id']!=job.get('installation_id') or
            (lease['lease_until'] or 0)<=time.time()):
            raise StaleJob('Job authorization expired')

    def check_job(self,job):
        with self.transaction(), self.conn() as c:
            self._check_job(c,job,lock=True)

    @contextmanager
    def job_scope(self,job):
        if self._job.get() is not None or self._active.get() is not None:
            raise RuntimeError('Job scopes cannot be nested')
        snapshot=dict(job)
        self.check_job(snapshot)
        token=self._job.set(snapshot)
        try:
            yield
        finally:
            self._job.reset(token)

    @contextmanager
    def transaction(self):
        """Atomically accept a delivery together with every resulting mutation."""
        if self._active.get() is not None:
            yield
            return
        with self.conn() as c:
            # conn() already starts a fenced transaction inside a job scope.
            if self._active.get() is not None:
                yield
                return
            self.begin(c)
            token = self._active.set(c)
            try:
                yield
                c.execute('COMMIT')
            except BaseException:
                c.execute('ROLLBACK')
                raise
            finally:
                self._active.reset(token)

    def upsert_repo(self, name: str, installation_id: int, default_branch: str):
        now = time.time()
        with self.transaction(), self.conn() as c:
            # Materialize before locking so concurrent first registrations also
            # serialize; an upsert must not overwrite an unseen installation.
            c.execute('''INSERT INTO repositories(full_name,installation_id,default_branch,updated_at,connection_id)
                VALUES(?,?,?,?,?) ON CONFLICT(full_name) DO NOTHING''',
                (name,installation_id,default_branch,now,uuid.uuid4().hex))
            previous=c.execute('SELECT installation_id FROM repositories WHERE full_name=?'+
                               (' FOR UPDATE' if self.backend=='postgresql' else ''),(name,)).fetchone()
            if previous and previous['installation_id']!=installation_id:
                # An installation change is a new integration boundary, not
                # proof that the former organization owns the new connection.
                self.remove_repo(name)
            c.execute("""INSERT INTO repositories(full_name,installation_id,default_branch,updated_at,connection_id)
                VALUES(?,?,?,?,?) ON CONFLICT(full_name) DO UPDATE SET
                connection_id=CASE WHEN repositories.installation_id=excluded.installation_id
                    THEN repositories.connection_id ELSE excluded.connection_id END,
                installation_id=excluded.installation_id,
                default_branch=excluded.default_branch,updated_at=excluded.updated_at""",
                      (name, installation_id, default_branch, now,uuid.uuid4().hex))

    def repository(self,repo):
        with self.conn() as c:
            row=c.execute('SELECT * FROM repositories WHERE full_name=?',(repo,)).fetchone()
            return dict(row) if row else None

    def set_scan_commit(self,scan_id,sha):
        with self.conn() as c:
            c.execute('UPDATE scans SET commit_sha=? WHERE id=?',(sha,scan_id))

    def remove_repo(self, name: str):
        # Clean security metadata when a GitHub App is uninstalled from a repo.
        with self.conn() as c:
            own = self._active.get() is None
            if own: self.begin(c)
            c.execute('DELETE FROM suppressions WHERE finding_id IN (SELECT id FROM findings WHERE repo=?)', (name,))
            c.execute('DELETE FROM scan_findings WHERE scan_id IN (SELECT id FROM scans WHERE repo=?)', (name,))
            for table in ('repositories','dependency_inventory'):
                c.execute(f"DELETE FROM {table} WHERE {'full_name' if table=='repositories' else 'repo'}=?",(name,))
            for table in ('jobs','findings','remediations','scans','audit_events','advisory_impacts','runner_reports'):
                c.execute(f"DELETE FROM {table} WHERE repo=?",(name,))
            if own: c.execute('COMMIT')

    def remove_installation(self, installation_id):
        with self.conn() as c:
            names = c.execute('SELECT full_name FROM repositories WHERE installation_id=?', (installation_id,)).fetchall()
        for row in names:
            self.remove_repo(row['full_name'])

    def add_delivery(self, delivery_id: str) -> bool:
        with self.conn() as c:
            result = c.execute("INSERT INTO deliveries VALUES(?,?) ON CONFLICT DO NOTHING", (delivery_id, time.time()))
            return result.rowcount == 1

    def quarantine_runner_report(self, report):
        import hashlib
        # Accept the validated type, never a caller-supplied raw dictionary.
        from .runner_report import RunnerReport
        if not isinstance(report,RunnerReport): raise TypeError('Validated runner report required')
        report=RunnerReport.model_validate(report)
        encoded=json.dumps(report.model_dump(),sort_keys=True,separators=(',',':'))
        id_=hashlib.sha256(encoded.encode()).hexdigest()
        with self.transaction(), self.conn() as c:
            if c.execute('SELECT 1 FROM repositories WHERE full_name=?',(report.repo,)).fetchone() is None:
                raise LookupError('Repository not registered')
            result=c.execute('INSERT INTO runner_reports(id,repo,commit_sha,report,received_at) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING',
                             (id_,report.repo,report.commit_sha,encoded,time.time()))
            if result.rowcount:
                self.audit_event(report.repo,None,'operator','runner_report_quarantined',
                                 {'report_id':id_,'commit_sha':report.commit_sha})
        return {'report_id':id_,'duplicate':result.rowcount==0,'trust_state':'quarantined'}

    def enqueue(self, kind: str, repo: str, payload: dict, key: str, delay: float = 0) -> bool:
        now = time.time()
        with self.transaction(), self.conn() as c:
            if self._job.get() is not None and self._job.get()['repo']!=repo:
                raise PermissionError('Child job must retain the repository scope')
            row=c.execute('SELECT * FROM repositories WHERE full_name=?'+
                          (' FOR UPDATE' if self.backend=='postgresql' else ''),(repo,)).fetchone()
            if row is None: raise LookupError('Repository not registered')
            owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(repo,)).fetchone()
            result = c.execute("""INSERT INTO jobs
            (unique_key,kind,repo,payload,available_at,created_at,connection_id,organization_id,installation_id)
            VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (row['connection_id']+':'+key,kind,repo,json.dumps(payload),now+delay,now,
             row['connection_id'],owner['organization_id'] if owner else None,row['installation_id']))
            return result.rowcount == 1

    def claim(self):
        now = time.time()
        with self.conn() as c:
            self.begin(c)
            row = c.execute("""SELECT * FROM jobs WHERE
                (state='pending' AND available_at<=?) OR
                (state='running' AND lease_until<?)
                ORDER BY id LIMIT 1"""+ (" FOR UPDATE SKIP LOCKED" if self.backend=="postgresql" else ""), (now, now)).fetchone()
            if row:
                token=uuid.uuid4().hex
                c.execute("UPDATE jobs SET state='running', lease_until=?, attempts=attempts+1,claim_token=? WHERE id=?",
                          (now+300,token,row['id']))
                row=dict(row)
                row.update(state='running',lease_until=now+300,attempts=row['attempts']+1,claim_token=token)
            c.execute("COMMIT")
            return dict(row) if row else None

    def finish(self, job: dict, error: str | None = None):
        with self.transaction(), self.conn() as c:
            self._check_job(c,job,lock=True)
            job_id=job['id']
            if error:
                attempts = c.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
                state = "failed" if attempts >= 4 else "pending"
                c.execute("UPDATE jobs SET state=?, last_error=?, available_at=?, lease_until=NULL,finished_at=?,claim_token=NULL WHERE id=?",
                          (state, error[:400], time.time()+min(300, 15*(2**attempts)),
                           time.time() if state=='failed' else None,job_id))
            else:
                c.execute("UPDATE jobs SET state='done',finished_at=?,lease_until=NULL,claim_token=NULL WHERE id=?",
                          (time.time(),job_id))

    def discard_job(self,job):
        """Only cancel this claim; a reclaimed lease belongs to another worker."""
        with self.conn() as c:
            c.execute("""UPDATE jobs SET state='cancelled',lease_until=NULL,claim_token=NULL,
                last_error='Job authorization expired',finished_at=?
                WHERE id=? AND claim_token=? AND state='running'""",
                (time.time(),job['id'],job['claim_token']))

    def renew_job(self,job):
        with self.transaction(),self.conn() as c:
            self._check_job(c,job,lock=True)
            c.execute('UPDATE jobs SET lease_until=? WHERE id=? AND claim_token=?',
                      (time.time()+300,job['id'],job['claim_token']))

    def dead_letters(self,limit=50,cursor=0):
        with self.conn() as c:
            return [dict(row) for row in c.execute('''SELECT id,kind,repo,organization_id,attempts,
                last_error,created_at,finished_at FROM jobs WHERE state='failed' AND id>?
                ORDER BY id LIMIT ?''',(cursor,max(1,min(100,limit))))]

    def retry_dead_letter(self,job_id):
        with self.transaction(),self.conn() as c:
            job=c.execute('SELECT * FROM jobs WHERE id=?',(job_id,)).fetchone()
            if job is None: return None
            # Same lock order as guarded worker writes: repository then job.
            repo=c.execute('SELECT * FROM repositories WHERE full_name=?'+
                           (' FOR UPDATE' if self.backend=='postgresql' else ''),(job['repo'],)).fetchone()
            job=c.execute('SELECT * FROM jobs WHERE id=?'+
                          (' FOR UPDATE' if self.backend=='postgresql' else ''),(job_id,)).fetchone()
            if job is None: return None
            if job['state']!='failed': raise ValueError('Only failed jobs can be retried')
            owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(job['repo'],)).fetchone()
            if (repo is None or repo['connection_id']!=job['connection_id'] or
                repo['installation_id']!=job['installation_id'] or
                (owner['organization_id'] if owner else None)!=job['organization_id']):
                raise StaleJob('Old connection payload cannot be replayed')
            key=f'retry:{job_id}'
            if not self.enqueue(job['kind'],job['repo'],json.loads(job['payload']),key):
                raise ValueError('Retry already exists')
            c.execute("UPDATE jobs SET state='retried' WHERE id=?",(job_id,))
            self.audit_event(job['repo'],None,'operator','dead_letter_retried',{'job_id':job_id})
            return {'retried_job_id':job_id,'state':'pending'}

    def save_finding(self, repo: str, key: str, category: str, severity: str,
                     title: str, file_path: str | None, commit_sha: str | None, details: dict):
        with self.transaction(), self.conn() as c:
            previous=c.execute('SELECT id,status,severity FROM findings WHERE repo=? AND key=?',(repo,key)).fetchone()
            c.execute("""INSERT INTO findings(repo,key,category,severity,title,file_path,commit_sha,details,detected_at)
            VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(repo,key) DO UPDATE SET
            severity=excluded.severity,title=excluded.title,details=excluded.details,
            status=CASE WHEN findings.status='suppressed' AND EXISTS (
                SELECT 1 FROM suppressions WHERE finding_id=findings.id AND expires_at>?
            ) THEN 'suppressed' ELSE 'open' END,
            commit_sha=excluded.commit_sha,detected_at=excluded.detected_at""",
            (repo,key,category,severity,title,file_path,commit_sha,json.dumps(details),time.time(),time.time()))
            current=c.execute('SELECT id,status,severity FROM findings WHERE repo=? AND key=?',(repo,key)).fetchone()
            self.audit_event(repo,current['id'],'scanner','finding_observed',{
                'before':dict(previous) if previous else None,'after':dict(current),
                'commit_sha':commit_sha,'scan_id':details.get('scan_id')})

    def resolve_missing_dependencies(self, repo: str, seen_keys: set[str]):
        """Close findings no longer present after a *successful* complete audit."""
        with self.transaction(), self.conn() as c:
            rows = c.execute("SELECT key FROM findings WHERE repo=? AND category='dependency' AND status='open'",
                             (repo,)).fetchall()
            for row in rows:
                if row['key'] not in seen_keys:
                    c.execute("UPDATE findings SET status='resolved' WHERE repo=? AND key=?",
                              (repo, row['key']))
                    finding=c.execute('SELECT id FROM findings WHERE repo=? AND key=?',(repo,row['key'])).fetchone()
                    self.audit_event(repo,finding['id'],'scanner','finding_resolved',{'reason':'absent_from_complete_audit'})

    @staticmethod
    def normalize_package(name: str, eco: str) -> str:
        import re
        if eco == 'PyPI': return re.sub(r'[-_.]+', '-', name).lower()
        if eco == 'crates.io': return name.lower().replace('_', '-')
        return name.lower() if eco in ('npm', 'NuGet', 'Packagist') else name

    def replace_inventory(self, repo: str, dependencies):
        now = time.time()
        with self.transaction(), self.conn() as c:
            c.execute("DELETE FROM dependency_inventory WHERE repo=?", (repo,))
            for dep in set(dependencies):
                c.execute("""INSERT INTO dependency_inventory
                    (repo,file_path,ecosystem,normalized_name,package_name,version,scanned_at)
                    VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
                    (repo,dep.file_path,dep.ecosystem,self.normalize_package(dep.name,dep.ecosystem),
                     dep.name,dep.version,now))

    def repos_using_packages(self, packages: list[tuple[str, str]]) -> set[str]:
        """Match advisory package names to known dependency inventory, not vulnerable ranges."""
        matching = set()
        with self.conn() as c:
            for eco,name in packages[:150]:
                normalized=self.normalize_package(name,eco)
                rows=c.execute("""SELECT DISTINCT repo FROM dependency_inventory
                    WHERE ecosystem=? AND normalized_name=?""", (eco,normalized)).fetchall()
                matching.update(r['repo'] for r in rows)
            # An incomplete inventory cannot rule out any package. Re-evaluate
            # those repositories conservatively rather than silently miss CVEs.
            rows=c.execute("""SELECT DISTINCT s.repo FROM scans s JOIN repositories r ON r.full_name=s.repo
                WHERE s.kind='dependencies' AND s.state IN ('incomplete','failed')
                AND NOT EXISTS (SELECT 1 FROM scans newer WHERE newer.repo=s.repo
                  AND newer.kind='dependencies' AND newer.started_at>s.started_at)""").fetchall()
            matching.update(r['repo'] for r in rows)
            rows=c.execute("""SELECT full_name FROM repositories r WHERE
                NOT EXISTS (SELECT 1 FROM dependency_inventory d WHERE d.repo=r.full_name)
                AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.repo=r.full_name
                    AND s.kind='dependencies' AND s.state='complete')""").fetchall()
            matching.update(r['full_name'] for r in rows)
        return matching

    def save_advisory(self, advisory, source='OSV'):
        import hashlib
        from datetime import datetime
        from .intelligence import advisory_identity
        canonical=advisory_identity(advisory)
        aliases=sorted({canonical,advisory['id'],*advisory.get('aliases',[])})
        encoded=json.dumps(advisory,sort_keys=True)
        now=time.time()
        with self.transaction(), self.conn() as c:
            previous=c.execute('SELECT * FROM advisories WHERE id=?',(canonical,)).fetchone()
            withdrawn=bool(advisory.get('withdrawn'))
            if previous:
                aliases=sorted(set(aliases)|set(json.loads(previous['aliases'])))
                def timestamp(value):
                    try: return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
                    except (AttributeError,TypeError,ValueError): return 0
                old=timestamp(json.loads(previous['data']).get('modified'))
                new=timestamp(advisory.get('modified'))
                stale=(old and new and new<old)
                # Source lag must not resurrect withdrawals or erase newer
                # signed range evidence. Reinstatement needs a newer GHSA event.
                blocked=(previous['withdrawn'] and not withdrawn and not
                         (source=='GitHub webhook' and old and new>old))
                preserve=previous['source']=='GitHub webhook' and source=='OSV' and new<=old
                if stale or blocked or preserve:
                    c.execute('UPDATE advisories SET aliases=? WHERE id=?',(json.dumps(aliases),canonical))
                    for alias in aliases:
                        c.execute('INSERT INTO advisory_aliases VALUES(?,?) ON CONFLICT DO NOTHING',(alias,canonical))
                    return canonical
            c.execute('''INSERT INTO advisories VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                aliases=excluded.aliases,summary=excluded.summary,source=excluded.source,data=excluded.data,
                source_sha256=excluded.source_sha256,withdrawn=excluded.withdrawn,updated_at=excluded.updated_at''',
                (canonical,json.dumps(aliases),str(advisory.get('summary',''))[:1000],source,encoded,
                 hashlib.sha256(encoded.encode()).hexdigest(),int(withdrawn),now,now))
            for alias in aliases:
                c.execute('INSERT INTO advisory_aliases VALUES(?,?) ON CONFLICT DO NOTHING',(alias,canonical))
            if withdrawn:
                scope=self._job.get()
                suffix=' AND repo=?' if scope else ''
                params=(scope['repo'],) if scope else ()
                c.execute("UPDATE advisory_impacts SET state='withdrawn',recommendations='[]',updated_at=? WHERE advisory_id=?"+suffix,(now,canonical,*params))
                findings=c.execute("SELECT id,repo,details FROM findings WHERE category='dependency' AND status!='resolved'"+suffix,params).fetchall()
                for finding in findings:
                    details=json.loads(finding['details'])
                    if details.get('advisory_id',details.get('osv_id'))!=canonical: continue
                    c.execute("UPDATE findings SET status='resolved' WHERE id=?",(finding['id'],))
                    self.audit_event(finding['repo'],finding['id'],'intelligence','advisory_withdrawn',{'advisory_id':canonical})
            return canonical

    def advisory(self, id_):
        with self.conn() as c:
            row=c.execute('SELECT * FROM advisories WHERE id=?',(id_,)).fetchone()
            if row is None: return None
            result=dict(row)
            for field in ('aliases','data'): result[field]=json.loads(result[field])
            return result

    def save_impact(self, repo, advisory_id, state, scan_id, evidence, recommendations):
        with self.conn() as c:
            c.execute('''INSERT INTO advisory_impacts(repo,advisory_id,state,scan_id,evidence,recommendations,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(repo,advisory_id) DO UPDATE SET
                state=excluded.state,scan_id=excluded.scan_id,evidence=excluded.evidence,
                recommendations=excluded.recommendations,updated_at=excluded.updated_at''',
                (repo,advisory_id,state,scan_id,json.dumps(evidence),json.dumps(recommendations),time.time()))

    def pending_impact(self, repo, advisory_id, delivery):
        advisory=self.advisory(advisory_id)
        state='withdrawn' if advisory['withdrawn'] else 'under_investigation'
        self.save_impact(repo,advisory_id,state,None,
                         {'reason':'advisory_changed_rescan_queued','delivery_id':delivery,
                          'source_sha256':advisory['source_sha256'],'reachability':'unknown'},[])

    def source_advisories(self):
        with self.conn() as c:
            items=[dict(r) for r in c.execute("SELECT * FROM advisories WHERE source='GitHub webhook' AND withdrawn=0")]
        for item in items:
            for field in ('aliases','data'): item[field]=json.loads(item[field])
        return items

    def impact_advisory_ids(self, repo):
        with self.conn() as c:
            return {r['advisory_id'] for r in c.execute('SELECT advisory_id FROM advisory_impacts WHERE repo=?',(repo,))}

    def impacted_repositories(self, advisory_id):
        with self.conn() as c:
            return {r['repo'] for r in c.execute('SELECT repo FROM advisory_impacts WHERE advisory_id=?',(advisory_id,))}

    def reconcile_impacts(self, repo, scan_id, seen, complete):
        """Only a full fresh audit can retire an earlier affected observation."""
        with self.conn() as c:
            rows=c.execute('SELECT * FROM advisory_impacts WHERE repo=?',(repo,)).fetchall()
            for row in rows:
                if row['advisory_id'] in seen or row['state']=='withdrawn': continue
                previous=json.loads(row['evidence'])
                known=row['state'] if row['state'] in ('affected','not_affected') else previous.get('last_confirmed_state')
                state='not_affected' if complete and known in ('affected','not_affected') else 'under_investigation'
                self.save_impact(repo,row['advisory_id'],state,scan_id,
                    {'reason':'not_returned_by_complete_osv_audit' if state=='not_affected' else 'incomplete_inventory_or_source_confirmation_pending',
                     'reachability':'unknown','coverage_complete':complete,'last_confirmed_state':known},[])

    def invalidate_impacts(self, repo, scan_id):
        with self.transaction(), self.conn() as c:
            rows=c.execute("SELECT * FROM advisory_impacts WHERE repo=? AND state!='withdrawn'",(repo,)).fetchall()
            for row in rows:
                evidence=json.loads(row['evidence'])
                known=row['state'] if row['state'] in ('affected','not_affected') else evidence.get('last_confirmed_state')
                evidence.update(reason='latest_audit_failed',stale=True,last_confirmed_state=known,coverage_complete=False)
                self.save_impact(repo,row['advisory_id'],'under_investigation',scan_id,evidence,[])

    def list_impacts(self, repo=None, advisory_id=None, state=None, cursor=0, limit=50):
        clauses=['i.id>?']
        args=[cursor]
        for column,value in [('i.repo',repo),('i.state',state)]:
            if value is not None:
                clauses.append(column+'=?')
                args.append(value)
        if advisory_id is not None:
            clauses.append('EXISTS (SELECT 1 FROM advisory_aliases x WHERE x.advisory_id=i.advisory_id AND x.alias=?)')
            args.append(advisory_id)
        with self.conn() as c:
            rows=c.execute('''SELECT i.*,a.summary,a.aliases,a.source,a.withdrawn FROM advisory_impacts i
                JOIN advisories a ON a.id=i.advisory_id WHERE '''+' AND '.join(clauses)+' ORDER BY i.id LIMIT ?',args+[limit+1]).fetchall()
        items=[dict(row) for row in rows[:limit]]
        for item in items:
            for field in ('aliases','evidence','recommendations'): item[field]=json.loads(item[field])
        return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None}

    def list_advisories(self, limit=50):
        with self.conn() as c:
            rows=c.execute('''SELECT a.id,a.aliases,a.summary,a.source,a.withdrawn,a.first_seen_at,a.updated_at,
                (SELECT COUNT(*) FROM advisory_impacts i WHERE i.advisory_id=a.id AND i.state='affected') AS affected_projects,
                (SELECT COUNT(*) FROM advisory_impacts i WHERE i.advisory_id=a.id AND i.state='under_investigation') AS pending_projects
                FROM advisories a ORDER BY a.updated_at DESC LIMIT ?''',(limit,)).fetchall()
        items=[dict(row) for row in rows]
        for item in items: item['aliases']=json.loads(item['aliases'])
        return items

    def save_remediation(self, repo: str, key: str, url: str):
        with self.conn() as c:
            c.execute("INSERT INTO remediations(repo,key,url,created_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING",
                      (repo,key,url,time.time()))

    def has_remediation(self, repo: str, key: str) -> bool:
        with self.conn() as c:
            return c.execute("SELECT 1 FROM remediations WHERE repo=? AND key=?", (repo,key)).fetchone() is not None

    def remediation_policy(self,repo):
        with self.conn() as c:
            row=c.execute('''SELECT p.* FROM remediation_policies p
                JOIN repositories r ON r.full_name=p.repo AND r.connection_id=p.connection_id
                JOIN repository_ownership o ON o.repo=p.repo AND o.organization_id=p.organization_id
                JOIN memberships m ON m.organization_id=p.organization_id AND m.user_id=p.approved_by
                WHERE p.repo=? AND p.enabled=1 AND m.role='org_admin' ''',(repo,)).fetchone()
            if row is None: return None
            result=dict(row)
            for field in ('allowed_packages','allowed_files'): result[field]=json.loads(result[field])
            return result

    def list_rows(self, table: str, limit: int = 100, repo: str | None = None):
        if table not in ("repositories", "jobs", "findings", "remediations", "dependency_inventory", "scans", "audit_events"):
            raise ValueError("Invalid table")
        limit = max(1, min(200, limit))
        order={'scans':'started_at DESC','repositories':'updated_at DESC',
               'findings':'detected_at DESC','dependency_inventory':'scanned_at DESC'}.get(table,'id DESC')
        with self.conn() as c:
            if repo:
                column='full_name' if table=='repositories' else 'repo'
                rows = c.execute(f"SELECT * FROM {table} WHERE {column}=? ORDER BY {order} LIMIT ?", (repo,limit))
            else:
                rows = c.execute(f"SELECT * FROM {table} ORDER BY {order} LIMIT ?", (limit,))
            return [dict(r) for r in rows]

    def start_scan(self, repo, kind, sha=None):
        scan_id = uuid.uuid4().hex
        with self.conn() as c:
            c.execute('INSERT INTO scans(id,repo,kind,commit_sha,state,started_at) VALUES(?,?,?,?,?,?)',
                      (scan_id,repo,kind,sha,'running',time.time()))
        return scan_id

    def finish_scan(self, scan_id, state, coverage, dependencies=None, sha=None):
        with self.conn() as c:
            c.execute('UPDATE scans SET state=?,coverage=?,dependencies=?,commit_sha=COALESCE(?,commit_sha),finished_at=? WHERE id=?',
                      (state,json.dumps(coverage),json.dumps(dependencies or []),sha,time.time(),scan_id))

    def record_scan_finding(self, scan_id, finding):
        with self.conn() as c:
            c.execute('INSERT INTO scan_findings VALUES(?,?,?) ON CONFLICT(scan_id,finding_key) DO UPDATE SET data=excluded.data',
                      (scan_id,finding['key'],json.dumps(finding)))

    def scan(self, scan_id):
        with self.conn() as c:
            row = c.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if row is None: return None
            result = dict(row)
            for field in ('coverage','dependencies'): result[field] = json.loads(result[field])
            result['findings'] = [json.loads(r['data']) for r in c.execute('SELECT data FROM scan_findings WHERE scan_id=? ORDER BY finding_key', (scan_id,))]
            return result

    def expire_suppressions(self):
        with self.transaction():
            with self.conn() as c:
                rows = c.execute("SELECT f.id,f.repo FROM findings f JOIN suppressions s ON s.finding_id=f.id WHERE f.status='suppressed' AND s.expires_at<=?", (time.time(),)).fetchall()
                for r in rows:
                    c.execute("UPDATE findings SET status='open' WHERE id=?", (r['id'],))
                    self.audit_event(r['repo'],r['id'],'system','suppression_expired',{})

    def audit_event(self, repo, finding_id, actor, action, details):
        with self.conn() as c:
            c.execute('INSERT INTO audit_events(repo,finding_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)',
                      (repo,finding_id,actor,action,json.dumps(details),time.time()))

    def triage(self, finding_id, status, reason, expires_at=None, *, actor='admin',organization_id=None):
        with self.transaction():
            with self.conn() as c:
                row = c.execute('SELECT * FROM findings WHERE id=?', (finding_id,)).fetchone()
                if row is None: return None
                c.execute('DELETE FROM suppressions WHERE finding_id=?', (finding_id,))
                if status == 'suppressed':
                    c.execute('INSERT INTO suppressions VALUES(?,?,?)', (finding_id,reason,expires_at))
                c.execute('UPDATE findings SET status=? WHERE id=?', (status,finding_id))
                details={'before':row['status'],'after':status,'reason':reason,'expires_at':expires_at}
                if organization_id is not None: details['organization_id']=organization_id
                self.audit_event(row['repo'],finding_id,actor,'triage',details)
                return {'id':finding_id,'status':status}

    def schedule_due(self, interval: int):
        now=time.time()
        with self.transaction(), self.conn() as c:
            rows = c.execute("SELECT * FROM repositories WHERE next_scan_at<=? LIMIT 100", (now,)).fetchall()
            for r in rows:
                c.execute("UPDATE repositories SET next_scan_at=? WHERE full_name=?", (now+interval, r['full_name']))
            for r in rows:
                self.enqueue("dependency_audit", r['full_name'], {},
                             f"audit:{r['full_name']}:{int(now//interval)}")
        return len(rows)
