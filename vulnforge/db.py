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
                self._apply_job_context(c,self._job.get())
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

    def _apply_job_context(self,c,job):
        pass

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
        active_job=self._job.get()
        if active_job is not None and (active_job.get('id')!=job.get('id') or active_job.get('claim_token')!=job.get('claim_token')):
            raise StaleJob('Job authorization expired')
        with self.transaction(), self.conn() as c:
            if active_job is None:
                self._apply_job_context(c,job)
            self._check_job(c,job,lock=True)

    @contextmanager
    def job_scope(self,job,*,catalog_scope='public'):
        if self._job.get() is not None or self._active.get() is not None:
            raise RuntimeError('Job scopes cannot be nested')
        if catalog_scope not in ('public','private_osv'):
            raise ValueError('Invalid job catalog scope')
        snapshot=dict(job)
        snapshot['catalog_scope_mode']=catalog_scope
        if catalog_scope=='private_osv':
            if not snapshot.get('organization_id'):
                raise StaleJob('Private catalog requires an organization-scoped job')
            snapshot['catalog_scope']='org:'+snapshot['organization_id']
        else:
            snapshot['catalog_scope']='public'
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
            if self._job.get() is not None:
                job=self._job.get()
                if name!=job['repo'] or installation_id!=job['installation_id']:
                    raise PermissionError('Installation outside job scope')
                c.execute("""UPDATE repositories SET
                    evidence_invalidated_at=CASE WHEN default_branch<>? THEN ? ELSE evidence_invalidated_at END,
                    default_branch=?,updated_at=?
                    WHERE full_name=? AND installation_id=? AND connection_id=?""",
                    (default_branch,now,default_branch,now,name,installation_id,job['connection_id']))
                return
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
                evidence_invalidated_at=CASE WHEN repositories.default_branch<>excluded.default_branch
                    THEN excluded.updated_at ELSE repositories.evidence_invalidated_at END,
                default_branch=excluded.default_branch,updated_at=excluded.updated_at""",
                      (name, installation_id, default_branch, now,uuid.uuid4().hex))

    def invalidate_repository_evidence(self,repo):
        with self.conn() as c:
            c.execute('UPDATE repositories SET evidence_invalidated_at=? WHERE full_name=?',(time.time(),repo))

    def record_branch_head(self,repo: str,sha: str):
        with self.conn() as c:
            c.execute('UPDATE repositories SET last_sha=?,updated_at=? WHERE full_name=?',(sha,time.time(),repo))

    def repository(self,repo):
        with self.conn() as c:
            row=c.execute('SELECT * FROM repositories WHERE full_name=?',(repo,)).fetchone()
            return dict(row) if row else None

    def set_scan_commit(self,scan_id,sha):
        with self.conn() as c:
            c.execute('UPDATE scans SET commit_sha=? WHERE id=?',(sha,scan_id))

    def remove_repo(self, name: str, *, reason: str | None = None, actor: str = 'github_webhook',
                    installation_id: int | None = None):
        # Clean security metadata when a GitHub App is uninstalled from a repo.
        with self.conn() as c:
            own = self._active.get() is None
            if own: self.begin(c)
            owner = c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?', (name,)).fetchone() if reason else None
            c.execute('DELETE FROM suppressions WHERE finding_id IN (SELECT id FROM findings WHERE repo=?)', (name,))
            c.execute('DELETE FROM scan_findings WHERE scan_id IN (SELECT id FROM scans WHERE repo=?)', (name,))
            c.execute('DELETE FROM runner_token_uses WHERE receipt_id IN (SELECT id FROM runner_receipts WHERE repo=?)', (name,))
            for table in ('repositories','dependency_inventory'):
                c.execute(f"DELETE FROM {table} WHERE {'full_name' if table=='repositories' else 'repo'}=?",(name,))
            for table in ('jobs','findings','remediations','scans','audit_events','advisory_impacts','runner_reports',
                          'remediation_policies','runner_policies','runner_receipts','repository_ownership'):
                c.execute(f"DELETE FROM {table} WHERE repo=?",(name,))
            if owner and reason:
                details={'repo':name,'reason':reason}
                if installation_id is not None: details['installation_id']=installation_id
                c.execute('INSERT INTO audit_events(repo,finding_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)',
                          ('organization:'+owner['organization_id'],None,actor,reason,json.dumps(details),time.time()))
            if own: c.execute('COMMIT')

    def remove_installation(self, installation_id, *, reason: str | None = None, actor: str = 'github_webhook'):
        with self.conn() as c:
            names = c.execute('SELECT full_name FROM repositories WHERE installation_id=?', (installation_id,)).fetchall()
        for row in names:
            self.remove_repo(row['full_name'], reason=reason, actor=actor, installation_id=installation_id)

    def reconcile_installation_permissions(self, installation_id: int, permissions: dict, *,
                                           repos: list[str] | None = None, metadata_only_required: bool = True) -> list[str]:
        clean={str(k):str(v) for k,v in (permissions.items() if isinstance(permissions,dict) else ())
               if isinstance(k,str) and isinstance(v,str) and len(k)<=64 and len(v)<=32}
        exceeds_metadata_only=(clean!={'metadata':'read'})
        now=time.time()
        with self.transaction(), self.conn() as c:
            rows=c.execute('SELECT full_name FROM repositories WHERE installation_id=?',(installation_id,)).fetchall()
            targets=sorted({r['full_name'] for r in rows}|set(repos or ()))
            reconciled=[]
            for name in targets:
                if c.execute('SELECT 1 FROM repositories WHERE full_name=? AND installation_id=?',
                             (name,installation_id)).fetchone() is None:
                    continue
                c.execute('UPDATE repositories SET evidence_invalidated_at=?,updated_at=? WHERE full_name=?',(now,now,name))
                if metadata_only_required and exceeds_metadata_only:
                    c.execute('UPDATE runner_policies SET enabled=0 WHERE repo=?',(name,))
                self.audit_event(name,None,'github_webhook','installation_permissions_changed',
                    {'installation_id':installation_id,'permissions':clean,
                     'exceeds_metadata_only':exceeds_metadata_only,
                     'runner_policy_disabled':bool(metadata_only_required and exceeds_metadata_only)})
                reconciled.append(name)
            return reconciled

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
        active_job=self._job.get()
        if active_job is not None and (active_job.get('id')!=job.get('id') or active_job.get('claim_token')!=job.get('claim_token')):
            raise StaleJob('Job authorization expired')
        with self.transaction(),self.conn() as c:
            if active_job is None:
                self._apply_job_context(c,job)
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
            status=CASE WHEN findings.status IN ('suppressed','risk_accepted') AND EXISTS (
                SELECT 1 FROM suppressions WHERE finding_id=findings.id AND expires_at>?
            ) THEN findings.status
            WHEN findings.status='false_positive' THEN 'false_positive'
            ELSE 'open' END,
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

    def resolve_patch_findings_with_proof(self, repo: str, merge_sha: str, pr_url: str, resolved_advisories: list[str]):
        """Close findings resolved by a verified merged patch PR and record closure proof."""
        adv_set = set(resolved_advisories)
        now = time.time()
        with self.transaction(), self.conn() as c:
            rows = c.execute("SELECT id, key, details FROM findings WHERE repo=? AND status='open'", (repo,)).fetchall()
            for r in rows:
                det = json.loads(r['details']) if isinstance(r['details'], str) else (r['details'] or {})
                adv_id = det.get('advisory_id') or det.get('rule') or r['key']
                if adv_id in adv_set or any(a in adv_set for a in det.get('aliases', [])):
                    det['closure_proof'] = {
                        'closure_reason': 'patch_merged_and_verified',
                        'merge_sha': merge_sha,
                        'pr_url': pr_url,
                        'resolved_at': now,
                        'verification_passed': True
                    }
                    c.execute("UPDATE findings SET status='resolved', details=? WHERE id=?",
                              (json.dumps(det, sort_keys=True), r['id']))
                    self.audit_event(repo, r['id'], 'system', 'finding_resolved_by_patch', det['closure_proof'])

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

    def _catalog_scope(self, catalog_scope=None):
        if catalog_scope is not None: return catalog_scope
        job=self._job.get()
        if job is not None: return job.get('catalog_scope','public')
        return 'public'

    @staticmethod
    def _scoped_advisory_id(advisory_id: str, scope: str) -> str:
        if scope=='public': return advisory_id
        prefix=scope+':'
        return advisory_id if advisory_id.startswith(prefix) else prefix+advisory_id

    def save_advisory(self, advisory, source='OSV', *, catalog_scope=None):
        import hashlib
        from datetime import datetime
        from .intelligence import advisory_identity
        scope=self._catalog_scope(catalog_scope)
        if scope!='public' and not scope.startswith('org:'):
            raise ValueError('Invalid advisory catalog scope')
        if scope.startswith('org:') and source=='OSV':
            source='Private OSV'
        raw_canonical=advisory_identity(advisory)
        aliases=sorted({str(x) for x in (raw_canonical,advisory['id'],*advisory.get('aliases',[])) if isinstance(x,str) and x})
        clean_payload={k:v for k,v in advisory.items() if not str(k).startswith('_')}
        source_sha256=hashlib.sha256(json.dumps(clean_payload,sort_keys=True).encode()).hexdigest()
        now=time.time()
        with self.transaction(), self.conn() as c:
            placeholders=','.join('?' for _ in aliases)
            linked_rows=c.execute(
                f'SELECT DISTINCT advisory_id FROM advisory_aliases WHERE catalog_scope=? AND alias IN ({placeholders})',
                (scope,*aliases)).fetchall() if aliases else []
            linked_ids=[r['advisory_id'] for r in linked_rows]
            if not raw_canonical.startswith('GHSA-') and linked_ids:
                ghsa_links=sorted(x for x in linked_ids if x.split(':',1)[-1].startswith('GHSA-'))
                canonical=ghsa_links[0] if ghsa_links else sorted(linked_ids)[0]
                raw_canonical=canonical.split(':',1)[-1] if scope!='public' and canonical.startswith(scope+':') else canonical
            else:
                canonical=self._scoped_advisory_id(raw_canonical,scope)
            aliases=sorted(set(aliases)|{raw_canonical})
            previous=c.execute('SELECT * FROM advisories WHERE id=? AND catalog_scope=?',(canonical,scope)).fetchone()
            revisions=[]
            for lid in linked_ids:
                if lid==canonical or lid.split(':',1)[-1].startswith('GHSA-'): continue
                lrow=c.execute('SELECT * FROM advisories WHERE id=? AND catalog_scope=?',(lid,scope)).fetchone()
                if lrow is None: continue
                aliases=sorted(set(aliases)|set(json.loads(lrow['aliases'])))
                ldata=json.loads(lrow['data'])
                lrevs=ldata.get('_revisions') or [{
                    'revision':1,'source':lrow['source'],'source_sha256':lrow['source_sha256'],
                    'modified':ldata.get('modified'),'withdrawn':bool(lrow['withdrawn']),
                    'aliases':json.loads(lrow['aliases']),'observed_at':lrow['updated_at']}]
                revisions.extend(lrevs)
                if previous is None:
                    previous=lrow
                if self._job.get() is None:
                    for impact in c.execute('SELECT * FROM advisory_impacts WHERE advisory_id=?',(lid,)).fetchall():
                        c.execute('''INSERT INTO advisory_impacts(repo,advisory_id,state,scan_id,evidence,recommendations,updated_at)
                            VALUES(?,?,?,?,?,?,?) ON CONFLICT(repo,advisory_id) DO NOTHING''',
                            (impact['repo'],canonical,impact['state'],impact['scan_id'],impact['evidence'],impact['recommendations'],impact['updated_at']))
                    c.execute('DELETE FROM advisory_impacts WHERE advisory_id=?',(lid,))
            withdrawn=bool(advisory.get('withdrawn'))
            if previous:
                aliases=sorted(set(aliases)|set(json.loads(previous['aliases'])))
                prev_data=json.loads(previous['data'])
                prev_revs=prev_data.get('_revisions') or [{
                    'revision':1,'source':previous['source'],'source_sha256':previous['source_sha256'],
                    'modified':prev_data.get('modified'),'withdrawn':bool(previous['withdrawn']),
                    'aliases':json.loads(previous['aliases']),'observed_at':previous['updated_at']}]
                for r in prev_revs:
                    if not any(x.get('source_sha256')==r.get('source_sha256') and x.get('source')==r.get('source') for x in revisions):
                        revisions.append(r)
                def timestamp(value):
                    try: return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
                    except (AttributeError,TypeError,ValueError): return 0
                old=timestamp(prev_data.get('modified'))
                new=timestamp(advisory.get('modified'))
                stale=(old and new and new<old)
                # Source lag must not resurrect withdrawals or erase newer
                # signed range evidence. Reinstatement needs a newer GHSA event.
                blocked=(previous['withdrawn'] and not withdrawn and not
                         (source=='GitHub webhook' and old and new>old))
                preserve=previous['source']=='GitHub webhook' and source=='OSV' and new<=old
                if stale or blocked or preserve:
                    if not any(x.get('source_sha256')==source_sha256 and x.get('source')==source for x in revisions):
                        revisions.append({
                            'revision':len(revisions)+1,'source':source,'source_sha256':source_sha256,
                            'modified':advisory.get('modified'),'withdrawn':withdrawn,
                            'aliases':aliases,'observed_at':now,'superseded':True})
                    prev_data['_revisions']=revisions[-50:]
                    c.execute('UPDATE advisories SET aliases=?,data=? WHERE id=? AND catalog_scope=?',
                              (json.dumps(aliases),json.dumps(prev_data,sort_keys=True),canonical,scope))
                    for alias in aliases:
                        c.execute('INSERT INTO advisory_aliases(alias,advisory_id,catalog_scope) VALUES(?,?,?) ON CONFLICT DO NOTHING',
                                  (alias,canonical,scope))
                    return canonical
            if not any(x.get('source_sha256')==source_sha256 and x.get('source')==source and x.get('withdrawn')==withdrawn for x in revisions):
                revisions.append({
                    'revision':len(revisions)+1,'source':source,'source_sha256':source_sha256,
                    'modified':advisory.get('modified'),'withdrawn':withdrawn,
                    'aliases':aliases,'observed_at':now,'superseded':False})
            stored_payload={**clean_payload,'_revisions':revisions[-50:]}
            encoded=json.dumps(stored_payload,sort_keys=True)
            c.execute('''INSERT INTO advisories(id,aliases,summary,source,data,source_sha256,withdrawn,first_seen_at,updated_at,catalog_scope)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                aliases=excluded.aliases,summary=excluded.summary,source=excluded.source,data=excluded.data,
                source_sha256=excluded.source_sha256,withdrawn=excluded.withdrawn,updated_at=excluded.updated_at
                WHERE advisories.catalog_scope=excluded.catalog_scope''',
                (canonical,json.dumps(aliases),str(advisory.get('summary',''))[:1000],source,encoded,
                 source_sha256,int(withdrawn),now,now,scope))
            for alias in aliases:
                c.execute('INSERT INTO advisory_aliases(alias,advisory_id,catalog_scope) VALUES(?,?,?) ON CONFLICT DO NOTHING',
                          (alias,canonical,scope))
            if withdrawn:
                job_scope=self._job.get()
                suffix=' AND repo=?' if job_scope else ''
                params=(job_scope['repo'],) if job_scope else ()
                match_ids={canonical,raw_canonical,*aliases,*linked_ids}
                id_placeholders=','.join('?' for _ in match_ids)
                c.execute(f"UPDATE advisory_impacts SET state='withdrawn',recommendations='[]',updated_at=? WHERE advisory_id IN ({id_placeholders})"+suffix,
                          (now,*match_ids,*params))
                findings=c.execute("SELECT id,repo,details FROM findings WHERE category='dependency' AND status!='resolved'"+suffix,params).fetchall()
                for finding in findings:
                    details=json.loads(finding['details'])
                    finding_ids={details.get('advisory_id'),details.get('osv_id'),*(details.get('aliases') or [])}
                    if not (finding_ids & match_ids): continue
                    c.execute("UPDATE findings SET status='resolved' WHERE id=?",(finding['id'],))
                    self.audit_event(finding['repo'],finding['id'],'intelligence','advisory_withdrawn',{'advisory_id':canonical})
            return canonical

    def _ensure_ingestion_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS advisory_ingestion_state (
            source TEXT NOT NULL,
            catalog_scope TEXT NOT NULL DEFAULT 'public',
            cursor TEXT,
            last_record_id TEXT,
            status TEXT NOT NULL DEFAULT 'idle',
            error TEXT,
            processed_count INTEGER NOT NULL DEFAULT 0,
            retry_count INTEGER NOT NULL DEFAULT 0,
            last_success_at REAL,
            updated_at REAL NOT NULL,
            PRIMARY KEY(source, catalog_scope)
        )''')

    def get_ingestion_state(self, source: str, *, catalog_scope=None) -> dict | None:
        scope = self._catalog_scope(catalog_scope)
        with self.conn() as c:
            self._ensure_ingestion_table(c)
            row = c.execute(
                'SELECT * FROM advisory_ingestion_state WHERE source=? AND catalog_scope=?',
                (source, scope)
            ).fetchone()
            return dict(row) if row else None

    _INGESTION_UNSET = object()

    def update_ingestion_state(self, source: str, *, cursor=_INGESTION_UNSET,
                               last_record_id=_INGESTION_UNSET, status: str = 'idle',
                               error: str | None = None, processed_delta: int = 0,
                               retry_increment: bool = False, reset_retry: bool = False,
                               success: bool = False, catalog_scope=None):
        scope = self._catalog_scope(catalog_scope)
        now = time.time()
        with self.transaction(), self.conn() as c:
            self._ensure_ingestion_table(c)
            prev = c.execute(
                'SELECT * FROM advisory_ingestion_state WHERE source=? AND catalog_scope=?',
                (source, scope)
            ).fetchone()
            cur_val = None if cursor is self._INGESTION_UNSET else cursor
            last_id_val = None if last_record_id is self._INGESTION_UNSET else last_record_id
            if prev is None:
                new_retry = 1 if retry_increment else 0
                new_count = processed_delta
                succ_at = now if success else None
                c.execute('''INSERT INTO advisory_ingestion_state
                    (source, catalog_scope, cursor, last_record_id, status, error, processed_count, retry_count, last_success_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)''',
                    (source, scope, cur_val, last_id_val, status, error, new_count, new_retry, succ_at, now))
            else:
                new_cursor = prev['cursor'] if cursor is self._INGESTION_UNSET else cursor
                new_last_id = prev['last_record_id'] if last_record_id is self._INGESTION_UNSET else last_record_id
                new_count = prev['processed_count'] + processed_delta
                if reset_retry:
                    new_retry = 0
                elif retry_increment:
                    new_retry = prev['retry_count'] + 1
                else:
                    new_retry = prev['retry_count']
                succ_at = now if success else prev['last_success_at']
                c.execute('''UPDATE advisory_ingestion_state
                    SET cursor=?, last_record_id=?, status=?, error=?, processed_count=?, retry_count=?, last_success_at=?, updated_at=?
                    WHERE source=? AND catalog_scope=?''',
                    (new_cursor, new_last_id, status, error, new_count, new_retry, succ_at, now, source, scope))

    def advisory(self, id_, *, catalog_scope=None):
        scope=self._catalog_scope(catalog_scope)
        scoped_id=self._scoped_advisory_id(id_,scope)
        is_ghsa=str(id_).split(':',1)[-1].startswith('GHSA-')
        with self.conn() as c:
            row=c.execute('SELECT * FROM advisories WHERE id=? AND catalog_scope=?',(scoped_id,scope)).fetchone() if is_ghsa else None
            if row is None:
                row=c.execute('''SELECT a.* FROM advisories a
                    JOIN advisory_aliases x ON x.advisory_id=a.id AND x.catalog_scope=a.catalog_scope
                    WHERE x.alias IN (?,?) AND a.catalog_scope=?
                    ORDER BY CASE WHEN a.id LIKE 'GHSA-%' OR a.id LIKE '%:GHSA-%' THEN 0 ELSE 1 END, a.updated_at DESC
                    LIMIT 1''',(id_,scoped_id,scope)).fetchone()
            if row is None and not is_ghsa:
                row=c.execute('SELECT * FROM advisories WHERE id=? AND catalog_scope=?',(scoped_id,scope)).fetchone()
            if row is None: return None
            result=dict(row)
            for field in ('aliases','data'): result[field]=json.loads(result[field])
            result['revisions']=list(result['data'].get('_revisions',[]))
            result['revision_count']=len(result['revisions'])
            return result

    def _ensure_vulnerability_metrics_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerability_metrics (
            cve_id TEXT PRIMARY KEY,
            cvss_score REAL,
            cvss_severity TEXT,
            cvss_vector TEXT,
            epss_score REAL,
            epss_percentile REAL,
            kev_date_added TEXT,
            kev_ransomware INTEGER NOT NULL DEFAULT 0,
            evidence TEXT NOT NULL,
            updated_at REAL NOT NULL
        )''')

    def save_vulnerability_metrics(self, metrics):
        now = time.time()
        ev_json = json.dumps(metrics.evidence, sort_keys=True)
        with self.transaction(), self.conn() as c:
            self._ensure_vulnerability_metrics_table(c)
            c.execute('''INSERT INTO vulnerability_metrics
                (cve_id, cvss_score, cvss_severity, cvss_vector, epss_score, epss_percentile, kev_date_added, kev_ransomware, evidence, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score=excluded.cvss_score, cvss_severity=excluded.cvss_severity, cvss_vector=excluded.cvss_vector,
                epss_score=excluded.epss_score, epss_percentile=excluded.epss_percentile,
                kev_date_added=excluded.kev_date_added, kev_ransomware=excluded.kev_ransomware,
                evidence=excluded.evidence, updated_at=excluded.updated_at''',
                (metrics.cve_id, metrics.cvss_score, metrics.cvss_severity, metrics.cvss_vector,
                 metrics.epss_score, metrics.epss_percentile, metrics.kev_date_added,
                 int(metrics.kev_ransomware), ev_json, now))

    def get_vulnerability_metrics(self, cve_id: str) -> dict | None:
        with self.conn() as c:
            self._ensure_vulnerability_metrics_table(c)
            row = c.execute('SELECT * FROM vulnerability_metrics WHERE cve_id=?', (cve_id,)).fetchone()
            if row is None:
                return None
            res = dict(row)
            res['evidence'] = json.loads(res['evidence']) if res.get('evidence') else {}
            res['kev_ransomware'] = bool(res.get('kev_ransomware'))
            return res

    def save_impact(self, repo, advisory_id, state, scan_id, evidence, recommendations):
        now = time.time()
        ev_dict = dict(evidence) if isinstance(evidence, dict) else (json.loads(evidence) if isinstance(evidence, str) else {})
        with self.transaction(), self.conn() as c:
            prev = c.execute('SELECT * FROM advisory_impacts WHERE repo=? AND advisory_id=?',
                             (repo, advisory_id)).fetchone()
            revisions = []
            if prev:
                prev_ev = json.loads(prev['evidence']) if isinstance(prev['evidence'], str) else dict(prev['evidence'] or {})
                revisions = list(prev_ev.get('_revisions', []))
                if not revisions:
                    prev_recs = json.loads(prev['recommendations']) if isinstance(prev['recommendations'], str) else prev['recommendations']
                    revisions.append({
                        'revision': 1,
                        'state': prev['state'],
                        'scan_id': prev['scan_id'],
                        'evidence': {k: v for k, v in prev_ev.items() if k != '_revisions'},
                        'recommendations': prev_recs,
                        'updated_at': prev['updated_at']
                    })
            revisions.append({
                'revision': len(revisions) + 1,
                'state': state,
                'scan_id': scan_id,
                'evidence': {k: v for k, v in ev_dict.items() if k != '_revisions'},
                'recommendations': recommendations,
                'updated_at': now
            })
            ev_dict['_revisions'] = revisions[-50:]
            c.execute('''INSERT INTO advisory_impacts(repo,advisory_id,state,scan_id,evidence,recommendations,updated_at)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(repo,advisory_id) DO UPDATE SET
                state=excluded.state,scan_id=excluded.scan_id,evidence=excluded.evidence,
                recommendations=excluded.recommendations,updated_at=excluded.updated_at''',
                (repo, advisory_id, state, scan_id, json.dumps(ev_dict, sort_keys=True),
                 json.dumps(recommendations, sort_keys=True), now))

    def impact_history(self, repo: str, advisory_id: str) -> list[dict]:
        with self.conn() as c:
            row = c.execute('SELECT evidence FROM advisory_impacts WHERE repo=? AND advisory_id=?',
                            (repo, advisory_id)).fetchone()
            if not row:
                return []
            ev = json.loads(row['evidence']) if isinstance(row['evidence'], str) else (row['evidence'] or {})
            return list(ev.get('_revisions', []))

    def _ensure_unfixed_mitigations_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS unfixed_mitigations (
            repo TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            package TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            current_version TEXT NOT NULL,
            mitigation_guidance TEXT NOT NULL,
            owner TEXT,
            priority TEXT NOT NULL,
            created_at REAL NOT NULL,
            sla_deadline REAL NOT NULL,
            recheck_interval_hours INTEGER NOT NULL DEFAULT 24,
            next_recheck_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            history TEXT NOT NULL DEFAULT '[]',
            PRIMARY KEY(repo, advisory_id)
        )''')

    def save_unfixed_mitigation(self, repo: str, advisory_id: str, package: str, ecosystem: str,
                                current_version: str, mitigation_guidance: str, *,
                                owner: str | None = None, priority: str = 'P2',
                                sla_hours: int = 336, recheck_interval_hours: int = 24):
        now = time.time()
        sla_deadline = now + sla_hours * 3600
        next_recheck = now + recheck_interval_hours * 3600
        init_history = json.dumps([{'action': 'created', 'at': now, 'owner': owner, 'priority': priority}])
        with self.transaction(), self.conn() as c:
            self._ensure_unfixed_mitigations_table(c)
            c.execute('''INSERT INTO unfixed_mitigations
                (repo, advisory_id, package, ecosystem, current_version, mitigation_guidance, owner, priority,
                 created_at, sla_deadline, recheck_interval_hours, next_recheck_at, status, history)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(repo, advisory_id) DO UPDATE SET
                mitigation_guidance=excluded.mitigation_guidance,
                owner=COALESCE(excluded.owner, unfixed_mitigations.owner),
                priority=excluded.priority,
                recheck_interval_hours=excluded.recheck_interval_hours''',
                (repo, advisory_id, package, ecosystem, current_version, mitigation_guidance, owner,
                 priority, now, sla_deadline, recheck_interval_hours, next_recheck, 'active', init_history))

    def get_unfixed_mitigations(self, repo: str | None = None) -> list[dict]:
        with self.conn() as c:
            self._ensure_unfixed_mitigations_table(c)
            if repo:
                rows = c.execute('SELECT * FROM unfixed_mitigations WHERE repo=? ORDER BY priority ASC, sla_deadline ASC', (repo,)).fetchall()
            else:
                rows = c.execute('SELECT * FROM unfixed_mitigations ORDER BY priority ASC, sla_deadline ASC').fetchall()
            out = []
            now = time.time()
            for r in rows:
                item = dict(r)
                item['history'] = json.loads(item['history']) if isinstance(item['history'], str) else []
                if item['status'] == 'active':
                    if now > item['sla_deadline']:
                        item['sla_status'] = 'breached'
                    elif now > (item['sla_deadline'] - 0.2 * (item['sla_deadline'] - item['created_at'])):
                        item['sla_status'] = 'at_risk'
                    else:
                        item['sla_status'] = 'within_sla'
                else:
                    item['sla_status'] = item['status']
                out.append(item)
            return out

    def extend_mitigation_sla(self, repo: str, advisory_id: str, additional_hours: int,
                              *, reason: str, actor: str):
        now = time.time()
        with self.transaction(), self.conn() as c:
            self._ensure_unfixed_mitigations_table(c)
            row = c.execute('SELECT * FROM unfixed_mitigations WHERE repo=? AND advisory_id=?', (repo, advisory_id)).fetchone()
            if not row:
                raise ValueError('Mitigation entry not found')
            new_deadline = row['sla_deadline'] + additional_hours * 3600
            history = json.loads(row['history']) if isinstance(row['history'], str) else []
            history.append({
                'action': 'sla_extended',
                'at': now,
                'additional_hours': additional_hours,
                'reason': reason,
                'actor': actor
            })
            c.execute('UPDATE unfixed_mitigations SET sla_deadline=?, history=? WHERE repo=? AND advisory_id=?',
                      (new_deadline, json.dumps(history, sort_keys=True), repo, advisory_id))

    def record_mitigation_recheck(self, repo: str, advisory_id: str, *, status: str, result_summary: str):
        now = time.time()
        with self.transaction(), self.conn() as c:
            self._ensure_unfixed_mitigations_table(c)
            row = c.execute('SELECT * FROM unfixed_mitigations WHERE repo=? AND advisory_id=?', (repo, advisory_id)).fetchone()
            if not row:
                raise ValueError('Mitigation entry not found')
            interval = row['recheck_interval_hours'] or 24
            next_recheck = now + interval * 3600
            history = json.loads(row['history']) if isinstance(row['history'], str) else []
            history.append({
                'action': 'rechecked',
                'at': now,
                'status': status,
                'summary': result_summary
            })
            c.execute('UPDATE unfixed_mitigations SET next_recheck_at=?, status=?, history=? WHERE repo=? AND advisory_id=?',
                      (next_recheck, status, json.dumps(history, sort_keys=True), repo, advisory_id))

    def _ensure_patch_validations_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS patch_validations (
            repo TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            all_checks_passed INTEGER NOT NULL,
            validated_at REAL NOT NULL,
            evidence TEXT NOT NULL,
            PRIMARY KEY(repo, plan_id)
        )''')

    def save_patch_validation(self, repo: str, plan_id: str, evidence: dict):
        all_passed = 1 if evidence.get('all_checks_passed') else 0
        validated_at = float(evidence.get('validated_at', time.time()))
        ev_str = json.dumps(evidence, sort_keys=True)
        with self.transaction(), self.conn() as c:
            self._ensure_patch_validations_table(c)
            c.execute('''INSERT INTO patch_validations(repo, plan_id, all_checks_passed, validated_at, evidence)
                VALUES(?,?,?,?,?)
                ON CONFLICT(repo, plan_id) DO UPDATE SET
                all_checks_passed=excluded.all_checks_passed,
                validated_at=excluded.validated_at,
                evidence=excluded.evidence''',
                (repo, plan_id, all_passed, validated_at, ev_str))

    def get_patch_validation(self, repo: str, plan_id: str) -> dict | None:
        with self.conn() as c:
            self._ensure_patch_validations_table(c)
            row = c.execute('SELECT * FROM patch_validations WHERE repo=? AND plan_id=?', (repo, plan_id)).fetchone()
            if not row:
                return None
            return json.loads(row['evidence']) if isinstance(row['evidence'], str) else row['evidence']

    def _ensure_patch_approvals_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS patch_approvals (
            repo TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            baseline_sha TEXT NOT NULL,
            diff_sha256 TEXT NOT NULL,
            approved_at REAL NOT NULL,
            status TEXT NOT NULL,
            invalidation_reason TEXT,
            PRIMARY KEY(repo, plan_id)
        )''')

    def record_patch_approval(self, repo: str, plan_id: str, user_id: int, baseline_sha: str, diff_sha256: str):
        now = time.time()
        with self.transaction(), self.conn() as c:
            self._ensure_patch_approvals_table(c)
            c.execute('''INSERT INTO patch_approvals(repo, plan_id, user_id, baseline_sha, diff_sha256, approved_at, status, invalidation_reason)
                VALUES(?,?,?,?,?,?,?,NULL)
                ON CONFLICT(repo, plan_id) DO UPDATE SET
                user_id=excluded.user_id,
                baseline_sha=excluded.baseline_sha,
                diff_sha256=excluded.diff_sha256,
                approved_at=excluded.approved_at,
                status='approved',
                invalidation_reason=NULL''',
                (repo, plan_id, user_id, baseline_sha, diff_sha256, now, 'approved'))

    def get_patch_approval(self, repo: str, plan_id: str) -> dict | None:
        with self.conn() as c:
            self._ensure_patch_approvals_table(c)
            row = c.execute('SELECT * FROM patch_approvals WHERE repo=? AND plan_id=?', (repo, plan_id)).fetchone()
            return dict(row) if row else None

    def invalidate_patch_approval(self, repo: str, plan_id: str, reason: str):
        with self.transaction(), self.conn() as c:
            self._ensure_patch_approvals_table(c)
            c.execute('UPDATE patch_approvals SET status=?, invalidation_reason=? WHERE repo=? AND plan_id=?',
                      ('invalidated', reason, repo, plan_id))

    def verify_patch_approval(self, repo: str, plan_id: str, current_baseline_sha: str, current_diff_sha256: str) -> tuple[bool, str | None]:
        with self.transaction(), self.conn() as c:
            self._ensure_patch_approvals_table(c)
            row = c.execute('SELECT * FROM patch_approvals WHERE repo=? AND plan_id=?', (repo, plan_id)).fetchone()
            if not row:
                return False, 'no_approval'
            if row['status'] != 'approved':
                return False, row['invalidation_reason'] or 'approval_not_active'
            if row['baseline_sha'] != current_baseline_sha:
                c.execute('UPDATE patch_approvals SET status=?, invalidation_reason=? WHERE repo=? AND plan_id=?',
                          ('invalidated', 'baseline_sha_mismatch', repo, plan_id))
                return False, 'baseline_sha_mismatch'
            if row['diff_sha256'] != current_diff_sha256:
                c.execute('UPDATE patch_approvals SET status=?, invalidation_reason=? WHERE repo=? AND plan_id=?',
                          ('invalidated', 'diff_content_changed', repo, plan_id))
                return False, 'diff_content_changed'
            return True, None

    def _ensure_notifications_table(self, c):
        c.execute('''CREATE TABLE IF NOT EXISTS notification_channels (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            events TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS notif_channels_org_idx ON notification_channels(organization_id)')

    def pending_impact(self, repo, advisory_id, delivery):
        advisory=self.advisory(advisory_id)
        state='withdrawn' if advisory['withdrawn'] else 'under_investigation'
        self.save_impact(repo,advisory_id,state,None,
                         {'reason':'advisory_changed_rescan_queued','delivery_id':delivery,
                          'source_sha256':advisory['source_sha256'],'reachability':'unknown'},[])

    def source_advisories(self):
        if self._catalog_scope()!='public': return []
        with self.conn() as c:
            items=[dict(r) for r in c.execute("SELECT * FROM advisories WHERE source='GitHub webhook' AND withdrawn=0 AND catalog_scope='public'")]
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
                advisory=self.advisory(row['advisory_id'])
                state='not_affected' if complete and advisory is not None and known in ('affected','not_affected') else 'under_investigation'
                self.save_impact(repo,row['advisory_id'],state,scan_id,
                    {'reason':'not_returned_by_complete_osv_audit' if state=='not_affected' else 'incomplete_inventory_or_source_confirmation_pending',
                     'reachability':'unknown','coverage_complete':complete,'last_confirmed_state':known,
                     'advisory_sha256':advisory['source_sha256'] if advisory is not None else previous.get('advisory_sha256')},[])

    def invalidate_impacts(self, repo, scan_id):
        with self.transaction(), self.conn() as c:
            rows=c.execute("SELECT * FROM advisory_impacts WHERE repo=? AND state!='withdrawn'",(repo,)).fetchall()
            for row in rows:
                evidence=json.loads(row['evidence'])
                known=row['state'] if row['state'] in ('affected','not_affected') else evidence.get('last_confirmed_state')
                evidence.update(reason='latest_audit_failed',stale=True,last_confirmed_state=known,coverage_complete=False)
                self.save_impact(repo,row['advisory_id'],'under_investigation',scan_id,evidence,[])

    def list_impacts(self, repo=None, advisory_id=None, state=None, cursor=0, limit=50):
        clauses=['i.id>?','a.catalog_scope!=?']
        args=[cursor,'quarantined_legacy']
        for column,value in [('i.repo',repo),('i.state',state)]:
            if value is not None:
                clauses.append(column+'=?')
                args.append(value)
        if advisory_id is not None:
            clauses.append('EXISTS (SELECT 1 FROM advisory_aliases x WHERE x.advisory_id=i.advisory_id AND x.catalog_scope=a.catalog_scope AND x.alias=?)')
            args.append(advisory_id)
        with self.conn() as c:
            rows=c.execute('''SELECT i.*,a.summary,a.aliases,a.source,a.withdrawn FROM advisory_impacts i
                JOIN advisories a ON a.id=i.advisory_id WHERE '''+' AND '.join(clauses)+' ORDER BY i.id LIMIT ?',args+[limit+1]).fetchall()
            items=[dict(row) for row in rows[:limit]]
            from .freshness import impact_view
            cache={}
            for index,item in enumerate(items):
                for field in ('aliases','evidence','recommendations'): item[field]=json.loads(item[field])
                items[index]=impact_view(c,item,cache)
        return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None,
                'filter_scope':'observed_state'}

    def list_advisories(self, limit=50, organization_id=None):
        scope='org:'+organization_id if organization_id else 'public'
        with self.conn() as c:
            rows=c.execute('''SELECT a.id,a.aliases,a.summary,a.source,a.source_sha256,a.data,a.withdrawn,a.first_seen_at,a.updated_at,
                (SELECT COUNT(*) FROM advisory_impacts i WHERE i.advisory_id=a.id AND i.state='affected') AS affected_projects,
                (SELECT COUNT(*) FROM advisory_impacts i WHERE i.advisory_id=a.id AND i.state='under_investigation') AS pending_projects
                FROM advisories a WHERE a.catalog_scope=? ORDER BY a.updated_at DESC LIMIT ?''',(scope,limit)).fetchall()
        items=[dict(row) for row in rows]
        for item in items:
            item['aliases']=json.loads(item['aliases'])
            data=json.loads(item.pop('data','{}'))
            item['revision_count']=len(data.get('_revisions',[])) or 1
        return items

    def save_remediation(self, repo: str, key: str, url: str):
        with self.conn() as c:
            c.execute("INSERT INTO remediations(repo,key,url,created_at) VALUES(?,?,?,?) ON CONFLICT DO NOTHING",
                      (repo,key,url,time.time()))

    def has_remediation(self, repo: str, key: str) -> bool:
        with self.conn() as c:
            return c.execute("SELECT 1 FROM remediations WHERE repo=? AND key=?", (repo,key)).fetchone() is not None

    def get_remediation(self, repo: str, key: str) -> dict | None:
        with self.conn() as c:
            row = c.execute("SELECT * FROM remediations WHERE repo=? AND key=?", (repo,key)).fetchone()
            return dict(row) if row else None

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
            items=[dict(r) for r in rows]
            from .freshness import repository_evidence,scan_evidence,finding_view
            cache={}
            for item in items:
                if table in ('repositories','dependency_inventory'):
                    repo_name=item['full_name'] if table=='repositories' else item['repo']
                    if repo_name not in cache: cache[repo_name]=repository_evidence(c,repo_name)
                    item['evidence_status']=cache[repo_name]
                elif table=='scans': item['evidence_status']=scan_evidence(c,item,cache)
                elif table=='findings':
                    item['details']=json.dumps(finding_view(c,item,cache)['details'])
            return items

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
            from .freshness import scan_evidence,finding_view
            result['evidence_status']=scan_evidence(c,result)
            result['findings']=[finding_view(c,{**finding,'repo':result['repo']}) for finding in result['findings']]
            return result

    def expire_suppressions(self):
        with self.transaction():
            with self.conn() as c:
                rows = c.execute("SELECT f.id,f.repo FROM findings f JOIN suppressions s ON s.finding_id=f.id WHERE f.status IN ('suppressed','risk_accepted') AND s.expires_at<=?", (time.time(),)).fetchall()
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
                if status in ('suppressed','risk_accepted'):
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

    def purge_organization(self, organization_id: str, actor_id: str = 'admin') -> dict:
        """Completely purge all tenant data, repositories, findings, inventories, scans, and memberships for an organization."""
        with self.transaction(), self.conn() as c:
            org_row = c.execute('SELECT id, name FROM organizations WHERE id=?', (organization_id,)).fetchone()
            if not org_row:
                raise LookupError('Organization not found')

            repo_rows = c.execute('SELECT repo FROM repository_ownership WHERE organization_id=?', (organization_id,)).fetchall()
            repos = [r['repo'] for r in repo_rows]

            for repo in repos:
                c.execute('DELETE FROM findings WHERE repo=?', (repo,))
                c.execute('DELETE FROM dependency_inventory WHERE repo=?', (repo,))
                c.execute('DELETE FROM advisory_impacts WHERE repo=?', (repo,))
                c.execute('DELETE FROM remediations WHERE repo=?', (repo,))
                scan_rows = c.execute('SELECT id FROM scans WHERE repo=?', (repo,)).fetchall()
                for s in scan_rows:
                    c.execute('DELETE FROM scan_findings WHERE scan_id=?', (s['id'],))
                c.execute('DELETE FROM scans WHERE repo=?', (repo,))
                if self.backend == 'sqlite':
                    try:
                        c.execute('DELETE FROM patch_validations WHERE repo=?', (repo,))
                        c.execute('DELETE FROM patch_approvals WHERE repo=?', (repo,))
                    except Exception:
                        pass
                c.execute('DELETE FROM repository_ownership WHERE repo=? AND organization_id=?', (repo, organization_id))
                c.execute('DELETE FROM remediation_policies WHERE repo=? AND organization_id=?', (repo, organization_id))

            c.execute('DELETE FROM memberships WHERE organization_id=?', (organization_id,))
            c.execute('DELETE FROM invitations WHERE organization_id=?', (organization_id,))
            c.execute('DELETE FROM connection_intents WHERE organization_id=?', (organization_id,))
            if self.backend == 'sqlite':
                try:
                    c.execute('DELETE FROM notification_channels WHERE organization_id=?', (organization_id,))
                except Exception:
                    pass
            c.execute('DELETE FROM organizations WHERE id=?', (organization_id,))

            self.audit_event(
                'org:' + organization_id, None, actor_id, 'organization_data_purged',
                {'organization_id': organization_id, 'purged_repos': repos}
            )

            return {
                'status': 'purged',
                'organization_id': organization_id,
                'purged_repositories': repos
            }
