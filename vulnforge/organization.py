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
        rows=c.execute(sql+''' AND x.status IN ('suppressed','risk_accepted') AND EXISTS (SELECT 1 FROM suppressions s
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

    def onboarding(self):
        with self.access('project.read') as c:
            sql, args = self.query('repositories', 'COUNT(*)')
            repo_count = c.execute(sql, args).fetchone()[0]

            sql, args = self.query('scans', 'COUNT(*)')
            scan_count = c.execute(sql, args).fetchone()[0]

            sql, args = self.query('findings', 'COUNT(*)')
            finding_count = c.execute(sql, args).fetchone()[0]

            install_status = 'installed' if repo_count > 0 else 'pending_setup'
            steps = [
                {'step': 'create_organization', 'title': 'Kuruluş oluştur', 'completed': True},
                {'step': 'connect_repository', 'title': 'GitHub projesi bağla', 'completed': repo_count > 0},
                {'step': 'run_initial_scan', 'title': 'İlk taramayı tamamla', 'completed': scan_count > 0},
                {'step': 'review_findings', 'title': 'Güvenlik bulgularını incele', 'completed': scan_count > 0}
            ]
            completed_count = sum(1 for s in steps if s['completed'])
            next_step = next((s['step'] for s in steps if not s['completed']), 'completed')
            return {
                'organization_id': self.organization_id,
                'installation_status': install_status,
                'steps': steps,
                'steps_completed': completed_count,
                'total_steps': len(steps),
                'next_step': next_step,
                'repo_count': repo_count,
                'scan_count': scan_count,
                'finding_count': finding_count
            }

    def project_health(self, repo: str) -> dict:
        with self.access('project.read') as c:
            self._repo(c, repo)
            self._expire_suppressions(c)

            # 1. Repo record & connection health
            sql, args = self.query('repositories', 'x.full_name, x.installation_id, x.default_branch, x.last_sha, x.updated_at')
            repo_row = c.execute(sql + ' AND x.full_name=?', args + [repo]).fetchone()
            if repo_row is None:
                raise ResourceNotFound('Repository not found')

            ownership_row = c.execute(
                'SELECT granted_by, verification_reference, created_at FROM repository_ownership WHERE repo=? AND organization_id=?',
                (repo, self.organization_id)
            ).fetchone()

            runner_configured = False
            runner_workflow = None
            try:
                runner_row = c.execute(
                    'SELECT enabled, workflow_ref FROM runner_policies WHERE repo=? AND organization_id=?',
                    (repo, self.organization_id)
                ).fetchone()
                if runner_row:
                    runner_configured = bool(runner_row['enabled'])
                    runner_workflow = runner_row['workflow_ref']
            except Exception:
                pass

            conn_status = 'connected' if repo_row['installation_id'] and repo_row['installation_id'] > 0 else 'pending'
            connection_health = {
                'repo': repo,
                'status': conn_status,
                'default_branch': repo_row['default_branch'],
                'last_sha': repo_row['last_sha'],
                'installation_id': repo_row['installation_id'],
                'connected_at': ownership_row['created_at'] if ownership_row else None,
                'runner_policy_configured': runner_configured,
                'runner_workflow_ref': runner_workflow,
                'last_sync_at': repo_row['updated_at']
            }

            # 2. Risk summary
            sql, args = self.query('findings', 'x.severity, x.status')
            findings_rows = c.execute(sql + ' AND x.repo=?', args + [repo]).fetchall()
            severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            statuses = {'open': 0, 'resolved': 0, 'false_positive': 0, 'risk_accepted': 0, 'suppressed': 0}
            for f in findings_rows:
                sev = f['severity']
                st = f['status']
                if st in statuses:
                    statuses[st] += 1
                if st == 'open' and sev in severities:
                    severities[sev] += 1

            risk_score = severities['critical'] * 10 + severities['high'] * 5 + severities['medium'] * 2 + severities['low'] * 1
            posture = ('critical' if severities['critical'] > 0
                       else 'high' if severities['high'] > 0
                       else 'medium' if severities['medium'] > 0
                       else 'low' if severities['low'] > 0
                       else 'healthy')
            risk_summary = {
                'risk_score': risk_score,
                'posture': posture,
                'open_findings': statuses['open'],
                'total_findings': len(findings_rows),
                'severities': severities,
                'status_counts': statuses
            }

            # 3. Latest scan & coverage
            sql, args = self.query('scans')
            scan_rows = c.execute(sql + ' AND x.repo=? ORDER BY x.started_at DESC, x.id DESC LIMIT 1', args + [repo]).fetchall()
            latest_scan = None
            coverage_data = {
                'files_total': 0,
                'files_scanned': 0,
                'files_skipped': 0,
                'coverage_percent': 0.0,
                'manifests': [],
                'scope': 'unknown',
                'issues': [],
                'ecosystems': [],
                'dependency_count': 0
            }

            dep_sql, dep_args = self.query('dependency_inventory', 'COUNT(*)')
            dep_count_row = c.execute(dep_sql + ' AND x.repo=?', dep_args + [repo]).fetchone()
            coverage_data['dependency_count'] = dep_count_row[0] if dep_count_row else 0

            ecos_sql, ecos_args = self.query('dependency_inventory', 'DISTINCT x.ecosystem')
            ecos_rows = c.execute(ecos_sql + ' AND x.repo=?', ecos_args + [repo]).fetchall()
            coverage_data['ecosystems'] = sorted([r[0] for r in ecos_rows if r[0]])

            if scan_rows:
                latest_scan_item = self.decode(scan_rows, ('coverage', 'dependencies'))[0]
                from .freshness import assess_scan
                cov = latest_scan_item.get('coverage') or {}
                if isinstance(cov, str):
                    cov = json.loads(cov)
                latest_scan = {
                    'id': latest_scan_item['id'],
                    'kind': latest_scan_item['kind'],
                    'state': latest_scan_item['state'],
                    'started_at': latest_scan_item['started_at'],
                    'finished_at': latest_scan_item.get('finished_at'),
                    'commit_sha': latest_scan_item.get('commit_sha'),
                    'evidence_status': assess_scan(latest_scan_item, default_branch=repo_row['default_branch'])
                }
                ft = cov.get('files_total', 0)
                fs = cov.get('files_scanned', 0)
                fskip = cov.get('files_skipped', 0)
                coverage_data.update({
                    'files_total': ft,
                    'files_scanned': fs,
                    'files_skipped': fskip,
                    'coverage_percent': round((fs / ft * 100.0), 1) if ft > 0 else 0.0,
                    'manifests': cov.get('manifests', []),
                    'scope': cov.get('scope', 'unknown'),
                    'issues': cov.get('issues', [])
                })

            # 4. Intelligence freshness
            from .freshness import repository_evidence
            intel_evidence = repository_evidence(c, repo)

            imp_sql, imp_args = self.query('advisory_impacts', 'x.state, COUNT(*)')
            imp_rows = c.execute(imp_sql + ' AND x.repo=? GROUP BY x.state', imp_args + [repo]).fetchall()
            impact_counts = {r[0]: r[1] for r in imp_rows}

            intelligence_freshness = {
                'status': intel_evidence.get('status', 'missing'),
                'inventory_age': intel_evidence.get('inventory_age', 'unknown'),
                'intelligence_age': intel_evidence.get('intelligence_age', 'unknown'),
                'reasons': intel_evidence.get('reasons', []),
                'inventory_observed_at': intel_evidence.get('inventory_observed_at'),
                'intelligence_checked_at': intel_evidence.get('intelligence_checked_at'),
                'advisory_impacts': {
                    'affected': impact_counts.get('affected', 0),
                    'not_affected': impact_counts.get('not_affected', 0),
                    'under_investigation': impact_counts.get('under_investigation', 0)
                }
            }

            return {
                'repo': repo,
                'risk_summary': risk_summary,
                'latest_scan': latest_scan,
                'coverage': coverage_data,
                'intelligence_freshness': intelligence_freshness,
                'connection_health': connection_health
            }

    def finding(self, finding_id: int) -> dict:
        with self.access('finding.read') as c:
            self._expire_suppressions(c)
            sql, args = self.query('findings')
            row = c.execute(sql + ' AND x.id=?', args + [finding_id]).fetchone()
            if row is None:
                raise ResourceNotFound('Finding not found')

            raw_item = self.decode([row], ('details',))[0]
            repo = raw_item['repo']

            from .freshness import finding_view
            finding_item = finding_view(c, raw_item)
            details = finding_item.get('details', {})

            # 1. Base commit and SHA drift check
            repo_row = c.execute('SELECT default_branch, last_sha FROM repositories WHERE full_name=?', (repo,)).fetchone()
            head_sha = repo_row['last_sha'] if repo_row else None
            baseline_sha = finding_item.get('commit_sha')
            head_drifted = bool(head_sha and baseline_sha and head_sha != baseline_sha)

            sha_info = {
                'commit_sha': baseline_sha,
                'head_sha': head_sha,
                'head_drifted': head_drifted,
                'default_branch': repo_row['default_branch'] if repo_row else 'main'
            }

            # 2. Advisory metadata (if linked to an advisory/CVE)
            advisory_info = None
            adv_id = details.get('advisory_id') or details.get('osv_id') or details.get('cve_id')
            if adv_id:
                scope = 'org:' + self.organization_id
                adv_row = c.execute(
                    "SELECT id, summary, data, source, source_sha256, withdrawn, catalog_scope, aliases, first_seen_at, updated_at "
                    "FROM advisories WHERE id=? AND catalog_scope IN ('public', ?)",
                    (adv_id, scope)
                ).fetchone()
                if adv_row:
                    adv_decoded = self.decode([adv_row], ('aliases',))[0]
                    adv_data = json.loads(adv_decoded.get('data') or '{}')
                    adv_details = adv_data.get('details') or adv_decoded.get('summary')
                    metrics_info = None
                    try:
                        cve_ids = [a for a in adv_decoded.get('aliases', []) if a.startswith('CVE-')]
                        if adv_id.startswith('CVE-'):
                            cve_ids.append(adv_id)
                        for cve in cve_ids:
                            m_row = c.execute("SELECT cvss_score, cvss_severity, cvss_vector, epss_score, epss_percentile, kev_date_added, kev_ransomware, updated_at FROM vulnerability_metrics WHERE cve_id=?", (cve,)).fetchone()
                            if m_row:
                                m_dict = dict(m_row)
                                metrics_info = {
                                    'cvss_score': m_dict['cvss_score'],
                                    'cvss_severity': m_dict['cvss_severity'],
                                    'cvss_vector': m_dict['cvss_vector'],
                                    'epss_score': m_dict['epss_score'],
                                    'epss_percentile': m_dict['epss_percentile'],
                                    'cisa_kev': bool(m_dict['kev_date_added']),
                                    'kev_date_added': m_dict['kev_date_added'],
                                    'calculated_at': m_dict['updated_at']
                                }
                                break
                    except Exception:
                        pass

                    advisory_info = {
                        'id': adv_decoded['id'],
                        'summary': adv_decoded['summary'],
                        'details': adv_details,
                        'aliases': adv_decoded.get('aliases', []),
                        'source': adv_decoded['source'],
                        'source_sha256': adv_decoded['source_sha256'],
                        'withdrawn': bool(adv_decoded['withdrawn']),
                        'metrics': metrics_info
                    }

            # 3. Package graph / dependency info
            package_graph = None
            package_name = details.get('package_name') or details.get('package')
            ecosystem = details.get('ecosystem')
            file_path = finding_item.get('file_path')

            dep_row = None
            if package_name:
                dep_sql, dep_args = self.query('dependency_inventory')
                dep_row = c.execute(
                    dep_sql + ' AND x.repo=? AND x.normalized_name=?',
                    dep_args + [repo, package_name.lower()]
                ).fetchone()

            if dep_row:
                dep_data = dict(dep_row)
                direct = details.get('direct', bool(dep_data.get('direct', True)))
                package_graph = {
                    'package': dep_data.get('package_name', package_name),
                    'version': dep_data['version'],
                    'ecosystem': dep_data['ecosystem'],
                    'file_path': dep_data['file_path'],
                    'direct': direct,
                    'scope': details.get('scope', dep_data.get('scope', 'runtime')),
                    'dependency_edges': details.get('dependency_edges') or (json.loads(dep_data.get('dependency_edges') or '[]') if dep_data.get('dependency_edges') else []),
                    'digest': details.get('digest') or dep_data.get('digest'),
                    'commit': details.get('commit') or dep_data.get('commit')
                }
            elif package_name:
                package_graph = {
                    'package': package_name,
                    'version': details.get('version', 'unknown'),
                    'ecosystem': ecosystem or 'unknown',
                    'file_path': file_path,
                    'direct': details.get('direct', True),
                    'scope': details.get('scope', 'runtime'),
                    'dependency_edges': details.get('dependency_edges', []),
                    'digest': None,
                    'commit': None
                }

            # 4. History (audit events, suppressions)
            history_rows = c.execute(
                "SELECT id, actor, action, details, created_at FROM audit_events "
                "WHERE repo=? AND finding_id=? ORDER BY created_at ASC, id ASC",
                (repo, finding_id)
            ).fetchall()
            history = []
            for h in history_rows:
                h_dict = dict(h)
                if isinstance(h_dict['details'], str):
                    try:
                        h_dict['details'] = json.loads(h_dict['details'])
                    except Exception:
                        pass
                history.append(h_dict)

            suppression_row = c.execute(
                "SELECT reason, expires_at FROM suppressions WHERE finding_id=?",
                (finding_id,)
            ).fetchone()
            active_suppression = dict(suppression_row) if suppression_row else None

            # 5. Update alternatives & recommendations
            recommendations = []
            rec = details.get('update_recommendation')
            if rec:
                recommendations.append(rec)

            if adv_id:
                imp_row = c.execute(
                    "SELECT recommendations FROM advisory_impacts WHERE repo=? AND advisory_id=?",
                    (repo, adv_id)
                ).fetchone()
                if imp_row and imp_row['recommendations']:
                    imp_recs = json.loads(imp_row['recommendations'])
                    for r in imp_recs:
                        if r not in recommendations:
                            recommendations.append(r)

            remediation_plan = None
            try:
                rem_row = c.execute(
                    "SELECT id, key, url, created_at FROM remediations WHERE repo=? AND (key LIKE ? OR key LIKE ?)",
                    (repo, f'%"{finding_id}"%', f'%{package_name or ""}%')
                ).fetchone()
                if rem_row:
                    remediation_plan = {
                        'id': rem_row['id'],
                        'plan_key': rem_row['key'],
                        'pr_url': rem_row['url'],
                        'created_at': rem_row['created_at']
                    }
            except Exception:
                pass

            evidence = {
                'file_path': finding_item.get('file_path'),
                'line': details.get('line'),
                'snippet': details.get('snippet'),
                'sink': details.get('sink'),
                'source': details.get('source'),
                'rule_id': details.get('rule_id') or finding_item.get('key'),
                'fingerprint': details.get('fingerprint'),
                'evidence_status': details.get('evidence_status') or finding_item.get('evidence_status'),
                'details': details
            }

            return {
                'id': finding_item['id'],
                'repo': repo,
                'key': finding_item['key'],
                'category': finding_item['category'],
                'severity': finding_item['severity'],
                'title': finding_item['title'],
                'file_path': finding_item['file_path'],
                'commit_sha': finding_item['commit_sha'],
                'status': finding_item['status'],
                'detected_at': finding_item['detected_at'],
                'sha_info': sha_info,
                'evidence': evidence,
                'advisory': advisory_info,
                'package_graph': package_graph,
                'history': history,
                'active_suppression': active_suppression,
                'recommendations': recommendations,
                'remediation_plan': remediation_plan
            }

    def rows(self,table,repo=None,limit=50,cursor=0,status=None,severity=None):
        permission={'findings':'finding.read','scans':'scan.read'}.get(table,'project.read')
        if table not in TABLES or table=='advisory_impacts': raise ValueError('Unsupported customer table')
        if type(limit) is not int or not 1<=limit<=100: raise ValueError('Invalid page limit')
        if type(cursor) is not int or cursor<0: raise ValueError('Invalid cursor')
        with self.access(permission) as c:
            self._repo(c,repo)
            if table=='findings': self._expire_suppressions(c)
            columns=('x.full_name,x.installation_id,x.default_branch,x.last_sha,x.updated_at' if table=='repositories' else 'x.*')
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
            from .freshness import repository_evidence,scan_evidence,finding_view
            cache={}
            for index,item in enumerate(items):
                if table in ('repositories','dependency_inventory'):
                    name=item['full_name'] if table=='repositories' else item['repo']
                    if name not in cache: cache[name]=repository_evidence(c,name)
                    item['evidence_status']=cache[name]
                    if table=='repositories':
                        item['connection_status']='connected' if item.get('installation_id',0)>0 else 'pending'
                elif table=='scans': item['evidence_status']=scan_evidence(c,item,cache)
                elif table=='findings': items[index]=finding_view(c,item,cache)
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
            from .freshness import scan_evidence,finding_view
            scan['evidence_status']=scan_evidence(c,scan)
            scan['findings']=[finding_view(c,{**finding,'repo':scan['repo']}) for finding in scan['findings']]
            if export:
                self.store.audit_event(scan['repo'],None,self.user_id,'scan_export_requested',
                    {'organization_id':self.organization_id,'scan_id':scan_id})
            return scan

    def remediation_plans(self, repo=None, status=None, limit=50, cursor=0):
        with self.access('project.read') as c:
            self._repo(c, repo)
            if self.store.backend == 'sqlite':
                try:
                    self.store._ensure_patch_validations_table(c)
                    self.store._ensure_patch_approvals_table(c)
                except Exception:
                    pass

            # 1. Published remediations
            sql, args = self.query('remediations')
            if repo is not None:
                sql += ' AND x.repo=?'
                args.append(repo)
            published_rows = c.execute(sql + ' ORDER BY x.id DESC', args).fetchall()
            published_items = []
            published_keys = set()
            for r in published_rows:
                r_dict = dict(r)
                r_dict['status'] = 'published'
                r_dict['plan_id'] = r_dict['key']
                published_items.append(r_dict)
                published_keys.add(r_dict['key'])

            # 2. Validated and pending patch plans
            v_rows = []
            try:
                v_sql, v_args = self.query('repositories', 'x.full_name')
                if repo is not None:
                    v_sql += ' AND x.full_name=?'
                    v_args.append(repo)
                v_rows = c.execute(
                    f'''SELECT v.repo, v.plan_id, v.all_checks_passed, v.validated_at, v.evidence
                        FROM patch_validations v JOIN ({v_sql}) r ON r.full_name=v.repo''',
                    v_args
                ).fetchall()
            except Exception:
                pass

            categorized = {
                'pending_approval': [],
                'validated': [],
                'blocked': [],
                'published': published_items
            }

            for v in v_rows:
                v_dict = dict(v)
                p_id = v_dict['plan_id']
                p_repo = v_dict['repo']
                evidence = json.loads(v_dict['evidence']) if isinstance(v_dict['evidence'], str) else v_dict['evidence']

                if any(p_id in pk for pk in published_keys):
                    continue

                appr_row = c.execute(
                    'SELECT user_id, baseline_sha, diff_sha256, approved_at, status, invalidation_reason FROM patch_approvals WHERE repo=? AND plan_id=?',
                    (p_repo, p_id)
                ).fetchone()
                approval = dict(appr_row) if appr_row else None

                all_passed = bool(v_dict['all_checks_passed'])
                blockers = list(evidence.get('blockers', []))

                repo_info = c.execute('SELECT last_sha FROM repositories WHERE full_name=?', (p_repo,)).fetchone()
                current_head = repo_info['last_sha'] if repo_info else None
                baseline_sha = evidence.get('baseline_sha')
                if current_head and baseline_sha and current_head != baseline_sha:
                    blockers.append('baseline_head_drift_detected')

                plan_entry = {
                    'plan_id': p_id,
                    'repo': p_repo,
                    'baseline_sha': baseline_sha,
                    'validated_at': v_dict['validated_at'],
                    'all_checks_passed': all_passed,
                    'approval': approval,
                    'blockers': sorted(set(blockers)),
                    'evidence': evidence
                }

                if not all_passed or blockers:
                    plan_entry['status'] = 'blocked'
                    categorized['blocked'].append(plan_entry)
                elif approval and approval.get('status') == 'approved':
                    plan_entry['status'] = 'validated'
                    categorized['validated'].append(plan_entry)
                else:
                    plan_entry['status'] = 'pending_approval'
                    categorized['pending_approval'].append(plan_entry)

            summary = {
                'pending_approval': len(categorized['pending_approval']),
                'validated': len(categorized['validated']),
                'blocked': len(categorized['blocked']),
                'published': len(categorized['published']),
                'total': sum(len(lst) for lst in categorized.values())
            }

            if status and status in categorized:
                selected_items = categorized[status]
            else:
                selected_items = (
                    categorized['pending_approval'] +
                    categorized['validated'] +
                    categorized['blocked'] +
                    categorized['published']
                )

            paginated = selected_items[cursor:cursor + limit]
            truncated = len(selected_items) > cursor + limit
            next_cursor = cursor + limit if truncated else None

            return {
                'items': paginated,
                'summary': summary,
                'categorized': categorized,
                'truncated': truncated,
                'next_cursor': next_cursor
            }

    def disconnect_repository(self, repo: str) -> dict:
        with self.access('project.read') as c:
            self._repo(c, repo)
        from .identity import Identities
        return Identities(self.store).remove_repository_ownership(self.organization_id, repo, self.user_id)

    def approve_patch(self, repo: str, plan_id: str, baseline_sha: str, diff_sha256: str) -> dict:
        with self.access('finding.triage') as c:
            self._repo(c, repo)
            if self.store.backend == 'sqlite':
                try:
                    self.store._ensure_patch_approvals_table(c)
                except Exception:
                    pass
            self.store.record_patch_approval(repo, plan_id, self.user_id, baseline_sha, diff_sha256)
            self.store.audit_event(
                repo,
                None,
                self.user_id,
                'patch_approved',
                {'plan_id': plan_id, 'baseline_sha': baseline_sha, 'diff_sha256': diff_sha256}
            )
            return {
                'plan_id': plan_id,
                'repo': repo,
                'status': 'approved',
                'approved_by': self.user_id,
                'baseline_sha': baseline_sha,
                'diff_sha256': diff_sha256
            }

    def list_notification_channels(self) -> list[dict]:
        with self.access('project.read') as c:
            if self.store.backend == 'sqlite':
                try: self.store._ensure_notifications_table(c)
                except Exception: pass
            try:
                rows = c.execute(
                    'SELECT id, organization_id, name, kind, target, events, enabled, created_at, updated_at FROM notification_channels WHERE organization_id=? ORDER BY created_at ASC',
                    (self.organization_id,)
                ).fetchall()
                res = []
                for r in rows:
                    item = dict(r)
                    item['events'] = json.loads(item['events']) if isinstance(item['events'], str) else item['events']
                    item['enabled'] = bool(item['enabled'])
                    res.append(item)
                return res
            except Exception:
                return []

    def create_notification_channel(self, name: str, kind: str, target: str, events: list[str], enabled: bool = True) -> dict:
        import uuid
        from .notifications import validate_channel_target, SUPPORTED_CHANNELS
        if kind not in SUPPORTED_CHANNELS:
            raise ValueError(f'Invalid channel kind: {kind}')
        validate_channel_target(kind, target)
        if not name or len(name) > 100:
            raise ValueError('Invalid channel name')
        now = time.time()
        channel_id = 'chan_' + uuid.uuid4().hex[:16]
        with self.access('finding.triage') as c:
            if self.store.backend == 'sqlite':
                try: self.store._ensure_notifications_table(c)
                except Exception: pass
            c.execute(
                '''INSERT INTO notification_channels (id, organization_id, name, kind, target, events, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (channel_id, self.organization_id, name, kind, target, json.dumps(events), 1 if enabled else 0, now, now)
            )
            self.store.audit_event(
                'org:' + self.organization_id, None, self.user_id, 'notification_channel_created',
                {'channel_id': channel_id, 'name': name, 'kind': kind}
            )
            return {
                'id': channel_id,
                'organization_id': self.organization_id,
                'name': name,
                'kind': kind,
                'target': target,
                'events': events,
                'enabled': enabled,
                'created_at': now,
                'updated_at': now
            }

    def update_notification_channel(self, channel_id: str, name: str, target: str, events: list[str], enabled: bool) -> dict:
        with self.access('finding.triage') as c:
            if self.store.backend == 'sqlite':
                try: self.store._ensure_notifications_table(c)
                except Exception: pass
            row = c.execute(
                'SELECT * FROM notification_channels WHERE id=? AND organization_id=?',
                (channel_id, self.organization_id)
            ).fetchone()
            if not row:
                raise ResourceNotFound('Notification channel not found')
            kind = row['kind']
            from .notifications import validate_channel_target
            validate_channel_target(kind, target)
            now = time.time()
            c.execute(
                '''UPDATE notification_channels SET name=?, target=?, events=?, enabled=?, updated_at=?
                   WHERE id=? AND organization_id=?''',
                (name, target, json.dumps(events), 1 if enabled else 0, now, channel_id, self.organization_id)
            )
            self.store.audit_event(
                'org:' + self.organization_id, None, self.user_id, 'notification_channel_updated',
                {'channel_id': channel_id, 'name': name}
            )
            return {
                'id': channel_id,
                'organization_id': self.organization_id,
                'name': name,
                'kind': kind,
                'target': target,
                'events': events,
                'enabled': enabled,
                'created_at': row['created_at'],
                'updated_at': now
            }

    def delete_notification_channel(self, channel_id: str) -> None:
        with self.access('finding.triage') as c:
            if self.store.backend == 'sqlite':
                try: self.store._ensure_notifications_table(c)
                except Exception: pass
            row = c.execute(
                'SELECT * FROM notification_channels WHERE id=? AND organization_id=?',
                (channel_id, self.organization_id)
            ).fetchone()
            if not row:
                raise ResourceNotFound('Notification channel not found')
            c.execute('DELETE FROM notification_channels WHERE id=? AND organization_id=?',
                      (channel_id, self.organization_id))
            self.store.audit_event(
                'org:' + self.organization_id, None, self.user_id, 'notification_channel_deleted',
                {'channel_id': channel_id}
            )

    async def test_notification_channel(self, channel_id: str) -> dict:
        with self.access('finding.triage') as c:
            if self.store.backend == 'sqlite':
                try: self.store._ensure_notifications_table(c)
                except Exception: pass
            row = c.execute(
                'SELECT * FROM notification_channels WHERE id=? AND organization_id=?',
                (channel_id, self.organization_id)
            ).fetchone()
            if not row:
                raise ResourceNotFound('Notification channel not found')
            channel = dict(row)
            channel['events'] = json.loads(channel['events']) if isinstance(channel['events'], str) else channel['events']
            from .notifications import NotificationDispatcher
            dispatcher = NotificationDispatcher()
            result = await dispatcher.dispatch(
                channel,
                'test_ping',
                'Test Notification from VulnForge',
                {'message': 'This is a test notification verifying your channel configuration.', 'status': 'ok'}
            )
            return result

    def impacts(self,repo=None,advisory_id=None,state=None,cursor=0,limit=50,ecosystem=None,package=None,assigned_to=None):
        with self.access('impact.read') as c:
            self._repo(c,repo)
            scope='org:'+self.organization_id
            sql,args=self.query('advisory_impacts')
            sql+=" AND x.id>? AND EXISTS (SELECT 1 FROM advisories a WHERE a.id=x.advisory_id AND a.catalog_scope IN ('public',?))"
            args.extend([cursor,scope])
            for column,value in (('repo',repo),('state',state)):
                if value is not None: sql+=' AND x.'+column+'=?';args.append(value)
            if advisory_id is not None:
                sql+=" AND EXISTS (SELECT 1 FROM advisory_aliases a WHERE a.advisory_id=x.advisory_id AND a.alias=? AND a.catalog_scope IN ('public',?))"
                args.extend([advisory_id,scope])
            if package is not None:
                sql+=" AND (x.recommendations LIKE ? OR x.evidence LIKE ?)"
                args.extend([f'%"{package}"%', f'%"{package}"%'])
            if ecosystem is not None:
                sql+=" AND (x.recommendations LIKE ? OR x.evidence LIKE ?)"
                args.extend([f'%"{ecosystem}"%', f'%"{ecosystem}"%'])
            if assigned_to is not None:
                if assigned_to == 'unassigned':
                    sql+=" AND (x.evidence NOT LIKE '%\"assigned_to\"%' OR x.evidence LIKE '%\"assigned_to\": null%')"
                else:
                    sql+=" AND x.evidence LIKE ?"
                    args.append(f'%"assigned_to": "{assigned_to}"%')
            rows=c.execute(sql+' ORDER BY x.id LIMIT ?',args+[limit+1]).fetchall()
            items=self.decode(rows[:limit],('evidence','recommendations'))
            from .freshness import impact_view
            cache={}
            items=[impact_view(c,item,cache) for item in items]
            for item in items:
                item['assigned_to'] = item.get('evidence', {}).get('assigned_to')
            return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None,
                    'filter_scope':'observed_state'}

    def assign_impact(self, impact_id: int, assigned_to: str | None) -> dict:
        with self.access('finding.triage') as c:
            sql, args = self.query('advisory_impacts')
            row = c.execute(sql + ' AND x.id=?', args + [impact_id]).fetchone()
            if row is None:
                raise ResourceNotFound('Impact not found')

            if assigned_to is not None:
                m_row = c.execute(
                    'SELECT user_id, role FROM memberships WHERE organization_id=? AND user_id=?',
                    (self.organization_id, assigned_to)
                ).fetchone()
                if m_row is None:
                    raise ResourceNotFound('Assignee is not a member of this organization')

            item = self.decode([row], ('evidence', 'recommendations'))[0]
            repo = item['repo']
            advisory_id = item['advisory_id']
            evidence = item.get('evidence', {})
            previous_assignee = evidence.get('assigned_to')
            evidence['assigned_to'] = assigned_to

            revisions = list(evidence.get('_revisions', []))
            revisions.append({
                'revision': len(revisions) + 1,
                'state': item['state'],
                'scan_id': item['scan_id'],
                'assigned_to': assigned_to,
                'previous_assigned_to': previous_assignee,
                'change': 'assigned' if assigned_to else 'unassigned',
                'actor_id': self.user_id,
                'updated_at': time.time()
            })
            evidence['_revisions'] = revisions[-50:]

            c.execute(
                'UPDATE advisory_impacts SET evidence=?, updated_at=? WHERE id=? AND repo=?',
                (json.dumps(evidence, sort_keys=True), time.time(), impact_id, repo)
            )

            self.store.audit_event(
                repo,
                impact_id,
                self.user_id,
                'impact_assigned',
                {
                    'organization_id': self.organization_id,
                    'advisory_id': advisory_id,
                    'assigned_to': assigned_to,
                    'previous_assigned_to': previous_assignee
                }
            )

            return {
                'id': impact_id,
                'repo': repo,
                'advisory_id': advisory_id,
                'assigned_to': assigned_to,
                'previous_assigned_to': previous_assignee,
                'updated_at': time.time()
            }

    def impact_history(self, impact_id: int) -> dict:
        with self.access('impact.read') as c:
            sql, args = self.query('advisory_impacts')
            row = c.execute(sql + ' AND x.id=?', args + [impact_id]).fetchone()
            if row is None:
                raise ResourceNotFound('Impact not found')

            item = self.decode([row], ('evidence', 'recommendations'))[0]
            repo = item['repo']
            advisory_id = item['advisory_id']
            evidence = item.get('evidence', {})
            revisions = list(evidence.get('_revisions', []))

            timeline = []
            for i, rev in enumerate(revisions):
                prev_rev = revisions[i - 1] if i > 0 else None
                diff = {}
                if prev_rev:
                    if prev_rev.get('state') != rev.get('state'):
                        diff['state_changed'] = {'from': prev_rev.get('state'), 'to': rev.get('state')}
                    if prev_rev.get('assigned_to') != rev.get('assigned_to'):
                        diff['assignment_changed'] = {'from': prev_rev.get('assigned_to'), 'to': rev.get('assigned_to')}
                else:
                    diff['initial_state'] = rev.get('state')

                timeline.append({
                    'revision': rev.get('revision', i + 1),
                    'state': rev.get('state'),
                    'assigned_to': rev.get('assigned_to'),
                    'updated_at': rev.get('updated_at'),
                    'diff': diff,
                    'scan_id': rev.get('scan_id'),
                    'recommendation_count': len(rev.get('recommendations') or [])
                })

            return {
                'id': impact_id,
                'repo': repo,
                'advisory_id': advisory_id,
                'current_state': item['state'],
                'current_assigned_to': evidence.get('assigned_to'),
                'total_revisions': len(revisions),
                'timeline': timeline
            }

    def advisories(self,limit=50):
        with self.access('impact.read') as c:
            scope='org:'+self.organization_id
            # Count only this org's projects, never reuse global advisory counters.
            rows=c.execute('''SELECT a.id,a.aliases,a.summary,a.source,a.withdrawn,a.first_seen_at,a.updated_at,
                SUM(CASE WHEN i.state='affected' THEN 1 ELSE 0 END) AS affected_projects,
                SUM(CASE WHEN i.state='under_investigation' THEN 1 ELSE 0 END) AS pending_projects
                FROM advisories a JOIN advisory_impacts i ON i.advisory_id=a.id
                JOIN repository_ownership o ON o.repo=i.repo WHERE o.organization_id=?
                AND a.catalog_scope IN ('public',?)
                AND EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id=o.organization_id AND m.user_id=?)
                GROUP BY a.id,a.aliases,a.summary,a.source,a.withdrawn,a.first_seen_at,a.updated_at
                ORDER BY a.updated_at DESC,a.id LIMIT ?''',(self.organization_id,scope,self.user_id,limit)).fetchall()
            return self.decode(rows,('aliases',))

    def triage(self,finding_id,status,reason,expires_at=None):
        if status not in ('open','resolved','false_positive','risk_accepted','suppressed'):
            raise ValueError('Invalid triage state')
        if not isinstance(reason,str) or not 5<=len(reason)<=2000: raise ValueError('Triage reason required')
        safe_metadata(reason)
        timed=status in ('suppressed','risk_accepted')
        if timed and (type(expires_at) not in (int,float) or not time.time()<expires_at<=time.time()+366*86400):
            raise ValueError('Suppression or risk acceptance expiry must be within the next year')
        if not timed and expires_at is not None:
            raise ValueError('Expiry applies only to suppression or risk acceptance')
        permission={'suppressed':'finding.suppress','risk_accepted':'finding.accept_risk'}.get(status,'finding.triage')
        with self.access(permission) as c:
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
