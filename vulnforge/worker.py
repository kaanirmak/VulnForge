"""Background processor. Run as separate process: python -m vulnforge.worker."""
import asyncio
import hashlib
import json
import logging
import time
import ast
from dataclasses import asdict

from .config import Config
from .db import Store, StaleJob
from .dependencies import inventory_manifest, Dependency
from .github import GitHub
from .osv import OSV
from .kev import KEV
from .scanner import scan_code
from .intelligence import recommend_updates, advisory_identity, github_matches

log=logging.getLogger('vulnforge')
CODE_SUFFIXES=('.py','.js','.jsx','.ts','.tsx','.env','.json','.yaml','.yml','.toml')


class Agent:
    def __init__(self, cfg: Config, store: Store, github: GitHub, osv: OSV,
                 kev: KEV | None = None):
        self.cfg, self.store, self.github, self.osv, self.kev = cfg, store, github, osv, kev

    async def process(self, job):
        # The server-populated queue snapshot is authoritative, never payload
        # organization/installation fields. Network waits hold no DB locks.
        from .job import GuardedProvider, JobStore
        if self.cfg.intelligence_mode=='private_osv':
            from .privacy import PrivacyError
            raise PrivacyError('Private queued intelligence requires a namespaced advisory catalog')
        original=self.github,self.osv,self.kev
        store=self.store
        check=lambda:store.check_job(job)
        with store.job_scope(job):
            self.store=JobStore(store,job)
            self.github=GuardedProvider(original[0],check)
            self.osv=GuardedProvider(original[1],check)
            self.kev=GuardedProvider(original[2],check) if original[2] else None
            try:
                await self._process(job)
            finally:
                self.github,self.osv,self.kev=original
                self.store=store

    async def _process(self,job):
        repo=job['repo']
        payload=json.loads(job['payload'])
        row=self.store.repository(repo)
        if row is None:
            log.warning('Skipping missing/uninstalled repo %s',repo)
            return
        installation_id=row['installation_id']
        if job['kind']=='push':
            await self.push(repo,installation_id,row['default_branch'],payload)
        elif job['kind']=='commit_scan':
            await self.scan_commit(repo,installation_id,payload['sha'])
        elif job['kind']=='pull_request_scan':
            await self.scan_commit(repo,installation_id,payload['sha'],payload['number'])
            await self.audit(repo,installation_id,row['default_branch'],snapshot_sha=payload['sha'])
        elif job['kind']=='dependency_audit':
            await self.audit(repo,installation_id,row['default_branch'],trigger_advisory=payload.get('advisory_id'))
        else:
            raise ValueError('Unknown job kind')

    async def push(self, repo: str, installation_id: int, default_branch: str, payload: dict):
        self.cfg.require_source_access()
        shas=await self.github.commit_shas(repo,installation_id,payload['before'],payload['after'],
                                           payload.get('commits', []))
        for sha in shas:
            self.store.enqueue('commit_scan',repo,{'sha':sha},f'commit:{repo}:{sha}')
        # Dependency inventory must refer to current protected default branch, not arbitrary feature pushes.
        if payload.get('ref')==f'refs/heads/{default_branch}':
            self.store.enqueue('dependency_audit',repo,{},f'audit:push:{repo}:{payload["after"]}')

    async def scan_commit(self, repo: str, installation_id: int, sha: str, pr_number=None):
        self.cfg.require_source_access()
        scan_id=self.store.start_scan(repo,'pull_request' if pr_number else 'commit',sha)
        coverage={'files_total':0,'files_scanned':0,'files_skipped':0,'issues':[], 'scope':'changed_files'}
        try:
            files=(await self.github.pull_files(repo,installation_id,pr_number,sha) if pr_number
                   else await self.github.changed_files(repo,installation_id,sha))
            coverage['files_total']=len(files)
            await self._scan_files(repo,installation_id,sha,files,scan_id,coverage,persist=not pr_number)
        except Exception:
            coverage['issues'].append({'reason':'provider_or_analysis_error'})
            coverage['files_unprocessed']=coverage['files_total']-coverage['files_scanned']-coverage['files_skipped']
            self.store.finish_scan(scan_id,'failed',coverage)
            raise
        state='incomplete' if coverage['issues'] else 'complete'
        self.store.finish_scan(scan_id,state,coverage)
        if self.cfg.enable_checks:
            await self.github.publish_check(repo,installation_id,self.store.scan(scan_id))

    async def _scan_files(self, repo, installation_id, sha, files, scan_id, coverage, persist=True):
        for item in files:
            path=item.get('filename','')
            if item.get('status')=='removed' or not path.endswith(CODE_SUFFIXES):
                coverage['files_skipped']+=1
                if item.get('status')!='removed':
                    coverage['issues'].append({'path':path,'reason':'unsupported_file_type'})
                continue
            file=await self.github.get_file(repo,installation_id,path,sha)
            if not file:
                coverage['files_skipped']+=1
                coverage['issues'].append({'path':path,'reason':'content_unavailable'})
                key='coverage:'+hashlib.sha256(f'{sha}:{path}'.encode()).hexdigest()[:24]
                f={'key':key,'category':'coverage','severity':'info',
                   'title':'File not analyzed: unreadable, binary or exceeds size limit',
                   'file_path':path,'details':{'reason':'content unavailable; do not infer this file is safe'}}
                self.store.record_scan_finding(scan_id,f)
                if persist:
                    self.store.save_finding(repo,key,'coverage','info',f['title'],path,sha,f['details'])
                continue
            if len(file['text'])>300_000 or len(file['text'].splitlines())>10000:
                coverage['files_skipped']+=1
                coverage['issues'].append({'path':path,'reason':'scanner_limit'})
                continue
            if path.endswith('.py'):
                try: ast.parse(file['text'])
                except SyntaxError:
                    coverage['issues'].append({'path':path,'reason':'python_parse_error'})
            coverage['files_scanned']+=1
            for f in scan_code(path,file['text']):
                self.store.record_scan_finding(scan_id,f)
                if persist:
                    self.store.save_finding(repo,f['key'],'code',f['severity'],f['title'],
                                            path,sha,f['details'])

    async def audit(self, repo: str, installation_id: int, default_branch: str, snapshot_sha=None, trigger_advisory=None):
        scan_id=self.store.start_scan(repo,'pr_dependencies' if snapshot_sha else 'dependencies',snapshot_sha)
        coverage={'files_total':0,'files_scanned':0,'files_skipped':0,'issues':[], 'manifests':[], 'scope':'dependency_manifests'}
        if trigger_advisory: coverage['trigger_advisory']=trigger_advisory
        deps=[]
        try:
            self.cfg.require_source_access()
            await self._audit(repo,installation_id,default_branch,scan_id,coverage,deps,snapshot_sha)
        except Exception:
            coverage['issues'].append({'reason':'inventory_or_feed_error'})
            self.store.finish_scan(scan_id,'failed',coverage,[asdict(d) for d in deps])
            if not snapshot_sha: self.store.invalidate_impacts(repo,scan_id)
            raise
        if self.cfg.enable_checks:
            await self.github.publish_check(repo,installation_id,self.store.scan(scan_id))

    async def _audit(self, repo, installation_id, default_branch, scan_id, coverage, deps, snapshot_sha):
        actual_branch=await self.github.default_branch(repo,installation_id)
        if actual_branch!=default_branch:
            self.store.upsert_repo(repo,installation_id,actual_branch)
            default_branch=actual_branch
        head=snapshot_sha or await self.github.branch_head(repo,installation_id,default_branch)
        self.store.set_scan_commit(scan_id,head)
        paths=await self.github.manifest_paths(repo,installation_id,head)
        coverage['files_total']=len(paths)
        if not paths:
            coverage['issues'].append({'reason':'no_supported_manifests'})
        files={}
        for path in paths:
            file=await self.github.get_file(repo,installation_id,path,head)
            if file is None:
                coverage['files_skipped']+=1
                coverage['issues'].append({'path':path,'reason':'manifest_content_unavailable'})
                continue
            files[path]=file
            try:
                result=inventory_manifest(path,file['text'])
                deps.extend(result.dependencies)
                coverage['issues'].extend(result.issues)
                coverage['files_scanned']+=1
                coverage['manifests'].append({'path':path,'sha256':hashlib.sha256(file['text'].encode()).hexdigest()})
            except (ValueError,TypeError,KeyError,AttributeError) as exc:
                coverage['files_skipped']+=1
                coverage['issues'].append({'path':path,'reason':'manifest_parse_error','error_type':type(exc).__name__})
        if len(deps)>1500:
            raise RuntimeError('Dependency inventory exceeds 1500 packages; split audit required')
        affected=await self.osv.check(deps)
        source_negatives=set()
        if not snapshot_sha:
            previous_ids=self.store.impact_advisory_ids(repo)
            for saved in self.store.source_advisories():
                state,matches=github_matches(saved,deps)
                affected.extend(matches)
                if state=='not_affected' and saved['id'] in previous_ids: source_negatives.add(saved['id'])
        grouped={}
        for dep,advisory in affected:
            previous=self.store.advisory(advisory_identity(advisory))
            if previous and previous['withdrawn']: continue
            grouped.setdefault(dep,[]).append(advisory)
        recommendations=await recommend_updates(grouped,self.osv) if not snapshot_sha else {}
        # KEV can only prioritize version-confirmed affected packages. Fail the
        # audit rather than falsely label anything "not known exploited" if an
        # operator enabled KEV but its catalog is inaccessible.
        kev_entries = await self.kev.entries() if self.kev is not None else None
        if not snapshot_sha and await self.github.branch_head(repo,installation_id,default_branch)!=head:
            coverage['issues'].append({'reason':'default_branch_moved'})
        complete=not coverage['issues']
        with self.store.transaction():
            if not snapshot_sha and complete:
                self.store.replace_inventory(repo,deps)
            seen=set()
            impacts={}
            for dep,advisory in affected:
                canonical=(advisory_identity(advisory) if advisory.get('_evidence_source')=='GitHub webhook'
                           else self.store.save_advisory(advisory))
                if self.store.advisory(canonical)['withdrawn']: continue
                id_=advisory['id']
                key='dep:'+hashlib.sha256(f'{dep.file_path}:{dep.ecosystem}:{dep.name}:{dep.version}:{id_}'.encode()).hexdigest()[:32]
                seen.add(key)
                aliases=advisory.get('aliases',[])
                cvss = advisory.get('severity',[])
                kev_match = KEV.match(advisory, kev_entries) if kev_entries is not None else None
                severity = 'critical' if kev_match else ('high' if cvss else 'medium')
                details={'osv_id':id_,'advisory_id':canonical,'aliases':aliases,'package':dep.name,'version':dep.version,
                     'ecosystem':dep.ecosystem,'summary':advisory.get('summary','')[:500],
                     'reference':(f'https://github.com/advisories/{canonical}' if advisory.get('_evidence_source')=='GitHub webhook'
                                  else f'https://osv.dev/vulnerability/{id_}'),
                     'known_exploited': bool(kev_match) if kev_entries is not None else None,
                     'kev': kev_match,
                     'priority_note': ('CISA KEV: known exploited in the wild; prioritize review'
                                       if kev_match else 'Severity is a heuristic, not a verified CVSS score'),
                     'impact_status':'affected','reachability':'unknown','scan_id':scan_id,
                     'source':advisory.get('_evidence_source','OSV'),'observed_at':time.time(),'advisory_modified':advisory.get('modified'),
                     'advisory_sha256':self.store.advisory(canonical)['source_sha256'],
                     'cvss_vectors':cvss,'epss':None,
                     'update_recommendation':recommendations.get(dep)}
                title=f'{dep.name}@{dep.version} affected by {id_}'
                self.store.record_scan_finding(scan_id,{'key':key,'category':'dependency','severity':severity,
                    'title':title,'file_path':dep.file_path,'details':details})
                if not snapshot_sha:
                    self.store.save_finding(repo,key,'dependency',severity,title,dep.file_path,head,details)
                impact=impacts.setdefault(canonical,{'dependencies':[],'recommendations':[],
                    'source':advisory.get('_evidence_source','OSV')})
                if asdict(dep) not in impact['dependencies']:
                    impact['dependencies'].append(asdict(dep))
                    if dep in recommendations:
                        impact['recommendations'].append(recommendations[dep])
            if complete and not snapshot_sha:
                self.store.resolve_missing_dependencies(repo,seen)
            if not snapshot_sha:
                for canonical,impact in impacts.items():
                    self.store.save_impact(repo,canonical,'affected',scan_id,
                        {'dependencies':impact['dependencies'],'commit_sha':head,'coverage_complete':complete,
                         'reachability':'unknown','version_affected':True,'source':impact['source'],
                         'advisory_sha256':self.store.advisory(canonical)['source_sha256']},
                        impact['recommendations'])
                confirmed_negatives=source_negatives-set(impacts) if complete else set()
                for canonical in confirmed_negatives:
                    self.store.save_impact(repo,canonical,'not_affected',scan_id,
                        {'reason':'outside_published_range_or_package_absent','source':'GitHub webhook',
                         'commit_sha':head,'coverage_complete':True,'reachability':'unknown',
                         'advisory_sha256':self.store.advisory(canonical)['source_sha256']},[])
                self.store.reconcile_impacts(repo,scan_id,set(impacts)|confirmed_negatives,complete)
            self.store.finish_scan(scan_id,'complete' if complete else 'incomplete',coverage,[asdict(d) for d in deps],head)
            if self.cfg.enable_auto_pr and not complete and not snapshot_sha:
                self.store.audit_event(repo,None,'system','remediation_blocked',{'scan_id':scan_id,'reason':'incomplete_inventory'})
        if self.cfg.enable_auto_pr and complete and not snapshot_sha:
            await self.maybe_propose_patches(repo,installation_id,default_branch,head,files,grouped)
        log.info('Audited %s: %d dependencies; %d affected entries',repo,len(deps),len(affected))

    async def maybe_propose_patches(self, repo, install, base, checked_head, files,
                                    grouped: dict[Dependency,list[dict]]):
        policy=self.store.remediation_policy(repo)
        self.store.audit_event(repo,None,'system','remediation_blocked',
            {'reason':'repository_opt_in_required' if policy is None else 'isolated_validation_and_bound_approval_required'})
        # Repository opt-in is necessary but does not prove resolver/build/test
        # validation or SHA+diff-bound human approval. Keep publication closed
        # until VF-063–069 provide those proofs.


async def run_worker():
    cfg=Config.from_env()
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    if cfg.source_access_allowed and (not cfg.app_id or not cfg.private_key_path):
        raise SystemExit('Configure GITHUB_APP_ID and GITHUB_PRIVATE_KEY_PATH before starting worker')
    store=Store(cfg.database_target,migrate=cfg.database_auto_migrate)
    last_schedule=0.0
    while True:
        if time.monotonic()-last_schedule>60:
            store.schedule_due(cfg.scan_interval_seconds)
            last_schedule=time.monotonic()
        job=store.claim()
        if not job:
            await asyncio.sleep(2)
            continue
        await execute_job(cfg,store,job)


async def execute_job(cfg,store,job):
    """No credential, HTTP cookie or advisory cache survives a queue job."""
    from contextlib import AsyncExitStack
    try:
        store.check_job(job)
        async with AsyncExitStack() as stack:
            github=GitHub(cfg)
            stack.push_async_callback(github.close)
            github.bind_job(job,lambda:store.check_job(job))
            osv=OSV(cfg.osv_api_url,policy=cfg.metadata_policy())
            stack.push_async_callback(osv.close)
            kev=KEV() if cfg.enable_kev else None
            if kev: stack.push_async_callback(kev.close)
            await run_leased_job(store,job,Agent(cfg,store,github,osv,kev).process(job))
        store.finish(job)
    except StaleJob:
        store.discard_job(job)
        log.info('Job %d cancelled: authorization expired',job['id'])
    except Exception as exc:
        # Provider exception messages may contain private package names, URLs
        # or source fragments. Persist/log only the error class.
        log.warning('Job %d failed (%s)',job['id'],type(exc).__name__)
        try:
            store.finish(job,type(exc).__name__)
        except StaleJob:
            store.discard_job(job)


async def run_leased_job(store,job,work,*,heartbeat=60,timeout=1800):
    """Renew only the live claim, cancel work on revocation, bound total duration."""
    async def renew():
        while True:
            await asyncio.sleep(heartbeat)
            # A DB operation must not block the asyncio provider event loop.
            await asyncio.to_thread(store.renew_job,job)
    task=asyncio.create_task(work)
    lease=asyncio.create_task(renew())
    try:
        async with asyncio.timeout(timeout):
            done,_=await asyncio.wait((task,lease),return_when=asyncio.FIRST_COMPLETED)
            if lease in done: lease.result()
            return task.result()
    finally:
        task.cancel();lease.cancel()
        await asyncio.gather(task,lease,return_exceptions=True)


if __name__=='__main__':
    asyncio.run(run_worker())
