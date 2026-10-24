"""Background processor. Run as separate process: python -m vulnforge.worker."""
import asyncio
import hashlib
import json
import logging
import time

from .config import Config
from .db import Store
from .dependencies import parse_manifest, Dependency
from .github import GitHub
from .osv import OSV
from .kev import KEV
from .remediation import patched_requirement, candidate_version, remediation_key, branch_for
from .scanner import scan_code

log=logging.getLogger('vulnforge')
CODE_SUFFIXES=('.py','.js','.jsx','.ts','.tsx','.env','.json','.yaml','.yml','.toml')


class Agent:
    def __init__(self, cfg: Config, store: Store, github: GitHub, osv: OSV,
                 kev: KEV | None = None):
        self.cfg, self.store, self.github, self.osv, self.kev = cfg, store, github, osv, kev

    async def process(self, job):
        repo=job['repo']
        payload=json.loads(job['payload'])
        with self.store.conn() as c:
            row=c.execute('SELECT * FROM repositories WHERE full_name=?',(repo,)).fetchone()
        if row is None:
            log.warning('Skipping missing/uninstalled repo %s',repo)
            return
        installation_id=row['installation_id']
        if job['kind']=='push':
            await self.push(repo,installation_id,row['default_branch'],payload)
        elif job['kind']=='commit_scan':
            await self.scan_commit(repo,installation_id,payload['sha'])
        elif job['kind']=='dependency_audit':
            await self.audit(repo,installation_id,row['default_branch'])
        else:
            raise ValueError('Unknown job kind')

    async def push(self, repo: str, installation_id: int, default_branch: str, payload: dict):
        shas=await self.github.commit_shas(repo,installation_id,payload['before'],payload['after'],
                                           payload.get('commits', []))
        for sha in shas:
            self.store.enqueue('commit_scan',repo,{'sha':sha},f'commit:{repo}:{sha}')
        # Dependency inventory must refer to current protected default branch, not arbitrary feature pushes.
        if payload.get('ref')==f'refs/heads/{default_branch}':
            self.store.enqueue('dependency_audit',repo,{},f'audit:push:{repo}:{payload["after"]}')

    async def scan_commit(self, repo: str, installation_id: int, sha: str):
        files=await self.github.changed_files(repo,installation_id,sha)
        for item in files:
            path=item.get('filename','')
            if item.get('status')=='removed' or not path.endswith(CODE_SUFFIXES):
                continue
            file=await self.github.get_file(repo,installation_id,path,sha)
            if not file:
                key='coverage:'+hashlib.sha256(f'{sha}:{path}'.encode()).hexdigest()[:24]
                self.store.save_finding(repo,key,'coverage','info',
                    'File not analyzed: unreadable, binary or exceeds size limit',path,sha,
                    {'reason':'content unavailable; do not infer this file is safe'})
                continue
            for f in scan_code(path,file['text']):
                self.store.save_finding(repo,f['key'],'code',f['severity'],f['title'],
                                        path,sha,f['details'])

    async def audit(self, repo: str, installation_id: int, default_branch: str):
        actual_branch=await self.github.default_branch(repo,installation_id)
        if actual_branch!=default_branch:
            self.store.upsert_repo(repo,installation_id,actual_branch)
            default_branch=actual_branch
        head=await self.github.branch_head(repo,installation_id,default_branch)
        paths=await self.github.manifest_paths(repo,installation_id,head)
        files={}
        deps=[]
        for path in paths:
            file=await self.github.get_file(repo,installation_id,path,head)
            if file is None:
                # Do not falsely resolve findings after skipping a potentially large lockfile.
                raise RuntimeError(f'Cannot load manifest {path}: too large or unsupported')
            files[path]=file
            try:
                deps += parse_manifest(path,file['text'])
            except (ValueError,TypeError,KeyError) as exc:
                raise RuntimeError(f'Cannot parse manifest {path}: {type(exc).__name__}') from exc
        if len(deps)>1500:
            raise RuntimeError('Dependency inventory exceeds 1500 packages; split audit required')
        affected=await self.osv.check(deps)
        # KEV can only prioritize affected packages proven by OSV. Fail the
        # audit rather than falsely label anything "not known exploited" if an
        # operator enabled KEV but its catalog is inaccessible.
        kev_entries = await self.kev.entries() if self.kev is not None else None
        self.store.replace_inventory(repo,deps)
        seen=set()
        grouped={}
        for dep,advisory in affected:
            id_=advisory['id']
            key='dep:'+hashlib.sha256(f'{dep.file_path}:{dep.ecosystem}:{dep.name}:{dep.version}:{id_}'.encode()).hexdigest()[:32]
            seen.add(key)
            aliases=advisory.get('aliases',[])
            cvss = advisory.get('severity',[])
            kev_match = KEV.match(advisory, kev_entries) if kev_entries is not None else None
            severity = 'critical' if kev_match else ('high' if cvss else 'medium')
            self.store.save_finding(repo,key,'dependency',severity,
                f'{dep.name}@{dep.version} affected by {id_}',dep.file_path,head,
                {'osv_id':id_,'aliases':aliases,'package':dep.name,'version':dep.version,
                 'ecosystem':dep.ecosystem,'summary':advisory.get('summary','')[:500],
                 'reference':f'https://osv.dev/vulnerability/{id_}',
                 'known_exploited': bool(kev_match) if kev_entries is not None else None,
                 'kev': kev_match,
                 'priority_note': ('CISA KEV: known exploited in the wild; prioritize review'
                                   if kev_match else 'Severity is a heuristic, not a verified CVSS score')})
            grouped.setdefault(dep,[]).append(advisory)
        self.store.resolve_missing_dependencies(repo,seen)
        if self.cfg.enable_auto_pr:
            await self.maybe_propose_patches(repo,installation_id,default_branch,head,files,grouped)
        log.info('Audited %s: %d dependencies; %d affected entries',repo,len(deps),len(affected))

    async def maybe_propose_patches(self, repo, install, base, checked_head, files,
                                    grouped: dict[Dependency,list[dict]]):
        # Any automatic action requires a current audit of the base branch.
        for dep,advisories in grouped.items():
            if dep.ecosystem!='PyPI' or not dep.file_path.endswith('requirements.txt'):
                continue
            candidate=candidate_version(dep,advisories)
            if candidate is None:
                continue
            existing=files.get(dep.file_path)
            if not existing:
                continue
            replacement=patched_requirement(existing['text'],dep,candidate)
            if replacement is None:
                continue
            # Re-query exact target: remediation must not introduce another known OSV vulnerability.
            future=Dependency(dep.name,candidate,dep.ecosystem,dep.file_path)
            if await self.osv.check([future]):
                continue
            key=remediation_key(dep.file_path,dep,candidate)
            if self.store.has_remediation(repo,key):
                continue
            if await self.github.branch_head(repo,install,base)!=checked_head:
                raise RuntimeError('Base branch moved during audit; retry against new HEAD')
            title=f'security: update {dep.name} {dep.version} → {candidate}'
            ids=', '.join(a['id'] for a in advisories)
            body=(f'Automated draft security patch for `{dep.file_path}`.\n\n'
                  f'- Package: `{dep.name}`\n- Current: `{dep.version}`\n'
                  f'- Proposed: `{candidate}`\n- OSV advisories: {ids}\n\n'
                  '**Safety:** The proposed version was checked against current OSV data; '
                  'that is not a guarantee of security or compatibility. '
                  '**CI/tests have not been verified by VulnForge.** '
                  'A maintainer must review and merge this draft PR. No automatic merge.\n')
            url=await self.github.create_fix_pr(repo,install,base,branch_for(dep,key),
                dep.file_path,existing['sha'],replacement,title,body)
            self.store.save_remediation(repo,key,url)
            log.info('Draft remediation PR created: %s',url)


async def run_worker():
    cfg=Config.from_env()
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    if not cfg.app_id or not cfg.private_key_path:
        raise SystemExit('Configure GITHUB_APP_ID and GITHUB_PRIVATE_KEY_PATH before starting worker')
    store=Store(cfg.database_path)
    github=GitHub(cfg)
    osv=OSV(cfg.osv_api_url)
    kev=KEV() if cfg.enable_kev else None
    agent=Agent(cfg,store,github,osv,kev)
    last_schedule=0.0
    try:
        while True:
            if time.monotonic()-last_schedule>60:
                store.schedule_due(cfg.scan_interval_seconds)
                last_schedule=time.monotonic()
            job=store.claim()
            if not job:
                await asyncio.sleep(2)
                continue
            try:
                await agent.process(job)
            except Exception as exc:
                log.exception('Job %d failed',job['id'])
                store.finish(job['id'], f'{type(exc).__name__}: {str(exc)[:250]}')
            else:
                store.finish(job['id'])
    finally:
        await github.close()
        await osv.close()
        if kev is not None:
            await kev.close()


if __name__=='__main__':
    asyncio.run(run_worker())
