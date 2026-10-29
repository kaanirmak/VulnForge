"""Public webhook receiver and admin-authenticated REST dashboard."""
import hashlib
import hmac
import json
from importlib import resources

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from .config import Config
from .db import Store, StaleJob
from .github import NAME_RE, SHA_RE
from .reports import sbom, sarif
from .runner_report import parse_report
from pydantic import BaseModel, Field
from typing import Literal
import time


class TriageRequest(BaseModel):
    status: Literal['open', 'resolved', 'false_positive', 'risk_accepted', 'suppressed']
    reason: str = Field(min_length=5, max_length=2000)
    expires_at: float | None = None

MAX_WEBHOOK_BYTES=2_000_000


def signature_ok(body: bytes, header: str | None, secret: str) -> bool:
    if not secret or not header:
        return False
    expected='sha256='+hmac.new(secret.encode('utf-8'),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,header)


def create_app(cfg: Config | None = None, store: Store | None = None):
    cfg=cfg or Config.from_env()
    store=store or Store(cfg.database_target,migrate=cfg.database_auto_migrate)
    app=FastAPI(title='VulnForge',version='0.3.0',
                description='GitHub commit and vulnerability response agent MVP')
    app.state.cfg=cfg
    app.state.store=store
    from .auth_routes import install_auth_routes
    install_auth_routes(app,cfg,store)
    from .organization_routes import install_organization_routes
    install_organization_routes(app,cfg,store)
    from .runner_routes import install_runner_routes
    install_runner_routes(app,cfg,store)

    async def admin(request:Request,authorization: str | None = Header(default=None)):
        if not cfg.admin_token and not cfg.operator_credentials:
            raise HTTPException(503,'Operator access is not configured')
        candidate=authorization[7:] if authorization and authorization.startswith('Bearer ') else ''
        actor=None
        for identity,credential in cfg.operator_credentials:
            if hmac.compare_digest(candidate.encode(),credential.encode()): actor=identity
        if cfg.admin_token and hmac.compare_digest(candidate.encode(),cfg.admin_token.encode()):
            actor='legacy-local-operator'
        if actor is None:
            raise HTTPException(401,'Invalid admin token',headers={'WWW-Authenticate':'Bearer'})
        route=request.scope.get('route')
        store.audit_event('operator:'+actor,None,actor,'operator_access',
                          {'method':request.method,'route':getattr(route,'path','operator')})
        return actor

    async def report_operator(authorization: str | None = Header(default=None)):
        if not cfg.operator_report_token:
            raise HTTPException(503,'Operator report intake is not configured')
        candidate=authorization[7:] if authorization and authorization.startswith('Bearer ') else ''
        if not hmac.compare_digest(candidate.encode(),cfg.operator_report_token.encode()):
            raise HTTPException(401,'Invalid operator credential',headers={'WWW-Authenticate':'Bearer'})

    @app.get('/api/v1/operator/jobs/dead-letters',dependencies=[Depends(admin)])
    async def dead_letters(limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0)):
        items=store.dead_letters(limit,cursor)
        return {'items':items,'next_cursor':items[-1]['id'] if len(items)==limit else None}

    @app.post('/api/v1/operator/jobs/{job_id}/retry',dependencies=[Depends(admin)],status_code=202)
    async def retry_dead_letter(job_id:int):
        try: result=store.retry_dead_letter(job_id)
        except StaleJob: raise HTTPException(409,'Repository connection changed; request a fresh scan') from None
        except ValueError: raise HTTPException(409,'Job cannot be retried') from None
        if result is None: raise HTTPException(404,'Job not found')
        return result

    @app.post('/api/v1/operator/runner-reports',dependencies=[Depends(report_operator)],status_code=202)
    async def operator_report(request: Request):
        if request.headers.get('content-encoding','identity')!='identity':
            raise HTTPException(415,'Encoded runner reports are not accepted')
        chunks=[]
        size=0
        async for chunk in request.stream():
            size+=len(chunk)
            if size>1_000_000: raise HTTPException(413,'Runner report exceeds limit')
            chunks.append(chunk)
        try:
            report=parse_report(b''.join(chunks))
        except (ValueError,RecursionError,UnicodeDecodeError):
            # Pydantic error details may contain submitted source/credentials.
            # Neither echo nor log the invalid payload or validation exception.
            raise HTTPException(422,'Runner report rejected by metadata policy') from None
        try:
            return store.quarantine_runner_report(report)
        except LookupError:
            raise HTTPException(404,'Repository not registered') from None

    @app.get('/api/v1/privacy',dependencies=[Depends(admin)])
    async def privacy_status():
        return {'scan_mode':cfg.scan_mode,'server_source_access':cfg.source_access_allowed,
                'intelligence_mode':cfg.intelligence_mode,
                'external_package_metadata_consent':cfg.allow_external_package_metadata,
                'runner_reports':('operator_and_identity_preview_quarantined' if cfg.runner_oidc_preview else 'operator_only_quarantined'),
                'runner_identity_preview':cfg.runner_oidc_preview,'runner_baseline_promotion':False,
                'customer_ingestion_ready':False,'tenant_isolation_ready':False,
                'path_reporting':'sha256_pseudonyms','source_upload_allowed':False}

    @app.get('/')
    async def home(): return RedirectResponse('/account',status_code=303)

    @app.get('/operator',response_class=HTMLResponse)
    async def dashboard():
        return resources.files('vulnforge').joinpath('dashboard.html').read_text(encoding='utf-8')

    @app.get('/health')
    async def health():
        return {'status':'ok','version':'0.3.0'}

    @app.post('/github/webhook',status_code=202)
    async def webhook(request: Request,
                      signature: str | None=Header(None, alias='X-Hub-Signature-256'),
                      event: str | None=Header(None,alias='X-GitHub-Event'),
                      delivery: str | None=Header(None,alias='X-GitHub-Delivery')):
        if not cfg.webhook_secret:
            raise HTTPException(503,'WEBHOOK_SECRET is not configured')
        length=request.headers.get('content-length')
        if length:
            try:
                if int(length)>MAX_WEBHOOK_BYTES:
                    raise HTTPException(413,'Webhook payload too large')
            except ValueError:
                raise HTTPException(400,'Malformed Content-Length')
        chunks=[]
        size=0
        async for chunk in request.stream():
            size+=len(chunk)
            if size>MAX_WEBHOOK_BYTES:
                raise HTTPException(413,'Webhook payload too large')
            chunks.append(chunk)
        body=b''.join(chunks)
        if len(body)>MAX_WEBHOOK_BYTES:
            raise HTTPException(413,'Webhook payload too large')
        if not signature_ok(body,signature,cfg.webhook_secret):
            raise HTTPException(403,'Invalid webhook signature')
        if not delivery or len(delivery)>128 or not event or len(event)>64:
            raise HTTPException(400,'Missing or invalid delivery/event ID')
        try:
            data=json.loads(body)
        except (json.JSONDecodeError,UnicodeDecodeError):
            raise HTTPException(400,'Malformed webhook JSON')
        if not isinstance(data,dict):
            raise HTTPException(400,'Webhook object expected')
        with store.transaction():
            return ingest(event, data, delivery)

    def ingest(event, data, delivery):
        # Delivery dedup ensures GitHub redelivery does not duplicate processing.
        if not store.add_delivery(delivery):
            return {'accepted':True,'duplicate':True}
        if event == 'security_advisory' and data.get('action') in ('published','updated','withdrawn'):
            # A new global advisory may not reference any one repository. Match it
            # against our stored SBOM/inventory and recheck *only* relevant repos.
            github_to_osv={'pip':'PyPI','npm':'npm','go':'Go','rust':'crates.io',
                            'composer':'Packagist','rubygems':'RubyGems'}
            packages=[]
            incoming=data.get('security_advisory') or {}
            vulnerabilities=incoming.get('vulnerabilities',[])
            advisory_id=incoming.get('ghsa_id')
            if isinstance(advisory_id,str) and advisory_id and len(advisory_id)<=256:
                extra_aliases=[incoming['cve_id']] if isinstance(incoming.get('cve_id'),str) and incoming.get('cve_id') else []
                for ident in incoming.get('identifiers',[]) if isinstance(incoming.get('identifiers'),list) else []:
                    if isinstance(ident,dict) and isinstance(ident.get('value'),str) and ident['value']:
                        extra_aliases.append(ident['value'])
                advisory_id=store.save_advisory({
                    'id':advisory_id,'aliases':sorted(set(extra_aliases)),
                    'summary':incoming.get('summary',''),'modified':incoming.get('updated_at'),
                    'published':incoming.get('published_at'),'vulnerabilities':vulnerabilities,
                    'withdrawn':incoming.get('withdrawn_at') or (str(time.time()) if data['action']=='withdrawn' else None)
                },source='GitHub webhook')
            else:
                advisory_id=None
            for entry in vulnerabilities[:150]:
                p=entry.get('package') or {}
                eco=github_to_osv.get(str(p.get('ecosystem','')).lower())
                name=p.get('name')
                if eco and isinstance(name,str) and len(name)<=256:
                    packages.append((eco,name))
            matching=store.repos_using_packages(packages)
            if advisory_id: matching.update(store.impacted_repositories(advisory_id))
            if len(vulnerabilities)>150 or not packages:
                # Withdrawals may omit old affected-package information. A
                # bounded candidate query must never silently omit recipients.
                with store.conn() as c:
                    matching.update(r['full_name'] for r in c.execute('SELECT full_name FROM repositories'))
            queued=0
            for repo in matching:
                if advisory_id: store.pending_impact(repo,advisory_id,delivery)
                if cfg.source_access_allowed:
                    queued+=store.enqueue('dependency_audit',repo,{'advisory_id':advisory_id},f'advisory:{delivery}:{repo}')
            return {'accepted':True,'queued':queued,'matching_repositories':len(matching)}
        installation=data.get('installation') or {}
        installation_id=installation.get('id')
        repos=[]
        repo_data=data.get('repository')
        if repo_data and isinstance(repo_data,dict):
            repos=[repo_data]
        elif event in ('installation','installation_repositories'):
            repos=data.get('repositories') or data.get('repositories_added') or []
        if type(installation_id) is not int or installation_id<1:
            # Non-installation events can be ignored; no credentials can be inferred.
            return {'accepted':True,'queued':0,'reason':'no installation'}
        action=data.get('action')
        if event=='installation_repositories':
            for item in data.get('repositories_removed',[]):
                name=item.get('full_name','')
                if NAME_RE.fullmatch(name): store.remove_repo(name)
        if event=='installation' and action in ('deleted','suspend'):
            store.remove_installation(installation_id)
            for item in repos:
                name=item.get('full_name','')
                if NAME_RE.fullmatch(name): store.remove_repo(name)
            return {'accepted':True,'queued':0}
        queued=0
        for item in repos:
            name=item.get('full_name','')
            if not NAME_RE.fullmatch(name) or '..' in name:
                continue
            branch=item.get('default_branch') or 'main'
            store.upsert_repo(name,installation_id,branch)
            if event=='push' and data.get('ref','').startswith('refs/heads/'):
                deleted=bool(data.get('deleted',False)) or data.get('after')=='0'*40
                if deleted:
                    if data.get('ref')=='refs/heads/'+branch:
                        store.invalidate_repository_evidence(name)
                        store.audit_event(name,None,'github_webhook','default_branch_deleted_observed',{'ref':data['ref']})
                    else:
                        store.audit_event(name,None,'github_webhook','branch_deleted_observed',{'ref':data['ref']})
                elif data.get('ref')=='refs/heads/'+branch:
                    # Keep a monotonic local invalidation, even in customer-runner
                    # mode. An out-of-order delivery may require an extra scan but
                    # must never make an older snapshot look current again.
                    store.invalidate_repository_evidence(name)
                    store.audit_event(name,None,'github_webhook','default_branch_push_observed',
                                      {'forced':bool(data.get('forced',False))})
            if cfg.scan_mode=='customer_runner':
                # All current worker jobs need source access. Customer mode
                # records integration metadata without generating source jobs.
                continue
            if event=='pull_request' and action in ('opened','synchronize','reopened','ready_for_review'):
                pr=data.get('pull_request') or {}
                sha=(pr.get('head') or {}).get('sha','')
                base_sha=(pr.get('base') or {}).get('sha','')
                number=data.get('number')
                if isinstance(sha,str) and SHA_RE.fullmatch(sha) and type(number) is int and number>0:
                    payload={'sha':sha,'number':number}
                    if isinstance(base_sha,str) and SHA_RE.fullmatch(base_sha):
                        payload['base_sha']=base_sha
                    queued+=store.enqueue('pull_request_scan',name,payload,f'pr:{name}:{number}:{sha}')
            elif event=='push' and not data.get('deleted',False) and data.get('after')!='0'*40 and data.get('ref','').startswith('refs/heads/'):
                after=data.get('after','')
                before=data.get('before','')
                if not SHA_RE.fullmatch(after):
                    continue
                if not SHA_RE.fullmatch(before):
                    before='0'*40
                shas=[c.get('id','') for c in data.get('commits',[]) if isinstance(c,dict)]
                payload={'before':before,'after':after,'commits':shas,'ref':data['ref'],
                         'forced':bool(data.get('forced',False))}
                queued+=store.enqueue('push',name,payload,f'push:{delivery}:{name}')
            elif event=='dependabot_alert' and action in ('created','reopened','reintroduced','fixed','dismissed'):
                queued+=store.enqueue('dependency_audit',name,{},f'alert:{delivery}:{name}')
            elif event in ('installation','installation_repositories') and action in ('created','added'):
                queued+=store.enqueue('dependency_audit',name,{},f'install:{delivery}:{name}')
        return {'accepted':True,'queued':queued}

    @app.get('/api/v1/advisories',dependencies=[Depends(admin)])
    async def advisories(limit: int=Query(50,ge=1,le=100)):
        return store.list_advisories(limit)

    @app.get('/api/v1/impacts',dependencies=[Depends(admin)])
    async def impacts(repo: str | None=None, advisory_id: str | None=None,
                      state: Literal['affected','not_affected','under_investigation','withdrawn'] | None=None,
                      cursor: int=Query(0,ge=0), limit: int=Query(50,ge=1,le=100)):
        return store.list_impacts(repo,advisory_id,state,cursor,limit)

    @app.post('/api/v1/intelligence/refresh',dependencies=[Depends(admin)],status_code=202)
    async def refresh_intelligence(repo: str | None=None):
        if not cfg.source_access_allowed:
            raise HTTPException(409,'Trusted customer inventory is not ready; source scanning stays disabled')
        with store.transaction(), store.conn() as c:
            rows=c.execute('SELECT full_name FROM repositories WHERE full_name=?',(repo,)).fetchall() if repo else c.execute('SELECT full_name FROM repositories').fetchall()
            if repo and not rows: raise HTTPException(404,'Repository not registered')
            queued=sum(store.enqueue('dependency_audit',r['full_name'],{},
                       f"intel-refresh:{r['full_name']}:{int(time.time()//60)}") for r in rows)
        return {'queued':queued,'repositories':len(rows)}

    @app.get('/api/repositories',dependencies=[Depends(admin)])
    async def repositories():
        return store.list_rows('repositories')

    @app.get('/api/jobs',dependencies=[Depends(admin)])
    async def jobs(repo: str | None=None):
        return store.list_rows('jobs',repo=repo)

    @app.get('/api/findings',dependencies=[Depends(admin)])
    async def findings(repo: str | None=None):
        store.expire_suppressions()
        return store.list_rows('findings',repo=repo)

    @app.get('/api/v1/findings',dependencies=[Depends(admin)])
    async def filtered_findings(repo: str | None=None, status: Literal['open','resolved','false_positive','risk_accepted','suppressed'] | None=None,
                                severity: Literal['critical','high','medium','low','info'] | None=None,
                                cursor: int=Query(0,ge=0), limit: int=Query(50,ge=1,le=100)):
        store.expire_suppressions()
        clauses=['id>?']
        args=[cursor]
        for column,value in [('repo',repo),('status',status),('severity',severity)]:
            if value is not None:
                clauses.append(f'{column}=?')
                args.append(value)
        with store.conn() as c:
            rows=c.execute('SELECT * FROM findings WHERE '+' AND '.join(clauses)+' ORDER BY id LIMIT ?',args+[limit+1]).fetchall()
        items=[dict(r) for r in rows[:limit]]
        from .freshness import finding_view
        with store.conn() as c:
            cache={}
            items=[finding_view(c,item,cache) for item in items]
        return {'items':items,'next_cursor':items[-1]['id'] if len(rows)>limit else None}

    @app.get('/api/v1/overview',dependencies=[Depends(admin)])
    async def overview():
        store.expire_suppressions()
        with store.conn() as c:
            return {'repositories':c.execute('SELECT COUNT(*) FROM repositories').fetchone()[0],
                    'open_findings':c.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0],
                    'remediations':c.execute('SELECT COUNT(*) FROM remediations').fetchone()[0],
                    'incomplete_repositories':c.execute("""SELECT COUNT(DISTINCT s.repo) FROM scans s
                        WHERE s.state IN ('incomplete','failed') AND s.kind='dependencies'
                        AND NOT EXISTS (SELECT 1 FROM scans n WHERE n.repo=s.repo AND n.kind=s.kind
                                        AND n.started_at>s.started_at)""").fetchone()[0]}

    @app.get('/api/dependencies',dependencies=[Depends(admin)])
    async def dependencies(repo: str | None=None):
        return store.list_rows('dependency_inventory',repo=repo)

    @app.get('/api/remediations',dependencies=[Depends(admin)])
    async def remediations(repo: str | None=None):
        return store.list_rows('remediations',repo=repo)

    @app.get('/api/scans',dependencies=[Depends(admin)])
    async def scans(repo: str | None=None):
        return store.list_rows('scans',repo=repo)

    def get_scan(scan_id):
        result=store.scan(scan_id)
        if result is None:
            raise HTTPException(404,'Scan not found')
        return result

    @app.get('/api/v1/scans/{scan_id}',dependencies=[Depends(admin)])
    async def scan_detail(scan_id: str):
        return get_scan(scan_id)

    @app.get('/api/v1/sbom/{scan_id}',dependencies=[Depends(admin)])
    async def export_sbom(scan_id: str):
        scan=get_scan(scan_id)
        if scan['kind'] not in ('dependencies','pr_dependencies'):
            raise HTTPException(409,'A dependency scan is required for SBOM export')
        if scan['state']=='running':
            raise HTTPException(409,'Scan is still running')
        return sbom(scan)

    @app.get('/api/v1/scans/{scan_id}/sarif',dependencies=[Depends(admin)])
    async def export_sarif(scan_id: str):
        return sarif(get_scan(scan_id))

    @app.patch('/api/v1/findings/{finding_id}/triage',dependencies=[Depends(admin)])
    async def triage_finding(finding_id: int, change: TriageRequest):
        timed=change.status in ('suppressed','risk_accepted')
        if timed and (change.expires_at is None or not time.time()<change.expires_at<=time.time()+366*86400):
            raise HTTPException(422,'Suppression requires expiry within the next year')
        if not timed and change.expires_at is not None:
            raise HTTPException(422,'Expiry applies only to suppression or risk acceptance')
        result=store.triage(finding_id,change.status,change.reason,change.expires_at)
        if result is None: raise HTTPException(404,'Finding not found')
        return result

    @app.get('/api/v1/audit/events',dependencies=[Depends(admin)])
    async def audit_events(repo: str | None=None):
        store.expire_suppressions()
        return store.list_rows('audit_events',repo=repo)

    @app.post('/api/rescan',dependencies=[Depends(admin)],status_code=202)
    async def rescan(repo: str):
        if not NAME_RE.fullmatch(repo) or '..' in repo:
            raise HTTPException(400,'Invalid repository')
        with store.conn() as c:
            exists=c.execute('SELECT 1 FROM repositories WHERE full_name=?',(repo,)).fetchone()
        if not exists:
            raise HTTPException(404,'Repository not registered')
        # Manual scans have a per-second key to avoid accidental double clicks.
        import time
        ok=store.enqueue('dependency_audit',repo,{},f'manual:{repo}:{int(time.time())}')
        return {'queued':bool(ok)}

    return app


app=create_app()
