"""Public webhook receiver and admin-authenticated REST dashboard."""
import hashlib
import hmac
import json
from importlib import resources

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from .config import Config
from .db import Store
from .github import NAME_RE, SHA_RE

MAX_WEBHOOK_BYTES=2_000_000


def signature_ok(body: bytes, header: str | None, secret: str) -> bool:
    if not secret or not header:
        return False
    expected='sha256='+hmac.new(secret.encode('utf-8'),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,header)


def create_app(cfg: Config | None = None, store: Store | None = None):
    cfg=cfg or Config.from_env()
    store=store or Store(cfg.database_path)
    app=FastAPI(title='VulnForge',version='0.2.0',
                description='GitHub commit and vulnerability response agent MVP')
    app.state.cfg=cfg
    app.state.store=store

    async def admin(authorization: str | None = Header(default=None)):
        if not cfg.admin_token:
            raise HTTPException(503,'ADMIN_TOKEN is not configured')
        candidate=authorization.removeprefix('Bearer ') if authorization else ''
        if not hmac.compare_digest(candidate,cfg.admin_token):
            raise HTTPException(401,'Invalid admin token',headers={'WWW-Authenticate':'Bearer'})

    @app.get('/',response_class=HTMLResponse)
    async def dashboard():
        return resources.files('vulnforge').joinpath('dashboard.html').read_text(encoding='utf-8')

    @app.get('/health')
    async def health():
        return {'status':'ok','version':'0.2.0'}

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
        body=await request.body()
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
        # Delivery dedup ensures GitHub redelivery does not duplicate processing.
        if not store.add_delivery(delivery):
            return {'accepted':True,'duplicate':True}
        if event == 'security_advisory' and data.get('action') in ('published','updated','withdrawn'):
            # A new global advisory may not reference any one repository. Match it
            # against our stored SBOM/inventory and recheck *only* relevant repos.
            github_to_osv={'pip':'PyPI','npm':'npm','go':'Go','rust':'crates.io',
                            'composer':'Packagist','rubygems':'RubyGems'}
            packages=[]
            for entry in (data.get('security_advisory') or {}).get('vulnerabilities',[])[:150]:
                p=entry.get('package') or {}
                eco=github_to_osv.get(str(p.get('ecosystem','')).lower())
                name=p.get('name')
                if eco and isinstance(name,str) and len(name)<=256:
                    packages.append((eco,name))
            matching=store.repos_using_packages(packages)
            queued=sum(store.enqueue('dependency_audit',repo,{},f'advisory:{delivery}:{repo}')
                       for repo in matching)
            return {'accepted':True,'queued':queued,'matching_repositories':len(matching)}
        installation=data.get('installation') or {}
        installation_id=installation.get('id')
        repos=[]
        repo_data=data.get('repository')
        if repo_data and isinstance(repo_data,dict):
            repos=[repo_data]
        elif event in ('installation','installation_repositories'):
            repos=data.get('repositories') or data.get('repositories_added') or []
        if installation_id is None or not isinstance(installation_id,int) or installation_id<1:
            # Non-installation events can be ignored; no credentials can be inferred.
            return {'accepted':True,'queued':0,'reason':'no installation'}
        action=data.get('action')
        if event=='installation_repositories':
            for item in data.get('repositories_removed',[]):
                name=item.get('full_name','')
                if NAME_RE.fullmatch(name): store.remove_repo(name)
        if event=='installation' and action=='deleted':
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
            if event=='push' and not data.get('deleted',False) and data.get('ref','').startswith('refs/heads/'):
                after=data.get('after','')
                before=data.get('before','')
                if not SHA_RE.fullmatch(after):
                    continue
                if not SHA_RE.fullmatch(before):
                    before='0'*40
                shas=[c.get('id','') for c in data.get('commits',[]) if isinstance(c,dict)]
                payload={'before':before,'after':after,'commits':shas,'ref':data['ref']}
                queued+=store.enqueue('push',name,payload,f'push:{delivery}:{name}')
            elif event=='dependabot_alert' and action in ('created','reopened','reintroduced','fixed','dismissed'):
                queued+=store.enqueue('dependency_audit',name,{},f'alert:{delivery}:{name}')
            elif event in ('installation','installation_repositories') and action in ('created','added'):
                queued+=store.enqueue('dependency_audit',name,{},f'install:{delivery}:{name}')
        return {'accepted':True,'queued':queued}

    @app.get('/api/repositories',dependencies=[Depends(admin)])
    async def repositories():
        return store.list_rows('repositories')

    @app.get('/api/jobs',dependencies=[Depends(admin)])
    async def jobs(repo: str | None=None):
        return store.list_rows('jobs',repo=repo)

    @app.get('/api/findings',dependencies=[Depends(admin)])
    async def findings(repo: str | None=None):
        return store.list_rows('findings',repo=repo)

    @app.get('/api/dependencies',dependencies=[Depends(admin)])
    async def dependencies(repo: str | None=None):
        return store.list_rows('dependency_inventory',repo=repo)

    @app.get('/api/remediations',dependencies=[Depends(admin)])
    async def remediations(repo: str | None=None):
        return store.list_rows('remediations',repo=repo)

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
