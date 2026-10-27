"""Loopback-only OIDC intake preview. Production customer ingestion stays closed."""
from fastapi import HTTPException,Request
from fastapi.responses import JSONResponse

from .github_metadata import GitHubMetadata,MetadataError
from .oidc import GitHubOIDC,OIDCError,RUNNER_PATH
from .runner_intake import RunnerIntake,RunnerDenied,RunnerConflict
from .runner_report import parse_report

def install_runner_routes(app,cfg,store):
    app.state.runner_oidc=GitHubOIDC(cfg.public_origin+RUNNER_PATH)
    app.state.github_metadata=GitHubMetadata(cfg)

    @app.middleware('http')
    async def runner_privacy(request,call_next):
        path=request.scope['path']
        protected=path==RUNNER_PATH or path.startswith(RUNNER_PATH+'/')
        if protected:
            # Tokens are accepted only in Authorization, never URLs/cookies.
            # Scrub query parameters even on rejection so access logs omit them.
            if request.scope.get('query_string'):
                request.scope['query_string']=b''
                return JSONResponse({'detail':'Query parameters are not accepted'},status_code=400,
                    headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
            if not cfg.runner_oidc_preview:
                return JSONResponse({'detail':'Runner identity preview is not enabled'},status_code=503,
                    headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
        response=await call_next(request)
        if protected:
            response.headers['Cache-Control']='no-store';response.headers['Referrer-Policy']='no-referrer'
        return response

    @app.post(RUNNER_PATH,status_code=202)
    async def upload(request:Request):
        if str(request.base_url).rstrip('/')!=cfg.public_origin:
            raise HTTPException(400,'Unexpected runner origin')
        if request.headers.get('content-encoding','identity')!='identity':
            raise HTTPException(415,'Encoded reports are not accepted')
        if request.headers.get('content-type','').split(';',1)[0].strip().lower()!='application/json':
            raise HTTPException(415,'JSON report required')
        auth=request.headers.get('authorization','')
        if len(request.headers.getlist('authorization'))!=1 or not auth.startswith('Bearer ') or len(auth)>16400:
            raise HTTPException(401,'GitHub Actions identity required')
        chunks=[];size=0
        async for chunk in request.stream():
            size+=len(chunk)
            if size>1_000_000: raise HTTPException(413,'Runner report exceeds limit')
            chunks.append(chunk)
        try: report=parse_report(b''.join(chunks))
        except (ValueError,UnicodeDecodeError,RecursionError):
            raise HTTPException(422,'Runner report rejected by metadata policy') from None
        try:
            identity=await app.state.runner_oidc.verify(auth[7:])
            return await RunnerIntake(store,cfg,app.state.github_metadata).accept(identity,report)
        except OIDCError: raise HTTPException(401,'Runner identity could not be verified') from None
        except RunnerDenied: raise HTTPException(403,'Runner scope is not authorized') from None
        except RunnerConflict: raise HTTPException(409,'Conflicting report or reused identity') from None
        except MetadataError: raise HTTPException(503,'GitHub repository verification unavailable') from None
