"""Customer account routes; intentionally disconnected from operator authority."""
import hmac
import re
from importlib import resources

from fastapi import HTTPException,Request
from fastapi.responses import HTMLResponse,JSONResponse,RedirectResponse,Response
from starlette.datastructures import QueryParams

from .auth import AuthError,AuthSessions,GitHubLogin,FLOW_SECONDS,SESSION_SECONDS


def install_auth_routes(app,cfg,store):
    sessions=AuthSessions(store,cfg)
    app.state.github_login=GitHubLogin(cfg)

    @app.middleware('http')
    async def auth_privacy_headers(request,call_next):
        path=request.scope['path']
        sensitive=path.startswith('/auth/') or path in ('/account','/api/v1/me')
        callbacks=('/auth/github/callback','/auth/github/connect/callback')
        if any(path==cb or path.startswith(cb+'/') for cb in callbacks):
            raw=request.scope.get('query_string',b'')
            # Routing consumes this private state instead of raw query params.
            # Uvicorn's normal access log then has no callback code/state query.
            request.scope['query_string']=b''
            if len(raw)>4096 or path not in callbacks:
                response=JSONResponse({'detail':'Invalid sign-in callback'},status_code=400)
            else:
                request.state.oauth_callback=QueryParams(raw)
                response=await call_next(request)
        else:
            response=await call_next(request)
        if sensitive:
            response.headers['Cache-Control']='no-store'
            response.headers['Referrer-Policy']='no-referrer'
            response.headers['X-Frame-Options']='DENY'
        return response

    def require_origin(request):
        if not cfg.oauth_enabled: raise HTTPException(503,'GitHub sign-in is not configured')
        if str(request.base_url).rstrip('/')!=cfg.public_origin:
            raise HTTPException(400,'Unexpected authentication origin')

    def set_cookie(response,name,value,max_age,http_only=True):
        response.set_cookie(sessions.cookie_prefix+name,value,max_age=max_age,
                            secure=sessions.secure,httponly=http_only,samesite='lax',path='/')

    def clear_cookie(response,name,http_only=True):
        response.delete_cookie(sessions.cookie_prefix+name,path='/',secure=sessions.secure,
                               httponly=http_only,samesite='lax')

    @app.get('/account',response_class=HTMLResponse)
    async def account():
        return resources.files('vulnforge').joinpath('account.html').read_text(encoding='utf-8')

    @app.get('/auth/status')
    async def status():
        return {'github_login_configured':cfg.oauth_enabled,'customer_access_ready':False,'github_connection_preview':cfg.github_connection_preview}

    @app.get('/auth/github/login')
    async def login(request:Request):
        require_origin(request)
        location,verifier=sessions.begin()
        response=RedirectResponse(location,status_code=303)
        set_cookie(response,'oauth',verifier,FLOW_SECONDS)
        return response

    @app.get('/auth/github/callback')
    async def callback(request:Request):
        require_origin(request)
        params=request.state.oauth_callback
        # Do not accept a return URL, installation ID or caller-supplied user ID.
        if (set(params)-{'state','code','error','error_description','error_uri'} or
            any(len(params.getlist(key))!=1 for key in params) or
            ('code' in params and 'error' in params)):
            raise HTTPException(400,'Invalid sign-in callback')
        code=params.get('code','')
        if 'error' not in params and not re.fullmatch(r'[A-Za-z0-9_-]{1,512}',code):
            raise HTTPException(400,'Invalid sign-in callback')
        verifier=request.cookies.get(sessions.cookie_prefix+'oauth','')
        try:
            sessions.consume(params.get('state',''),verifier)
        except AuthError:
            raise HTTPException(401,'Invalid or expired sign-in') from None
        if 'error' in params:
            response=JSONResponse({'detail':'GitHub sign-in was not completed'},status_code=401)
        else:
            try:
                identity=await app.state.github_login.exchange_user(code,verifier)
                user=sessions.verified_user(identity)
            except (AuthError,ValueError,KeyError,TypeError):
                response=JSONResponse({'detail':'GitHub identity could not be verified'},status_code=502)
            else:
                token,csrf=sessions.create(user['id'],request.cookies.get(sessions.cookie_prefix+'session'))
                response=RedirectResponse('/account',status_code=303)
                set_cookie(response,'session',token,SESSION_SECONDS)
                set_cookie(response,'csrf',csrf,SESSION_SECONDS,http_only=False)
        clear_cookie(response,'oauth')
        return response

    @app.get('/api/v1/me')
    async def me(request:Request):
        require_origin(request)
        user=sessions.current(request.cookies.get(sessions.cookie_prefix+'session'))
        if not user: raise HTTPException(401,'Sign-in required')
        return {key:user[key] for key in ('id','login','expires_at')} | {'customer_access_ready':False}

    @app.post('/auth/logout',status_code=204)
    async def logout(request:Request):
        require_origin(request)
        if request.headers.get('origin')!=cfg.public_origin:
            raise HTTPException(403,'Same-origin request required')
        csrf=request.headers.get('x-csrf-token','')
        if not csrf or not hmac.compare_digest(csrf.encode(),request.cookies.get(sessions.cookie_prefix+'csrf','').encode()):
            raise HTTPException(403,'CSRF check failed')
        try:
            sessions.logout(request.cookies.get(sessions.cookie_prefix+'session'),csrf)
        except AuthError:
            raise HTTPException(403,'Session or CSRF check failed') from None
        response=Response(status_code=204)
        for name in ('session','oauth'): clear_cookie(response,name)
        clear_cookie(response,'csrf',http_only=False)
        return response
