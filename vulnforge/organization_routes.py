"""Local-only customer API preview. Production tenant readiness remains false."""
import hmac
from typing import Literal

from fastapi import APIRouter,Depends,HTTPException,Query,Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel,ConfigDict,Field

from .auth import AuthSessions,digest
from .identity import Identities
from .organization import OrganizationData,ResourceNotFound,RoleDenied
from .reports import sarif,sbom
from .rls import CustomerStore,verify_operator

ROOT='/api/v1/organizations'


class CustomerTriage(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    status:Literal['open','resolved','false_positive','risk_accepted','suppressed']
    reason:str=Field(min_length=5,max_length=2000)
    expires_at:float|None=None


class InvitationRequest(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    github_id:int=Field(gt=0,lt=2**63)
    role:Literal['org_admin','maintainer','analyst','viewer','auditor']


class InvitationAccept(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    token:str=Field(pattern=r'^[A-Za-z0-9_-]{43}$')


class MembershipChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    role:Literal['org_admin','maintainer','analyst','viewer','auditor']


class RemediationPolicyChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    repo:str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$',max_length=256)
    enabled:bool
    packages:list[str]=Field(min_length=1,max_length=100)
    paths:list[str]=Field(min_length=1,max_length=80)


class RunnerPolicyChange(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    repo:str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$',max_length=256)
    workflow_ref:str=Field(min_length=1,max_length=512)


class OrganizationCreate(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    name:str=Field(min_length=1,max_length=100)


class ConnectionBegin(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    repo:str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$',max_length=256)
    consent:bool
    consent_version:Literal['metadata-v1']


def install_organization_routes(app,cfg,store):
    sessions=AuthSessions(store,cfg)
    from .connections import ConnectionFlows,GitHubConnectionVerifier,CALLBACK
    app.state.connection_verifier=GitHubConnectionVerifier(cfg)
    flows=ConnectionFlows(store,cfg)
    data_store=store
    if cfg.customer_api_preview and store.backend=='postgresql':
        if not cfg.customer_database_url:
            raise ValueError('PostgreSQL customer preview requires a separate restricted connection')
        verify_operator(store)
        data_store=CustomerStore(cfg.customer_database_url)
    app.state.customer_store=data_store if cfg.customer_api_preview else None

    async def principal(request:Request):
        if not cfg.customer_api_preview: raise HTTPException(503,'Customer API is not enabled')
        if str(request.base_url).rstrip('/')!=cfg.public_origin:
            raise HTTPException(400,'Unexpected authentication origin')
        token=request.cookies.get(sessions.cookie_prefix+'session')
        user=sessions.current(token)
        if not user: raise HTTPException(401,'Sign-in required')
        return {**user,'session_hash':digest(token)}

    async def scoped(organization_id:str,user=Depends(principal)):
        return OrganizationData(data_store,organization_id,user['id'],user['session_hash'])

    async def csrf(request:Request,user=Depends(principal)):
        token=request.headers.get('x-csrf-token','')
        cookie=request.cookies.get(sessions.cookie_prefix+'csrf','')
        if (request.headers.get('origin')!=cfg.public_origin or not token or
            not hmac.compare_digest(token.encode(),cookie.encode()) or
            not hmac.compare_digest(digest(token),user['csrf_hash'])):
            raise HTTPException(403,'Session or CSRF check failed')

    @app.middleware('http')
    async def preview_boundaries(request,call_next):
        protected=request.scope['path']==ROOT or request.scope['path'].startswith(ROOT+'/')
        if protected and request.method in ('POST','PUT','PATCH'):
            chunks=[];size=0
            async for chunk in request.stream():
                size+=len(chunk)
                if size>4096:
                    return JSONResponse({'detail':'Customer request exceeds limit'},status_code=413,
                        headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
                chunks.append(chunk)
            # Starlette's cached Request replays the bounded body to the router.
            request._body=b''.join(chunks)
        response=await call_next(request)
        if protected:
            response.headers['Cache-Control']='no-store'
            response.headers['Referrer-Policy']='no-referrer'
        return response

    @app.exception_handler(ResourceNotFound)
    async def not_found(request,exc): return JSONResponse({'detail':'Resource not found'},status_code=404)

    @app.exception_handler(RoleDenied)
    async def forbidden(request,exc): return JSONResponse({'detail':'Organization role does not allow this action'},status_code=403)

    @app.exception_handler(RequestValidationError)
    async def invalid(request,exc):
        if request.scope['path']==ROOT or request.scope['path'].startswith(ROOT+'/'):
            return JSONResponse({'detail':'Invalid customer request'},status_code=422)
        return await request_validation_exception_handler(request,exc)

    @app.get(ROOT)
    async def organizations(user=Depends(principal)):
        if isinstance(data_store,CustomerStore):
            with data_store.organization_scope('',user['id'],user['session_hash']):
                return {'items':Identities(data_store).list_organizations(user['id'])}
        return {'items':Identities(data_store).list_organizations(user['id'])}

    @app.post(ROOT,dependencies=[Depends(csrf)],status_code=201)
    async def create_organization(body:OrganizationCreate,user=Depends(principal)):
        try: return Identities(store).create_organization(user['id'],body.name)
        except ValueError: raise HTTPException(422,'Organization name rejected') from None

    @app.get(CALLBACK)
    async def connect_callback(request:Request):
        import re
        from .auth import AuthError,FLOW_SECONDS
        from .connections import ConnectionDenied,ConnectionConflict
        from .github_metadata import MetadataError
        from fastapi.responses import RedirectResponse
        if not cfg.github_connection_preview: raise HTTPException(503,'Connection preview is not enabled')
        user=await principal(request)
        params=request.state.oauth_callback
        if (set(params)-{'state','code','error','error_description','error_uri'} or
            any(len(params.getlist(key))!=1 for key in params) or
            ('code' in params and 'error' in params) or
            ('error' not in params and not re.fullmatch(r'[A-Za-z0-9_-]{1,512}',params.get('code','')))):
            raise HTTPException(400,'Invalid connection callback')
        try:
            intent=flows.consume(params.get('state',''),request.cookies.get(sessions.cookie_prefix+'connect',''),
                                 user['session_hash'])
            if 'error' in params: raise AuthError('Authorization declined')
            proof=await app.state.connection_verifier.verify(params['code'],
                request.cookies.get(sessions.cookie_prefix+'connect',''),intent['repo'],intent['github_id'])
            flows.complete(intent,proof)
            outcome='connected'
        except (AuthError,ConnectionDenied,ConnectionConflict,MetadataError,PermissionError,ValueError):
            outcome='failed'
        response=RedirectResponse('/account?connection='+outcome,status_code=303)
        response.delete_cookie(sessions.cookie_prefix+'connect',path='/',secure=sessions.secure,
                               httponly=True,samesite='lax')
        return response

    def membership_operation(operation,*args):
        try: return operation(*args)
        except PermissionError: raise HTTPException(403,'Organization administrator permission required') from None
        except LookupError: raise HTTPException(404,'Resource not found') from None
        except ValueError: raise HTTPException(409,'Membership operation cannot be completed') from None

    @app.post(ROOT+'/invitations/accept',dependencies=[Depends(csrf)])
    async def accept_invitation(body:InvitationAccept,user=Depends(principal)):
        return membership_operation(Identities(store).accept_invitation,body.token,user['id'])

    router=APIRouter(prefix=ROOT+'/{organization_id}')

    @router.post('/connections/begin',dependencies=[Depends(csrf)])
    async def begin_connection(organization_id:str,body:ConnectionBegin,user=Depends(principal)):
        from .auth import FLOW_SECONDS
        if not cfg.github_connection_preview: raise HTTPException(503,'Connection preview is not enabled')
        try:
            location,verifier=flows.begin(organization_id,user['session_hash'],body.repo,body.consent_version,body.consent)
        except PermissionError: raise HTTPException(403,'Connection is not authorized') from None
        except ValueError: raise HTTPException(422,'Repository and consent required') from None
        response=JSONResponse({'authorization_url':location,'expires_in':FLOW_SECONDS,'source_access':False})
        response.set_cookie(sessions.cookie_prefix+'connect',verifier,max_age=FLOW_SECONDS,path='/',
                            secure=sessions.secure,httponly=True,samesite='lax')
        return response

    @router.put('/runner-policy',dependencies=[Depends(csrf)])
    async def runner_policy(organization_id:str,body:RunnerPolicyChange,user=Depends(principal)):
        from .runner_intake import RunnerIntake,RunnerConflict
        from .github_metadata import MetadataError
        if not cfg.runner_oidc_preview: raise HTTPException(503,'Runner identity preview is not enabled')
        try:
            return await RunnerIntake(store,cfg,app.state.github_metadata).configure(
                organization_id,body.repo,user['id'],body.workflow_ref)
        except MetadataError: raise HTTPException(503,'GitHub repository verification unavailable') from None
        except PermissionError: raise HTTPException(403,'Runner policy cannot be configured') from None
        except LookupError: raise HTTPException(404,'Repository unavailable') from None
        except RunnerConflict: raise HTTPException(409,'Repository changed; verify again') from None

    @router.delete('/runner-policy',dependencies=[Depends(csrf)],status_code=204)
    async def disable_runner_policy(organization_id:str,repo:str,user=Depends(principal)):
        from .runner_intake import RunnerIntake
        if not cfg.runner_oidc_preview: raise HTTPException(503,'Runner identity preview is not enabled')
        membership_operation(RunnerIntake(store,cfg,app.state.github_metadata).disable,
                             organization_id,repo,user['id'])

    @router.put('/remediation-policy',dependencies=[Depends(csrf)])
    async def remediation_policy(organization_id:str,body:RemediationPolicyChange,user=Depends(principal)):
        return membership_operation(Identities(store).set_remediation_policy,organization_id,body.repo,user['id'],
                                    body.enabled,body.packages,body.paths)

    @router.post('/invitations',dependencies=[Depends(csrf)],status_code=201)
    async def invite(organization_id:str,body:InvitationRequest,user=Depends(principal)):
        return membership_operation(Identities(store).invite,organization_id,body.github_id,body.role,user['id'])

    @router.delete('/invitations/{invitation_id}',dependencies=[Depends(csrf)],status_code=204)
    async def revoke_invitation(organization_id:str,invitation_id:str,user=Depends(principal)):
        membership_operation(Identities(store).revoke_invitation,organization_id,invitation_id,user['id'])

    @router.patch('/memberships/{user_id}',dependencies=[Depends(csrf)])
    async def change_membership(organization_id:str,user_id:str,body:MembershipChange,user=Depends(principal)):
        return membership_operation(Identities(store).change_membership,organization_id,user_id,body.role,user['id'])

    @router.delete('/memberships/{user_id}',dependencies=[Depends(csrf)],status_code=204)
    async def remove_membership(organization_id:str,user_id:str,user=Depends(principal)):
        membership_operation(Identities(store).remove_membership,organization_id,user_id,user['id'])

    @router.get('/overview')
    async def overview(data=Depends(scoped)): return data.overview()

    @router.get('/repositories')
    async def repositories(limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return data.rows('repositories',limit=limit)

    @router.get('/dependencies')
    async def dependencies(repo:str|None=None,limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return data.rows('dependency_inventory',repo,limit)

    @router.get('/remediations')
    async def remediations(repo:str|None=None,limit:int=Query(50,ge=1,le=100),
                           cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.rows('remediations',repo,limit,cursor)

    @router.get('/findings')
    async def findings(repo:str|None=None,status:Literal['open','resolved','false_positive','risk_accepted','suppressed']|None=None,
                       severity:Literal['critical','high','medium','low','info']|None=None,
                       limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.rows('findings',repo,limit,cursor,status,severity)

    @router.patch('/findings/{finding_id}/triage',dependencies=[Depends(csrf)])
    async def triage(finding_id:int,change:CustomerTriage,data=Depends(scoped)):
        try: return data.triage(finding_id,change.status,change.reason,change.expires_at)
        except ValueError: raise HTTPException(422,'Triage change rejected') from None

    @router.get('/scans')
    async def scans(repo:str|None=None,limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return data.rows('scans',repo,limit)

    @router.get('/scans/{scan_id}')
    async def scan(scan_id:str,data=Depends(scoped)): return data.scan(scan_id)

    @router.get('/scans/{scan_id}/sarif')
    async def sarif_export(scan_id:str,data=Depends(scoped)): return sarif(data.scan(scan_id,export=True))

    @router.get('/scans/{scan_id}/sbom')
    async def sbom_export(scan_id:str,data=Depends(scoped)):
        scan=data.scan(scan_id,export=True)
        if scan['kind'] not in ('dependencies','pr_dependencies'):
            raise HTTPException(409,'A dependency scan is required for SBOM export')
        if scan['state']=='running': raise HTTPException(409,'Scan is still running')
        return sbom(scan)

    @router.get('/impacts')
    async def impacts(repo:str|None=None,advisory_id:str|None=None,
                      state:Literal['affected','not_affected','under_investigation','withdrawn']|None=None,
                      limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.impacts(repo,advisory_id,state,cursor,limit)

    @router.get('/advisories')
    async def advisories(limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return {'items':data.advisories(limit)}

    @router.get('/audit/events')
    async def audit(repo:str|None=None,limit:int=Query(50,ge=1,le=100),
                    cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.audit(repo,cursor,limit)

    app.include_router(router)
