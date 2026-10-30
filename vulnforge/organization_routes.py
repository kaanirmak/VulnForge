"""Local-only customer API preview. Production tenant readiness remains false."""
import hmac
import re
import time
import uuid
from typing import Literal

from fastapi import APIRouter,Depends,HTTPException,Query,Request,Response
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

ERROR_CODE_MAP = {
    400: 'BAD_REQUEST',
    401: 'UNAUTHORIZED',
    403: 'FORBIDDEN',
    404: 'NOT_FOUND',
    409: 'CONFLICT',
    413: 'PAYLOAD_TOO_LARGE',
    422: 'UNPROCESSABLE_ENTITY',
    500: 'INTERNAL_ERROR',
    502: 'BAD_GATEWAY',
    503: 'SERVICE_UNAVAILABLE'
}

_IDEMPOTENCY_RECORDS: dict[str, dict] = {}


class CustomerTriage(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    status:Literal['open','resolved','false_positive','risk_accepted','suppressed']
    reason:str=Field(min_length=5,max_length=2000)
    expires_at:float|None=None


class ImpactAssign(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    assigned_to:str|None=Field(default=None,max_length=64)


class PatchApprovalRequest(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    baseline_sha:str=Field(pattern=r'^[0-9a-f]{40}$')
    diff_sha256:str=Field(pattern=r'^[0-9a-f]{64}$')


class NotificationChannelCreate(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    name:str=Field(min_length=1,max_length=100)
    kind:Literal['email','slack','teams']
    target:str=Field(min_length=3,max_length=512)
    events:list[str]=Field(default_factory=lambda:['scan_completed','critical_finding'],max_length=20)
    enabled:bool=True


class NotificationChannelUpdate(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True)
    name:str=Field(min_length=1,max_length=100)
    target:str=Field(min_length=3,max_length=512)
    events:list[str]=Field(default_factory=lambda:['scan_completed','critical_finding'],max_length=20)
    enabled:bool


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
    async def preview_boundaries(request: Request, call_next):
        protected = request.scope['path'] == ROOT or request.scope['path'].startswith(ROOT + '/')
        req_id = request.headers.get('x-request-id')
        if not req_id or not re.match(r'^[A-Za-z0-9_-]{8,64}$', req_id):
            req_id = f"req-{uuid.uuid4().hex[:16]}"
        request.state.request_id = req_id

        if protected and request.method in ('POST', 'PUT', 'PATCH'):
            chunks = []; size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 4096:
                    return JSONResponse({
                        'detail': 'Customer request exceeds limit',
                        'error_code': 'PAYLOAD_TOO_LARGE',
                        'message': 'Customer request exceeds limit',
                        'request_id': req_id
                    }, status_code=413, headers={
                        'Cache-Control': 'no-store',
                        'Referrer-Policy': 'no-referrer',
                        'X-Request-ID': req_id
                    })
                chunks.append(chunk)
            request._body = b''.join(chunks)

        idemp_key = request.headers.get('idempotency-key') or request.headers.get('x-idempotency-key')
        full_key = None
        if protected and idemp_key and request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            full_key = f"{request.method}:{request.scope['path']}:{idemp_key}"
            record = _IDEMPOTENCY_RECORDS.get(full_key)
            if record:
                if record.get('status') == 'in_progress':
                    return JSONResponse({
                        'detail': 'A mutation with this Idempotency-Key is currently in progress',
                        'error_code': 'IDEMPOTENCY_CONFLICT',
                        'message': 'A mutation with this Idempotency-Key is currently in progress',
                        'request_id': req_id
                    }, status_code=409, headers={
                        'X-Request-ID': req_id,
                        'Cache-Control': 'no-store',
                        'Referrer-Policy': 'no-referrer'
                    })
                elif record.get('status') == 'completed':
                    return Response(
                        content=record['body'],
                        status_code=record['status_code'],
                        headers={
                            **record.get('headers', {}),
                            'X-Request-ID': req_id,
                            'X-Idempotent-Replayed': 'true',
                            'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'
                        },
                        media_type=record.get('media_type', 'application/json')
                    )
            _IDEMPOTENCY_RECORDS[full_key] = {'status': 'in_progress', 'created_at': time.time()}

        try:
            response = await call_next(request)
        except Exception:
            if full_key:
                _IDEMPOTENCY_RECORDS.pop(full_key, None)
            raise

        if protected:
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Request-ID'] = req_id

        if full_key and idemp_key:
            try:
                body_chunks = []
                async for chunk in response.body_iterator:
                    body_chunks.append(chunk)
                response_body = b''.join(body_chunks)
                if 200 <= response.status_code < 500:
                    _IDEMPOTENCY_RECORDS[full_key] = {
                        'status': 'completed',
                        'status_code': response.status_code,
                        'body': response_body,
                        'headers': {k: v for k, v in response.headers.items() if k.lower() not in ('content-length', 'content-encoding')},
                        'media_type': response.media_type or 'application/json',
                        'created_at': time.time()
                    }
                else:
                    _IDEMPOTENCY_RECORDS.pop(full_key, None)
                response = Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
            except Exception:
                _IDEMPOTENCY_RECORDS.pop(full_key, None)

        return response

    def error_response(request: Request, status_code: int, detail: str, error_code: str):
        req_id = getattr(request.state, 'request_id', 'req-unknown')
        headers = {
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Request-ID': req_id,
            'X-Error-Code': error_code
        }
        v1_requested = bool(request.headers.get('x-request-id') or request.headers.get('idempotency-key') or request.headers.get('x-v1-schema'))
        if v1_requested:
            body = {
                'detail': detail,
                'error_code': error_code,
                'message': detail,
                'request_id': req_id
            }
        else:
            body = {'detail': detail}
        return JSONResponse(body, status_code=status_code, headers=headers)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        code = ERROR_CODE_MAP.get(exc.status_code, 'HTTP_ERROR')
        if request.scope['path'] == ROOT or request.scope['path'].startswith(ROOT + '/'):
            return error_response(request, exc.status_code, str(exc.detail), code)
        req_id = getattr(request.state, 'request_id', 'req-unknown')
        return JSONResponse({'detail': exc.detail}, status_code=exc.status_code, headers={'X-Request-ID': req_id})

    @app.exception_handler(ResourceNotFound)
    async def not_found(request: Request, exc):
        return error_response(request, 404, 'Resource not found', 'RESOURCE_NOT_FOUND')

    @app.exception_handler(RoleDenied)
    async def forbidden(request: Request, exc):
        return error_response(request, 403, 'Organization role does not allow this action', 'ROLE_DENIED')

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc):
        if request.scope['path'] == ROOT or request.scope['path'].startswith(ROOT + '/'):
            return error_response(request, 422, 'Invalid customer request', 'VALIDATION_FAILED')
        return await request_validation_exception_handler(request, exc)

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

    @router.get('/onboarding')
    async def onboarding(data=Depends(scoped)): return data.onboarding()

    @router.get('/repositories')
    async def repositories(limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return data.rows('repositories',limit=limit)

    @router.delete('/repositories/{repo:path}',dependencies=[Depends(csrf)],status_code=200)
    async def disconnect_repository(repo:str,data=Depends(scoped)):
        try: return data.disconnect_repository(repo)
        except LookupError: raise HTTPException(404,'Repository connection not found') from None
        except PermissionError: raise HTTPException(403,'Organization administrator permission required') from None

    @router.delete('/data',dependencies=[Depends(csrf)],status_code=200)
    async def purge_data(data=Depends(scoped)):
        try: return data.purge_data()
        except LookupError: raise HTTPException(404,'Organization not found') from None
        except PermissionError: raise HTTPException(403,'Organization administrator permission required') from None

    @router.get('/repositories/{repo:path}/health')
    async def repository_health(repo:str,data=Depends(scoped)):
        return data.project_health(repo)

    @router.get('/projects/{repo:path}/health')
    async def project_health(repo:str,data=Depends(scoped)):
        return data.project_health(repo)

    @router.get('/dependencies')
    async def dependencies(repo:str|None=None,limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return data.rows('dependency_inventory',repo,limit)

    @router.get('/remediations')
    async def remediations(repo:str|None=None,
                           status:Literal['all','pending_approval','validated','blocked','published']|None=None,
                           limit:int=Query(50,ge=1,le=100),
                           cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.remediation_plans(repo=repo,status=status,limit=limit,cursor=cursor)

    @router.post('/remediations/{plan_id}/approve',dependencies=[Depends(csrf)])
    async def approve_patch(plan_id:str,body:PatchApprovalRequest,repo:str=Query(...),data=Depends(scoped)):
        try: return data.approve_patch(repo,plan_id,body.baseline_sha,body.diff_sha256)
        except LookupError: raise HTTPException(404,'Plan or repository not found') from None

    @router.get('/findings')
    async def findings(repo:str|None=None,status:Literal['open','resolved','false_positive','risk_accepted','suppressed']|None=None,
                       severity:Literal['critical','high','medium','low','info']|None=None,
                       limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.rows('findings',repo,limit,cursor,status,severity)

    @router.get('/findings/{finding_id}')
    async def finding(finding_id:int,data=Depends(scoped)):
        return data.finding(finding_id)

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
                      ecosystem:str|None=None,package:str|None=None,assigned_to:str|None=None,
                      limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.impacts(repo,advisory_id,state,cursor,limit,ecosystem=ecosystem,package=package,assigned_to=assigned_to)

    @router.patch('/impacts/{impact_id}/assign',dependencies=[Depends(csrf)])
    async def assign_impact(impact_id:int,body:ImpactAssign,data=Depends(scoped)):
        try: return data.assign_impact(impact_id,body.assigned_to)
        except LookupError: raise HTTPException(404,'Impact or assignee not found') from None
        except ValueError: raise HTTPException(422,'Invalid assignment request') from None

    @router.get('/impacts/{impact_id}/history')
    async def impact_history(impact_id:int,data=Depends(scoped)):
        return data.impact_history(impact_id)

    @router.get('/advisories')
    async def advisories(limit:int=Query(50,ge=1,le=100),data=Depends(scoped)):
        return {'items':data.advisories(limit)}

    @router.get('/audit/events')
    async def audit(repo:str|None=None,limit:int=Query(50,ge=1,le=100),
                    cursor:int=Query(0,ge=0),data=Depends(scoped)):
        return data.audit(repo,cursor,limit)

    @router.get('/notifications/channels')
    async def notification_channels(limit:int=Query(50,ge=1,le=100),cursor:int=Query(0,ge=0),data=Depends(scoped)):
        all_channels = data.list_notification_channels()
        items = all_channels[cursor:cursor+limit]
        has_more = (cursor + limit) < len(all_channels)
        return {
            'items': items,
            'total': len(all_channels),
            'cursor': cursor,
            'next_cursor': cursor + limit if has_more else None,
            'has_more': has_more
        }

    @router.post('/notifications/channels',dependencies=[Depends(csrf)],status_code=201)
    async def create_notification_channel(body:NotificationChannelCreate,data=Depends(scoped)):
        try: return data.create_notification_channel(body.name,body.kind,body.target,body.events,body.enabled)
        except ValueError as exc: raise HTTPException(422,str(exc)) from None

    @router.put('/notifications/channels/{channel_id}',dependencies=[Depends(csrf)])
    async def update_notification_channel(channel_id:str,body:NotificationChannelUpdate,data=Depends(scoped)):
        try: return data.update_notification_channel(channel_id,body.name,body.target,body.events,body.enabled)
        except ValueError as exc: raise HTTPException(422,str(exc)) from None

    @router.delete('/notifications/channels/{channel_id}',dependencies=[Depends(csrf)],status_code=204)
    async def delete_notification_channel(channel_id:str,data=Depends(scoped)):
        data.delete_notification_channel(channel_id)

    @router.post('/notifications/channels/{channel_id}/test',dependencies=[Depends(csrf)])
    async def test_notification_channel(channel_id:str,data=Depends(scoped)):
        try: return await data.test_notification_channel(channel_id)
        except Exception as exc: raise HTTPException(502,f'Notification test failed: {str(exc)}') from None

    app.include_router(router)
