"""Bounded GitHub Actions OIDC verification. No discovery/header-selected URLs."""
import asyncio
from dataclasses import dataclass
import json
import re
import time

import httpx
import jwt

ISSUER='https://token.actions.githubusercontent.com'
JWKS_URL=ISSUER+'/.well-known/jwks'
RUNNER_PATH='/api/v1/runner/reports'
NETWORK_SECONDS=15
SHA=re.compile(r'[0-9a-f]{40}\Z')
WORKFLOW=re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml@([0-9a-f]{40})\Z')
REPO=re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')


class OIDCError(PermissionError): pass


def unique_json(body):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('Duplicate JSON key')
            result[key]=value
        return result
    def constant(value): raise ValueError('Non-finite JSON number')
    return json.loads(body,object_pairs_hook=unique,parse_constant=constant)


async def bounded_json(client,method,url,*,limit=65536,expected_status=200,**kwargs):
    async with asyncio.timeout(NETWORK_SECONDS):
        async with client.stream(method,url,**kwargs) as response:
            if response.status_code!=expected_status: raise ValueError('Provider request rejected')
            if response.headers.get('content-encoding','identity')!='identity':
                raise ValueError('Encoded provider response rejected')
            chunks=[];size=0
            async for chunk in response.aiter_bytes():
                size+=len(chunk)
                if size>limit: raise ValueError('Provider response limit')
                chunks.append(chunk)
            result=unique_json(b''.join(chunks))
            if not isinstance(result,dict): raise ValueError('Provider object required')
            return result


@dataclass(frozen=True,repr=False)
class RunnerIdentity:
    repository:str
    repository_id:int
    owner_id:int
    commit_sha:str
    ref:str
    workflow_ref:str
    workflow_sha:str
    caller_workflow_ref:str
    run_id:str
    run_attempt:str
    event:str
    subject:str
    jti:str
    issued_at:int
    expires_at:int
    runner_environment:str


class GitHubOIDC:
    def __init__(self,audience,client=None):
        if not isinstance(audience,str) or not 1<=len(audience)<=512: raise ValueError('Fixed audience required')
        self.audience=audience
        self.client=client
        self._keys={};self._expires=0;self._last_refresh=float('-inf')
        self._lock=asyncio.Lock()

    async def _refresh(self):
        async def fetch(client):
            return await bounded_json(client,'GET',JWKS_URL,headers={'Accept-Encoding':'identity'})
        if self.client is not None: data=await fetch(self.client)
        else:
            async with httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
                data=await fetch(client)
        keys=data.get('keys')
        if not isinstance(keys,list) or not 1<=len(keys)<=20: raise ValueError('Invalid key set')
        parsed={}
        for key in keys:
            if (not isinstance(key,dict) or key.get('kty')!='RSA' or key.get('alg')!='RS256' or
                key.get('use','sig')!='sig' or key.get('e')!='AQAB' or
                key.get('key_ops',['verify'])!=['verify'] or
                any(field in key for field in ('d','p','q','dp','dq','qi','oth')) or
                not isinstance(key.get('kid'),str) or not re.fullmatch(r'[A-Za-z0-9_.=-]{1,128}',key['kid']) or
                key['kid'] in parsed or not isinstance(key.get('n'),str) or
                not re.fullmatch(r'[A-Za-z0-9_-]{342,1366}',key['n'])):
                raise ValueError('Invalid signing key')
            public=jwt.PyJWK.from_dict(key,algorithm='RS256').key
            if not 2048<=public.key_size<=8192: raise ValueError('Unsafe signing key size')
            parsed[key['kid']]=public
        self._keys=parsed;self._expires=time.monotonic()+300

    async def verify(self,token):
        try:
            if (not isinstance(token,str) or not 50<=len(token)<=16384 or
                not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token)):
                raise ValueError('Invalid token')
            # Check duplicate fields before the library's normal JSON decoder.
            header=unique_json(jwt.utils.base64url_decode(token.split('.')[0]))
            payload=unique_json(jwt.utils.base64url_decode(token.split('.')[1]))
            if (not isinstance(header,dict) or not isinstance(payload,dict) or
                set(header)-{'alg','kid','typ','x5t','x5t#S256'} or
                header.get('alg')!='RS256' or header.get('typ')!='JWT' or
                not isinstance(header.get('kid'),str) or not re.fullmatch(r'[A-Za-z0-9_.=-]{1,128}',header['kid'])):
                raise ValueError('Unexpected token header')
            if payload.get('iss')!=ISSUER or payload.get('aud')!=self.audience:
                raise ValueError('Unexpected issuer or audience')
            async with self._lock:
                now=time.monotonic()
                if now>=self._expires or header['kid'] not in self._keys:
                    # Unknown kid cannot turn each unauthenticated request into
                    # a provider fetch. Failed fetches also consume the cooldown.
                    if now-self._last_refresh<30: raise ValueError('Signing key unavailable')
                    self._last_refresh=now
                    await self._refresh()
                key=self._keys.get(header['kid'])
                if key is None: raise ValueError('Unknown signing key')
            claims=jwt.decode(token,key,algorithms=['RS256'],issuer=ISSUER,audience=self.audience,
                options={'require':['iss','aud','sub','exp','iat','nbf','jti'],'strict_aud':True},leeway=0)
            for name in ('exp','iat','nbf'):
                if type(claims[name]) is not int: raise ValueError('Integer token times required')
            if not 0<claims['exp']-claims['iat']<=600 or claims['nbf']>claims['iat']:
                raise ValueError('Token lifetime rejected')
            def text(name,pattern,limit=1024):
                value=claims.get(name)
                if not isinstance(value,str) or len(value)>limit or not re.fullmatch(pattern,value):
                    raise ValueError('Invalid identity claim')
                return value
            repository=text('repository',REPO,256)
            if '..' in repository: raise ValueError('Invalid repository identity')
            repo_id=int(text('repository_id',r'[1-9][0-9]{0,18}',19))
            owner_id=int(text('repository_owner_id',r'[1-9][0-9]{0,18}',19))
            if max(repo_id,owner_id)>=2**63: raise ValueError('Identity outside database range')
            if text('repository_owner',r'[A-Za-z0-9_.-]+',100)!=repository.split('/')[0]:
                raise ValueError('Repository owner mismatch')
            sha=text('sha',SHA,40)
            ref=text('ref',r'refs/heads/[A-Za-z0-9_./-]+',256)
            if '..' in ref or '//' in ref or ref.endswith(('/','.')): raise ValueError('Invalid branch ref')
            if claims.get('ref_type')!='branch' or claims.get('event_name') not in ('push','schedule','workflow_dispatch'):
                raise ValueError('Untrusted event context')
            if claims.get('head_ref','')!='' or claims.get('base_ref','')!='':
                raise ValueError('Pull request context rejected')
            if claims.get('ref_protected') is not True and claims.get('ref_protected')!='true':
                raise ValueError('Protected branch context required')
            workflow=text('job_workflow_ref',WORKFLOW,512)
            workflow_sha=text('job_workflow_sha',SHA,40)
            if WORKFLOW.fullmatch(workflow)[1]!=workflow_sha or '..' in workflow:
                raise ValueError('Reusable workflow must be pinned by commit')
            caller=text('workflow_ref',r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml@refs/heads/[A-Za-z0-9_./-]+',512)
            if not caller.startswith(repository+'/.github/workflows/') or caller.rsplit('@',1)[1]!=ref:
                raise ValueError('Caller workflow identity mismatch')
            text('workflow_sha',SHA,40)
            environment=text('runner_environment',r'github-hosted|self-hosted',32)
            subject=text('sub',r'[^\x00-\x20\x7f]+',1024)
            # Do not parse the changing legacy/immutable subject format into an
            # authorization decision. Explicit immutable IDs and policy bind it.
            return RunnerIdentity(repository,repo_id,owner_id,sha,ref,workflow,workflow_sha,caller,
                text('run_id',r'[1-9][0-9]{0,19}',20),text('run_attempt',r'[1-9][0-9]{0,5}',6),
                claims['event_name'],subject,text('jti',r'[A-Za-z0-9_.:-]{1,200}',200),claims['iat'],claims['exp'],environment)
        except (ValueError,TypeError,KeyError,OverflowError,RecursionError,TimeoutError,httpx.HTTPError,jwt.PyJWTError):
            raise OIDCError('Runner identity could not be verified') from None
