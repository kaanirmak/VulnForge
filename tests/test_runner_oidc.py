import asyncio
import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
import httpx
import jwt
import pytest

from vulnforge.oidc import GitHubOIDC,OIDCError,ISSUER,JWKS_URL

WORKFLOW='platform/security/.github/workflows/scan.yml@'+'b'*40
AUDIENCE='http://127.0.0.1:8000/api/v1/runner/reports'


@pytest.fixture(scope='module')
def signing_key(): return rsa.generate_private_key(public_exponent=65537,key_size=2048)


def claims(**overrides):
    now=int(time.time())
    return {'iss':ISSUER,'aud':AUDIENCE,'sub':'repo:alpha@101/project@201:ref:refs/heads/main',
        'exp':now+300,'iat':now-1,'nbf':now-1,'jti':'fixture-jti-1','repository':'alpha/project',
        'repository_owner':'alpha','repository_id':'201','repository_owner_id':'101','sha':'a'*40,
        'ref':'refs/heads/main','ref_type':'branch','ref_protected':'true','event_name':'push',
        'head_ref':'','base_ref':'','job_workflow_ref':WORKFLOW,'job_workflow_sha':'b'*40,
        'workflow_ref':'alpha/project/.github/workflows/customer.yml@refs/heads/main','workflow_sha':'c'*40,
        'run_id':'12345','run_attempt':'1','runner_environment':'github-hosted',**overrides}


def signed(key,values=None,**headers):
    return jwt.encode(values or claims(),key,algorithm='RS256',headers={'kid':'fixture-key',**headers})


def jwk(key,kid='fixture-key'):
    return {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),
            'kid':kid,'alg':'RS256','use':'sig'}


def verifier(key,handler=None):
    def default(request):
        assert str(request.url)==JWKS_URL
        assert 'authorization' not in request.headers
        return httpx.Response(200,json={'keys':[jwk(key)]})
    return GitHubOIDC(AUDIENCE,httpx.AsyncClient(transport=httpx.MockTransport(handler or default)))


def verify(key,token):
    async def run():
        oidc=verifier(key)
        try: return await oidc.verify(token)
        finally: await oidc.client.aclose()
    return asyncio.run(run())


def test_verified_immutable_and_legacy_subjects_use_immutable_claims(signing_key):
    for subject in ('repo:alpha/project:ref:refs/heads/main',claims()['sub']):
        identity=verify(signing_key,signed(signing_key,claims(sub=subject)))
        assert identity.repository_id==201 and identity.owner_id==101
        assert identity.commit_sha=='a'*40 and identity.workflow_ref==WORKFLOW
        assert identity.jti not in repr(identity)


@pytest.mark.parametrize('change',[
    {'iss':'https://attacker.example'},{'aud':'different-service'},{'aud':[AUDIENCE]},
    {'exp':1},{'nbf':int(time.time())+3600},{'iat':int(time.time())+3600},
    {'exp':int(time.time())+1800},{'iat':1},{'exp':True},
    {'repository_id':'99999999999999999999'},{'repository_id':201},{'repository_owner_id':'0'},
    {'repository_owner':'bravo'},{'repository':'alpha/../project'},
    {'sha':'not-a-sha'},{'ref':'refs/pull/1/merge'},{'ref':'refs/heads/../main'},
    {'ref_type':'tag'},{'ref_protected':False},{'ref_protected':'false'},
    {'event_name':'pull_request'},{'event_name':'pull_request_target'},{'event_name':'dynamic'},
    {'head_ref':'fork-branch'},{'base_ref':'main'},
    {'job_workflow_ref':'platform/security/.github/workflows/scan.yml@refs/heads/main'},
    {'job_workflow_sha':'d'*40},{'job_workflow_ref':None},
    {'workflow_ref':'bravo/project/.github/workflows/customer.yml@refs/heads/main'},
    {'workflow_ref':'alpha/project/.github/workflows/customer.yml@refs/heads/other'},
    {'run_attempt':'0'},{'run_id':'not-a-run'},{'runner_environment':'unknown'},
    {'jti':'private\nmarker'},{'sub':'private\nmarker'},
])
def test_untrusted_or_malformed_claims_fail_closed(signing_key,change):
    with pytest.raises(OIDCError,match='Runner identity could not be verified'):
        verify(signing_key,signed(signing_key,claims(**change)))


def test_wrong_key_hmac_unsigned_and_header_urls_are_rejected(signing_key):
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    tokens=[signed(other),jwt.encode(claims(),'fixture-secret'*4,algorithm='HS256',headers={'kid':'fixture-key'}),
            signed(signing_key,jku='https://attacker.example/keys'),signed(signing_key,crit=['exp']),
            signed(signing_key,jwk=jwk(other)),signed(signing_key,typ='not-jwt')]
    for token in tokens:
        with pytest.raises(OIDCError): verify(signing_key,token)


def test_duplicate_signed_json_fields_are_rejected(signing_key):
    def encode(value): return base64.urlsafe_b64encode(value).rstrip(b'=')
    header=encode(b'{"alg":"RS256","kid":"fixture-key","typ":"JWT"}')
    body=encode(json.dumps(claims()).encode()[:-1]+b',"repository_id":"999"}')
    message=header+b'.'+body
    signature=signing_key.sign(message,padding.PKCS1v15(),hashes.SHA256())
    with pytest.raises(OIDCError): verify(signing_key,(message+b'.'+encode(signature)).decode())


def test_key_cache_cooldown_and_concurrent_fetch_are_bounded(signing_key):
    calls=[]
    def handler(request): calls.append(request.url);return httpx.Response(200,json={'keys':[jwk(signing_key)]})
    async def run():
        oidc=verifier(signing_key,handler)
        try:
            results=await asyncio.gather(*(oidc.verify(signed(signing_key)) for _ in range(5)))
            assert len(results)==5 and len(calls)==1
            for n in range(5):
                with pytest.raises(OIDCError): await oidc.verify(signed(signing_key,kid=f'unknown-{n}'))
            assert len(calls)==1
        finally: await oidc.client.aclose()
    asyncio.run(run())


@pytest.mark.parametrize('response',[
    lambda key:httpx.Response(302,headers={'Location':'https://attacker.example'}),
    lambda key:httpx.Response(503,json={'private':'marker'}),
    lambda key:httpx.Response(200,json={'keys':[jwk(key),jwk(key)]}),
    lambda key:httpx.Response(200,json={'keys':[{**jwk(key),'alg':'HS256'}]}),
    lambda key:httpx.Response(200,content=b'x'*65537),
])
def test_provider_redirect_error_bad_keys_and_size_are_rejected(signing_key,response):
    async def run():
        oidc=verifier(signing_key,lambda request:response(signing_key))
        try:
            with pytest.raises(OIDCError): await oidc.verify(signed(signing_key))
        finally: await oidc.client.aclose()
    asyncio.run(run())


def test_signing_key_rotation_refreshes_after_cooldown(signing_key):
    rotated=rsa.generate_private_key(public_exponent=65537,key_size=2048);calls=[]
    def handler(request):
        calls.append(request.url)
        key=signing_key if len(calls)==1 else rotated
        kid='fixture-key' if len(calls)==1 else 'rotated-key'
        return httpx.Response(200,json={'keys':[jwk(key,kid)]})
    async def run():
        oidc=verifier(signing_key,handler)
        try:
            await oidc.verify(signed(signing_key))
            oidc._last_refresh-=31
            identity=await oidc.verify(signed(rotated,kid='rotated-key'))
            assert identity.repository_id==201 and len(calls)==2
            with pytest.raises(OIDCError): await oidc.verify(signed(signing_key))
            assert len(calls)==2
        finally: await oidc.client.aclose()
    asyncio.run(run())


def test_slow_key_response_has_total_deadline_and_closes_stream(signing_key,monkeypatch):
    from vulnforge import oidc as module
    monkeypatch.setattr(module,'NETWORK_SECONDS',.01)
    closed=[]
    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(10)
            yield b'{}'
        async def aclose(self): closed.append(True)
    async def run():
        oidc=verifier(signing_key,lambda request:httpx.Response(200,stream=Slow()))
        try:
            with pytest.raises(OIDCError): await oidc.verify(signed(signing_key))
            assert not oidc._keys and closed
        finally: await oidc.client.aclose()
    asyncio.run(run())
