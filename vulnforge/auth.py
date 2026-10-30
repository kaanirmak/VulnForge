"""Login-only GitHub OAuth, single-use PKCE flows and opaque local sessions.

No provider access/refresh token is persisted. Customer sessions are never admin
credentials and cannot authorize legacy APIs or runner report ingestion.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode

import httpx

from .identity import Identities

FLOW_SECONDS=600
SESSION_SECONDS=8*3600
IDLE_SECONDS=30*60
GITHUB_OAUTH_ISSUER='https://github.com/login/oauth'
OPAQUE=re.compile(r'[A-Za-z0-9_-]{43,128}\Z')


class AuthError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class GitHubLogin:
    """Fixed public GitHub issuer; redirects and enterprise overrides unsupported."""
    def __init__(self,cfg): self.cfg=cfg

    async def exchange_user(self,code,verifier):
        return await self._authorize(code,verifier,'/auth/github/callback')

    async def _authorize(self,code,verifier,callback_path,consumer=None):
        # Never enable redirects or use GITHUB_API_URL for identity verification.
        # A redirected bearer/client secret must not reach an arbitrary host.
        if not self.cfg.oauth_enabled: raise AuthError('GitHub sign-in is not configured')
        if callback_path not in ('/auth/github/callback','/auth/github/connect/callback'):
            raise AuthError('Invalid authorization purpose')
        try:
            async with asyncio.timeout(45),httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
                token_data=await self._json(client,'POST','https://github.com/login/oauth/access_token',
                    data={'client_id':self.cfg.github_oauth_client_id,
                          'client_secret':self.cfg.github_oauth_client_secret,
                          'code':code,'code_verifier':verifier,
                          'redirect_uri':self.cfg.public_origin+callback_path},
                    headers={'Accept':'application/json'})
                token=token_data.get('access_token')
                if (not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,512}',token) or
                    token_data.get('token_type','').lower()!='bearer' or 'error' in token_data):
                    raise AuthError('GitHub authorization failed')
                user=await self._json(client,'GET','https://api.github.com/user',
                    headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                             'X-GitHub-Api-Version':'2026-03-10'})
                # Only verified, bounded public identity enters the local model.
                if (type(user.get('id')) is not int or not 0<user['id']<2**63 or
                    not isinstance(user.get('login'),str) or
                    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',user['login'])):
                    raise AuthError('GitHub identity could not be verified')
                identity={'id':user['id'],'login':user['login']}
                return await consumer(client,token,identity) if consumer else identity
        except (httpx.HTTPError,ValueError,KeyError,TypeError,AttributeError,RecursionError,TimeoutError):
            # Do not expose or log provider response bodies, codes or credentials.
            raise AuthError('GitHub identity could not be verified') from None

    @staticmethod
    async def _json(client,method,url,**kwargs):
        async with client.stream(method,url,**kwargs) as response:
            if response.status_code!=200: raise AuthError('GitHub request failed')
            chunks=[];size=0
            async for chunk in response.aiter_bytes():
                size+=len(chunk)
                if size>65536: raise AuthError('GitHub response exceeds limit')
                chunks.append(chunk)
            def unique(pairs):
                result={}
                for key,value in pairs:
                    if key in result: raise AuthError('Invalid provider response')
                    result[key]=value
                return result
            result=json.loads(b''.join(chunks),object_pairs_hook=unique)
            if not isinstance(result,dict): raise AuthError('Invalid provider response')
            return result


class AuthSessions:
    def __init__(self,store,cfg): self.store=store;self.cfg=cfg

    @property
    def cookie_prefix(self):
        return '__Host-vf_' if self.cfg.public_origin.startswith('https://') else 'vf_local_'

    @property
    def secure(self): return self.cfg.public_origin.startswith('https://')

    def begin(self,callback_path='/auth/github/callback'):
        if callback_path not in ('/auth/github/callback','/auth/github/connect/callback'):
            raise AuthError('Invalid authorization purpose')
        state=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        now=time.time()
        with self.store.transaction(),self.store.conn() as c:
            c.execute('DELETE FROM auth_states WHERE expires_at<=?',(now,))
            c.execute('INSERT INTO auth_states VALUES(?,?,?)',(digest(state),digest(verifier),now+FLOW_SECONDS))
        url='https://github.com/login/oauth/authorize?'+urlencode({
            'client_id':self.cfg.github_oauth_client_id,'redirect_uri':self.cfg.public_origin+callback_path,
            'state':state,'code_challenge':challenge,'code_challenge_method':'S256'})
        return url,verifier

    def consume(self,state,verifier):
        if not OPAQUE.fullmatch(state or '') or not OPAQUE.fullmatch(verifier or ''):
            raise AuthError('Invalid or expired sign-in')
        valid=False
        with self.store.transaction(),self.store.conn() as c:
            row=c.execute('SELECT * FROM auth_states WHERE state_hash=?'+
                (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(digest(state),)).fetchone()
            if row and hmac.compare_digest(row['browser_hash'],digest(verifier)):
                c.execute('DELETE FROM auth_states WHERE state_hash=?',(digest(state),))
                valid=row['expires_at']>time.time()
        if not valid: raise AuthError('Invalid or expired sign-in')

    def create(self,user_id,previous=None):
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);now=time.time()
        with self.store.transaction(),self.store.conn() as c:
            c.execute('DELETE FROM user_sessions WHERE expires_at<=? OR last_seen_at<=?',(now,now-IDLE_SECONDS))
            if OPAQUE.fullmatch(previous or ''):
                c.execute('DELETE FROM user_sessions WHERE token_hash=?',(digest(previous),))
            c.execute('INSERT INTO user_sessions VALUES(?,?,?,?,?,?)',
                (digest(token),user_id,digest(csrf),now,now+SESSION_SECONDS,now))
            self.store.audit_event('user:'+user_id,None,user_id,'session_created',{})
        return token,csrf

    def current(self,token):
        if not OPAQUE.fullmatch(token or ''): return None
        now=time.time();result=None
        with self.store.transaction(),self.store.conn() as c:
            row=c.execute('SELECT * FROM user_sessions WHERE token_hash=?'+
                (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(digest(token),)).fetchone()
            if row:
                if row['expires_at']<=now or row['last_seen_at']<=now-IDLE_SECONDS:
                    c.execute('DELETE FROM user_sessions WHERE token_hash=?',(digest(token),))
                else:
                    user=c.execute('SELECT id,login FROM users WHERE id=?',(row['user_id'],)).fetchone()
                    c.execute('UPDATE user_sessions SET last_seen_at=? WHERE token_hash=?',(now,digest(token)))
                    if user: result={**dict(user),'expires_at':row['expires_at'],'csrf_hash':row['csrf_hash']}
        return result

    def logout(self,token,csrf):
        # CSRF verification and revoke share a transaction; no read/touch TOCTOU.
        if not OPAQUE.fullmatch(token or '') or not OPAQUE.fullmatch(csrf or ''):
            raise AuthError('Session or CSRF check failed')
        now=time.time()
        with self.store.transaction(),self.store.conn() as c:
            row=c.execute('SELECT * FROM user_sessions WHERE token_hash=?'+
                (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(digest(token),)).fetchone()
            if (not row or row['expires_at']<=now or row['last_seen_at']<=now-IDLE_SECONDS or
                not hmac.compare_digest(row['csrf_hash'],digest(csrf))):
                raise AuthError('Session or CSRF check failed')
            c.execute('DELETE FROM user_sessions WHERE token_hash=?',(digest(token),))
            self.store.audit_event('user:'+row['user_id'],None,row['user_id'],'session_revoked',{})

    def verified_user(self,identity):
        return Identities(self.store).record_github_user(identity['id'],identity['login'])
