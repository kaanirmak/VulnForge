"""Session-bound, source-free repository onboarding. Provider tokens stay in memory."""
from dataclasses import dataclass
import re
import time
import uuid
from urllib.parse import parse_qs,urlsplit

from .auth import AuthError,AuthSessions,GitHubLogin,digest,IDLE_SECONDS,FLOW_SECONDS
from .github_metadata import GitHubMetadata
from .identity import Identities
from .oidc import bounded_json

CALLBACK='/auth/github/connect/callback'
CONSENT='metadata-v1'


class ConnectionDenied(PermissionError): pass
class ConnectionConflict(ValueError): pass


@dataclass(frozen=True,repr=False)
class VerifiedConnection:
    github_user_id:int
    repo:str
    installation_id:int
    repository_id:int
    owner_id:int
    default_branch:str


class GitHubConnectionVerifier(GitHubLogin):
    @staticmethod
    async def _pages(client,headers,path,key,maximum):
        records=[];total=None;seen=set()
        for page in range(1,maximum//100+2):
            data=await bounded_json(client,'GET','https://api.github.com'+path,
                limit=2_000_000,headers=headers,params={'per_page':100,'page':page})
            count=data.get('total_count');rows=data.get(key)
            if (type(count) is not int or not 0<=count<=maximum or
                not isinstance(rows,list) or len(rows)>100 or
                (total is not None and count!=total)):
                raise AuthError('Provider listing is incomplete')
            total=count
            for row in rows:
                id_=row.get('id') if isinstance(row,dict) else None
                if type(id_) is not int or not 0<id_<2**63 or id_ in seen:
                    raise AuthError('Provider listing is ambiguous')
                seen.add(id_);records.append(row)
            if len(records)==total:return records
            if len(records)>total or not rows:raise AuthError('Provider listing is incomplete')
        raise AuthError('Provider listing exceeds limit')

    async def _catalog(self,client,token,owner=None):
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                 'Accept-Encoding':'identity','X-GitHub-Api-Version':'2026-03-10'}
        catalog=[];seen=set()
        for installation in await self._pages(client,headers,'/user/installations','installations',500):
            if type(installation.get('app_id')) is not int or installation['app_id']!=int(self.cfg.app_id):
                raise AuthError('OAuth client and App do not match')
            if installation.get('suspended_at') is not None:continue
            if installation.get('permissions')!={'metadata':'read'}:
                raise AuthError('Metadata-only App required')
            account=installation.get('account')
            if not isinstance(account,dict):raise AuthError('Invalid installation account')
            if owner is not None and account.get('login')!=owner:continue
            rows=await self._pages(client,headers,'/user/installations/'+str(installation['id'])+'/repositories','repositories',2000)
            for row in rows:
                name=row.get('full_name')
                if (not isinstance(name,str) or len(name)>256 or
                    not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',name) or '..' in name or
                    row['id'] in seen):
                    raise AuthError('Invalid repository listing')
                seen.add(row['id']);catalog.append((installation,row))
                if len(catalog)>2000:raise AuthError('Repository listing exceeds limit')
        return catalog

    async def discover(self,code,verifier,github_user_id):
        async def inspect(client,token,user):
            if user['id']!=github_user_id:raise AuthError('GitHub account changed')
            choices=[]
            for installation,row in await self._catalog(client,token):
                if row.get('permissions',{}).get('admin') is not True:continue
                # Only bounded display metadata leaves this request. Never tokens.
                choices.append({'full_name':row['full_name']})
            return sorted(choices,key=lambda row:row['full_name'].lower())
        return await self._authorize(code,verifier,CALLBACK,inspect)

    async def verify(self,code,verifier,repo,github_user_id):
        async def inspect(client,token,user):
            if user['id']!=github_user_id:raise AuthError('GitHub account changed')
            matches=[]
            for installation,row in await self._catalog(client,token,repo.split('/')[0]):
                if row.get('full_name')!=repo:continue
                permissions=row.get('permissions')
                if not isinstance(permissions,dict) or permissions.get('admin') is not True:
                    raise AuthError('GitHub repository administrator required')
                matches.append((installation,row))
            if len(matches)!=1:raise AuthError('Selected repository is not uniquely accessible')
            installation,row=matches[0]
            verified=await GitHubMetadata(self.cfg,client).repository(repo,installation['id'])
            if (row['id']!=verified['repository_id'] or type(row.get('owner',{}).get('id')) is not int or
                row.get('owner',{}).get('id')!=verified['owner_id'] or
                row.get('default_branch')!=verified['default_branch']):
                raise AuthError('Repository changed during verification')
            return VerifiedConnection(user['id'],repo,installation['id'],verified['repository_id'],
                                      verified['owner_id'],verified['default_branch'])
        return await self._authorize(code,verifier,CALLBACK,inspect)


class ConnectionFlows:
    def __init__(self,store,cfg): self.store=store;self.cfg=cfg;self.sessions=AuthSessions(store,cfg)

    def _authority(self,c,session_hash,organization):
        now=time.time()
        row=c.execute('''SELECT s.*,u.github_id FROM user_sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>? AND s.last_seen_at>?'''+
            (' FOR UPDATE OF s' if self.store.backend=='postgresql' else ''),
            (session_hash,now,now-IDLE_SECONDS)).fetchone()
        if row is None: raise ConnectionDenied('Session expired or revoked')
        Identities._require_admin(c,organization,row['user_id'])
        return dict(row)

    def begin(self,organization,session_hash,repo,consent_version,consent,*,discovery=False):
        if not self.cfg.github_connection_preview: raise ConnectionDenied('Connection preview is disabled')
        if discovery:
            repo='__repository_selection__';consent_version='repository-selection-v1'
        if not discovery and (consent is not True or consent_version!=CONSENT or not isinstance(repo,str) or
            len(repo)>256 or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or '..' in repo):
            raise ValueError('Repository and explicit metadata consent required')
        with self.store.transaction(),self.store.conn() as c:
            Identities(self.store)._lock_organization(c,organization)
            actor=self._authority(c,session_hash,organization)
            owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(repo,)).fetchone()
            if owner is not None and owner['organization_id']!=organization:
                raise ConnectionDenied('Repository unavailable')
            existing=c.execute('SELECT connection_id FROM repositories WHERE full_name=?',(repo,)).fetchone()
            # One outstanding connection flow per session; restart cannot leave
            # a stack of valid consent intents or mix selected projects.
            c.execute('DELETE FROM auth_states WHERE state_hash IN (SELECT state_hash FROM connection_intents WHERE session_hash=?)',
                      (session_hash,))
            location,verifier=self.sessions.begin(CALLBACK)
            state=parse_qs(urlsplit(location).query)['state'][0]
            c.execute('INSERT INTO connection_intents VALUES(?,?,?,?,?,?,?)',
                      (digest(state),session_hash,organization,repo,existing['connection_id'] if existing else None,consent_version,time.time()))
            self.store.audit_event('organization:'+organization,None,actor['user_id'],'repository_selection_started' if discovery else 'connection_consent_started',
                                   {'organization_id':organization,'consent_version':consent_version})
        return location,verifier

    def consume(self,state,verifier,session_hash):
        with self.store.transaction(),self.store.conn() as c:
            row=c.execute('SELECT * FROM connection_intents WHERE state_hash=?',(digest(state),)).fetchone()
            if row is None or row['session_hash']!=session_hash: raise ConnectionDenied('Connection flow unavailable')
            intent=dict(row)
            Identities(self.store)._lock_organization(c,intent['organization_id'])
            actor=self._authority(c,session_hash,intent['organization_id'])
            self.sessions.consume(state,verifier)
            # consume deletes the auth state and its intent via FK cascade.
            return {**intent,'github_id':actor['github_id'],'user_id':actor['user_id']}

    def authorize_selection(self,organization,session_hash):
        if not self.cfg.github_connection_preview:raise ConnectionDenied('Connection preview is disabled')
        with self.store.transaction(),self.store.conn() as c:
            self._authority(c,session_hash,organization)

    def complete(self,intent,proof):
        if (not isinstance(proof,VerifiedConnection) or proof.repo!=intent['repo'] or
            proof.github_user_id!=intent['github_id'] or intent['consent_version']!=CONSENT or
            not 0<=time.time()-intent['created_at']<FLOW_SECONDS):
            raise ConnectionDenied('Verified repository consent required')
        with self.store.transaction(),self.store.conn() as c:
            Identities(self.store)._lock_organization(c,intent['organization_id'])
            actor=self._authority(c,intent['session_hash'],intent['organization_id'])
            if actor['user_id']!=intent['user_id']: raise ConnectionDenied('Session changed')
            # All onboarding writers serialize this repo before first creation,
            # including when there is no repository row to lock yet.
            if self.store.backend=='postgresql':
                c.execute('SELECT pg_advisory_xact_lock(hashtextextended(?,1))',(proof.repo,))
            row=c.execute('SELECT * FROM repositories WHERE full_name=?'+
                (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(proof.repo,)).fetchone()
            owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(proof.repo,)).fetchone()
            if owner and owner['organization_id']!=intent['organization_id']:
                raise ConnectionDenied('Repository unavailable')
            expected=intent['expected_connection_id']
            if ((expected is not None and (row is None or row['connection_id']!=expected)) or
                (row is not None and row['installation_id']!=proof.installation_id)):
                raise ConnectionConflict('Repository connection changed; start again')
            self.store.upsert_repo(proof.repo,proof.installation_id,proof.default_branch)
            reference='github-user-installation:'+uuid.uuid4().hex
            Identities(self.store).record_repository_ownership(intent['organization_id'],proof.repo,
                intent['user_id'],reference)
            self.store.audit_event(proof.repo,None,intent['user_id'],'repository_connected',
                {'organization_id':intent['organization_id'],'consent_version':CONSENT,
                 'repository_id':proof.repository_id,'owner_id':proof.owner_id,
                 'installation_id':proof.installation_id,'verification_reference':reference,
                 'scan_mode':'customer_runner','source_access':False,'external_package_sharing':False})
        return {'repo':proof.repo,'organization_id':intent['organization_id'],'state':'awaiting_runner',
                'baseline_ready':False}
