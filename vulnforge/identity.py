"""Identity persistence and trusted server-side membership/ownership changes.

Call these methods from trusted server code after authenticating the principal;
Customer requests derive user IDs from the verified session, not request fields.
"""
import re
import time
import uuid
import secrets
import hashlib
import json

from .privacy import safe_metadata

ROLES=frozenset(('org_admin','maintainer','analyst','viewer','auditor'))


class Identities:
    def __init__(self,store): self.store=store

    def record_github_user(self,github_id,login):
        """Persist the immutable GitHub ID returned by a verified OAuth call."""
        if type(github_id) is not int or not 0<github_id<2**63:
            raise ValueError('Invalid verified GitHub identity')
        if not isinstance(login,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',login):
            raise ValueError('Invalid GitHub login')
        now=time.time()
        with self.store.transaction(), self.store.conn() as c:
            c.execute('''INSERT INTO users VALUES(?,?,?,?,?) ON CONFLICT(github_id) DO UPDATE SET
                login=excluded.login,updated_at=excluded.updated_at''',(uuid.uuid4().hex,github_id,login,now,now))
            return dict(c.execute('SELECT * FROM users WHERE github_id=?',(github_id,)).fetchone())

    def create_organization(self,actor_id,name):
        if not isinstance(name,str) or not name.strip() or len(name)>100:
            raise ValueError('Organization name is required')
        safe_metadata(name)
        id_=uuid.uuid4().hex;now=time.time()
        with self.store.transaction(), self.store.conn() as c:
            if c.execute('SELECT 1 FROM users WHERE id=?',(actor_id,)).fetchone() is None:
                raise PermissionError('Authenticated identity required')
            c.execute('INSERT INTO organizations VALUES(?,?,?,?)',(id_,name.strip(),actor_id,now))
            c.execute('INSERT INTO memberships VALUES(?,?,?,?,?)',(id_,actor_id,'org_admin',now,now))
            self.store.audit_event('organization:'+id_,None,actor_id,'organization_created',{})
        return {'id':id_,'name':name.strip(),'created_by':actor_id}

    def _lock_organization(self,c,organization_id):
        if self.store.backend=='postgresql':
            c.execute('SELECT pg_advisory_xact_lock(hashtextextended(?,0))',(organization_id,))
        # SQLite BEGIN IMMEDIATE already serializes writes.

    @staticmethod
    def _require_admin(c,organization_id,actor_id):
        row=c.execute('SELECT role FROM memberships WHERE organization_id=? AND user_id=?',(organization_id,actor_id)).fetchone()
        if row is None or row['role']!='org_admin':
            raise PermissionError('Organization administrator permission required')

    def set_membership(self,organization_id,user_id,role,actor_id):
        if role not in ROLES: raise ValueError('Invalid organization role')
        now=time.time()
        with self.store.transaction(), self.store.conn() as c:
            self._lock_organization(c,organization_id)
            self._require_admin(c,organization_id,actor_id)
            if c.execute('SELECT 1 FROM users WHERE id=?',(user_id,)).fetchone() is None:
                raise ValueError('Registered user required')
            old=c.execute('SELECT role FROM memberships WHERE organization_id=? AND user_id=?',(organization_id,user_id)).fetchone()
            if old and old['role']=='org_admin' and role!='org_admin':
                count=c.execute("SELECT COUNT(*) FROM memberships WHERE organization_id=? AND role='org_admin'",(organization_id,)).fetchone()[0]
                if count<=1: raise PermissionError('An organization must retain an administrator')
            c.execute('''INSERT INTO memberships VALUES(?,?,?,?,?) ON CONFLICT(organization_id,user_id)
                DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at''',(organization_id,user_id,role,now,now))
            if old and old['role']!=role:
                self._revoke_authority(c,organization_id,user_id,now)
            self.store.audit_event('organization:'+organization_id,None,actor_id,'membership_set',
                {'user_id':user_id,'before':old['role'] if old else None,'after':role})
        return {'organization_id':organization_id,'user_id':user_id,'role':role}

    @staticmethod
    def _revoke_authority(c,organization_id,user_id,now):
        # Conservative policy: a changed role requires sign-in again everywhere.
        # Database membership checks also apply immediately to an in-flight UI.
        c.execute('DELETE FROM user_sessions WHERE user_id=?',(user_id,))
        c.execute('UPDATE invitations SET revoked_at=? WHERE organization_id=? AND invited_by=? AND accepted_at IS NULL',
                  (now,organization_id,user_id))

    def change_membership(self,organization_id,user_id,role,actor_id):
        with self.store.transaction(),self.store.conn() as c:
            self._lock_organization(c,organization_id)
            self._require_admin(c,organization_id,actor_id)
            if not c.execute('SELECT 1 FROM memberships WHERE organization_id=? AND user_id=?',
                             (organization_id,user_id)).fetchone():
                raise LookupError('Membership not found; invite the user first')
            return self.set_membership(organization_id,user_id,role,actor_id)

    def remove_membership(self,organization_id,user_id,actor_id):
        with self.store.transaction(),self.store.conn() as c:
            self._lock_organization(c,organization_id)
            self._require_admin(c,organization_id,actor_id)
            old=c.execute('SELECT role FROM memberships WHERE organization_id=? AND user_id=?',
                          (organization_id,user_id)).fetchone()
            if old is None: raise LookupError('Membership not found')
            if old['role']=='org_admin' and c.execute(
                "SELECT COUNT(*) FROM memberships WHERE organization_id=? AND role='org_admin'",(organization_id,)).fetchone()[0]<=1:
                raise PermissionError('An organization must retain an administrator')
            c.execute('DELETE FROM memberships WHERE organization_id=? AND user_id=?',(organization_id,user_id))
            now=time.time();self._revoke_authority(c,organization_id,user_id,now)
            c.execute('''UPDATE invitations SET revoked_at=? WHERE organization_id=? AND
                github_id=(SELECT github_id FROM users WHERE id=?) AND accepted_at IS NULL''',(now,organization_id,user_id))
            self.store.audit_event('organization:'+organization_id,None,actor_id,'membership_removed',{'user_id':user_id})

    def invite(self,organization_id,github_id,role,actor_id):
        if role not in ROLES or type(github_id) is not int or not 0<github_id<2**63:
            raise ValueError('Invalid invitation')
        token=secrets.token_urlsafe(32);now=time.time();id_=uuid.uuid4().hex
        with self.store.transaction(),self.store.conn() as c:
            self._lock_organization(c,organization_id)
            self._require_admin(c,organization_id,actor_id)
            if c.execute('''SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id
                WHERE m.organization_id=? AND u.github_id=?''',(organization_id,github_id)).fetchone():
                raise ValueError('User is already a member')
            count=c.execute('''SELECT COUNT(*) FROM invitations WHERE organization_id=? AND github_id<>?
                AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>?''',(organization_id,github_id,now)).fetchone()[0]
            if count>=100: raise ValueError('Active invitation limit reached')
            c.execute('''UPDATE invitations SET revoked_at=? WHERE organization_id=? AND github_id=?
                AND accepted_at IS NULL AND revoked_at IS NULL''',(now,organization_id,github_id))
            c.execute('INSERT INTO invitations VALUES(?,?,?,?,?,?,?,?,NULL,NULL)',
                      (id_,hashlib.sha256(token.encode()).hexdigest(),organization_id,github_id,role,actor_id,now,now+7*86400))
            self.store.audit_event('organization:'+organization_id,None,actor_id,'invitation_created',
                                   {'invitation_id':id_,'github_id':github_id,'role':role})
        return {'id':id_,'token':token,'expires_at':now+7*86400}

    def revoke_invitation(self,organization_id,id_,actor_id):
        with self.store.transaction(),self.store.conn() as c:
            self._lock_organization(c,organization_id);self._require_admin(c,organization_id,actor_id)
            result=c.execute('''UPDATE invitations SET revoked_at=? WHERE id=? AND organization_id=?
                AND accepted_at IS NULL AND revoked_at IS NULL''',(time.time(),id_,organization_id))
            if not result.rowcount: raise LookupError('Invitation not found')
            self.store.audit_event('organization:'+organization_id,None,actor_id,'invitation_revoked',{'invitation_id':id_})

    def accept_invitation(self,token,actor_id):
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):
            raise LookupError('Invitation unavailable')
        with self.store.transaction(),self.store.conn() as c:
            invitation=c.execute('SELECT * FROM invitations WHERE token_hash=?',
                                 (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if invitation is None: raise LookupError('Invitation unavailable')
            self._lock_organization(c,invitation['organization_id'])
            invitation=c.execute('SELECT * FROM invitations WHERE id=?',(invitation['id'],)).fetchone()
            user=c.execute('SELECT github_id FROM users WHERE id=?',(actor_id,)).fetchone()
            now=time.time()
            if (user is None or user['github_id']!=invitation['github_id'] or invitation['accepted_at'] is not None or
                invitation['revoked_at'] is not None or invitation['expires_at']<=now):
                raise LookupError('Invitation unavailable')
            self._require_admin(c,invitation['organization_id'],invitation['invited_by'])
            if c.execute('SELECT 1 FROM memberships WHERE organization_id=? AND user_id=?',
                         (invitation['organization_id'],actor_id)).fetchone():
                raise ValueError('User is already a member')
            c.execute('INSERT INTO memberships VALUES(?,?,?,?,?)',
                      (invitation['organization_id'],actor_id,invitation['role'],now,now))
            c.execute('UPDATE invitations SET accepted_at=? WHERE id=?',(now,invitation['id']))
            self.store.audit_event('organization:'+invitation['organization_id'],None,actor_id,'invitation_accepted',
                                   {'invitation_id':invitation['id']})
            return {'organization_id':invitation['organization_id'],'role':invitation['role']}

    def list_organizations(self,user_id):
        with self.store.conn() as c:
            return [dict(row) for row in c.execute('''SELECT o.id,o.name,m.role FROM organizations o
                JOIN memberships m ON m.organization_id=o.id WHERE m.user_id=? ORDER BY o.created_at''',(user_id,))]

    def record_repository_ownership(self,organization_id,repo,actor_id,verification_reference):
        """After server-side GitHub ownership verification (VF-024), record its reference.

        The reference is an audit correlation ID, not cryptographic proof. Never
        pass a reference supplied by an unauthenticated/customer request here.
        """
        if (not isinstance(verification_reference,str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}',verification_reference)):
            raise ValueError('Server verification reference required')
        with self.store.transaction(), self.store.conn() as c:
            self._lock_organization(c,organization_id)
            self._require_admin(c,organization_id,actor_id)
            if c.execute('SELECT 1 FROM repositories WHERE full_name=?',(repo,)).fetchone() is None:
                raise ValueError('Repository must be registered by the integration')
            c.execute('''INSERT INTO repository_ownership VALUES(?,?,?,?,?) ON CONFLICT(repo) DO NOTHING''',
                (repo,organization_id,actor_id,verification_reference,time.time()))
            owner=c.execute('SELECT organization_id FROM repository_ownership WHERE repo=?',(repo,)).fetchone()
            if owner['organization_id']!=organization_id:
                raise PermissionError('Repository is already owned by another organization')
            self.store.audit_event(repo,None,actor_id,'repository_ownership_recorded',
                {'organization_id':organization_id,'verification_reference':verification_reference})
        return {'repo':repo,'organization_id':organization_id}

    def set_remediation_policy(self,organization_id,repo,actor_id,enabled,packages,paths):
        from .privacy import path_id
        if (type(enabled) is not bool or not isinstance(packages,list) or not isinstance(paths,list) or
            not 1<=len(packages)<=100 or not 1<=len(paths)<=80):
            raise ValueError('Explicit package and file allowlists are required')
        for package in packages:
            if not isinstance(package,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,213}',package):
                raise ValueError('Only exact PyPI package names are supported')
        for path in paths:
            path_id(path)
            if path.rsplit('/',1)[-1]!='requirements.txt' or any(p.startswith('.') for p in path.split('/')):
                raise ValueError('Only explicitly selected requirements files are supported')
        with self.store.transaction(),self.store.conn() as c:
            self._lock_organization(c,organization_id);self._require_admin(c,organization_id,actor_id)
            repository=c.execute('''SELECT r.connection_id FROM repositories r JOIN repository_ownership o ON o.repo=r.full_name
                WHERE r.full_name=? AND o.organization_id=?'''+(' FOR UPDATE OF r' if self.store.backend=='postgresql' else ''),
                (repo,organization_id)).fetchone()
            if repository is None: raise LookupError('Repository unavailable')
            normalized=sorted({re.sub(r'[-_.]+','-',p).lower() for p in packages})
            c.execute('''INSERT INTO remediation_policies VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(repo) DO UPDATE SET
                connection_id=excluded.connection_id,organization_id=excluded.organization_id,approved_by=excluded.approved_by,
                enabled=excluded.enabled,allowed_packages=excluded.allowed_packages,allowed_files=excluded.allowed_files,updated_at=excluded.updated_at''',
                (repo,repository['connection_id'],organization_id,actor_id,int(enabled),json.dumps(normalized),json.dumps(sorted(set(paths))),time.time()))
            self.store.audit_event(repo,None,actor_id,'remediation_policy_changed',{'enabled':enabled,'organization_id':organization_id})
        return {'repo':repo,'enabled':enabled,'automerge':False,'publication_ready':False}
