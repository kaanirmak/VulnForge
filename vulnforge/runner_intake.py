"""Local preview of identity-verified runner intake; never promotes a scan baseline."""
import hashlib
import json
import math
import time

from .identity import Identities
from .oidc import RunnerIdentity
from .runner_report import RunnerReport


class RunnerDenied(PermissionError): pass
class RunnerConflict(ValueError): pass


def digest(value): return hashlib.sha256(value.encode()).hexdigest()


def policy_digest(policy):
    return digest(json.dumps({key:policy[key] for key in (
        'repo','connection_id','organization_id','repository_id','owner_id','workflow_ref','ref','approved_by','verified_at')},
        sort_keys=True,separators=(',',':')))


class RunnerIntake:
    def __init__(self,store,cfg,metadata): self.store=store;self.cfg=cfg;self.metadata=metadata

    def _registration(self,organization,repo,actor):
        with self.store.conn() as c:
            Identities._require_admin(c,organization,actor)
            row=c.execute('''SELECT r.* FROM repositories r JOIN repository_ownership o ON o.repo=r.full_name
                WHERE r.full_name=? AND o.organization_id=?''',(repo,organization)).fetchone()
            if row is None: raise LookupError('Repository unavailable')
            return dict(row)

    async def configure(self,organization,repo,actor,workflow):
        if workflow not in self.cfg.runner_trusted_workflows: raise RunnerDenied('Workflow not approved by platform')
        snapshot=self._registration(organization,repo,actor)
        verified=await self.metadata.repository(repo,snapshot['installation_id'])
        with self.store.transaction(),self.store.conn() as c:
            Identities(self.store)._lock_organization(c,organization)
            c.execute('SELECT full_name FROM repositories WHERE full_name=?'+
                      (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(repo,)).fetchone()
            current=self._registration(organization,repo,actor)
            if (current['connection_id']!=snapshot['connection_id'] or
                current['installation_id']!=snapshot['installation_id'] or
                verified['default_branch']!=current['default_branch']):
                raise RunnerConflict('Repository changed; verify again')
            c.execute('''INSERT INTO runner_policies VALUES(?,?,?,?,?,?,?,?,?,1) ON CONFLICT(repo) DO UPDATE SET
                connection_id=excluded.connection_id,organization_id=excluded.organization_id,
                repository_id=excluded.repository_id,owner_id=excluded.owner_id,workflow_ref=excluded.workflow_ref,
                ref=excluded.ref,approved_by=excluded.approved_by,verified_at=excluded.verified_at,enabled=1''',
                (repo,current['connection_id'],organization,verified['repository_id'],verified['owner_id'],workflow,
                 'refs/heads/'+current['default_branch'],actor,time.time()))
            self.store.audit_event(repo,None,actor,'runner_policy_configured',
                                   {'organization_id':organization,'workflow_ref':workflow})
        return {'repo':repo,'workflow_ref':workflow,'upload_state':'preview_quarantine','baseline_ready':False}

    def disable(self,organization,repo,actor):
        with self.store.transaction(),self.store.conn() as c:
            Identities(self.store)._lock_organization(c,organization)
            self._registration(organization,repo,actor)
            c.execute('DELETE FROM runner_policies WHERE repo=? AND organization_id=?',(repo,organization))
            self.store.audit_event(repo,None,actor,'runner_policy_disabled',{'organization_id':organization})

    def policy(self,repo):
        with self.store.conn() as c:
            row=c.execute('''SELECT p.* FROM runner_policies p
                JOIN repositories r ON r.full_name=p.repo AND r.connection_id=p.connection_id
                JOIN repository_ownership o ON o.repo=p.repo AND o.organization_id=p.organization_id
                JOIN memberships m ON m.organization_id=p.organization_id AND m.user_id=p.approved_by
                WHERE p.repo=? AND p.enabled=1 AND m.role='org_admin'
                AND p.ref=('refs/heads/' || r.default_branch)''',(repo,)).fetchone()
        if row is None or row['workflow_ref'] not in self.cfg.runner_trusted_workflows:
            raise RunnerDenied('Runner policy unavailable')
        return dict(row)

    @staticmethod
    def _matches(identity,report,policy):
        if (identity.repository!=report.repo or identity.commit_sha!=report.commit_sha or
            identity.repository_id!=policy['repository_id'] or identity.owner_id!=policy['owner_id'] or
            identity.workflow_ref!=policy['workflow_ref'] or identity.ref!=policy['ref'] or
            identity.issued_at<math.ceil(policy['verified_at']) or identity.expires_at<=time.time()):
            raise RunnerDenied('Runner scope rejected')

    async def accept(self,identity,report):
        if not isinstance(identity,RunnerIdentity) or not isinstance(report,RunnerReport):
            raise TypeError('Verified identity and validated report required')
        report=RunnerReport.model_validate(report)
        policy=self.policy(identity.repository);self._matches(identity,report,policy)
        repository=self.store.repository(identity.repository)
        if repository is None or repository['connection_id']!=policy['connection_id']:
            raise RunnerDenied('Repository connection changed')
        verified=await self.metadata.repository(identity.repository,repository['installation_id'])
        if (verified['repository_id']!=identity.repository_id or verified['owner_id']!=identity.owner_id or
            'refs/heads/'+verified['default_branch']!=identity.ref):
            raise RunnerDenied('Repository verification mismatch')
        canonical=json.dumps(report.model_dump(),sort_keys=True,separators=(',',':'),ensure_ascii=True)
        body_hash=digest(canonical);proof=policy_digest(policy)
        id_=digest(':'.join((policy['connection_id'],identity.run_id,identity.run_attempt,report.scan_kind,body_hash)))
        jti_hash=digest(identity.jti)
        with self.store.transaction(),self.store.conn() as c:
            Identities(self.store)._lock_organization(c,policy['organization_id'])
            row=c.execute('SELECT * FROM repositories WHERE full_name=?'+
                          (' FOR UPDATE' if self.store.backend=='postgresql' else ''),(report.repo,)).fetchone()
            if row is None or row['connection_id']!=policy['connection_id']:
                raise RunnerDenied('Repository connection changed')
            current=self.policy(identity.repository);self._matches(identity,report,current)
            if policy_digest(current)!=proof: raise RunnerDenied('Runner policy changed')
            used=c.execute('''SELECT r.id FROM runner_token_uses t JOIN runner_receipts r ON r.id=t.receipt_id
                WHERE t.jti_hash=?''',(jti_hash,)).fetchone()
            if used is not None and used['id']!=id_: raise RunnerConflict('Token already used for another report')
            previous=c.execute('''SELECT * FROM runner_receipts WHERE connection_id=? AND run_id=?
                AND run_attempt=? AND scan_kind=?''',
                (policy['connection_id'],identity.run_id,identity.run_attempt,report.scan_kind)).fetchone()
            if previous is not None and (previous['id']!=id_ or previous['policy_digest']!=proof):
                raise RunnerConflict('Run report already recorded with different evidence')
            duplicate=previous is not None
            if not duplicate:
                c.execute('''INSERT INTO runner_receipts(id,repo,connection_id,organization_id,policy_digest,
                    body_digest,commit_sha,scan_kind,report,workflow_ref,caller_workflow_ref,run_id,run_attempt,
                    event_name,runner_environment,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (id_,report.repo,policy['connection_id'],policy['organization_id'],proof,body_hash,
                     report.commit_sha,report.scan_kind,canonical,identity.workflow_ref,identity.caller_workflow_ref,
                     identity.run_id,identity.run_attempt,identity.event,identity.runner_environment,time.time()))
            inserted=c.execute('INSERT INTO runner_token_uses VALUES(?,?,?) ON CONFLICT DO NOTHING',
                               (jti_hash,id_,identity.expires_at)).rowcount
            if not inserted:
                target=c.execute('SELECT receipt_id FROM runner_token_uses WHERE jti_hash=?',(jti_hash,)).fetchone()
                if target['receipt_id']!=id_: raise RunnerConflict('Token replay rejected')
            if not duplicate:
                self.store.audit_event(report.repo,None,'github-actions','runner_identity_verified',
                    {'receipt_id':id_,'organization_id':policy['organization_id'],'run_id':identity.run_id,
                     'run_attempt':identity.run_attempt,'workflow_ref':identity.workflow_ref})
        return {'receipt_id':id_,'duplicate':duplicate,'trust_state':'identity_verified_quarantined','baseline_ready':False}
