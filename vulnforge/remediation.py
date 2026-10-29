"""Conservative, opt-in automatic draft-PR builder (never merges)."""
import hashlib
import re
from packaging.version import Version, InvalidVersion
from .dependencies import Dependency
from .osv import fixed_version


# Only exact, unadorned requirement pins can be safely replaced here.
REQ_LINE = re.compile(r'^(?P<indent>\s*)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>\s*==\s*)'
                      r'(?P<version>[A-Za-z0-9_.!+-]+)(?P<rest>\s*(?:#.*)?)$', re.MULTILINE)


def patched_requirement(source: str, dep: Dependency, target: str) -> str | None:
    if dep.file_path.rsplit('/',1)[-1]!='requirements.txt' or dep.ecosystem!='PyPI':
        return None
    try:
        if Version(target) <= Version(dep.version) or Version(target).is_prerelease:
            return None
    except InvalidVersion:
        return None
    matches=[m for m in REQ_LINE.finditer(source) if m['name'].lower().replace('_','-') == dep.name.lower().replace('_','-')
             and m['version']==dep.version]
    if len(matches)!=1:
        return None
    match=matches[0]
    return source[:match.start('version')]+target+source[match.end('version'):]


def candidate_version(dep: Dependency, advisories: list[dict]):
    """Choose a version that is >= every known fixed version for package."""
    versions=[]
    for a in advisories:
        v=fixed_version(dep,a)
        if not v:
            return None
        versions.append(Version(v))
    return str(max(versions)) if versions else None


def remediation_key(path: str, dep: Dependency, target: str):
    return hashlib.sha256(f'{path}:{dep.name}:{dep.version}->{target}'.encode()).hexdigest()[:24]


def branch_for(dep: Dependency, key: str):
    safe=re.sub(r'[^a-z0-9-]+','-',dep.name.lower())[:35].strip('-')
    return f'vulnforge/security/{safe}-{key[:10]}'


REQUIRED_CHECKS=(
    'lockfile_resolution',
    'isolated_build_and_test',
    'post_patch_sast_sca_rescan',
    'inventory_diff_verification',
    'sha_diff_bound_human_approval',
)
SHA_PATTERN=re.compile(r'^[0-9a-f]{40}$')


def _upgrade_class(current: str, target: str) -> str:
    try:
        cur,tgt=Version(current),Version(target)
        if tgt<=cur or tgt.is_prerelease or cur.is_prerelease: return 'unknown'
        if tgt.major!=cur.major: return 'major'
        if tgt.minor!=cur.minor: return 'minor'
        return 'patch'
    except InvalidVersion:
        return 'unknown'


def build_patch_plan(repo: str, base_branch: str, baseline_sha: str, policy: dict,
                     files: dict, dep: Dependency, advisories: list[dict],
                     recommendation: dict | None = None) -> dict | None:
    """Create a deterministic metadata-only patch plan; never publishes or merges."""
    from .db import Store
    from .intelligence import advisory_identity
    from .privacy import PrivacyError, path_id
    if not isinstance(baseline_sha,str) or not SHA_PATTERN.fullmatch(baseline_sha):
        raise ValueError('Valid 40-character baseline SHA required')
    if not isinstance(base_branch,str) or not base_branch or any(c.isspace() for c in base_branch):
        raise ValueError('Valid base branch required')
    if (not isinstance(policy,dict) or not policy.get('enabled') or policy.get('repo')!=repo or
        not policy.get('connection_id') or not policy.get('organization_id')):
        return None
    normalized=Store.normalize_package(dep.name,dep.ecosystem)
    allowed_packages=set(policy.get('allowed_packages') or ())
    allowed_files=set(policy.get('allowed_files') or ())
    if normalized not in allowed_packages or dep.file_path not in allowed_files:
        return None
    try: path_id(dep.file_path)
    except PrivacyError: return None
    filename = dep.file_path.rsplit('/',1)[-1]
    if filename not in ('requirements.txt', 'package.json', 'package-lock.json') or any(p.startswith('.') for p in dep.file_path.split('/')):
        return None
    target=None
    if recommendation is not None:
        if recommendation.get('status')=='candidate_verified':
            target=recommendation.get('recommended_version')
    else:
        target=candidate_version(dep,advisories)
    try:
        if target and (Version(target)<=Version(dep.version) or Version(target).is_prerelease):
            target=None
    except InvalidVersion:
        target=None
    upgrade=_upgrade_class(dep.version,target) if target else 'unknown'
    file_entry=files.get(dep.file_path) if isinstance(files,dict) else None
    manifest_text=file_entry.get('text') if isinstance(file_entry,dict) else None
    manifest_sha256=(hashlib.sha256(manifest_text.encode('utf-8')).hexdigest()
                     if isinstance(manifest_text,str) else None)
    patched_sha256=None
    lockfile_path=None
    lockfile_sha256=None
    patched_lockfile_sha256=None
    if isinstance(files, dict) and target:
        from .patch_resolver import resolve_manifest_and_lockfile
        res = resolve_manifest_and_lockfile(files, dep, target)
        if res.get('success'):
            manifest_sha256 = res.get('manifest_sha256')
            patched_sha256 = res.get('updated_manifest_sha256')
            if res.get('lockfile_path'):
                lockfile_path = res.get('lockfile_path')
                lockfile_sha256 = res.get('lockfile_sha256')
                patched_lockfile_sha256 = res.get('updated_lockfile_sha256')
        elif isinstance(manifest_text, str):
            patched = patched_requirement(manifest_text, dep, target)
            if patched is not None:
                patched_sha256 = hashlib.sha256(patched.encode('utf-8')).hexdigest()
    elif isinstance(manifest_text,str) and target:
        patched=patched_requirement(manifest_text,dep,target)
        if patched is not None:
            patched_sha256=hashlib.sha256(patched.encode('utf-8')).hexdigest()
    blockers=[]
    if not target:
        blockers.append('no_verified_target_version')
    if manifest_sha256 is None:
        blockers.append('baseline_manifest_unavailable')
    if patched_sha256 is None:
        blockers.append('lockfile_resolver_required')
    if upgrade=='major':
        blockers.append('major_upgrade_requires_explicit_review')
    blockers.extend(('isolated_validation_required','bound_human_approval_required'))
    key=remediation_key(dep.file_path,dep,target or 'unverified')
    advisory_ids=sorted({advisory_identity(a) for a in advisories if isinstance(a,dict) and a.get('id')})
    return {
        'plan_id':key,
        'repo':repo,
        'connection_id':policy['connection_id'],
        'organization_id':policy['organization_id'],
        'base_branch':base_branch,
        'baseline_sha':baseline_sha,
        'ecosystem':dep.ecosystem,
        'package':dep.name,
        'normalized_package':normalized,
        'current_version':dep.version,
        'target_version':target,
        'upgrade_class':upgrade,
        'file_path':dep.file_path,
        'allowed_files':[dep.file_path] if not lockfile_path else [dep.file_path, lockfile_path],
        'manifest_sha256':manifest_sha256,
        'patched_manifest_sha256':patched_sha256,
        'lockfile_path':lockfile_path,
        'lockfile_sha256':lockfile_sha256,
        'patched_lockfile_sha256':patched_lockfile_sha256,
        'advisory_ids':advisory_ids,
        'branch_name':branch_for(dep,key) if target else None,
        'required_checks':list(REQUIRED_CHECKS),
        'validation_status':'pending_isolated_execution',
        'approval_status':'pending_human_approval',
        'status':'planned_pending_validation' if target and manifest_sha256 else 'blocked',
        'publication_allowed':False,
        'automerge_allowed':False,
        'blockers':blockers,
    }


def compute_patch_diff_hash(original_files: dict, patched_files: dict) -> str:
    """Deterministic hash of unified diff / patched modifications."""
    chunks = []
    for path in sorted(patched_files.keys()):
        orig_entry = original_files.get(path)
        orig_text = orig_entry.get('text') if isinstance(orig_entry, dict) else (orig_entry or "")
        patched_text = patched_files[path]
        chunks.append(f"--- a/{path}\n+++ b/{path}\n{orig_text}=>{patched_text}\n")
    return hashlib.sha256("".join(chunks).encode('utf-8')).hexdigest()


def evaluate_publication_gate(
    plan: dict,
    *,
    validation_evidence: dict | None = None,
    approval: dict | None = None,
    current_head_sha: str | None = None,
    current_diff_sha256: str | None = None,
    touched_files: list[str] | tuple[str, ...] | None = None,
    policy: dict | None = None
) -> dict:
    """Strict publication gate enforcing validation, bound human approval, safe files, minor/patch only, and head freshness."""
    blockers = []

    # 1. Validation check
    if not validation_evidence or not validation_evidence.get('all_checks_passed'):
        blockers.append('validation_failed_or_missing')
    elif validation_evidence.get('plan_id') != plan.get('plan_id'):
        blockers.append('validation_plan_mismatch')
    elif validation_evidence.get('baseline_sha') != plan.get('baseline_sha'):
        blockers.append('validation_baseline_mismatch')

    # 2. HEAD drift check
    if current_head_sha is not None and current_head_sha != plan.get('baseline_sha'):
        blockers.append('baseline_head_drift_detected')

    # 3. Risky / unauthorized file check
    files_to_check = set(touched_files or plan.get('allowed_files') or [])
    allowed = set(policy.get('allowed_files') if policy else plan.get('allowed_files') or [])
    for f in sorted(files_to_check):
        if f not in allowed:
            blockers.append(f'unauthorized_file_modified:{f}')
        if any(f.startswith(p) or f.endswith(('.sh', '.env', '.exe', '.bat')) for p in ('.github/', '.circleci/', '.gitlab-ci', '.env')):
            blockers.append(f'risky_file_modified:{f}')

    # 4. Major upgrade check
    if plan.get('upgrade_class') == 'major':
        blockers.append('major_upgrade_requires_explicit_review')

    # 5. Bound human approval check
    if not approval or approval.get('status') != 'approved':
        blockers.append('bound_human_approval_required')
    else:
        if approval.get('baseline_sha') != plan.get('baseline_sha'):
            blockers.append('approval_baseline_mismatch')
        if current_diff_sha256 and approval.get('diff_sha256') != current_diff_sha256:
            blockers.append('approval_diff_mismatch')
        if not approval.get('user_id'):
            blockers.append('approval_user_missing')

    publication_allowed = len(blockers) == 0
    return {
        'plan_id': plan.get('plan_id'),
        'publication_allowed': publication_allowed,
        'blockers': sorted(set(blockers)),
        'baseline_sha': plan.get('baseline_sha'),
        'current_head_sha': current_head_sha,
        'approval_status': 'approved' if (approval and approval.get('status') == 'approved' and not any(b.startswith('approval_') for b in blockers)) else 'pending_human_approval',
        'gate_status': 'passed' if publication_allowed else 'halted'
    }


def build_patch_plans(repo: str, base_branch: str, baseline_sha: str, policy: dict | None,
                      files: dict, grouped: dict[Dependency,list[dict]],
                      recommendations: dict[Dependency,dict] | None = None) -> list[dict]:
    if not policy:
        return []
    plans=[]
    for dep,advisories in sorted(grouped.items(),key=lambda item:(item[0].file_path,item[0].ecosystem,item[0].name,item[0].version)):
        rec=recommendations.get(dep) if isinstance(recommendations,dict) else None
        plan=build_patch_plan(repo,base_branch,baseline_sha,policy,files,dep,advisories,rec)
        if plan is not None:
            plans.append(plan)
    return plans


def build_unfixed_mitigation_plan(
    repo: str,
    dep: Dependency,
    advisory: dict,
    recommendation: dict,
    *,
    owner: str | None = None,
    priority: str = 'P2',
    recheck_interval_hours: int = 24
) -> dict:
    """Build an active mitigation and SLA tracking record for unfixed vulnerabilities."""
    from .intelligence import advisory_identity
    adv_id = advisory_identity(advisory)
    guidance = (
        f"No published fix currently exists for {dep.name}=={dep.version} ({adv_id}). "
        f"Recommended mitigations: 1) Apply network/WAF filtering rules if applicable; "
        f"2) Disable affected component via feature flag; "
        f"3) Track upstream maintainer release issues; "
        f"4) Audit usage for exploitable call paths."
    )
    sla_map = {'P0': 24, 'P1': 72, 'P2': 336, 'P3': 720}
    sla_hours = sla_map.get(priority, 336)
    return {
        'repo': repo,
        'advisory_id': adv_id,
        'package': dep.name,
        'ecosystem': dep.ecosystem,
        'current_version': dep.version,
        'mitigation_guidance': guidance,
        'owner': owner,
        'priority': priority,
        'sla_hours': sla_hours,
        'recheck_interval_hours': recheck_interval_hours,
        'status': 'active'
    }


def evaluate_sla_status(plan: dict, now: float | None = None) -> str:
    import time
    t = time.time() if now is None else now
    deadline = plan.get('sla_deadline', 0.0)
    created = plan.get('created_at', 0.0)
    if plan.get('status') != 'active':
        return plan.get('status', 'resolved')
    if t > deadline:
        return 'breached'
    total_window = max(1.0, deadline - created)
    if t > (deadline - 0.2 * total_window):
        return 'at_risk'
    return 'within_sla'
