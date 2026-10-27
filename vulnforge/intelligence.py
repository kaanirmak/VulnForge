"""Evidence-based upgrade suggestions; never installs or executes project code."""
import re
import time
from packaging.version import InvalidVersion, Version

from .dependencies import Dependency


def version_key(version: str, ecosystem: str):
    """Only compare version schemes understood here; ambiguity is not an upgrade."""
    if ecosystem == 'PyPI':
        parsed = Version(version)
        if parsed.is_prerelease or parsed.is_devrelease or parsed.local:
            raise ValueError('Unstable or local version')
        return parsed
    if ecosystem not in ('npm', 'Go', 'crates.io', 'Packagist'):
        raise ValueError('Unsupported ecosystem comparator')
    pattern = r'(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?'
    match = re.fullmatch(('v' if ecosystem == 'Go' else '') + pattern, version)
    if not match:
        raise ValueError('Unsupported release version')
    return tuple(int(value) for value in match.groups())


def package_key(name, ecosystem):
    if ecosystem == 'PyPI': return re.sub(r'[-_.]+', '-', name).lower()
    if ecosystem == 'crates.io': return name.lower().replace('_', '-')
    return name.lower() if ecosystem in ('npm', 'Packagist', 'NuGet') else name


def fixed_releases(dep: Dependency, advisory: dict):
    candidates = []
    old = version_key(dep.version, dep.ecosystem)
    for affected in advisory.get('affected', []):
        package = affected.get('package', {})
        if (package.get('ecosystem') != dep.ecosystem or
            package_key(package.get('name', ''), dep.ecosystem) != package_key(dep.name, dep.ecosystem)):
            continue
        for interval in affected.get('ranges', []):
            if interval.get('type') not in ('ECOSYSTEM', 'SEMVER'):
                continue
            for event in interval.get('events', []):
                target = event.get('fixed')
                if not isinstance(target, str): continue
                try:
                    key = version_key(target, dep.ecosystem)
                    if key > old: candidates.append((key, target))
                except (InvalidVersion, ValueError):
                    continue
    return sorted(set(candidates))


def upgrade_class(dep, target):
    old, new = version_key(dep.version, dep.ecosystem), version_key(target, dep.ecosystem)
    if dep.ecosystem == 'PyPI':
        if old.epoch != new.epoch: return 'major'
        old, new = old.release, new.release
    old = tuple(old) + (0, 0, 0)
    new = tuple(new) + (0, 0, 0)
    return 'major' if old[0] != new[0] else 'minor' if old[1] != new[1] else 'patch'


async def recommend_updates(grouped: dict[Dependency, list[dict]], osv):
    """Check targets against *all* current OSV advisories for the package.

    Advisory fix metadata is a candidate, not proof of a published release,
    compatibility, successful tests, reachability, or a safe installation.
    """
    output = {}
    checks = {}
    pending = {}
    for dep, advisories in grouped.items():
        result = {'package': dep.name, 'ecosystem': dep.ecosystem, 'file_path': dep.file_path,
                  'current_version': dep.version, 'recommended_version': None,
                  'advisory_ids': sorted({a['id'] for a in advisories}),
                  'status': 'no_known_fix', 'release_verified': False, 'tests_verified': False,
                  'compatibility_verified': False, 'requires_review': True,
                  'note': 'No supported fixed release is documented; review mitigations and upstream guidance.'}
        output[dep] = result
        try:
            options = [fixed_releases(dep, a) for a in advisories]
            if not all(options): continue
            # Try the minimum common target, then other documented fixed releases
            # if the first one is still affected by a separate advisory.
            floor = max(values[0][0] for values in options)
            candidates = sorted({pair for values in options for pair in values if pair[0] >= floor})
        except (InvalidVersion, ValueError):
            result.update(status='unsupported_version', note='Version scheme requires manual review.')
            continue
        accepted=[]
        source_ranges=[a.get('github_range') for a in advisories if a.get('_evidence_source')=='GitHub webhook']
        for _, target in candidates[:20]:
            decisions=[in_github_range(target,dep.ecosystem,interval) for interval in source_ranges]
            if any(value is not False for value in decisions):
                result.update(status='target_still_affected',note='Target is not proven outside the newly published advisory range.')
            else:
                accepted.append(target)
        if accepted: pending[dep]=accepted

    # Verify one candidate per package in a batch, coalescing identical targets
    # across manifests. OSV itself chunks these requests into groups of 100.
    def query_key(dep, target):
        return dep.ecosystem,package_key(dep.name,dep.ecosystem),target
    while pending:
        selected=[(dep,targets.pop(0)) for dep,targets in pending.items()]
        missing={query_key(dep,target):Dependency(dep.name,target,dep.ecosystem,dep.file_path)
                 for dep,target in selected if query_key(dep,target) not in checks}
        if missing:
            try:
                affected=await osv.check(list(missing.values()))
                affected_keys={query_key(dep,dep.version) for dep,_ in affected}
                for key in missing: checks[key]=key in affected_keys
            except Exception:
                for dep,target in selected:
                    if query_key(dep,target) in missing:
                        output[dep].update(status='verification_failed',note='Could not verify the target against OSV; no verified upgrade recommendation.')
                        pending.pop(dep,None)
        for dep,target in selected:
            if dep not in pending: continue
            if checks[query_key(dep,target)]:
                output[dep].update(status='target_still_affected',note='Documented fix still has an OSV advisory; review another release.')
                if not pending[dep]: pending.pop(dep)
                continue
            output[dep].update(status='update_available',recommended_version=target,
                upgrade_class=upgrade_class(dep,target),verified_at=time.time(),
                verification_source='OSV package/version query',
                note='No known advisory returned by OSV for this target. Confirm release availability, regenerate lockfiles and run tests before upgrading.')
            pending.pop(dep)
    return output


def advisory_identity(advisory):
    identifiers = {advisory['id'], *advisory.get('aliases', [])}
    ghsas = sorted(value for value in identifiers if value.startswith('GHSA-'))
    return ghsas[0] if ghsas else advisory['id']


GITHUB_ECOSYSTEMS = {'pip':'PyPI','npm':'npm','go':'Go','rust':'crates.io',
                     'composer':'Packagist','rubygems':'RubyGems','nuget':'NuGet'}


def in_github_range(version, ecosystem, expression):
    """Evaluate only explicit comparison ranges. Unsupported syntax stays unknown."""
    if not isinstance(expression,str) or not expression.strip() or len(expression)>1000:
        return None
    try: current=version_key(version,ecosystem)
    except (ValueError,InvalidVersion): return None
    alternatives=[]
    for group in expression.split('||'):
        clauses=[]
        for clause in group.split(','):
            match=re.fullmatch(r'\s*(>=|<=|==|>|<|=)?\s*([A-Za-z0-9.!+_-]+)\s*',clause)
            if not match:
                clauses.append(None)
                continue
            try: bound=version_key(match[2],ecosystem)
            except (ValueError,InvalidVersion):
                clauses.append(None)
                continue
            op=match[1] or '='
            clauses.append({'<':current<bound,'<=':current<=bound,'>':current>bound,
                            '>=':current>=bound,'=':current==bound,'==':current==bound}[op])
        alternatives.append(False if False in clauses else None if None in clauses else True)
    return True if True in alternatives else None if None in alternatives else False


def github_matches(saved, dependencies):
    """Match a signed GHSA payload even before its OSV index is updated.

    Positive matches need exact package/version evidence. A negative repository
    result additionally requires a complete inventory (enforced by the caller).
    """
    data=saved['data']
    rows=data.get('vulnerabilities',[])
    unknown=not rows or len(rows)>150
    matches=[]
    by_package={}
    for dep in dependencies:
        by_package.setdefault((dep.ecosystem,package_key(dep.name,dep.ecosystem)),[]).append(dep)
    for row in rows[:150]:
        package=row.get('package') or {}
        eco=GITHUB_ECOSYSTEMS.get(str(package.get('ecosystem','')).lower())
        name=package.get('name')
        if not eco or not isinstance(name,str):
            unknown=True
            continue
        for dep in by_package.get((eco,package_key(name,eco)),[]):
            decision=in_github_range(dep.version,eco,row.get('vulnerable_version_range'))
            if decision is None:
                unknown=True
            if decision is not True: continue
            fixed=row.get('first_patched_version')
            if isinstance(fixed,dict): fixed=fixed.get('identifier')
            events=[{'introduced':'0'}]+([{'fixed':fixed}] if isinstance(fixed,str) else [])
            advisory={'id':saved['id'],'aliases':saved['aliases'],'summary':saved['summary'],
                'modified':data.get('modified'),'_evidence_source':'GitHub webhook',
                'github_range':row.get('vulnerable_version_range'),
                'affected':[{'package':{'ecosystem':eco,'name':name},
                             'ranges':[{'type':'ECOSYSTEM','events':events}]}]}
            matches.append((dep,advisory))
    return ('affected' if matches else 'under_investigation' if unknown else 'not_affected'),matches
