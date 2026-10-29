"""Evidence-based upgrade suggestions; never installs or executes project code."""
import re
import time
import httpx
from packaging.version import InvalidVersion, Version

from .dependencies import Dependency


def version_key(version: str, ecosystem: str):
    """Only compare version schemes understood here; ambiguity is not an upgrade."""
    if not isinstance(version, str) or not version.strip():
        raise ValueError('Empty version')
    if ecosystem == 'PyPI':
        parsed = Version(version)
        if parsed.is_prerelease or parsed.is_devrelease or parsed.local:
            raise ValueError('Unstable or local version')
        return parsed
    if ecosystem in ('npm', 'Go', 'crates.io'):
        pattern = r'(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?'
        match = re.fullmatch(('v' if ecosystem == 'Go' else '') + pattern, version)
        if not match:
            raise ValueError('Unsupported release version')
        a, b, c = (int(value) for value in match.groups())
        return (a, b, c, 0)
    if ecosystem == 'Packagist':
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:\+[0-9A-Za-z.-]+)?', version)
        if not match:
            raise ValueError('Unsupported release version')
        parts = [int(v) if v is not None else 0 for v in match.groups()]
        return tuple(parts)
    if ecosystem in ('RubyGems', 'NuGet', 'Maven'):
        match = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\+[0-9A-Za-z.-]+)?', version)
        if not match:
            raise ValueError('Unsupported release version')
        parts = [int(v) if v is not None else 0 for v in match.groups()]
        return tuple(parts)
    raise ValueError('Unsupported ecosystem comparator')


def compare_versions(left: str, right: str, ecosystem: str) -> int | None:
    """Compare two versions within an ecosystem; return -1, 0, 1, or None if unknown."""
    try:
        lk = version_key(left, ecosystem)
        rk = version_key(right, ecosystem)
    except (InvalidVersion, ValueError, TypeError):
        return None
    return -1 if lk < rk else (1 if lk > rk else 0)


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


async def recommend_updates(grouped: dict[Dependency, list[dict]], osv, *, registry_verifier=None):
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
            if registry_verifier is not None:
                try:
                    reg = await registry_verifier.verify_release(dep.name, target, dep.ecosystem)
                except Exception:
                    reg = {'published': False, 'error': True}
                if not reg.get('published'):
                    output[dep].update(status='release_not_published', release_verified=False,
                                       note='Target release not published in package registry; review another candidate.')
                    if not pending[dep]: pending.pop(dep)
                    continue
                if reg.get('yanked'):
                    output[dep].update(status='release_yanked', release_verified=True, yanked=True,
                                       yanked_reason=reg.get('yanked_reason'),
                                       note='Target release has been yanked in package registry; review another candidate.')
                    if not pending[dep]: pending.pop(dep)
                    continue
                if reg.get('deprecated'):
                    output[dep].update(status='release_deprecated', release_verified=True, deprecated=True,
                                       deprecation_reason=reg.get('deprecation_reason'),
                                       note='Target release is deprecated in package registry; review another candidate.')
                    if not pending[dep]: pending.pop(dep)
                    continue
                output[dep].update(status='update_available', recommended_version=target,
                    release_verified=True, yanked=False, deprecated=False,
                    upgrade_class=upgrade_class(dep,target), verified_at=time.time(),
                    verification_source='OSV + package registry',
                    note='Verified release published in package registry with no known advisory.')
                pending.pop(dep)
                continue

            output[dep].update(status='update_available',recommended_version=target,
                upgrade_class=upgrade_class(dep,target),verified_at=time.time(),
                release_verified=False, yanked=False, deprecated=False,
                verification_source='OSV package/version query',
                note='No known advisory returned by OSV for this target. Confirm release availability, regenerate lockfiles and run tests before upgrading.')
            pending.pop(dep)
    return output


def advisory_identity(advisory):
    identifiers = {advisory['id'], *advisory.get('aliases', [])}
    ghsas = sorted(value for value in identifiers if value.startswith('GHSA-'))
    return ghsas[0] if ghsas else advisory['id']


GITHUB_ECOSYSTEMS = {'pip':'PyPI','npm':'npm','go':'Go','rust':'crates.io',
                     'composer':'Packagist','rubygems':'RubyGems','nuget':'NuGet','maven':'Maven'}


def in_github_range(version, ecosystem, expression):
    """Evaluate only explicit comparison ranges. Unsupported syntax stays unknown."""
    if not isinstance(expression,str) or not expression.strip() or len(expression)>1000:
        return None
    try: current=version_key(version,ecosystem)
    except (ValueError,InvalidVersion,TypeError): return None
    alternatives=[]
    for group in expression.split('||'):
        clauses=[]
        for clause in group.split(','):
            match=re.fullmatch(r'\s*(>=|<=|!=|==|>|<|=)?\s*([A-Za-z0-9.!+_-]+)\s*',clause)
            if not match:
                clauses.append(None)
                continue
            try: bound=version_key(match[2],ecosystem)
            except (ValueError,InvalidVersion,TypeError):
                clauses.append(None)
                continue
            op=match[1] or '='
            clauses.append({'<':current<bound,'<=':current<=bound,'>':current>bound,
                            '>=':current>=bound,'=':current==bound,'==':current==bound,
                            '!=':current!=bound}[op])
        alternatives.append(False if False in clauses else None if None in clauses else True)
    return True if True in alternatives else None if None in alternatives else False


def in_osv_range(version: str, ecosystem: str, ranges: list[dict]) -> bool | None:
    """Evaluate OSV ECOSYSTEM/SEMVER event ranges; unsupported ranges return None."""
    if not isinstance(ranges, list) or not ranges:
        return None
    try:
        current = version_key(version, ecosystem)
    except (ValueError, InvalidVersion, TypeError):
        return None
    unknown = False
    for interval in ranges:
        if not isinstance(interval, dict) or interval.get('type') not in ('ECOSYSTEM', 'SEMVER'):
            unknown = True
            continue
        events = interval.get('events')
        if not isinstance(events, list) or not events:
            unknown = True
            continue
        intro = None
        has_intro = False
        interval_unknown = False
        matched_interval = False
        for ev in events:
            if not isinstance(ev, dict) or len(ev) != 1:
                interval_unknown = True
                break
            if 'introduced' in ev:
                raw_intro = ev['introduced']
                has_intro = True
                if raw_intro in ('0', '0.0.0'):
                    intro = None
                else:
                    try:
                        intro = version_key(raw_intro, ecosystem)
                    except (ValueError, InvalidVersion, TypeError):
                        interval_unknown = True
                        break
            elif 'fixed' in ev:
                try:
                    fixed = version_key(ev['fixed'], ecosystem)
                except (ValueError, InvalidVersion, TypeError):
                    interval_unknown = True
                    break
                if has_intro and (intro is None or current >= intro) and current < fixed:
                    matched_interval = True
                has_intro = False
                intro = None
            elif 'last_affected' in ev:
                try:
                    last_aff = version_key(ev['last_affected'], ecosystem)
                except (ValueError, InvalidVersion, TypeError):
                    interval_unknown = True
                    break
                if has_intro and (intro is None or current >= intro) and current <= last_aff:
                    matched_interval = True
                has_intro = False
                intro = None
            else:
                interval_unknown = True
                break
        if interval_unknown:
            unknown = True
            continue
        if has_intro and (intro is None or current >= intro):
            matched_interval = True
        if matched_interval:
            return True
    return None if unknown else False


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


class AdvisoryIngestionRunner:
    """Persistent cursor-based advisory ingestion job with interruption resume and retry tracking."""

    def __init__(self, store, source_name: str, *, catalog_scope='public', max_retries: int = 3):
        self.store = store
        self.source_name = source_name
        self.catalog_scope = catalog_scope
        self.max_retries = max_retries

    async def ingest_batch(self, fetcher):
        """Execute one ingestion batch, updating persistent cursor and retry state.

        fetcher: async callable(cursor: str | None) -> tuple[list[dict], str | None, bool]
                 returns (advisories, next_cursor, has_more)
        """
        state = self.store.get_ingestion_state(self.source_name, catalog_scope=self.catalog_scope)
        current_cursor = state['cursor'] if state else None
        self.store.update_ingestion_state(
            self.source_name,
            status='running',
            catalog_scope=self.catalog_scope
        )
        try:
            advisories, next_cursor, has_more = await fetcher(current_cursor)
            saved_ids = []
            for adv in advisories:
                adv_id = self.store.save_advisory(adv, source=self.source_name, catalog_scope=self.catalog_scope)
                saved_ids.append(adv_id)

            last_id = saved_ids[-1] if saved_ids else (state['last_record_id'] if state else None)
            self.store.update_ingestion_state(
                self.source_name,
                cursor=next_cursor,
                last_record_id=last_id,
                status='idle' if not has_more else 'pending',
                processed_delta=len(advisories),
                reset_retry=True,
                success=True,
                error=None,
                catalog_scope=self.catalog_scope
            )
            return {
                'processed': len(advisories),
                'cursor': next_cursor,
                'has_more': has_more,
                'status': 'success'
            }
        except Exception as exc:
            self.store.update_ingestion_state(
                self.source_name,
                status='failed',
                error=str(exc),
                retry_increment=True,
                catalog_scope=self.catalog_scope
            )
            raise


class PackageRegistryVerifier:
    """Verifies that recommended releases are published, not yanked, and not deprecated."""

    def __init__(self, client: httpx.AsyncClient | None = None):
        self.client = client
        self.owns_client = client is None

    async def close(self):
        if self.owns_client and self.client:
            await self.client.aclose()

    async def verify_release(self, package: str, version: str, ecosystem: str) -> dict:
        now = time.time()
        client = self.client or httpx.AsyncClient(timeout=15, follow_redirects=True)
        should_close = self.client is None
        try:
            if ecosystem == 'PyPI':
                canonical = re.sub(r'[-_.]+', '-', package).lower()
                resp = await client.get(f'https://pypi.org/pypi/{canonical}/json')
                if resp.status_code == 404:
                    return {'published': False, 'yanked': False, 'deprecated': False, 'verified_at': now}
                resp.raise_for_status()
                data = resp.json()
                releases = data.get('releases', {})
                if version not in releases:
                    return {'published': False, 'yanked': False, 'deprecated': False, 'verified_at': now}
                files = releases[version]
                is_yanked = any(bool(f.get('yanked')) for f in files) if files else False
                yank_reason = next((f.get('yanked_reason') for f in files if f.get('yanked')), None) if is_yanked else None
                return {
                    'published': True,
                    'yanked': is_yanked,
                    'yanked_reason': yank_reason,
                    'deprecated': False,
                    'deprecation_reason': None,
                    'verified_at': now
                }
            elif ecosystem == 'npm':
                resp = await client.get(f'https://registry.npmjs.org/{package}')
                if resp.status_code == 404:
                    return {'published': False, 'yanked': False, 'deprecated': False, 'verified_at': now}
                resp.raise_for_status()
                data = resp.json()
                versions = data.get('versions', {})
                if version not in versions:
                    return {'published': False, 'yanked': False, 'deprecated': False, 'verified_at': now}
                ver_info = versions[version]
                is_deprecated = bool(ver_info.get('deprecated'))
                dep_reason = ver_info.get('deprecated') if is_deprecated else None
                return {
                    'published': True,
                    'yanked': False,
                    'yanked_reason': None,
                    'deprecated': is_deprecated,
                    'deprecation_reason': dep_reason,
                    'verified_at': now
                }
            elif ecosystem == 'crates.io':
                headers = {'User-Agent': 'VulnForge-Package-Verifier (security@vulnforge.dev)'}
                resp = await client.get(f'https://crates.io/api/v1/crates/{package}/{version}', headers=headers)
                if resp.status_code == 404:
                    return {'published': False, 'yanked': False, 'deprecated': False, 'verified_at': now}
                resp.raise_for_status()
                data = resp.json()
                ver_info = data.get('version', {})
                is_yanked = bool(ver_info.get('yanked'))
                return {
                    'published': True,
                    'yanked': is_yanked,
                    'yanked_reason': 'Yanked by crate owner' if is_yanked else None,
                    'deprecated': False,
                    'deprecation_reason': None,
                    'verified_at': now
                }
            return {'published': True, 'yanked': False, 'deprecated': False, 'verified_at': now}
        finally:
            if should_close:
                await client.aclose()
