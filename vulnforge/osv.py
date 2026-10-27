"""OSV client: batch package/version checks; fetch full advisory for patch data."""
import httpx
import re
from urllib.parse import quote
from packaging.version import InvalidVersion, Version
from .dependencies import Dependency
from .privacy import MetadataPolicy, safe_metadata


class OSV:
    def __init__(self, base_url='https://api.osv.dev', client: httpx.AsyncClient | None=None,
                 policy: MetadataPolicy | None=None):
        self.base = base_url.rstrip('/')
        self.client = client or httpx.AsyncClient(timeout=25, follow_redirects=False)
        self.owns = client is None
        self.cache: dict[str,dict] = {}
        self.policy=policy or MetadataPolicy()

    async def close(self):
        self.cache.clear()
        self.client.cookies.clear()
        if self.owns:
            await self.client.aclose()

    async def check(self, deps: list[Dependency]):
        """Return dependency+advisory pairs. Fail closed on pagination/errors."""
        results=[]
        # A long-lived worker must observe updated/withdrawn advisories on every audit.
        self.cache.clear()
        deps=list(dict.fromkeys(deps))
        if not deps: return []
        self.policy.require_packages(deps,self.base)
        for offset in range(0,len(deps),100):
            batch=deps[offset:offset+100]
            payload={'queries':[{'package':{'ecosystem':d.ecosystem,'name':d.name},'version':d.version}
                               for d in batch]}
            res=await self.client.post(f'{self.base}/v1/querybatch',json=payload)
            res.raise_for_status()
            answers=res.json().get('results',[])
            if len(answers)!=len(batch):
                raise RuntimeError('OSV returned incomplete batch results')
            for dep,answer in zip(batch,answers):
                vulns=list(answer.get('vulns',[]))
                token=answer.get('next_page_token')
                visited=set()
                while token:
                    if token in visited or len(visited)>=100:
                        raise RuntimeError('OSV pagination did not complete')
                    visited.add(token)
                    page=await self.client.post(f'{self.base}/v1/query',json={
                        'package':{'ecosystem':dep.ecosystem,'name':dep.name},
                        'version':dep.version,'page_token':token})
                    page.raise_for_status()
                    answer=page.json()
                    vulns.extend(answer.get('vulns',[]))
                    token=answer.get('next_page_token')
                for id_ in dict.fromkeys(v['id'] for v in vulns):
                    advisory=await self.advisory(id_)
                    if advisory.get('withdrawn'):
                        continue
                    results.append((dep,advisory))
        return results

    async def advisory(self, id_: str):
        self.policy.require_endpoint(self.base)
        safe_metadata(id_)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}',id_):
            raise ValueError('Invalid advisory identifier')
        if id_ not in self.cache:
            res=await self.client.get(f'{self.base}/v1/vulns/{quote(id_, safe="")}')
            res.raise_for_status()
            self.cache[id_]=res.json()
        return self.cache[id_]


def fixed_version(dep: Dependency, advisory: dict):
    """Find a fixed ECOSYSTEM range; treat advisory data as untrusted."""
    options=[]
    for affected in advisory.get('affected',[]):
        p=affected.get('package',{})
        if (p.get('name','').lower()!=dep.name.lower() or p.get('ecosystem')!=dep.ecosystem):
            continue
        for r in affected.get('ranges',[]):
            if r.get('type')!='ECOSYSTEM':
                continue
            for ev in r.get('events',[]):
                if ev.get('fixed'):
                    try: options.append(Version(ev['fixed']))
                    except InvalidVersion: pass
    if not options:
        return None
    try:
        old=Version(dep.version)
    except InvalidVersion:
        return None
    higher=[v for v in options if v>old and not v.is_prerelease]
    return str(min(higher)) if higher else None
