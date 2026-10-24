"""OSV client: batch package/version checks; fetch full advisory for patch data."""
import httpx
from packaging.version import InvalidVersion, Version
from .dependencies import Dependency


class OSV:
    def __init__(self, base_url='https://api.osv.dev', client: httpx.AsyncClient | None=None):
        self.base = base_url.rstrip('/')
        self.client = client or httpx.AsyncClient(timeout=25, follow_redirects=False)
        self.owns = client is None
        self.cache: dict[str,dict] = {}

    async def close(self):
        if self.owns:
            await self.client.aclose()

    async def check(self, deps: list[Dependency]):
        """Return dependency+advisory pairs. Fail closed on pagination/errors."""
        results=[]
        deps=list(dict.fromkeys(deps))
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
                if answer.get('next_page_token'):
                    raise RuntimeError('OSV pagination needed; refusing incomplete audit')
                for vuln in answer.get('vulns',[]):
                    advisory=await self.advisory(vuln['id'])
                    if advisory.get('withdrawn'):
                        continue
                    results.append((dep,advisory))
        return results

    async def advisory(self, id_: str):
        if id_ not in self.cache:
            res=await self.client.get(f'{self.base}/v1/vulns/{id_}')
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
