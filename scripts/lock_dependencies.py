"""Refresh reviewed installed versions with PyPI wheel hashes; never upgrades packages.

Developer tooling, not part of the customer scanner. Supports CPython 3.11/3.12
on POSIX. Review/test the environment before explicitly running --refresh.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import distribution
import json
from pathlib import Path
import re
from urllib.request import build_opener,ProxyHandler

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOTS=('fastapi','pydantic','uvicorn','httpx','PyJWT[crypto]','packaging','psycopg[binary]')


def closure(roots):
    pending=list(roots);visited=set();versions={}
    while pending:
        requirement=Requirement(pending.pop())
        name=canonicalize_name(requirement.name)
        package=distribution(name)
        if package.version not in requirement.specifier: raise ValueError('Installed requirement mismatch')
        extras=tuple(sorted(requirement.extras));key=(name,extras)
        if key in visited:continue
        visited.add(key);versions[name]=package.version
        for text in package.requires or ():
            child=Requirement(text)
            active=False
            for python in ('3.11','3.12'):
                for system in ('linux','darwin'):
                    for extra in ('',*extras):
                        env={**default_environment(),'python_version':python,'python_full_version':python+'.0',
                             'sys_platform':system,'os_name':'posix','extra':extra,
                             'implementation_name':'cpython','platform_python_implementation':'CPython'}
                        active=active or not child.marker or child.marker.evaluate(env)
            if active:pending.append(str(child))
    return versions


def hashes(pair):
    name,version=pair
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*',name) or not re.fullmatch(r'[0-9A-Za-z.!+_-]+',version):
        raise ValueError('Invalid package identity')
    opener=build_opener(ProxyHandler({}))
    with opener.open('https://pypi.org/pypi/'+name+'/'+version+'/json',timeout=20) as response:
        if response.status!=200:raise ValueError('PyPI metadata unavailable')
        raw=response.read(4_000_001)
    if len(raw)>4_000_000:raise ValueError('PyPI metadata limit')
    data=json.loads(raw)
    if canonicalize_name(data['info']['name'])!=name or data['info']['version']!=version:
        raise ValueError('PyPI identity mismatch')
    found=set()
    for item in data['urls']:
        if item.get('yanked') or item['packagetype']!='bdist_wheel':continue
        checksum=item['digests']['sha256']
        if not re.fullmatch(r'[0-9a-f]{64}',checksum):raise ValueError('Invalid wheel hash')
        found.add(checksum)
    if not found:raise ValueError('No non-yanked wheel')
    return name,sorted(found)


def render(versions,checksums):
    header='# Generated from reviewed installed versions; wheel-only, CPython 3.11/3.12 POSIX.\n# Install with --require-hashes --only-binary=:all:. Refresh: scripts/lock_dependencies.py --refresh\n'
    return header+'\n'.join(name+'=='+version+' \\\n'+''.join('    --hash=sha256:'+value+(' \\\n' if index<len(checksums[name])-1 else '\n')
        for index,value in enumerate(checksums[name])) for name,version in sorted(versions.items()))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--refresh',action='store_true')
    if not parser.parse_args().refresh:parser.error('--refresh is required')
    runtime=closure(ROOTS);development=closure((*ROOTS,'pytest','setuptools'))
    with ThreadPoolExecutor(max_workers=6) as pool:checksums=dict(pool.map(hashes,sorted(development.items())))
    folder=Path(__file__).resolve().parent.parent/'requirements';folder.mkdir(exist_ok=True)
    outputs={'runtime.lock':render(runtime,checksums),'development.lock':render(development,checksums),
             'build.lock':render({'setuptools':development['setuptools']},checksums),
             'lock-metadata.json':json.dumps({'source':'https://pypi.org/pypi/{name}/{version}/json',
                'python':['3.11','3.12'],'platforms':['linux','darwin'],'runtime':runtime,
                'development':development,'roots':ROOTS,'hashes':checksums},indent=2,sort_keys=True)+'\n'}
    # Compute/fetch everything before replacing any lock file.
    for name,value in outputs.items():
        temporary=folder/(name+'.tmp');temporary.write_text(value);temporary.replace(folder/name)
    print('Locked '+str(len(runtime))+' runtime and '+str(len(development))+' development/build packages.')


if __name__=='__main__':main()
