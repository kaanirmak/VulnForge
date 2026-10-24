"""Parse exact locked versions only; intentionally skip ambiguous/unlocked packages."""
import json
import re
import tomllib
from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    file_path: str


def parse_manifest(path: str, content: str) -> list[Dependency]:
    name = path.rsplit('/', 1)[-1]
    packages: list[Dependency] = []

    def add(pkg, ver, eco):
        if isinstance(pkg,str) and isinstance(ver,str) and pkg and ver:
            packages.append(Dependency(pkg,ver,eco,path))

    if name == 'requirements.txt':
        for line in content.splitlines():
            line = line.strip()
            m = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([A-Za-z0-9_.!+-]+)(?:\s*(?:#.*)?)?$',line)
            if m: add(m[1],m[2],'PyPI')
    elif name == 'package-lock.json':
        obj = json.loads(content)
        # lockfile v2/v3: packages contains transitive resolved versions.
        for key, entry in obj.get('packages',{}).items():
            if not key or not key.startswith('node_modules/') or not isinstance(entry,dict):
                continue
            pkg = key.split('node_modules/')[-1]
            if entry.get('version') and not entry.get('link'):
                add(pkg,entry['version'],'npm')
        # Old lockfile v1: recursively walk dependency tree.
        if not obj.get('packages'):
            def walk(deps):
                for pkg, info in deps.items():
                    if isinstance(info,dict):
                        add(pkg,info.get('version'),'npm')
                        walk(info.get('dependencies',{}))
            walk(obj.get('dependencies',{}))
    elif name == 'poetry.lock':
        obj = tomllib.loads(content)
        for item in obj.get('package',[]):
            add(item.get('name'),item.get('version'),'PyPI')
    elif name == 'Cargo.lock':
        obj = tomllib.loads(content)
        for item in obj.get('package',[]):
            if item.get('source','').startswith('registry+'):
                add(item.get('name'),item.get('version'),'crates.io')
    elif name == 'composer.lock':
        obj = json.loads(content)
        for item in obj.get('packages',[])+obj.get('packages-dev',[]):
            add(item.get('name'),str(item.get('version','')).lstrip('v'),'Packagist')
    elif name == 'go.mod':
        in_block=False
        for line in content.splitlines():
            line=line.split('//',1)[0].strip()
            if line.startswith('require ('): in_block=True; continue
            if in_block and line==')': in_block=False; continue
            if line.startswith('require '): line=line[len('require '):]
            elif not in_block: continue
            m=re.match(r'^([^\s()]+)\s+(v[^\s]+)$',line)
            if m: add(m[1],m[2],'Go')
    return list(dict.fromkeys(packages))
