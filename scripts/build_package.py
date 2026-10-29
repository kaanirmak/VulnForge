"""Build a checksum-bound local candidate; no upload, tag, release or signing."""
import argparse
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent


def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT,text=True,stderr=subprocess.DEVNULL).strip()


def build(output,allow_dirty=False):
    dirty=bool(git('status','--porcelain'))
    if dirty and not allow_dirty:raise ValueError('A clean working tree is required; use --allow-dirty only for a local preview')
    revision=git('rev-parse','HEAD');epoch=git('log','-1','--format=%ct')
    if not epoch.isdecimal():raise ValueError('Invalid source timestamp')
    expected=json.loads((ROOT/'requirements/lock-metadata.json').read_text())['development']['setuptools']
    if version('setuptools')!=expected:raise ValueError('Install the locked build environment first')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    subprocess.run([sys.executable,'-m','pip','wheel','--no-deps','--no-build-isolation',
        '--wheel-dir',str(output),str(ROOT)],check=True,cwd=ROOT,capture_output=True,
        env={**os.environ,'SOURCE_DATE_EPOCH':epoch,'PIP_NO_INDEX':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1'})
    wheels=list(output.glob('vulnforge_mvp-*.whl'))
    if len(wheels)!=1:raise ValueError('Output folder must contain exactly one VulnForge wheel')
    wheel=wheels[0];checksum=hashlib.sha256(wheel.read_bytes()).hexdigest()
    action_sha=hashlib.sha256((ROOT/'action.yml').read_bytes()).hexdigest()
    action_script_sha=hashlib.sha256((ROOT/'scripts/action_scan.py').read_bytes()).hexdigest()
    cli_sha=hashlib.sha256((ROOT/'vulnforge/cli.py').read_bytes()).hexdigest()
    lock_sha=hashlib.sha256((ROOT/'requirements/runtime.lock').read_bytes()).hexdigest()
    manifest={'artifact':wheel.name,'sha256':checksum,'source_revision':None if dirty else revision,
        'source_base_revision':revision,'source_dirty':dirty,'source_date_epoch':int(epoch),
        'build_backend':'setuptools=='+expected,'python':sys.version.split()[0],
        'published':False,'signed':False,
        'dependency_lock_sha256':lock_sha,
        'action_yml_sha256':action_sha,
        'action_script_sha256':action_script_sha,
        'cli_sha256':cli_sha,
        'provenance':{
            'predicate_type':'https://slsa.dev/provenance/v1',
            'subject':{'name':wheel.name,'digest':{'sha256':checksum}},
            'materials':[
                {'uri':'requirements/runtime.lock','digest':{'sha256':lock_sha}},
                {'uri':'action.yml','digest':{'sha256':action_sha}},
                {'uri':'scripts/action_scan.py','digest':{'sha256':action_script_sha}},
                {'uri':'vulnforge/cli.py','digest':{'sha256':cli_sha}},
            ],
        }}
    (output/'SHA256SUMS').write_text(checksum+'  '+wheel.name+'\n')
    (output/'build-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return manifest


def verify_distribution(output) -> dict:
    output=Path(output).resolve()
    manifest=json.loads((output/'build-manifest.json').read_text(encoding='utf-8'))
    sums=(output/'SHA256SUMS').read_text(encoding='utf-8').strip().splitlines()
    if len(sums)!=1: raise ValueError('Invalid SHA256SUMS')
    digest,name=sums[0].split('  ',1)
    wheel=output/name
    if name!=manifest['artifact'] or digest!=manifest['sha256']:
        raise ValueError('Manifest and SHA256SUMS mismatch')
    actual=hashlib.sha256(wheel.read_bytes()).hexdigest()
    if actual!=digest:
        raise ValueError('Wheel SHA-256 verification failed')
    lock_sha=hashlib.sha256((ROOT/'requirements/runtime.lock').read_bytes()).hexdigest()
    if manifest.get('dependency_lock_sha256')!=lock_sha:
        raise ValueError('Runtime lockfile SHA-256 mismatch')
    return {'verified':True,'artifact':name,'sha256':actual,'dependency_lock_sha256':lock_sha}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',default=str(ROOT/'dist'))
    parser.add_argument('--allow-dirty',action='store_true');args=parser.parse_args()
    try:result=build(args.output,args.allow_dirty)
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError):
        print('Build refused or failed. Use the locked environment and a clean source tree; no release was published.',file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
