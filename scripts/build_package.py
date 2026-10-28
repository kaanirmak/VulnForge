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
    manifest={'artifact':wheel.name,'sha256':checksum,'source_revision':None if dirty else revision,
        'source_base_revision':revision,'source_dirty':dirty,'source_date_epoch':int(epoch),
        'build_backend':'setuptools=='+expected,'python':sys.version.split()[0],
        'published':False,'signed':False,
        'dependency_lock_sha256':hashlib.sha256((ROOT/'requirements/runtime.lock').read_bytes()).hexdigest()}
    (output/'SHA256SUMS').write_text(checksum+'  '+wheel.name+'\n')
    (output/'build-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',default=str(ROOT/'dist'))
    parser.add_argument('--allow-dirty',action='store_true');args=parser.parse_args()
    try:result=build(args.output,args.allow_dirty)
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError):
        print('Build refused or failed. Use the locked environment and a clean source tree; no release was published.',file=sys.stderr)
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
