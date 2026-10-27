"""Run tests, optionally on a newly created, private Unix-socket PostgreSQL cluster."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlencode


def postgres_binary(name):
    found=shutil.which(name)
    if found: return found
    config=shutil.which('pg_config')
    if config:
        result=subprocess.run([config,'--bindir'],check=True,capture_output=True,text=True)
        candidate=Path(result.stdout.strip())/name
        if candidate.is_file(): return str(candidate)
    raise RuntimeError('Install PostgreSQL tools to run the required database checks')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--postgres',action='store_true')
    args,pytest_args=parser.parse_known_args()
    command=[sys.executable,'-m','pytest',*(pytest_args or ['-q'])]
    if not args.postgres: return subprocess.run(command).returncode
    control=postgres_binary('pg_ctl');initialize=postgres_binary('initdb')
    base='/private/tmp' if sys.platform=='darwin' else '/tmp'
    directory=Path(tempfile.mkdtemp(prefix='vulnforge-pg.',dir=base));os.chmod(directory,0o700)
    data=directory/'data';started=False
    try:
        subprocess.run([initialize,'-D',str(data),'-U','vulnforge_test','-A','trust','--no-locale','--encoding=UTF8'],
                       check=True,stdout=subprocess.DEVNULL)
        subprocess.run([control,'-D',str(data),'-l',str(directory/'server.log'),'-o',
                        f"-k {directory} -p 55439 -c listen_addresses='' -c max_connections=20 -c shared_buffers=16MB",
                        '-t','20','-w','start'],check=True)
        started=True
        environment={**os.environ,'VULNFORGE_TEST_PG_URL':
                     'postgresql://vulnforge_test@/postgres?'+urlencode({'host':str(directory),'port':55439})}
        return subprocess.run(command,env=environment).returncode
    finally:
        # If startup failed ambiguously, still attempt a controlled stop. Never
        # delete a live database directory after a failed shutdown.
        stopped=True
        if started or (data/'postmaster.pid').exists():
            stopped=subprocess.run([control,'-D',str(data),'-m','fast','-t','20','-w','stop']).returncode==0
        if stopped: shutil.rmtree(directory)


if __name__=='__main__':
    try: raise SystemExit(main())
    except (RuntimeError,OSError,subprocess.SubprocessError):
        print('Verification infrastructure failed; no checks were reported as passed.',file=sys.stderr)
        raise SystemExit(2)
