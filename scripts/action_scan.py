"""Trusted composite-action entry point. Never import modules from the checkout."""
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile

from vulnforge.cli import scan,write_report


def main():
    directory=None
    try:
        root=Path(os.environ['VF_ROOT']).resolve(strict=True)
        interpreter=Path(sys.executable).resolve(strict=True)
        if interpreter.is_relative_to(root):
            raise ValueError('Scanner runtime must be outside the checkout')
        repo=os.environ['VF_REPOSITORY'];sha=os.environ['VF_SHA']
        threshold=os.environ.get('VF_FAIL_ON','none')
        rank={'critical':4,'high':3,'medium':2,'low':1,'info':0}
        if threshold not in ('none','critical','high','medium','low'): raise ValueError('Invalid threshold')
        directory=Path(tempfile.mkdtemp(prefix='vulnforge-',dir=os.environ['RUNNER_TEMP']))
        reports={kind:scan(root,repo,sha,kind) for kind in ('code','dependencies')}
        for kind,report in reports.items(): write_report(report,directory/(kind+'.json'))
        # GitHub outputs contain only generated paths, never user metadata.
        # Reject newline-containing runner infrastructure paths explicitly.
        if any(char in str(directory) for char in ('\r','\n')): raise ValueError('Invalid runner path')
        with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as output:
            output.write(f'code-report={directory / "code.json"}\n')
            output.write(f'dependency-report={directory / "dependencies.json"}\n')
        print(json.dumps({kind:{'state':report.coverage.state,'findings':len(report.findings)}
                          for kind,report in reports.items()}))
        if threshold!='none' and any(rank[f.severity]>=rank[threshold] for f in reports['code'].findings):
            shutil.rmtree(directory);directory=None
            return 1
        return 0
    except (OSError,ValueError,KeyError,TypeError,RecursionError,KeyboardInterrupt):
        if directory is not None: shutil.rmtree(directory,ignore_errors=True)
        print('Action scan failed; private metadata omitted.',file=sys.stderr)
        return 2


if __name__=='__main__':
    def interrupted(signum,frame): raise InterruptedError('Action interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    raise SystemExit(main())
