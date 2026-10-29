"""Trusted composite-action entry point. Never import modules from the checkout."""
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile

from vulnforge.cli import PROFILES,compare_pr_reports,scan,write_report


def main():
    directory=None
    try:
        root=Path(os.environ['VF_ROOT']).resolve(strict=True)
        interpreter=Path(sys.executable).resolve(strict=True)
        if interpreter.is_relative_to(root):
            raise ValueError('Scanner runtime must be outside the checkout')
        repo=os.environ['VF_REPOSITORY'];sha=os.environ['VF_SHA']
        threshold=os.environ.get('VF_FAIL_ON','none')
        profile=os.environ.get('VF_PROFILE','default_branch')
        base_root_raw=os.environ.get('VF_BASE_ROOT','').strip()
        require_complete=os.environ.get('VF_REQUIRE_COMPLETE','false').lower()
        rank={'critical':4,'high':3,'medium':2,'low':1,'info':0}
        if threshold not in ('none','critical','high','medium','low'): raise ValueError('Invalid threshold')
        if profile not in PROFILES: raise ValueError('Invalid scan profile')
        if require_complete not in ('true','false'): raise ValueError('Invalid completeness flag')
        if base_root_raw and profile!='pull_request': raise ValueError('Base root requires pull_request profile')
        base_root=Path(base_root_raw).resolve(strict=True) if base_root_raw else None
        if base_root is not None and interpreter.is_relative_to(base_root):
            raise ValueError('Scanner runtime must be outside the base checkout')
        directory=Path(tempfile.mkdtemp(prefix='vulnforge-',dir=os.environ['RUNNER_TEMP']))
        reports={kind:scan(root,repo,sha,kind) for kind in ('code','dependencies')}
        base_reports=({kind:scan(base_root,repo,sha,kind) for kind in ('code','dependencies')}
                      if base_root is not None else {})
        for kind,report in reports.items(): write_report(report,directory/(kind+'.json'))
        # GitHub outputs contain only generated paths, never user metadata.
        # Reject newline-containing runner infrastructure paths explicitly.
        if any(char in str(directory) for char in ('\r','\n')): raise ValueError('Invalid runner path')
        with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as output:
            output.write(f'code-report={directory / "code.json"}\n')
            output.write(f'dependency-report={directory / "dependencies.json"}\n')
        gated_code_findings=reports['code'].findings
        summary={'profile':profile}
        for kind,report in reports.items():
            item={'state':report.coverage.state,'findings':len(report.findings)}
            if profile=='pull_request':
                diff=compare_pr_reports(base_reports.get(kind),report)
                item['diff_status']=diff['diff_status']
                item['new_findings']=len(diff['new_findings'])
                item['pre_existing_findings']=len(diff['pre_existing_findings'])
                if kind=='code': gated_code_findings=diff['new_findings']
            summary[kind]=item
        print(json.dumps(summary))
        if (require_complete=='true' or profile=='scheduled') and any(r.coverage.state!='complete' for r in reports.values()):
            shutil.rmtree(directory);directory=None
            return 3
        if threshold!='none' and any(rank[f.severity]>=rank[threshold] for f in gated_code_findings):
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
