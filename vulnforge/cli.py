"""Offline customer-runner scanner. Never executes repository code or invokes tools."""
import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from .dependencies import inventory_manifest
from .privacy import path_id
from .runner_report import RunnerReport,ReportDependency,parse_report
from .scanner import scan_code,to_runner_finding

MANIFESTS=frozenset(('requirements.txt','package-lock.json','poetry.lock','Cargo.lock','composer.lock','go.mod','uv.lock','Pipfile.lock','pnpm-lock.yaml','pnpm-lock.yml','yarn.lock'))
CODE_SUFFIXES=('.py','.js','.jsx','.ts','.tsx','.env','.json','.yaml','.yml','.toml')
EXCLUDED=frozenset(('.git','.hg','.svn','node_modules','.venv','venv','__pycache__','.tox'))
MAX_FILE_BYTES=300_000
MAX_TOTAL_BYTES=50_000_000
MAX_ENTRIES=20_000
MAX_DEPTH=32
MAX_SECONDS=120
REPORT_BYTES=1_000_000
PROFILES=('default_branch','push','pull_request','scheduled')


class ScanLimit(ValueError): pass


def compare_pr_reports(base_report: RunnerReport | None, head_report: RunnerReport) -> dict:
    if base_report is None or base_report.coverage.state!='complete':
        return {
            'diff_status':'unknown',
            'new_findings':list(head_report.findings),
            'pre_existing_findings':[],
            'new_dependencies':list(head_report.dependencies),
            'pre_existing_dependencies':[],
        }
    base_fps={f.fingerprint for f in base_report.findings}
    base_rule_paths={(f.path_id,f.rule_id) for f in base_report.findings}
    new_f=[];pre_f=[]
    for f in head_report.findings:
        if f.fingerprint in base_fps or (f.path_id,f.rule_id) in base_rule_paths:
            pre_f.append(f)
        else:
            new_f.append(f)
    base_deps={(d.ecosystem,d.name.lower(),d.version,d.path_id) for d in base_report.dependencies}
    new_d=[];pre_d=[]
    for d in head_report.dependencies:
        if (d.ecosystem,d.name.lower(),d.version,d.path_id) in base_deps:
            pre_d.append(d)
        else:
            new_d.append(d)
    return {
        'diff_status':'compared',
        'new_findings':new_f,
        'pre_existing_findings':pre_f,
        'new_dependencies':new_d,
        'pre_existing_dependencies':pre_d,
    }


def scan(root,repo,sha,kind='code'):
    # Validate all caller metadata before touching the tree. This also prevents
    # a report carrying arbitrary free-text repository/SHA fields.
    RunnerReport.model_validate({'report_version':'1','scan_mode':'customer_runner','repo':repo,
        'commit_sha':sha,'scan_kind':kind,'coverage':{'state':'incomplete','files_total':0,
        'files_scanned':0,'files_skipped':0}})
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    root_fd=os.open(root,flags)
    started=time.monotonic();entries=0;total_bytes=0;total=0;scanned=0;skipped=0
    reasons=Counter();dependencies=[];findings=[];manifests=[]
    def reason(value): reasons[value]+=1
    def walk(directory,prefix='',depth=0):
        nonlocal entries,total_bytes,total,scanned,skipped
        # Descriptor-relative opens with NOFOLLOW protect every path component,
        # including a directory replaced with a symlink while we traverse it.
        with os.scandir(directory) as items:
            for item in items:
                entries+=1
                if entries>MAX_ENTRIES or time.monotonic()-started>MAX_SECONDS:
                    raise ScanLimit('Tree limit')
                relative=prefix+item.name
                try:
                    info=item.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if item.name in EXCLUDED: continue
                        if depth>=MAX_DEPTH: raise ScanLimit('Depth limit')
                        child=os.open(item.name,flags,dir_fd=directory)
                        try:
                            try: os.stat('.git',dir_fd=child,follow_symlinks=False)
                            except FileNotFoundError: walk(child,relative+'/',depth+1)
                            else:
                                total+=1;skipped+=1;reason('content_unavailable')
                        finally: os.close(child)
                        continue
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                        total+=1;skipped+=1;reason('content_unavailable');continue
                    selected=((item.name in MANIFESTS or (item.name.startswith('requirements') and item.name.endswith('.txt'))) if kind=='dependencies' else
                              item.name.endswith(CODE_SUFFIXES))
                    if not selected: continue
                    total+=1
                    try: pseudonym=path_id(relative)
                    except ValueError:
                        skipped+=1;reason('content_unavailable');continue
                    fd=os.open(item.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
                    try:
                        before=os.fstat(fd)
                        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_FILE_BYTES:
                            skipped+=1;reason('scanner_limit');continue
                        with os.fdopen(fd,'rb',closefd=False) as source:
                            data=source.read(MAX_FILE_BYTES+1)
                        after=os.fstat(fd)
                        total_bytes+=len(data)
                        if total_bytes>MAX_TOTAL_BYTES: raise ScanLimit('Byte limit')
                        if (len(data)>MAX_FILE_BYTES or before.st_size!=after.st_size or
                            before.st_mtime_ns!=after.st_mtime_ns or before.st_ino!=after.st_ino):
                            skipped+=1;reason('scanner_limit');continue
                        try: text=data.decode('utf-8')
                        except UnicodeDecodeError:
                            skipped+=1;reason('content_unavailable');continue
                        if '\x00' in text or len(text.splitlines())>10000:
                            skipped+=1;reason('scanner_limit');continue
                    finally: os.close(fd)
                    if kind=='code':
                        if relative.endswith('.py'):
                            try: ast.parse(text)
                            except (SyntaxError,ValueError,RecursionError): reason('parse_error')
                        for finding in scan_code(relative,text):
                            findings.append(to_runner_finding(finding,path_pseudonym=pseudonym))
                            if len(findings)>5000: raise ScanLimit('Finding limit')
                    else:
                        if len(manifests)>=80: raise ScanLimit('Manifest limit')
                        manifests.append({'path_id':pseudonym,'sha256':hashlib.sha256(data).hexdigest()})
                        try:
                            result=inventory_manifest(relative,text)
                            for dep in result.dependencies:
                                try:
                                    record=ReportDependency(name=dep.name,version=dep.version,
                                        ecosystem=dep.ecosystem,path_id=pseudonym)
                                except ValueError:
                                    reason('unresolved_dependency');continue
                                dependencies.append(record.model_dump())
                            for issue in result.issues:
                                reason('transitive_graph_unavailable' if issue['reason']=='transitive_graph_unavailable'
                                       else 'unresolved_dependency')
                        except (ValueError,TypeError,KeyError,AttributeError,RecursionError): reason('parse_error')
                        if len(dependencies)>1500: raise ScanLimit('Dependency limit')
                    scanned+=1
                except OSError:
                    # No path, filename, source or OS exception enters the report.
                    if total>scanned+skipped: skipped+=1
                    else: total+=1;skipped+=1
                    reason('content_unavailable')
    try:
        try: walk(root_fd)
        except ScanLimit:
            if total>scanned+skipped: skipped+=total-scanned-skipped
            reason('scanner_limit')
    finally: os.close(root_fd)
    if kind=='dependencies' and not manifests: reason('no_supported_manifests')
    dependencies=list({(d['ecosystem'],d['name'],d['version'],d['path_id']):d for d in dependencies}.values())
    report={'report_version':'1','scan_mode':'customer_runner','repo':repo,'commit_sha':sha,'scan_kind':kind,
        'coverage':{'state':'incomplete' if reasons else 'complete','files_total':total,
                    'files_scanned':scanned,'files_skipped':skipped,
                    'unresolved_dependencies':reasons.get('unresolved_dependency',0),
                    'dependency_scope':('declared' if reasons else 'resolved') if kind=='dependencies' else 'unknown',
                    'reasons':dict(reasons)},'manifests':manifests,'dependencies':dependencies,'findings':findings}
    validated=RunnerReport.model_validate(report)
    encoded=validated.model_dump_json().encode()
    if len(encoded)>REPORT_BYTES: raise ScanLimit('Report limit')
    # Re-use exactly the ingestion contract, including duplicate/extra-field rules.
    return parse_report(encoded)


def write_report(report,output):
    target=Path(output)
    # Exclusive temporary file, owner-only permissions; interruption never
    # leaves a truncated report under the requested final name.
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent,prefix='.vf-report-',delete=False) as stream:
            temporary=stream.name
            os.chmod(temporary,0o600)
            stream.write(report.model_dump_json().encode())
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,target)
    finally:
        if temporary and os.path.exists(temporary): os.unlink(temporary)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',required=True)
    parser.add_argument('--repo',required=True)
    parser.add_argument('--sha',required=True)
    parser.add_argument('--kind',choices=('code','dependencies'),default='code')
    parser.add_argument('--profile',choices=PROFILES,default='default_branch')
    parser.add_argument('--base-root',default=None)
    parser.add_argument('--output',required=True)
    parser.add_argument('--require-complete',action='store_true')
    parser.add_argument('--fail-on',choices=('none','critical','high','medium','low'),default='none')
    args=parser.parse_args(argv)
    require_complete=args.require_complete or args.profile=='scheduled'
    try:
        if args.base_root is not None and args.profile!='pull_request':
            raise ValueError('Base root applies only to pull_request profile')
        report=scan(args.root,args.repo,args.sha,args.kind)
        base_report=scan(args.base_root,args.repo,args.sha,args.kind) if args.base_root else None
        write_report(report,args.output)
    except (OSError,ValueError,TypeError,RecursionError):
        print('Scan failed; private paths and contents are omitted.',file=sys.stderr)
        return 2
    summary={'profile':args.profile,'state':report.coverage.state,'files_scanned':report.coverage.files_scanned,
             'files_skipped':report.coverage.files_skipped,'findings':len(report.findings)}
    gated_findings=report.findings
    if args.profile=='pull_request':
        diff=compare_pr_reports(base_report,report)
        summary['diff_status']=diff['diff_status']
        summary['new_findings']=len(diff['new_findings'])
        summary['pre_existing_findings']=len(diff['pre_existing_findings'])
        gated_findings=diff['new_findings']
    print(json.dumps(summary))
    if require_complete and report.coverage.state!='complete': return 3
    rank={'critical':4,'high':3,'medium':2,'low':1,'info':0}
    if args.fail_on!='none' and any(rank[f.severity]>=rank[args.fail_on] for f in gated_findings): return 1
    return 0


if __name__=='__main__': raise SystemExit(main())
