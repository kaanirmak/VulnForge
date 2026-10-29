"""Prepare GitHub App registration settings locally; never creates or publishes an app."""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlencode,urlsplit

MODES={
    'customer_runner':{'metadata':'read'},
    'managed_read':{'metadata':'read','contents':'read','pull_requests':'read'},
    'remediation_write':{'metadata':'read','contents':'write','pull_requests':'write'},
}
CHECKOUT_ACTION_REF='actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683'
ACTION_REF_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$')
BRANCH_RE=re.compile(r'^[A-Za-z0-9._/-]{1,120}$')
RUNNER_LABEL_RE=re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
PYTHON_PATH_RE=re.compile(r'^/[A-Za-z0-9_./-]{3,240}$')
CRON_RE=re.compile(r'^[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+\s+[0-9*/,-]+$')


def render_workflow_template(template='default_branch',*,action_ref,default_branch='main',
                             scanner_python='/opt/vulnforge/bin/python',runner_labels=None,
                             fail_on='none',require_complete=False,cron='17 3 * * *'):
    if template not in ('default_branch','pull_request','scheduled'):
        raise ValueError('Unsupported workflow template')
    if (not isinstance(action_ref,str) or not ACTION_REF_RE.fullmatch(action_ref) or
        '..' in action_ref or action_ref.lower().startswith('owner/vulnforge@')):
        raise ValueError('A reviewed immutable owner/repo@40-hex-sha Action reference is required')
    if (not isinstance(default_branch,str) or not BRANCH_RE.fullmatch(default_branch) or
        default_branch[0] in './' or default_branch[-1] in './' or '..' in default_branch or '//' in default_branch):
        raise ValueError('Invalid default branch name')
    if (not isinstance(scanner_python,str) or not PYTHON_PATH_RE.fullmatch(scanner_python) or
        '..' in scanner_python or '//' in scanner_python or
        scanner_python.startswith(('/github/workspace','/workspace','/tmp/'))):
        raise ValueError('Scanner Python must be an absolute path outside the repository checkout')
    if fail_on not in ('none','critical','high','medium','low') or type(require_complete) is not bool:
        raise ValueError('Invalid scan policy flags')
    if not isinstance(cron,str) or len(cron)>64 or not CRON_RE.fullmatch(cron.strip()):
        raise ValueError('Invalid schedule cron expression')
    default_labels=(['self-hosted','linux','vulnforge-ephemeral-untrusted'] if template=='pull_request'
                    else ['self-hosted','linux','vulnforge'])
    labels=list(default_labels if runner_labels is None else runner_labels)
    if (not isinstance(labels,list) or not 1<=len(labels)<=10 or
        any(not isinstance(x,str) or not RUNNER_LABEL_RE.fullmatch(x) for x in labels)):
        raise ValueError('Invalid runner labels')
    if template=='pull_request' and 'vulnforge-ephemeral-untrusted' not in labels:
        raise ValueError('Pull request workflows require the vulnforge-ephemeral-untrusted runner label')
    runs_on='['+', '.join(labels)+']'
    req_flag='true' if (require_complete or template=='scheduled') else 'false'
    if template=='pull_request':
        return (
            'name: VulnForge pull request profile\n'
            'on:\n'
            '  pull_request:\n'
            '    types: [opened, synchronize, reopened]\n'
            'permissions:\n'
            '  contents: read\n'
            'jobs:\n'
            '  scan:\n'
            f'    runs-on: {runs_on}\n'
            '    timeout-minutes: 10\n'
            '    steps:\n'
            f'      - uses: {CHECKOUT_ACTION_REF}\n'
            '        with:\n'
            '          persist-credentials: false\n'
            '          submodules: false\n'
            '          ref: ${{ github.event.pull_request.head.sha }}\n'
            '          fetch-depth: 1\n'
            '      - id: scan\n'
            f'        uses: {action_ref}\n'
            '        with:\n'
            f'          scanner-python: {scanner_python}\n'
            '          commit-sha: ${{ github.event.pull_request.head.sha }}\n'
            '          repository: ${{ github.repository }}\n'
            f'          fail-on: {fail_on}\n'
            f"          require-complete: '{req_flag}'\n"
            "      - if: always() && steps.scan.outputs.code-report != ''\n"
            '        env:\n'
            '          VF_REPORT: ${{ steps.scan.outputs.code-report }}\n'
            f'        run: {scanner_python} -I -m vulnforge.runner_cleanup --report "$VF_REPORT" --runner-temp "$RUNNER_TEMP"\n'
        )
    if template=='scheduled':
        trigger=(
            'on:\n'
            '  schedule:\n'
            f"    - cron: '{cron.strip()}'\n"
            '  workflow_dispatch:\n'
        )
        wf_name='VulnForge scheduled audit'
    else:
        trigger=(
            'on:\n'
            '  push:\n'
            f'    branches: [{default_branch}]\n'
            '  schedule:\n'
            f"    - cron: '{cron.strip()}'\n"
            '  workflow_dispatch:\n'
        )
        wf_name='VulnForge customer runner'
    return (
        f'name: {wf_name}\n'
        f'{trigger}'
        'permissions:\n'
        '  contents: read\n'
        'concurrency:\n'
        '  group: vulnforge-${{ github.repository }}-${{ github.ref }}\n'
        '  cancel-in-progress: true\n'
        'jobs:\n'
        '  scan:\n'
        f'    runs-on: {runs_on}\n'
        '    timeout-minutes: 10\n'
        '    steps:\n'
        f'      - uses: {CHECKOUT_ACTION_REF}\n'
        '        with:\n'
        '          persist-credentials: false\n'
        '          submodules: false\n'
        '          fetch-depth: 1\n'
        '      - id: scan\n'
        f'        uses: {action_ref}\n'
        '        with:\n'
        f'          scanner-python: {scanner_python}\n'
        '          commit-sha: ${{ github.sha }}\n'
        f'          fail-on: {fail_on}\n'
        f"          require-complete: '{req_flag}'\n"
        "      - if: always() && steps.scan.outputs.code-report != ''\n"
        '        env:\n'
        '          VF_REPORT: ${{ steps.scan.outputs.code-report }}\n'
        f'        run: {scanner_python} -I -m vulnforge.runner_cleanup --report "$VF_REPORT" --runner-temp "$RUNNER_TEMP"\n'
    )


def validate_workflow_template(yaml_text: str) -> dict:
    if not isinstance(yaml_text,str) or not yaml_text.strip() or '\x00' in yaml_text:
        raise ValueError('Workflow YAML must be non-empty text')
    lines=yaml_text.splitlines()
    name_match=next((line.split(':',1)[1].strip() for line in lines if line.startswith('name:')),None)
    if not name_match: raise ValueError('Missing workflow name')
    if 'pull_request_target:' in yaml_text:
        raise ValueError('Unsafe pull_request_target trigger is forbidden')
    if 'permissions:\n  contents: read' not in yaml_text or 'id-token: write' in yaml_text:
        raise ValueError('Customer runner workflow must request only contents: read')
    uses_refs=[m.group(1).strip() for m in re.finditer(r'^\s*-?\s*uses:\s*([^\s#]+)',yaml_text,re.M)]
    if len(uses_refs)<2 or any(not ACTION_REF_RE.fullmatch(ref) for ref in uses_refs):
        raise ValueError('All GitHub Action references must be pinned to a 40-char commit SHA')
    if 'persist-credentials: false' not in yaml_text or 'submodules: false' not in yaml_text:
        raise ValueError('Checkout must disable credential persistence and submodules')
    if "always() && steps.scan.outputs.code-report != ''" not in yaml_text or 'vulnforge.runner_cleanup' not in yaml_text:
        raise ValueError('Workflow must clean up temporary reports in an always() step')
    triggers=[t for t in ('push','pull_request','schedule','workflow_dispatch')
              if re.search(rf'^\s{{2}}{t}:',yaml_text,re.M)]
    if not triggers: raise ValueError('Missing workflow triggers')
    if 'pull_request' in triggers and 'vulnforge-ephemeral-untrusted' not in yaml_text:
        raise ValueError('PR workflow must target an ephemeral untrusted runner')
    return {'valid':True,'name':name_match,'triggers':sorted(triggers),'uses':uses_refs}


def registration(origin,mode='customer_runner',*,public=False,checks=False):
    parsed=urlsplit(origin)
    parsed.port  # Reject malformed/out-of-range ports before preparing a URL.
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or
        parsed.path or parsed.query or parsed.fragment or any(c.isspace() for c in origin)):
        raise ValueError('A fixed HTTPS origin without a path is required')
    if parsed.hostname in ('localhost','localhost.localdomain') or parsed.hostname.endswith('.localhost'):
        raise ValueError('A public origin is required')
    try:
        if not ipaddress.ip_address(parsed.hostname).is_global: raise ValueError('Public address required')
    except ValueError:
        # A domain rather than an IP is normal. Invalid numeric/colon addresses
        # must not masquerade as a domain after IP validation fails.
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',parsed.hostname):
            raise ValueError('Invalid public host') from None
        if re.fullmatch(r'[0-9.]+',parsed.hostname): raise ValueError('Public address required') from None
    if mode not in MODES or type(public) is not bool or type(checks) is not bool:
        raise ValueError('Invalid registration policy')
    if checks and mode=='customer_runner':
        raise ValueError('Check publication needs a separately enabled write integration')
    permissions=dict(MODES[mode])
    if checks: permissions['checks']='write'
    events=[] if mode=='customer_runner' else ['push','pull_request']
    fields=[('name','VulnForge-'+mode),('url',origin),('public',str(public).lower()),
            ('callback_urls[]',origin+'/auth/github/callback'),
            ('callback_urls[]',origin+'/auth/github/connect/callback'),
            ('request_oauth_on_install','false'),('webhook_active','true'),
            ('webhook_url',origin+'/github/webhook')]
    fields.extend(permissions.items());fields.extend(('events[]',event) for event in events)
    return {'mode':mode,'public':public,'permissions':permissions,'events':events,
            'automatic_events':['installation','installation_repositories'],
            'registration_url':'https://github.com/settings/apps/new?'+urlencode(fields),
            'callback_url':origin+'/auth/github/callback','webhook_url':origin+'/github/webhook',
            'live_verified':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin',required=True)
    parser.add_argument('--mode',choices=tuple(MODES),default='customer_runner')
    parser.add_argument('--public',action='store_true')
    parser.add_argument('--checks',action='store_true')
    args=parser.parse_args(argv)
    try: result=registration(args.origin,args.mode,public=args.public,checks=args.checks)
    except ValueError:
        print('Invalid registration settings; a fixed public HTTPS origin and explicit policy are required.',file=sys.stderr)
        return 2
    print(json.dumps(result,indent=2));return 0


if __name__=='__main__': raise SystemExit(main())
