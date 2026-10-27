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
