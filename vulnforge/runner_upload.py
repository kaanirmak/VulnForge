"""Explicit metadata upload from a trusted Actions job; no long-lived upload secret."""
import argparse
import asyncio
import json
import ipaddress
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode

import httpx

from .oidc import bounded_json,RUNNER_PATH
from .runner_report import parse_report


class UploadError(ValueError): pass


def valid_host(host):
    if not isinstance(host,str) or len(host)>253: return False
    try: ipaddress.ip_address(host);return True
    except ValueError:
        label=r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
        return re.fullmatch(label+r'(?:\.'+label+r')*',host) is not None


def destination(origin,allow_loopback=False):
    parsed=urlsplit(origin)
    port=parsed.port
    local=allow_loopback and parsed.hostname in ('localhost','127.0.0.1','::1')
    if (not valid_host(parsed.hostname) or parsed.username or parsed.password or parsed.path or parsed.query or
        parsed.fragment or any(c.isspace() for c in origin) or
        (parsed.scheme!='https' and not (local and parsed.scheme=='http'))):
        raise UploadError('Fixed approved origin required')
    if not local and parsed.hostname in ('localhost','127.0.0.1','::1'):
        raise UploadError('Loopback preview requires explicit permission')
    return origin+RUNNER_PATH


def token_endpoint(url,audience):
    parsed=urlsplit(url)
    if (parsed.scheme!='https' or not valid_host(parsed.hostname) or parsed.username or parsed.password or
        parsed.port not in (None,443) or parsed.fragment or
        not parsed.hostname.endswith('.actions.githubusercontent.com') or
        not parsed.path.endswith('/oidctoken') or '..' in parsed.path or '%' in parsed.path or len(url)>2048):
        raise UploadError('Trusted GitHub token endpoint required')
    params=parse_qsl(parsed.query,keep_blank_values=True)
    if len(params)!=1 or params[0][0]!='api-version' or not re.fullmatch(r'[0-9]+\.[0-9]+(?:-preview(?:\.[0-9]+)?)?',params[0][1]):
        raise UploadError('Unexpected token endpoint parameters')
    return urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(params+[('audience',audience)]),''))


def load_report(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1_000_000:
            raise UploadError('Metadata report required')
        with os.fdopen(fd,'rb',closefd=False) as stream: data=stream.read(1_000_001)
        after=os.fstat(fd)
        if (len(data)>1_000_000 or before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns):
            raise UploadError('Changing report rejected')
        return parse_report(data)
    finally: os.close(fd)


async def upload(report_path,origin,*,consent=False,allow_loopback=False,client=None,environ=None):
    if consent is not True: raise UploadError('Explicit metadata upload consent required')
    env=os.environ if environ is None else environ
    if env.get('GITHUB_ACTIONS')!='true': raise UploadError('Trusted Actions job required')
    target=destination(origin,allow_loopback)
    report=load_report(report_path)
    endpoint=token_endpoint(env.get('ACTIONS_ID_TOKEN_REQUEST_URL',''),target)
    request_token=env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{8,8192}',request_token): raise UploadError('Actions identity unavailable')
    async def send(http):
        http.cookies.clear()
        token_data=await bounded_json(http,'GET',endpoint,limit=32768,
            headers={'Authorization':'Bearer '+request_token,'Accept-Encoding':'identity'})
        token=token_data.get('value')
        if (not isinstance(token,str) or len(token)>16384 or
            not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token)):
            raise UploadError('Actions identity unavailable')
        http.cookies.clear()
        result=await bounded_json(http,'POST',target,limit=8192,expected_status=202,
            headers={'Authorization':'Bearer '+token,'Accept-Encoding':'identity','Content-Type':'application/json'},
            content=report.model_dump_json().encode())
        if (not isinstance(result.get('receipt_id'),str) or not re.fullmatch(r'[0-9a-f]{64}',result['receipt_id']) or
            type(result.get('duplicate')) is not bool or result.get('trust_state')!='identity_verified_quarantined' or
            result.get('baseline_ready') is not False):
            raise UploadError('Unexpected receipt')
        return {key:result[key] for key in ('receipt_id','duplicate','trust_state','baseline_ready')}
    try:
        if client is not None: return await send(client)
        async with httpx.AsyncClient(timeout=20,follow_redirects=False,trust_env=False) as http:
            return await send(http)
    except (ValueError,TypeError,KeyError,RecursionError,TimeoutError,httpx.HTTPError,httpx.InvalidURL):
        raise UploadError('Metadata upload failed; provider details omitted') from None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',required=True);parser.add_argument('--server',required=True)
    parser.add_argument('--consent-metadata-upload',action='store_true')
    parser.add_argument('--allow-loopback-preview',action='store_true')
    args=parser.parse_args(argv)
    try:
        result=asyncio.run(upload(args.report,args.server,consent=args.consent_metadata_upload,
                                  allow_loopback=args.allow_loopback_preview))
    except (UploadError,OSError,ValueError,TypeError,RecursionError):
        print('Metadata upload failed; paths, tokens and provider details omitted.',file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Metadata upload cancelled.',file=sys.stderr)
        return 130
    print(json.dumps(result));return 0


if __name__=='__main__': raise SystemExit(main())
