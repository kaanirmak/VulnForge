"""Read-only installation/repository identity checks, without source permissions."""
import re
import time
import asyncio

import httpx
import jwt

from .oidc import bounded_json

API='https://api.github.com'


class MetadataError(PermissionError): pass


class GitHubMetadata:
    def __init__(self,cfg,client=None): self.cfg=cfg;self.client=client

    async def repository(self,repo,installation_id):
        try:
            if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or '..' in repo or
                type(installation_id) is not int or installation_id<=0 or
                not re.fullmatch(r'[1-9][0-9]{0,18}',self.cfg.app_id)):
                raise ValueError('Configured App and repository identity required')
            now=int(time.time())
            credential=jwt.encode({'iat':now-60,'exp':now+540,'iss':self.cfg.app_id},
                                  self.cfg.private_key(),algorithm='RS256')
            async def read(client):
                def headers(token):
                    return {'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                            'Accept-Encoding':'identity','X-GitHub-Api-Version':'2026-03-10'}
                installation=await bounded_json(client,'GET',API+f'/app/installations/{installation_id}',
                                                headers=headers(credential))
                if (type(installation.get('id')) is not int or type(installation.get('app_id')) is not int or
                    installation.get('id')!=installation_id or installation.get('app_id')!=int(self.cfg.app_id) or
                    installation.get('suspended_at') is not None or
                    installation.get('permissions')!={'metadata':'read'}):
                    raise ValueError('A metadata-only installation is required')
                # POST token creation has 201 rather than the read helper's 200.
                async with client.stream('POST',API+f'/app/installations/{installation_id}/access_tokens',
                    headers=headers(credential),json={'repositories':[repo.split('/')[1]],
                                                      'permissions':{'metadata':'read'}}) as response:
                    if response.status_code!=201: raise ValueError('Metadata credential rejected')
                    if response.headers.get('content-encoding','identity')!='identity':
                        raise ValueError('Encoded token response rejected')
                    chunks=[];size=0
                    async for chunk in response.aiter_bytes():
                        size+=len(chunk)
                        if size>16384: raise ValueError('Metadata credential response limit')
                        chunks.append(chunk)
                    from .oidc import unique_json
                    token_data=unique_json(b''.join(chunks))
                token=token_data.get('token')
                if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{8,4096}',token):
                    raise ValueError('Invalid metadata credential')
                if token_data.get('permissions')!={'metadata':'read'}:
                    raise ValueError('Metadata-only permission proof required')
                metadata=await bounded_json(client,'GET',API+'/repos/'+repo,headers=headers(token))
                owner=metadata.get('owner',{}).get('id')
                if (metadata.get('full_name')!=repo or type(metadata.get('id')) is not int or
                    not 0<metadata['id']<2**63 or type(owner) is not int or not 0<owner<2**63 or
                    installation.get('account',{}).get('id')!=owner or metadata.get('archived') is True or
                    metadata.get('disabled') is True): raise ValueError('Repository unavailable')
                branch=metadata.get('default_branch')
                if (not isinstance(branch,str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}',branch) or
                    '..' in branch or '//' in branch or branch.endswith(('/','.'))):
                    raise ValueError('Invalid default branch')
                return {'repository_id':metadata['id'],'owner_id':owner,'default_branch':branch}
            if self.client is not None: return await asyncio.wait_for(read(self.client),timeout=30)
            async with httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
                return await asyncio.wait_for(read(client),timeout=30)
        except (ValueError,TypeError,KeyError,AttributeError,RecursionError,TimeoutError,OSError,httpx.HTTPError,jwt.PyJWTError):
            raise MetadataError('Repository installation could not be verified') from None
