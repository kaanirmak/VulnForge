"""GitHub App REST client. Only calls the configured GitHub API host."""
import base64
import re
import time
from urllib.parse import quote

import httpx
import jwt

from .config import Config

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class GitHubError(RuntimeError):
    pass


class GitHub:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self.client = client or httpx.AsyncClient(timeout=20, follow_redirects=False)
        self.owns_client = client is None
        self.tokens: dict[int, tuple[str, float]] = {}
        self._job=None
        self._guard=None

    def bind_job(self,job,guard):
        if self._job is not None or self.tokens:
            raise GitHubError('A GitHub client belongs to one job only')
        self._job=dict(job)
        self._guard=guard

    def _check_job(self,installation_id,path=None):
        if self._guard is None: return
        self._guard()
        if installation_id!=self._job['installation_id']:
            raise GitHubError('Installation outside job scope')
        if path is not None:
            prefix=self.repo_path(self._job['repo'])
            if path!=prefix and not path.startswith(prefix+'/'):
                raise GitHubError('Repository outside job scope')

    async def close(self):
        self.tokens.clear()
        self.client.cookies.clear()
        if self.owns_client:
            await self.client.aclose()

    def app_jwt(self) -> str:
        self.cfg.require_source_access()
        now = int(time.time())
        return jwt.encode({"iat": now-60, "exp": now+540, "iss": self.cfg.app_id},
                          self.cfg.private_key(), algorithm="RS256")

    async def token(self, installation_id: int) -> str:
        self._check_job(installation_id)
        self.cfg.require_source_access()
        cached = self.tokens.get(installation_id)
        if cached and cached[1] > time.time()+90:
            return cached[0]
        response = await self.client.post(
            f"{self.cfg.github_api_url}/app/installations/{int(installation_id)}/access_tokens",
            headers=self.headers(self.app_jwt()), json={
                **({'repositories':[self._job['repo'].split('/',1)[1]]} if self._job else {}),
                'permissions':{
                'metadata':'read','contents':'write' if self.cfg.enable_auto_pr and self._job is None else 'read',
                'pull_requests':'write' if self.cfg.enable_auto_pr and self._job is None else 'read',
                **({'checks':'write'} if self.cfg.enable_checks else {})}})
        self.validate(response)
        self._check_job(installation_id)
        data = response.json()
        import datetime
        expires = datetime.datetime.fromisoformat(data['expires_at'].replace('Z','+00:00')).timestamp()
        self.tokens[installation_id] = (data['token'], expires)
        return data['token']

    @staticmethod
    def headers(token: str):
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "VulnForge-MVP/0.2.0"}

    @staticmethod
    def validate(res: httpx.Response):
        if res.status_code >= 400:
            raise GitHubError(f"GitHub API response HTTP {res.status_code}")

    async def request(self, method: str, path: str, installation_id: int, **kwargs):
        # A credential alone must not bypass the selected privacy mode. The
        # customer-runner server has no reason to fetch repository content.
        self.cfg.require_source_access()
        self._check_job(installation_id,path)
        if method.upper() not in ('GET','HEAD'):
            verb=method.upper()
            prefix=r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'
            is_check=self.cfg.enable_checks and (
                (verb=='POST' and re.fullmatch(prefix+r'/check-runs',path)) or
                (verb=='PATCH' and re.fullmatch(prefix+r'/check-runs/[0-9]+',path)))
            body=kwargs.get('json',{})
            is_draft=self.cfg.enable_auto_pr and self._job is None and isinstance(body,dict) and (
                (verb=='POST' and re.fullmatch(prefix+r'/pulls',path) and body.get('draft') is True) or
                (verb=='POST' and re.fullmatch(prefix+r'/git/refs',path) and
                 str(body.get('ref','')).startswith('refs/heads/vulnforge/security/')) or
                (verb=='PUT' and re.fullmatch(prefix+r'/contents/(?:[^/]+/)*requirements\.txt',path) and
                 str(body.get('branch','')).startswith('vulnforge/security/')))
            if not is_check and not is_draft:
                raise GitHubError('Repository write operation is outside the allowed draft/check policy')
        token = await self.token(installation_id)
        self._check_job(installation_id,path)
        res = await self.client.request(method, f"{self.cfg.github_api_url}{path}",
                                        headers=self.headers(token), **kwargs)
        self.validate(res)
        self._check_job(installation_id,path)
        return res.json()

    @staticmethod
    def repo_path(full_name: str):
        if not NAME_RE.fullmatch(full_name) or '..' in full_name:
            raise ValueError("Invalid repository name")
        return "/repos/" + "/".join(quote(p, safe='') for p in full_name.split('/'))

    async def default_branch(self, repo: str, installation_id: int) -> str:
        result=await self.request('GET', self.repo_path(repo), installation_id)
        branch=result['default_branch']
        if not isinstance(branch,str) or not branch or len(branch)>200:
            raise GitHubError('Invalid default branch from repository API')
        return branch

    async def commit_shas(self, repo: str, installation_id: int, before: str,
                          after: str, fallback: list[str]):
        """Compare commits for full push coverage; never assume webhook array complete."""
        if not SHA_RE.fullmatch(after):
            raise ValueError("Invalid commit SHA")
        if not SHA_RE.fullmatch(before) or before == '0'*40:
            shas=[]
            for page in range(1,21):
                batch=await self.request('GET',f'{self.repo_path(repo)}/commits',installation_id,
                                         params={'sha':after,'per_page':100,'page':page})
                for commit in batch:
                    if not SHA_RE.fullmatch(commit.get('sha','')):
                        raise GitHubError('Invalid SHA in commit history')
                    shas.append(commit['sha'])
                if len(batch)<100:
                    if not shas or after not in shas:
                        raise GitHubError('Incomplete initial commit history')
                    return list(dict.fromkeys(reversed(shas)))
            raise GitHubError('Initial history exceeds 2000 commits; reconciliation required')
        shas = []
        for page in range(1, 21):
            result = await self.request('GET',
                f"{self.repo_path(repo)}/compare/{before}...{after}", installation_id,
                params={'per_page': 100, 'page': page})
            if result.get('status') not in ('ahead', 'identical'):
                raise GitHubError("Non-linear/force push: cannot reliably enumerate commits")
            commits = result.get('commits', [])
            shas += [c['sha'] for c in commits if SHA_RE.fullmatch(c.get('sha', ''))]
            if len(commits) < 100:
                return list(dict.fromkeys(shas))
        raise GitHubError('Compare exceeds 2000 commits; manual reconciliation required')

    async def backfill_commits(self, repo: str, installation_id: int, head_sha: str,
                               *, stop_sha: str | None = None, max_commits: int = 200) -> tuple[list[str], bool]:
        if not SHA_RE.fullmatch(head_sha):
            raise ValueError('Invalid commit SHA')
        stop=stop_sha if isinstance(stop_sha,str) and SHA_RE.fullmatch(stop_sha) and stop_sha!='0'*40 else None
        limit=max(1,min(2000,int(max_commits)))
        per_page=min(100,limit)
        max_pages=(limit+per_page-1)//per_page
        collected=[]
        for page in range(1,max_pages+1):
            batch=await self.request('GET',f'{self.repo_path(repo)}/commits',installation_id,
                                     params={'sha':head_sha,'per_page':per_page,'page':page})
            if not isinstance(batch,list):
                raise GitHubError('Invalid commit history response')
            for idx,commit in enumerate(batch):
                sha=commit.get('sha','') if isinstance(commit,dict) else ''
                if not SHA_RE.fullmatch(sha):
                    raise GitHubError('Invalid SHA in commit history')
                if stop and sha==stop:
                    return list(dict.fromkeys(reversed(collected))),False
                collected.append(sha)
                if len(collected)>=limit:
                    truncated=(idx+1<len(batch)) or (len(batch)>=per_page)
                    return list(dict.fromkeys(reversed(collected))),truncated
            if len(batch)<per_page:
                if not collected or head_sha not in collected:
                    raise GitHubError('Incomplete commit history during backfill')
                return list(dict.fromkeys(reversed(collected))),False
        return list(dict.fromkeys(reversed(collected))),True

    async def reconcile_push(self, repo: str, installation_id: int, before: str, after: str,
                             fallback: list[str], *, forced: bool = False,
                             last_sha: str | None = None, max_backfill: int = 200) -> dict:
        """Reconcile initial branch, missed deliveries, force-push, and oversized pushes."""
        if not SHA_RE.fullmatch(after):
            raise ValueError('Invalid commit SHA')
        valid_before=isinstance(before,str) and bool(SHA_RE.fullmatch(before)) and before!='0'*40
        valid_last=isinstance(last_sha,str) and bool(SHA_RE.fullmatch(last_sha)) and last_sha!='0'*40
        if not valid_before:
            shas,truncated=await self.backfill_commits(repo,installation_id,after,max_commits=max_backfill)
            return {'shas':shas,'mode':'initial_branch','truncated':truncated,'base_sha':'0'*40}
        if forced:
            stop=last_sha if valid_last else before
            shas,truncated=await self.backfill_commits(repo,installation_id,after,stop_sha=stop,max_commits=max_backfill)
            return {'shas':shas,'mode':'force_push_backfill','truncated':truncated,'base_sha':stop}
        base=last_sha if (valid_last and last_sha!=before) else before
        mode='missed_delivery_backfill' if base!=before else 'linear'
        try:
            shas=await self.commit_shas(repo,installation_id,base,after,fallback)
            if len(shas)>max_backfill:
                return {'shas':shas[-max_backfill:],'mode':'large_push_backfill','truncated':True,'base_sha':base}
            return {'shas':shas,'mode':mode,'truncated':False,'base_sha':base}
        except GitHubError as exc:
            msg=str(exc)
            if 'Non-linear/force push' in msg:
                shas,truncated=await self.backfill_commits(repo,installation_id,after,stop_sha=base,max_commits=max_backfill)
                return {'shas':shas,'mode':'force_push_backfill','truncated':truncated,'base_sha':base}
            if 'exceeds 2000 commits' in msg:
                shas,truncated=await self.backfill_commits(repo,installation_id,after,stop_sha=base,max_commits=max_backfill)
                return {'shas':shas,'mode':'large_push_backfill','truncated':True,'base_sha':base}
            raise

    async def changed_files(self, repo: str, installation_id: int, sha: str):
        if not SHA_RE.fullmatch(sha):
            raise ValueError('Invalid commit SHA')
        files = []
        for page in range(1, 11):
            result = await self.request('GET', f"{self.repo_path(repo)}/commits/{sha}",
                                        installation_id, params={'per_page':100,'page':page})
            batch = result.get('files', [])
            files.extend(batch)
            if len(batch) < 100:
                return files
        raise GitHubError('Commit contains >1000 changed files; scanner refused incomplete result')

    async def get_file(self, repo: str, installation_id: int, path: str, ref: str):
        """Download only normal files through GitHub Contents API, no Git execution."""
        if path.startswith('/') or '\\' in path or any(x in ('', '.', '..') for x in path.split('/')):
            raise ValueError('Unsafe repository file path')
        if len(path) > 1024:
            raise ValueError('File path too long')
        result = await self.request('GET',
            f"{self.repo_path(repo)}/contents/{quote(path, safe='/')}",
            installation_id, params={'ref': ref})
        if result.get('type') != 'file' or result.get('encoding') != 'base64':
            return None
        if result.get('size', 0) > self.cfg.max_file_bytes:
            return None
        raw = base64.b64decode(result.get('content',''), validate=False)
        if len(raw) > self.cfg.max_file_bytes or b'\x00' in raw:
            return None
        try:
            return {'text': raw.decode('utf-8'), 'sha': result['sha'], 'path': path}
        except UnicodeDecodeError:
            return None

    async def manifest_paths(self, repo: str, installation_id: int, sha: str):
        if not SHA_RE.fullmatch(sha):
            raise ValueError('Invalid commit SHA')
        git_commit = await self.request('GET',
            f"{self.repo_path(repo)}/git/commits/{sha}", installation_id)
        tree_sha = git_commit['tree']['sha']
        if not SHA_RE.fullmatch(tree_sha):
            raise GitHubError('GitHub returned an invalid tree SHA')
        result = await self.request('GET',
            f"{self.repo_path(repo)}/git/trees/{tree_sha}", installation_id,
            params={'recursive': '1'})
        if result.get('truncated'):
            raise GitHubError('GitHub tree truncated; inventory incomplete')
        wanted = {'requirements.txt', 'package-lock.json', 'poetry.lock', 'Cargo.lock', 'go.mod', 'composer.lock',
                  'yarn.lock','pnpm-lock.yaml','uv.lock','Pipfile.lock','Gemfile.lock','pom.xml',
                  'build.gradle','build.gradle.kts','gradle.lockfile','packages.lock.json',
                  'Gemfile','Pipfile','setup.py','setup.cfg','go.sum','packages.config'}
        blobs={x['path'] for x in result.get('tree',[]) if x.get('type')=='blob'}
        paths=[]
        companions={'package.json':('package-lock.json',),'pyproject.toml':('poetry.lock',),
                    'composer.json':('composer.lock',),'Cargo.toml':('Cargo.lock',)}
        for path in (x['path'] for x in result.get('tree',[]) if x.get('type')=='blob'):
            parent,_,name=path.rpartition('/')
            prefix=parent+'/' if parent else ''
            # Keep unsupported/unlocked manifests visible to the coverage layer.
            if (name in wanted or name.endswith('.csproj') or
                (name in companions and not any(prefix+lock in blobs for lock in companions[name])) or
                (name.startswith('requirements') and name.endswith('.txt'))):
                paths.append(path)
        if len(paths) > 80:
            raise GitHubError('More than 80 dependency manifests; split audit needed')
        return paths

    async def branch_head(self, repo: str, installation_id: int, branch: str):
        ref = quote(branch, safe='/')
        obj = await self.request('GET', f"{self.repo_path(repo)}/git/ref/heads/{ref}", installation_id)
        return obj['object']['sha']

    async def pull_files(self, repo, installation_id, number, expected_sha):
        """Paginate the whole PR diff and reject changes to HEAD during collection."""
        prefix=f'{self.repo_path(repo)}/pulls/{int(number)}'
        async def verify():
            pr=await self.request('GET',prefix,installation_id)
            if pr['head']['sha']!=expected_sha:
                raise GitHubError('Pull request HEAD changed; scan the new event instead')
            return pr
        pr=await verify()
        files=[]
        for page in range(1,32):
            batch=await self.request('GET',prefix+'/files',installation_id,params={'per_page':100,'page':page})
            files.extend(batch)
            if len(files)>3000:
                raise GitHubError('PR exceeds GitHub diff limit')
            if len(batch)<100:
                await verify()
                if len(files)!=pr.get('changed_files',len(files)):
                    raise GitHubError('Incomplete PR file list')
                return files
        raise GitHubError('PR file pagination limit exceeded')

    async def publish_check(self, repo, installation_id, scan):
        """Publish coverage and annotations in batches of at most 50."""
        findings=scan['findings']
        conclusion=('action_required' if scan['state']!='complete' else
                    'failure' if any(f['severity'] in ('high','critical') for f in findings) else 'success')
        annotations=[]
        for f in findings:
            line=f['details'].get('line')
            if not f.get('file_path') or not isinstance(line,int) or line<1:
                continue
            annotations.append({'path':f['file_path'],'start_line':line,'end_line':line,
                                'annotation_level':'failure' if f['severity'] in ('high','critical') else 'warning',
                                'message':f['title'][:2000]})
        output={'title':f"VulnForge {scan['kind']}: {scan['state']}",
                'summary':f"Snapshot: `{scan['commit_sha']}`\n\nAnalysis: **{scan['state']}**; {len(findings)} findings. "
                          'This result covers only the stated scan scope. Reachability is unknown.',
                'annotations':annotations[:50]}
        path=f'{self.repo_path(repo)}/check-runs'
        check=await self.request('POST',path,installation_id,json={
            'name':f"VulnForge / {scan['kind']}",'head_sha':scan['commit_sha'],'external_id':scan['id'],
            'status':'in_progress','output':output})
        for offset in range(50,len(annotations),50):
            await self.request('PATCH',f"{path}/{check['id']}",installation_id,
                               json={'output':{'title':output['title'],'summary':output['summary'],
                                               'annotations':annotations[offset:offset+50]}})
        await self.request('PATCH',f"{path}/{check['id']}",installation_id,
                           json={'status':'completed','conclusion':conclusion})

    async def create_fix_pr(self, repo: str, installation_id: int, base: str,
                            branch: str, path: str, old_sha: str, new_text: str,
                            title: str, body: str):
        self.cfg.require_source_access()
        if not self.cfg.enable_auto_pr:
            raise GitHubError('Draft PR publication is not enabled')
        head_sha = await self.branch_head(repo, installation_id, base)
        await self.request('POST', f"{self.repo_path(repo)}/git/refs", installation_id,
                           json={'ref': f'refs/heads/{branch}', 'sha': head_sha})
        await self.request('PUT', f"{self.repo_path(repo)}/contents/{quote(path, safe='/')}", installation_id,
                           json={'message': title, 'content': base64.b64encode(new_text.encode()).decode(),
                                 'branch': branch, 'sha': old_sha})
        pr = await self.request('POST', f"{self.repo_path(repo)}/pulls", installation_id,
                                json={'title': title, 'head': branch, 'base': base,
                                      'body': body, 'draft': True})
        return pr['html_url']
