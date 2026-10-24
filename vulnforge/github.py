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

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    def app_jwt(self) -> str:
        now = int(time.time())
        return jwt.encode({"iat": now-60, "exp": now+540, "iss": self.cfg.app_id},
                          self.cfg.private_key(), algorithm="RS256")

    async def token(self, installation_id: int) -> str:
        cached = self.tokens.get(installation_id)
        if cached and cached[1] > time.time()+90:
            return cached[0]
        response = await self.client.post(
            f"{self.cfg.github_api_url}/app/installations/{int(installation_id)}/access_tokens",
            headers=self.headers(self.app_jwt()), json={})
        self.validate(response)
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
        token = await self.token(installation_id)
        res = await self.client.request(method, f"{self.cfg.github_api_url}{path}",
                                        headers=self.headers(token), **kwargs)
        self.validate(res)
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
            return list(dict.fromkeys([s for s in fallback if SHA_RE.fullmatch(s)] + [after]))
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
        wanted = {'requirements.txt', 'package-lock.json', 'poetry.lock', 'Cargo.lock', 'go.mod', 'composer.lock'}
        paths = [x['path'] for x in result.get('tree', []) if x.get('type') == 'blob'
                 and x.get('path','').split('/')[-1] in wanted]
        if len(paths) > 80:
            raise GitHubError('More than 80 dependency manifests; split audit needed')
        return paths

    async def branch_head(self, repo: str, installation_id: int, branch: str):
        ref = quote(branch, safe='/')
        obj = await self.request('GET', f"{self.repo_path(repo)}/git/ref/heads/{ref}", installation_id)
        return obj['object']['sha']

    async def create_fix_pr(self, repo: str, installation_id: int, base: str,
                            branch: str, path: str, old_sha: str, new_text: str,
                            title: str, body: str):
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
