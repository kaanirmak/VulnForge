"""CISA KEV catalog reader for *prioritizing* confirmed OSV dependency matches.

CISA KEV is CVE-centric, not a package-version matching service. It MUST NOT
be used alone to claim a dependency is affected. Only enrich OSV results.
"""
import re
import time

import httpx

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,19}$')


class KEV:
    def __init__(self, url: str = KEV_URL, refresh_seconds: int = 6 * 3600,
                 client: httpx.AsyncClient | None = None):
        self.url = url
        self.refresh_seconds = max(3600, refresh_seconds)
        self.client = client or httpx.AsyncClient(timeout=30, follow_redirects=False)
        self.owns_client = client is None
        self._entries: dict[str, dict] | None = None
        self._expires_at = 0.0

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    async def entries(self) -> dict[str, dict]:
        if self._entries is not None and time.monotonic() < self._expires_at:
            return self._entries
        response = await self.client.get(self.url, headers={'Accept': 'application/json'})
        response.raise_for_status()
        if len(response.content) > 12_000_000:
            raise ValueError('CISA KEV catalog exceeds maximum allowed size')
        payload = response.json()
        rows = payload.get('vulnerabilities') if isinstance(payload, dict) else None
        if not isinstance(rows, list) or not rows:
            raise ValueError('CISA KEV catalog is empty or malformed')
        if payload.get('count') != len(rows):
            raise ValueError('CISA KEV catalog count mismatch; refusing partial data')
        entries = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('CISA KEV catalog has malformed vulnerability entries')
            cve = row.get('cveID', '')
            if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
                raise ValueError('CISA KEV catalog has malformed CVE ID')
            entries[cve] = {
                'cve': cve,
                'date_added': str(row.get('dateAdded', ''))[:10],
                'ransomware': row.get('knownRansomwareCampaignUse') == 'Known',
            }
        self._entries = entries
        self._expires_at = time.monotonic() + self.refresh_seconds
        return entries

    @staticmethod
    def match(advisory: dict, entries: dict[str, dict]) -> dict | None:
        """Enrich only an already-confirmed OSV match, never infer vulnerable versions."""
        ids = [advisory.get('id'), *(advisory.get('aliases') or [])]
        for id_ in ids:
            if isinstance(id_, str) and CVE_RE.fullmatch(id_) and id_ in entries:
                return entries[id_]
        return None
