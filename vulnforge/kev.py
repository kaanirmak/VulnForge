"""CISA KEV, NVD CVSS, and FIRST EPSS threat intelligence catalog reader.

Enriches version-confirmed dependency matches with CVSS, EPSS and KEV while
strictly preserving cryptographic hash and timestamp evidence from each source.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re
import time

import httpx

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS_URL = 'https://api.first.org/data/v1/epss'
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,19}$')


@dataclass(frozen=True)
class VulnerabilityMetrics:
    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_date_added: str | None = None
    kev_ransomware: bool = False
    evidence: dict = field(default_factory=dict)


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
        self._entries=None
        self._expires_at=0.0
        self.client.cookies.clear()
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
        """Enrich only an already-confirmed match, never infer vulnerable versions."""
        ids = [advisory.get('id'), *(advisory.get('aliases') or [])]
        for id_ in ids:
            if isinstance(id_, str) and CVE_RE.fullmatch(id_) and id_ in entries:
                return entries[id_]
        return None


class NVD:
    def __init__(self, url: str = NVD_URL, client: httpx.AsyncClient | None = None):
        self.url = url
        self.client = client or httpx.AsyncClient(timeout=30, follow_redirects=False)
        self.owns_client = client is None

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    @staticmethod
    def parse_nvd_cve(data: dict | bytes | str) -> dict:
        """Parse NVD CVE 2.0 response or item with cryptographic hash evidence."""
        if isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
            payload = json.loads(raw_bytes.decode('utf-8'))
        elif isinstance(data, str):
            raw_bytes = data.encode('utf-8')
            payload = json.loads(data)
        elif isinstance(data, dict):
            payload = data
            raw_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        else:
            raise ValueError('Invalid NVD data format')

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        now = time.time()

        vuln = payload
        if 'vulnerabilities' in payload and isinstance(payload['vulnerabilities'], list) and payload['vulnerabilities']:
            vuln = payload['vulnerabilities'][0].get('cve', {})
        elif 'cve' in payload:
            vuln = payload['cve']

        cve_id = vuln.get('id', '')
        if not CVE_RE.fullmatch(cve_id):
            raise ValueError(f'Invalid CVE ID in NVD payload: {cve_id}')

        metrics = vuln.get('metrics', {})
        cvss_score = None
        cvss_severity = None
        cvss_vector = None

        for key in ('cvssMetricV31', 'cvssMetricV30'):
            entries = metrics.get(key, [])
            if entries and isinstance(entries, list):
                primary = entries[0].get('cvssData', {})
                cvss_score = float(primary.get('baseScore', 0.0))
                cvss_severity = str(primary.get('baseSeverity', '')).upper() or None
                cvss_vector = primary.get('vectorString')
                break

        if cvss_score is None and 'cvssMetricV2' in metrics:
            entries = metrics.get('cvssMetricV2', [])
            if entries and isinstance(entries, list):
                primary = entries[0].get('cvssData', {})
                cvss_score = float(primary.get('baseScore', 0.0))
                cvss_severity = str(entries[0].get('baseSeverity', '')).upper() or None
                cvss_vector = primary.get('vectorString')

        return {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'cvss_severity': cvss_severity,
            'cvss_vector': cvss_vector,
            'evidence': {
                'source': 'NVD',
                'source_sha256': sha256,
                'observed_at': now
            }
        }


class EPSS:
    def __init__(self, url: str = EPSS_URL, client: httpx.AsyncClient | None = None):
        self.url = url
        self.client = client or httpx.AsyncClient(timeout=30, follow_redirects=False)
        self.owns_client = client is None

    async def close(self):
        if self.owns_client:
            await self.client.aclose()

    @staticmethod
    def parse_epss_response(data: dict | bytes | str) -> dict[str, dict]:
        """Parse FIRST EPSS API response with cryptographic hash evidence."""
        if isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
            payload = json.loads(raw_bytes.decode('utf-8'))
        elif isinstance(data, str):
            raw_bytes = data.encode('utf-8')
            payload = json.loads(data)
        elif isinstance(data, dict):
            payload = data
            raw_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        else:
            raise ValueError('Invalid EPSS data format')

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        now = time.time()

        rows = payload.get('data', [])
        if not isinstance(rows, list):
            raise ValueError('Malformed EPSS payload: missing data array')

        results = {}
        for row in rows:
            cve = row.get('cve', '')
            if not CVE_RE.fullmatch(cve):
                continue
            try:
                score = float(row.get('epss', 0.0))
                percentile = float(row.get('percentile', 0.0))
            except (ValueError, TypeError):
                continue
            results[cve] = {
                'cve_id': cve,
                'epss_score': score,
                'epss_percentile': percentile,
                'evidence': {
                    'source': 'EPSS',
                    'source_sha256': sha256,
                    'observed_at': now
                }
            }
        return results


def enrich_advisory_metrics(advisory: dict, *, nvd_data: dict | None = None,
                            epss_data: dict | None = None, kev_data: dict | None = None) -> VulnerabilityMetrics:
    """Combine NVD, EPSS, and KEV threat intelligence preserving source/time/hash evidence."""
    cve_id = None
    all_ids = [advisory.get('id'), *(advisory.get('aliases') or [])]
    for i in all_ids:
        if isinstance(i, str) and CVE_RE.fullmatch(i):
            cve_id = i
            break
    if not cve_id:
        cve_id = str(advisory.get('id', 'unknown'))

    evidence = {}
    cvss_score = None
    cvss_severity = None
    cvss_vector = None
    if nvd_data:
        cvss_score = nvd_data.get('cvss_score')
        cvss_severity = nvd_data.get('cvss_severity')
        cvss_vector = nvd_data.get('cvss_vector')
        if 'evidence' in nvd_data:
            evidence['nvd'] = nvd_data['evidence']

    epss_score = None
    epss_percentile = None
    if epss_data:
        epss_score = epss_data.get('epss_score')
        epss_percentile = epss_data.get('epss_percentile')
        if 'evidence' in epss_data:
            evidence['epss'] = epss_data['evidence']

    kev_date_added = None
    kev_ransomware = False
    if kev_data:
        kev_date_added = kev_data.get('date_added')
        kev_ransomware = bool(kev_data.get('ransomware'))
        evidence['kev'] = {
            'source': 'CISA-KEV',
            'observed_at': time.time(),
            'date_added': kev_date_added
        }

    return VulnerabilityMetrics(
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cvss_vector=cvss_vector,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_date_added=kev_date_added,
        kev_ransomware=kev_ransomware,
        evidence=evidence
    )
