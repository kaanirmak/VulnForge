"""Self-hosted, On-Premises, and Air-gapped deployment manager for VulnForge."""
from dataclasses import dataclass, field
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


INTERNAL_HOST_PATTERNS = (
    re.compile(r"^(localhost|127\.0\.0\.1|::1)$"),
    re.compile(r"^.*\.local$"),
    re.compile(r"^.*\.internal$"),
    re.compile(r"^.*\.corp$"),
    re.compile(r"^.*\.lan$"),
)


@dataclass
class AirgappedConfig:
    airgapped: bool = True
    osv_mirror_path: Optional[str] = None
    local_registry_url: Optional[str] = None
    disallow_external_egress: bool = True
    trusted_internal_domains: List[str] = field(default_factory=lambda: ["local", "internal", "lan", "corp"])


def is_airgapped_safe_host(host_or_url: str, trusted_domains: Optional[List[str]] = None) -> bool:
    """Verify if a host or URL resides within an isolated/internal network boundary."""
    if not host_or_url or not isinstance(host_or_url, str):
        return False

    raw_host = host_or_url.strip()
    if "://" in raw_host:
        parsed = urlparse(raw_host)
        raw_host = parsed.hostname or ""
    elif ":" in raw_host and not raw_host.startswith("["):
        raw_host = raw_host.split(":", 1)[0]

    # Check loopback or IP addresses
    try:
        ip = ipaddress.ip_address(raw_host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass

    # Check known internal suffix patterns
    domains = trusted_domains or ["local", "internal", "lan", "corp"]
    for d in domains:
        if raw_host == d or raw_host.endswith(f".{d}"):
            return True

    return any(p.match(raw_host) for p in INTERNAL_HOST_PATTERNS)


def validate_airgapped_isolation(config: AirgappedConfig, endpoints: List[str]) -> bool:
    """Validate that all provided system endpoints conform to strict air-gapped isolation."""
    if not config.airgapped:
        return True

    violating_endpoints = []
    for ep in endpoints:
        if not is_airgapped_safe_host(ep, config.trusted_internal_domains):
            violating_endpoints.append(ep)

    if violating_endpoints:
        raise ValueError(
            f"Air-gapped isolation violation: External internet endpoints forbidden: {', '.join(violating_endpoints)}"
        )

    return True


def load_offline_advisories_bundle(store: Any, bundle_path: str) -> int:
    """Import an offline threat advisory JSON bundle into the store with zero network calls."""
    path = Path(bundle_path)
    if not path.is_file():
        raise FileNotFoundError(f"Offline advisory bundle not found at {bundle_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        if isinstance(data, dict) and "advisories" in data:
            data = data["advisories"]
        else:
            raise ValueError("Bundle must contain a list of advisory records")

    count = 0
    for adv in data:
        adv_id = adv.get("id")
        if adv_id and isinstance(adv_id, str):
            store.save_advisory(adv, source="Offline Bundle")
            count += 1

    return count


def generate_onprem_compose(
    db_password: str = "change_me_in_prod",
    image_tag: str = "0.3.0",
    storage_volume: str = "vf_data",
) -> str:
    """Generate self-contained, air-gapped Docker Compose manifest."""
    return f"""# VulnForge On-Premises & Air-Gapped Deployment
version: '3.8'

services:
  db:
    image: postgres:14-alpine
    restart: always
    environment:
      POSTGRES_DB: vulnforge
      POSTGRES_USER: vulnforge
      POSTGRES_PASSWORD: {db_password}
    volumes:
      - vf_db_data:/var/lib/postgresql/data
    networks:
      - vf_internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulnforge -d vulnforge"]
      interval: 5s
      timeout: 5s
      retries: 5

  vulnforge:
    image: vulnforge/server:{image_tag}
    restart: always
    depends_on:
      db:
        condition: service_healthy
    environment:
      ENVIRONMENT: production
      SCAN_MODE: customer_runner
      AIRGAPPED: "true"
      DATABASE_URL: postgresql://vulnforge:{db_password}@db:5432/vulnforge
      PUBLIC_ORIGIN: https://vulnforge.internal
      ALLOW_INSECURE_LOCAL_AUTH: "false"
      WEBHOOK_SECRET: "change_to_high_entropy_webhook_secret_32bytes"
      ADMIN_TOKEN: "change_to_high_entropy_admin_token_32bytes"
    volumes:
      - {storage_volume}:/opt/vulnforge/data
    ports:
      - "8443:8443"
    networks:
      - vf_internal

volumes:
  vf_db_data:
  {storage_volume}:

networks:
  vf_internal:
    internal: true
"""
