"""Network boundaries, TLS enforcement, security ingress headers, rate limiting, and private database isolation."""
import ipaddress
import re
import time
from typing import Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# RFC 1918 and loopback private networks
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
]

# Sensitive cloud metadata and link-local forbidden destinations
BLOCKED_NETWORKS = [
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local / Cloud metadata (AWS, GCP, Azure)
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('224.0.0.0/4'),    # Multicast
    ipaddress.ip_network('240.0.0.0/4'),    # Reserved
]

PRIVATE_HOST_SUFFIXES = (
    '.internal',
    '.local',
    '.vpc',
    '.lan',
    '.cluster.local',
    '.private'
)


def is_private_or_loopback_host(hostname: str) -> bool:
    """Check if a hostname resolves to a private IP, loopback, or internal domain suffix."""
    hostname = hostname.strip().lower()
    if hostname in ('localhost', '::1', '127.0.0.1'):
        return True
    if any(hostname.endswith(suffix) for suffix in PRIVATE_HOST_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_blocked_destination(hostname: str) -> bool:
    """Check if destination IP is link-local, cloud metadata, or multicast."""
    hostname = hostname.strip().lower()
    try:
        ip = ipaddress.ip_address(hostname)
        return any(ip in net for net in BLOCKED_NETWORKS)
    except ValueError:
        return False


def validate_database_network_isolation(db_url: str, environment: str = 'development') -> None:
    """
    Ensure database connections in production and staging follow private network boundaries:
    - Must not connect to cloud metadata or link-local endpoints.
    - In production/staging: public IPs/hosts without TLS (sslmode=require / verify-full) are strictly forbidden.
    - Internal private networks (RFC 1918) or SSL-enforced endpoints are required.
    - Local Unix domain sockets are inherently private and permitted.
    """
    if not db_url or not db_url.startswith(('postgresql://', 'postgres://')):
        return

    parsed = urlsplit(db_url)
    query_params = parse_qs(parsed.query)

    # Check for Unix domain socket connections (query param host=/path/to/socket or empty host)
    socket_path = query_params.get('host', [''])[0]
    if socket_path and (socket_path.startswith('/') or socket_path.startswith('.')):
        return

    hostname = parsed.hostname or socket_path or ''
    if not hostname:
        # Default PostgreSQL local unix domain socket connection
        return

    if is_blocked_destination(hostname):
        raise ValueError(f"Database network violation: Connection to metadata/link-local address '{hostname}' is blocked")

    query_params = parse_qs(parsed.query)
    sslmode = query_params.get('sslmode', [''])[0].lower()

    if environment in ('production', 'staging'):
        is_private = is_private_or_loopback_host(hostname)
        has_ssl = sslmode in ('require', 'verify-ca', 'verify-full')

        if not is_private and not has_ssl:
            raise ValueError(
                f"Database network boundary violation in {environment}: "
                f"Host '{hostname}' is a public endpoint but does not enforce TLS (sslmode=require or verify-full)."
            )


def is_safe_egress_endpoint(url: str) -> bool:
    """Validate external egress URLs against SSRF and private metadata leakage."""
    if not url:
        return False
    parsed = urlsplit(url)
    if parsed.scheme != 'https':
        return False
    hostname = parsed.hostname or ''
    if not hostname or is_blocked_destination(hostname) or is_private_or_loopback_host(hostname):
        return False
    return True


class IngressRateLimiter:
    """Sliding-window rate limiter per client key (IP or token)."""

    def __init__(self, limit: int = 120, window_seconds: float = 60.0):
        self.limit = limit
        self.window_seconds = window_seconds
        self._history: Dict[str, list[float]] = {}

    def is_allowed(self, client_key: str, now: Optional[float] = None) -> Tuple[bool, int, float]:
        """
        Check if request is allowed.
        Returns: (allowed, remaining, retry_after)
        """
        if now is None:
            now = time.time()
        window_start = now - self.window_seconds

        times = self._history.setdefault(client_key, [])
        # Prune old requests
        times = [t for t in times if t > window_start]
        self._history[client_key] = times

        if len(times) >= self.limit:
            oldest = times[0]
            retry_after = max(1.0, round((oldest + self.window_seconds) - now, 1))
            return False, 0, retry_after

        times.append(now)
        remaining = self.limit - len(times)
        return True, remaining, 0.0


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies strict security headers, TLS enforcement, and ingress boundaries."""

    def __init__(self, app, cfg, rate_limiter: Optional[IngressRateLimiter] = None):
        super().__init__(app)
        self.cfg = cfg
        self.rate_limiter = rate_limiter or IngressRateLimiter(limit=240, window_seconds=60.0)

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. TLS Enforcement in production
        forwarded_proto = request.headers.get('x-forwarded-proto', request.url.scheme).lower()
        is_tls = forwarded_proto == 'https'
        is_loopback = request.url.hostname in ('localhost', '127.0.0.1', '::1')

        if self.cfg.environment == 'production' and not is_tls and not (self.cfg.allow_insecure_local_auth and is_loopback):
            return JSONResponse({
                'detail': 'TLS connection is required',
                'error_code': 'TLS_REQUIRED',
                'message': 'TLS connection is required'
            }, status_code=403, headers={'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'})

        # 2. Ingress rate limit
        client_ip = request.headers.get('x-forwarded-for', request.client.host if request.client else '127.0.0.1').split(',')[0].strip()
        client_key = f"{client_ip}:{request.headers.get('authorization', '')[:16]}"
        allowed, remaining, retry_after = self.rate_limiter.is_allowed(client_key)

        if not allowed:
            return JSONResponse({
                'detail': 'Ingress rate limit exceeded',
                'error_code': 'RATE_LIMIT_EXCEEDED',
                'message': f"Too many requests. Please retry in {retry_after} seconds."
            }, status_code=429, headers={
                'Retry-After': str(int(retry_after)),
                'X-RateLimit-Limit': str(self.rate_limiter.limit),
                'X-RateLimit-Remaining': '0'
            })

        response = await call_next(request)

        # 3. Security Ingress Headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        if 'Referrer-Policy' not in response.headers:
            response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['X-RateLimit-Limit'] = str(self.rate_limiter.limit)
        response.headers['X-RateLimit-Remaining'] = str(remaining)

        # Enforce HSTS for TLS connections or production
        if is_tls or self.cfg.environment == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'

        # Modern Content-Security-Policy (allows safe self assets)
        if 'Content-Security-Policy' not in response.headers:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "base-uri 'self';"
            )

        return response
