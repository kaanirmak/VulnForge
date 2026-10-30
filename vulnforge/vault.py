"""Secret vault management, least-privilege scoping, and zero-downtime key rotation."""
import hashlib
import hmac
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Least privilege mapping: which components are granted access to specific secrets
COMPONENT_SECRET_PERMISSIONS: Dict[str, Set[str]] = {
    'worker': {
        'worker_database_url',
        'osv_api_url',
        'osv_allowed_packages',
        'private_package_patterns'
    },
    'api': {
        'database_url',
        'customer_database_url',
        'webhook_secret',
        'github_oauth_client_id',
        'github_oauth_client_secret',
        'admin_token',
        'operator_report_token',
        'operator_credentials'
    },
    'github_app': {
        'github_app_id',
        'github_private_key',
        'webhook_secret'
    },
    'operator': {
        'database_url',
        'admin_token',
        'operator_credentials',
        'operator_report_token'
    }
}


class SecretEntry:
    def __init__(self, name: str, current_value: str):
        self.name = name
        self.current_value = current_value
        self.previous_value: Optional[str] = None
        self.rotated_at: Optional[float] = None
        self.grace_period_seconds: float = 86400.0
        self.rotation_history: List[Dict[str, Any]] = []

    def rotate(self, new_value: str, grace_period_seconds: float = 86400.0, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        old_digest = hashlib.sha256(self.current_value.encode('utf-8')).hexdigest()
        self.rotation_history.append({
            'fingerprint': old_digest[:16],
            'rotated_at': now,
            'grace_period_seconds': grace_period_seconds
        })
        self.previous_value = self.current_value
        self.current_value = new_value
        self.rotated_at = now
        self.grace_period_seconds = grace_period_seconds

    def active_values(self, now: Optional[float] = None) -> List[str]:
        if now is None:
            now = time.time()
        values = [self.current_value]
        if self.previous_value and self.rotated_at is not None:
            if (now - self.rotated_at) <= self.grace_period_seconds:
                values.append(self.previous_value)
        return values


class ScopedVaultView:
    """Restricts secret visibility to the minimal set required by a specific service component."""

    def __init__(self, vault: 'SecretVault', component: str):
        self._vault = vault
        self._component = component
        self._allowed_secrets = COMPONENT_SECRET_PERMISSIONS.get(component, set())

    def get_secret(self, name: str) -> Optional[str]:
        if name not in self._allowed_secrets:
            raise PermissionError(
                f"Access denied: Component '{self._component}' is not authorized to access secret '{name}'"
            )
        return self._vault.get_secret(name)


class SecretVault:
    """In-memory secure secret vault supporting role isolation and zero-downtime key rotation."""

    def __init__(self):
        self._secrets: Dict[str, SecretEntry] = {}

    def set_secret(self, name: str, value: str) -> None:
        if name in self._secrets:
            self._secrets[name].current_value = value
        else:
            self._secrets[name] = SecretEntry(name, value)

    def get_secret(self, name: str) -> Optional[str]:
        entry = self._secrets.get(name)
        return entry.current_value if entry else None

    def rotate_secret(self, name: str, new_value: str, grace_period_seconds: float = 86400.0, now: Optional[float] = None) -> Dict[str, Any]:
        entry = self._secrets.get(name)
        if not entry:
            entry = SecretEntry(name, new_value)
            self._secrets[name] = entry
            return {'name': name, 'status': 'created', 'fingerprint': hashlib.sha256(new_value.encode()).hexdigest()[:16]}

        entry.rotate(new_value, grace_period_seconds, now=now)
        return {
            'name': name,
            'status': 'rotated',
            'rotated_at': entry.rotated_at,
            'grace_period_seconds': grace_period_seconds,
            'current_fingerprint': hashlib.sha256(new_value.encode()).hexdigest()[:16],
            'previous_fingerprint': hashlib.sha256(entry.previous_value.encode()).hexdigest()[:16] if entry.previous_value else None
        }

    def verify_hmac_signature(self, secret_name: str, payload: bytes, signature_header: str, now: Optional[float] = None) -> bool:
        """
        Verify an incoming HMAC SHA-256 signature against all currently active secrets for a key,
        supporting seamless zero-downtime rotation during the grace period.
        """
        if not signature_header or not signature_header.startswith('sha256='):
            return False

        entry = self._secrets.get(secret_name)
        if not entry:
            return False

        candidates = entry.active_values(now=now)
        for candidate_key in candidates:
            expected = 'sha256=' + hmac.new(candidate_key.encode('utf-8'), payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, signature_header):
                return True
        return False

    def scoped_view(self, component: str) -> ScopedVaultView:
        return ScopedVaultView(self, component)

    @classmethod
    def from_config(cls, cfg) -> 'SecretVault':
        vault = cls()
        if cfg.webhook_secret:
            vault.set_secret('webhook_secret', cfg.webhook_secret)
        if cfg.admin_token:
            vault.set_secret('admin_token', cfg.admin_token)
        if cfg.operator_report_token:
            vault.set_secret('operator_report_token', cfg.operator_report_token)
        if cfg.github_oauth_client_id:
            vault.set_secret('github_oauth_client_id', cfg.github_oauth_client_id)
        if cfg.github_oauth_client_secret:
            vault.set_secret('github_oauth_client_secret', cfg.github_oauth_client_secret)
        if cfg.database_url:
            vault.set_secret('database_url', cfg.database_url)
        if cfg.customer_database_url:
            vault.set_secret('customer_database_url', cfg.customer_database_url)
        if cfg.worker_database_url:
            vault.set_secret('worker_database_url', cfg.worker_database_url)
        if cfg.app_id:
            vault.set_secret('github_app_id', cfg.app_id)
        if hasattr(cfg, 'private_key_path') and cfg.private_key_path:
            try:
                key_text = cfg.private_key()
                vault.set_secret('github_private_key', key_text)
            except Exception:
                pass
        return vault
