"""Enterprise compliance, data residency, customer-managed encryption keys (BYOK), and audit exports."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DataRegion(str, Enum):
    EU_WEST = "eu-west-1"         # Frankfurt / Ireland
    US_EAST = "us-east-1"         # N. Virginia
    APAC_SINGAPORE = "ap-southeast-1"
    LOCAL_ONPREM = "local-onprem"


class DataResidencyViolationError(Exception):
    """Raised when an operation violates an organization's pinned data residency region."""
    def __init__(self, org_id: str, requested_region: str, allowed_region: str):
        msg = f"Data residency violation for org '{org_id}': requested region '{requested_region}' does not match pinned region '{allowed_region}'."
        super().__init__(msg)
        self.org_id = org_id
        self.requested_region = requested_region
        self.allowed_region = allowed_region


class KeyStateError(Exception):
    """Raised when an enterprise encryption key is revoked, disabled, or inaccessible."""
    def __init__(self, key_id: str, state: str):
        super().__init__(f"Enterprise KMS key '{key_id}' is not in active state (state: {state}).")
        self.key_id = key_id
        self.state = state


@dataclass
class CustomerKeyConfig:
    key_id: str
    kms_uri: str
    region: DataRegion
    state: str = "active"  # active, disabled, revoked
    key_created_at: float = field(default_factory=time.time)
    last_rotated_at: float = field(default_factory=time.time)
    rotation_interval_days: int = 90
    _raw_secret_key: bytes = field(default_factory=lambda: os.urandom(32))

    def rotate_key(self) -> None:
        self._raw_secret_key = os.urandom(32)
        self.last_rotated_at = time.time()


@dataclass
class TenantComplianceProfile:
    org_id: str
    pinned_region: DataRegion
    key_config: Optional[CustomerKeyConfig] = None
    soc2_compliant: bool = True
    iso27001_compliant: bool = True
    gdpr_dpa_signed: bool = True
    data_retention_days: int = 365
    audit_trail_immutable: bool = True


class EnterpriseComplianceManager:
    """Manages tenant data residency, customer-managed keys (BYOK), envelope encryption, and compliance bundles."""

    def __init__(self):
        self._profiles: dict[str, TenantComplianceProfile] = {}
        self._audit_records: dict[str, list[dict[str, Any]]] = {}

    def configure_tenant(
        self,
        org_id: str,
        region: DataRegion,
        kms_uri: str | None = None,
        retention_days: int = 365,
    ) -> TenantComplianceProfile:
        key_cfg = None
        if kms_uri:
            key_id = f"key-{hashlib.sha256(kms_uri.encode()).hexdigest()[:12]}"
            key_cfg = CustomerKeyConfig(
                key_id=key_id,
                kms_uri=kms_uri,
                region=region,
            )

        profile = TenantComplianceProfile(
            org_id=org_id,
            pinned_region=region,
            key_config=key_cfg,
            data_retention_days=retention_days,
        )
        self._profiles[org_id] = profile
        if org_id not in self._audit_records:
            self._audit_records[org_id] = []
        return profile

    def get_profile(self, org_id: str) -> TenantComplianceProfile:
        if org_id not in self._profiles:
            # Default EU-West with standard compliance
            self.configure_tenant(org_id, DataRegion.EU_WEST)
        return self._profiles[org_id]

    def validate_operation_region(self, org_id: str, target_region: str | DataRegion) -> None:
        """Verifies that the target execution/storage region matches tenant's pinned residency."""
        profile = self.get_profile(org_id)
        target_str = target_region.value if isinstance(target_region, DataRegion) else str(target_region)
        pinned_str = profile.pinned_region.value

        if target_str != pinned_str:
            raise DataResidencyViolationError(
                org_id=org_id,
                requested_region=target_str,
                allowed_region=pinned_str,
            )

    def encrypt_tenant_payload(self, org_id: str, plaintext: bytes | str) -> dict[str, Any]:
        """Encrypts data using tenant-specific BYOK envelope key."""
        profile = self.get_profile(org_id)
        key_cfg = profile.key_config
        if not key_cfg:
            raise ValueError(f"No BYOK customer key configured for organization '{org_id}'.")
        if key_cfg.state != "active":
            raise KeyStateError(key_cfg.key_id, key_cfg.state)

        data_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext

        # Deterministic envelope derivation using HMAC-SHA256
        ephemeral_iv = os.urandom(16)
        mac = hmac.new(key_cfg._raw_secret_key, ephemeral_iv + data_bytes, hashlib.sha256).digest()
        
        # XOR keystream simulation for demonstration
        keystream = hashlib.sha256(key_cfg._raw_secret_key + ephemeral_iv).digest()
        cipher_bytes = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(data_bytes))

        return {
            "key_id": key_cfg.key_id,
            "kms_uri": key_cfg.kms_uri,
            "region": key_cfg.region.value,
            "iv": base64.b64encode(ephemeral_iv).decode("ascii"),
            "ciphertext": base64.b64encode(cipher_bytes).decode("ascii"),
            "hmac": base64.b64encode(mac).decode("ascii"),
            "encrypted_at": time.time(),
        }

    def decrypt_tenant_payload(self, org_id: str, envelope: dict[str, Any]) -> bytes:
        """Decrypts envelope payload and verifies cryptographic integrity."""
        profile = self.get_profile(org_id)
        key_cfg = profile.key_config
        if not key_cfg:
            raise ValueError(f"No BYOK customer key configured for organization '{org_id}'.")
        if key_cfg.state != "active":
            raise KeyStateError(key_cfg.key_id, key_cfg.state)

        if envelope["key_id"] != key_cfg.key_id:
            raise ValueError(f"Key mismatch: payload encrypted with '{envelope['key_id']}', current is '{key_cfg.key_id}'.")

        ephemeral_iv = base64.b64decode(envelope["iv"])
        cipher_bytes = base64.b64decode(envelope["ciphertext"])
        expected_mac = base64.b64decode(envelope["hmac"])

        keystream = hashlib.sha256(key_cfg._raw_secret_key + ephemeral_iv).digest()
        data_bytes = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(cipher_bytes))

        # Check HMAC
        actual_mac = hmac.new(key_cfg._raw_secret_key, ephemeral_iv + data_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_mac, expected_mac):
            raise ValueError("Cryptographic verification failed: HMAC tag mismatch.")

        return data_bytes

    def record_compliance_audit(self, org_id: str, actor: str, action: str, details: dict[str, Any]) -> dict[str, Any]:
        """Appends a cryptographically chained audit event for the tenant."""
        records = self._audit_records.setdefault(org_id, [])
        prev_hash = records[-1]["record_hash"] if records else "GENESIS_0000000000000000000000000000000000000000000000000000000000000000"

        event = {
            "seq": len(records) + 1,
            "org_id": org_id,
            "actor": actor,
            "action": action,
            "details": details,
            "timestamp": time.time(),
            "prev_hash": prev_hash,
        }
        event_str = json.dumps(event, sort_keys=True)
        event["record_hash"] = hashlib.sha256(event_str.encode()).hexdigest()
        records.append(event)
        return event

    def generate_compliance_bundle(self, org_id: str) -> dict[str, Any]:
        """Generates a complete SOC 2 / ISO 27001 / GDPR audit export package."""
        profile = self.get_profile(org_id)
        audit_events = self._audit_records.get(org_id, [])

        key_summary = None
        if profile.key_config:
            key_summary = {
                "key_id": profile.key_config.key_id,
                "kms_uri": profile.key_config.kms_uri,
                "region": profile.key_config.region.value,
                "state": profile.key_config.state,
                "rotation_days": profile.key_config.rotation_interval_days,
                "last_rotated_at": profile.key_config.last_rotated_at,
            }

        bundle_payload = {
            "compliance_standards": {
                "soc2_type_ii": profile.soc2_compliant,
                "iso_27001": profile.iso27001_compliant,
                "gdpr_dpa_active": profile.gdpr_dpa_signed,
            },
            "data_governance": {
                "org_id": org_id,
                "data_region": profile.pinned_region.value,
                "retention_period_days": profile.data_retention_days,
                "immutable_audit_logging": profile.audit_trail_immutable,
            },
            "cryptographic_byok": key_summary,
            "subprocessor_manifest": [
                {"name": "AWS / Equinix Cloud Infrastructure", "purpose": "Compute and network hosting", "region": profile.pinned_region.value},
                {"name": "GitHub Enterprise API", "purpose": "SCM connector and webhook ingestion", "region": "global"},
            ],
            "audit_ledger": {
                "total_events": len(audit_events),
                "chain_head_hash": audit_events[-1]["record_hash"] if audit_events else None,
                "events": audit_events,
            },
            "exported_at": time.time(),
        }

        bundle_bytes = json.dumps(bundle_payload, sort_keys=True).encode()
        bundle_payload["bundle_sha256"] = hashlib.sha256(bundle_bytes).hexdigest()
        return bundle_payload
