"""Tests for enterprise compliance, data residency, BYOK encryption, and audit bundles."""
import pytest
from vulnforge.compliance import (
    DataRegion,
    DataResidencyViolationError,
    EnterpriseComplianceManager,
    KeyStateError,
)


def test_data_residency_enforcement():
    mgr = EnterpriseComplianceManager()
    org_id = "org_eu_bank"

    # Configure tenant pinned to EU_WEST
    mgr.configure_tenant(org_id, region=DataRegion.EU_WEST)

    # Allowed in EU_WEST
    mgr.validate_operation_region(org_id, DataRegion.EU_WEST)
    mgr.validate_operation_region(org_id, "eu-west-1")

    # Mismatched region US_EAST or APAC raises DataResidencyViolationError
    with pytest.raises(DataResidencyViolationError) as exc_us:
        mgr.validate_operation_region(org_id, DataRegion.US_EAST)
    assert exc_us.value.requested_region == "us-east-1"
    assert exc_us.value.allowed_region == "eu-west-1"

    with pytest.raises(DataResidencyViolationError):
        mgr.validate_operation_region(org_id, "ap-southeast-1")


def test_byok_encryption_roundtrip_and_tampering():
    mgr = EnterpriseComplianceManager()
    org_id = "org_byok_healthcare"

    kms_uri = "kms://eu-west-1/vulnforge-hcls-secret-key-1"
    mgr.configure_tenant(org_id, region=DataRegion.EU_WEST, kms_uri=kms_uri)

    plaintext = "SECRET_REPORT_CVE-2024-9999_AFFECTS_PRODUCTION_CORE"
    envelope = mgr.encrypt_tenant_payload(org_id, plaintext)

    assert envelope["kms_uri"] == kms_uri
    assert envelope["region"] == "eu-west-1"
    assert "ciphertext" in envelope
    assert "hmac" in envelope

    # Successful decryption
    decrypted = mgr.decrypt_tenant_payload(org_id, envelope)
    assert decrypted.decode("utf-8") == plaintext

    # Tampering test: tamper with ciphertext
    tampered_envelope = dict(envelope)
    tampered_envelope["ciphertext"] = tampered_envelope["ciphertext"][:-2] + "AA"
    with pytest.raises(ValueError, match="Cryptographic verification failed"):
        mgr.decrypt_tenant_payload(org_id, tampered_envelope)


def test_byok_key_revocation_and_state_check():
    mgr = EnterpriseComplianceManager()
    org_id = "org_revocation_test"

    kms_uri = "kms://eu-west-1/key-99"
    profile = mgr.configure_tenant(org_id, region=DataRegion.EU_WEST, kms_uri=kms_uri)

    # Normal encryption works
    mgr.encrypt_tenant_payload(org_id, b"sensitive-data")

    # Disable key
    profile.key_config.state = "revoked"

    with pytest.raises(KeyStateError) as exc:
        mgr.encrypt_tenant_payload(org_id, b"sensitive-data")
    assert exc.value.state == "revoked"


def test_immutable_audit_ledger_and_compliance_bundle():
    mgr = EnterpriseComplianceManager()
    org_id = "org_fintech_corp"

    kms_uri = "kms://eu-west-1/fintech-primary-key"
    mgr.configure_tenant(org_id, region=DataRegion.EU_WEST, kms_uri=kms_uri, retention_days=730)

    # Record some compliance events
    e1 = mgr.record_compliance_audit(org_id, actor="admin@fintech.com", action="role_change", details={"target_user": "bob", "new_role": "maintainer"})
    e2 = mgr.record_compliance_audit(org_id, actor="ci_runner", action="patch_deploy", details={"plan_id": "plan-123", "target_sha": "abc1234"})

    assert e1["seq"] == 1
    assert e2["seq"] == 2
    assert e2["prev_hash"] == e1["record_hash"]

    # Generate full compliance export bundle
    bundle = mgr.generate_compliance_bundle(org_id)

    assert bundle["compliance_standards"]["soc2_type_ii"] is True
    assert bundle["compliance_standards"]["iso_27001"] is True
    assert bundle["compliance_standards"]["gdpr_dpa_active"] is True
    assert bundle["data_governance"]["data_region"] == "eu-west-1"
    assert bundle["data_governance"]["retention_period_days"] == 730
    assert bundle["cryptographic_byok"]["kms_uri"] == kms_uri
    assert bundle["audit_ledger"]["total_events"] == 2
    assert bundle["audit_ledger"]["chain_head_hash"] == e2["record_hash"]
    assert "bundle_sha256" in bundle

