"""Enterprise OIDC / SAML SSO integration and Just-In-Time (JIT) provisioning."""
from dataclasses import dataclass, field
import json
import re
import time
from typing import Any, Dict, List, Optional
import uuid

import jwt


ROLES = ("org_admin", "maintainer", "analyst", "viewer")


@dataclass
class SSOConfig:
    issuer: str
    client_id: str
    client_secret: Optional[str] = None
    default_role: str = "viewer"
    group_role_mapping: Dict[str, str] = field(default_factory=dict)
    enforce_sso: bool = False


class EnterpriseSSO:
    """Manages enterprise OIDC single-sign-on and role-based JIT provisioning."""

    def __init__(self, config: SSOConfig, signing_key_or_jwks: Optional[Any] = None):
        self.config = config
        self.signing_key = signing_key_or_jwks

    def decode_and_validate_token(
        self,
        token: str,
        *,
        verify_signature: bool = True,
        nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate and decode OpenID Connect JWT token."""
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a non-empty string")

        options = {
            "verify_signature": verify_signature,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True,
        }

        # If verification is enabled, signing key must be provided
        key = self.signing_key if verify_signature else ""

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256", "HS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer,
                options=options,
            )
        except jwt.PyJWTError as exc:
            raise ValueError(f"Invalid SSO ID token: {str(exc)}") from exc

        if nonce and claims.get("nonce") != nonce:
            raise ValueError("Invalid SSO nonce")

        # Required OIDC claims
        if not claims.get("sub"):
            raise ValueError("Missing 'sub' subject claim in ID token")

        return claims

    def resolve_role(self, claims: Dict[str, Any]) -> str:
        """Map IdP groups or claims to VulnForge internal roles."""
        user_groups = claims.get("groups") or claims.get("roles") or []
        if isinstance(user_groups, str):
            user_groups = [user_groups]

        # Check explicit group-to-role mappings in priority order
        for grp in user_groups:
            if grp in self.config.group_role_mapping:
                mapped_role = self.config.group_role_mapping[grp]
                if mapped_role in ROLES:
                    return mapped_role

        return self.config.default_role if self.config.default_role in ROLES else "viewer"

    def jit_provision_user(
        self,
        store: Any,
        organization_id: str,
        claims: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Just-In-Time (JIT) provision or update user and membership in the organization."""
        sub = str(claims["sub"])
        email = claims.get("email") or f"{sub}@sso.local"
        name = claims.get("name") or claims.get("preferred_username") or email.split("@")[0]
        # Clean login name for alphanumeric/hyphen constraints
        login = re.sub(r"[^A-Za-z0-9-]", "-", name)[:38] or f"sso-{sub[:8]}"

        role = self.resolve_role(claims)
        now = time.time()

        numeric_id = (abs(hash(sub)) % 1000000000) or 1
        with store.transaction(), store.conn() as c:
            # 1. Find or create user
            user = c.execute("SELECT * FROM users WHERE github_id=?", (numeric_id,)).fetchone()
            if not user:
                # Generate unique synthetic user for SSO
                user_id = uuid.uuid4().hex
                c.execute(
                    "INSERT INTO users (id, github_id, login, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, numeric_id, login, now, now)
                )
            else:
                user_id = user["id"]

            # 2. Update membership and role
            existing_m = c.execute(
                "SELECT role FROM memberships WHERE organization_id=? AND user_id=?",
                (organization_id, user_id)
            ).fetchone()

            if not existing_m:
                c.execute(
                    "INSERT INTO memberships (organization_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (organization_id, user_id, role, now, now)
                )
                action = "sso_jit_created"
            else:
                if existing_m["role"] != role:
                    c.execute(
                        "UPDATE memberships SET role=?, updated_at=? WHERE organization_id=? AND user_id=?",
                        (role, now, organization_id, user_id)
                    )
                    action = "sso_role_synced"
                else:
                    action = "sso_login_verified"

            store.audit_event(
                repo=f"organization:{organization_id}",
                finding_id=None,
                actor=f"sso:{user_id}",
                action=action,
                details={"user_id": user_id, "role": role, "email": email, "sub": sub},
                organization_id=organization_id
            )

        return {
            "user_id": user_id,
            "organization_id": organization_id,
            "role": role,
            "email": email,
            "login": login,
            "action": action
        }

    def check_sso_enforcement(self, login_method: str) -> bool:
        """Check if non-SSO login is allowed."""
        if self.config.enforce_sso and login_method != "enterprise_sso":
            return False
        return True
