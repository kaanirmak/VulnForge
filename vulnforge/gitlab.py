"""GitLab integration adapter supporting webhooks, OAuth, Merge Requests, and Pipeline statuses."""
import hmac
import json
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode


GITLAB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITLAB_PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitLabAdapter:
    """Adapter for GitLab v4 API, webhooks, and Merge Request integrations."""

    def __init__(
        self,
        gitlab_url: str = "https://gitlab.com",
        webhook_secret: Optional[str] = None,
        oauth_client_id: Optional[str] = None,
        oauth_client_secret: Optional[str] = None,
    ):
        self.gitlab_url = gitlab_url.rstrip("/")
        self.webhook_secret = webhook_secret
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret

    def verify_webhook_token(self, token_header: Optional[str]) -> bool:
        """Verify the X-GitLab-Token secret header against configured secret."""
        if not self.webhook_secret:
            return False
        if not token_header or not isinstance(token_header, str):
            return False
        return hmac.compare_digest(token_header.strip(), self.webhook_secret.strip())

    def parse_webhook_event(
        self,
        event_header: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Normalize GitLab webhook events into VulnForge internal job format."""
        if not isinstance(payload, dict):
            raise ValueError("Invalid payload format")

        project = payload.get("project") or {}
        repo_path = project.get("path_with_namespace") or ""
        default_branch = project.get("default_branch") or "main"

        if not repo_path or not GITLAB_PROJECT_RE.fullmatch(repo_path):
            raise ValueError("Missing or invalid project path")

        # 1. Push Event
        if event_header in ("Push Hook", "Tag Push Hook"):
            ref = payload.get("ref", "")
            before = payload.get("before", "0" * 40)
            after = payload.get("after", "0" * 40)
            commits = [c.get("id") for c in payload.get("commits", []) if isinstance(c, dict) and c.get("id")]
            is_deleted = after == "0" * 40

            return {
                "provider": "gitlab",
                "event": "push",
                "repo": repo_path,
                "default_branch": default_branch,
                "ref": ref,
                "before": before,
                "after": after,
                "commits": commits,
                "deleted": is_deleted,
                "forced": False,  # GitLab does not provide explicit forced flag in push hook
            }

        # 2. Merge Request Event
        elif event_header == "Merge Request Hook":
            attrs = payload.get("object_attributes") or {}
            action = attrs.get("action")
            mr_iid = attrs.get("iid")
            sha = attrs.get("last_commit", {}).get("id")
            base_sha = attrs.get("target_branch")

            if not mr_iid or not sha or not GITLAB_SHA_RE.fullmatch(sha):
                raise ValueError("Invalid merge request payload")

            return {
                "provider": "gitlab",
                "event": "merge_request",
                "action": action,
                "repo": repo_path,
                "mr_iid": mr_iid,
                "sha": sha,
                "target_branch": base_sha,
            }

        # 3. Pipeline Event
        elif event_header == "Pipeline Hook":
            attrs = payload.get("object_attributes") or {}
            pipeline_id = attrs.get("id")
            status = attrs.get("status")
            sha = attrs.get("sha")

            return {
                "provider": "gitlab",
                "event": "pipeline",
                "repo": repo_path,
                "pipeline_id": pipeline_id,
                "status": status,
                "sha": sha,
            }

        else:
            raise ValueError(f"Unsupported GitLab event: {event_header}")

    def build_oauth_authorize_url(
        self,
        redirect_uri: str,
        state: str,
        scope: str = "read_user api",
    ) -> str:
        """Construct the GitLab OAuth authorize URL."""
        if not self.oauth_client_id:
            raise ValueError("GitLab OAuth client ID is not configured")

        params = {
            "client_id": self.oauth_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "scope": scope,
        }
        return f"{self.gitlab_url}/oauth/authorize?{urlencode(params)}"

    def format_mr_vulnerability_note(self, findings: list[dict]) -> str:
        """Format vulnerability findings into a GitLab MR markdown comment."""
        if not findings:
            return "### 🛡️ VulnForge Security Scan\n\nNo vulnerabilities detected in this Merge Request. ✅"

        lines = [
            "### 🛡️ VulnForge Security Findings Detected\n",
            f"**{len(findings)}** security issue(s) identified in dependency changes:\n",
            "| Severity | Package | Advisory | Recommendation |",
            "|---|---|---|---|",
        ]
        for f in findings:
            sev = f.get("severity", "unknown").upper()
            pkg = f.get("package", "unknown")
            adv = f.get("advisory_id", "-")
            rec = f.get("recommended_version", "upgrade available")
            lines.append(f"| **{sev}** | `{pkg}` | {adv} | `{rec}` |")

        lines.append("\n*Scan verified by VulnForge policy engine.*")
        return "\n".join(lines)
