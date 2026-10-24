"""Configuration is loaded at runtime, not at module import time."""
from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class Config:
    webhook_secret: str = ""
    admin_token: str = ""
    app_id: str = ""
    private_key_path: str = ""
    database_path: str = "./data/vulnforge.db"
    enable_auto_pr: bool = False
    enable_kev: bool = False
    scan_interval_seconds: int = 3600
    github_api_url: str = "https://api.github.com"
    osv_api_url: str = "https://api.osv.dev"
    max_file_bytes: int = 300_000

    @classmethod
    def from_env(cls):
        return cls(
            webhook_secret=os.getenv("WEBHOOK_SECRET", ""),
            admin_token=os.getenv("ADMIN_TOKEN", ""),
            app_id=os.getenv("GITHUB_APP_ID", ""),
            private_key_path=os.getenv("GITHUB_PRIVATE_KEY_PATH", ""),
            database_path=os.getenv("DATABASE_PATH", "./data/vulnforge.db"),
            enable_auto_pr=os.getenv("ENABLE_AUTO_PR", "false").lower() == "true",
            enable_kev=os.getenv("ENABLE_KEV", "false").lower() == "true",
            scan_interval_seconds=max(60, int(os.getenv("SCAN_INTERVAL_SECONDS", "3600"))),
            github_api_url=os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
            osv_api_url=os.getenv("OSV_API_URL", "https://api.osv.dev").rstrip("/"),
        )

    def private_key(self) -> str:
        if not self.private_key_path:
            raise ValueError("GITHUB_PRIVATE_KEY_PATH is not configured")
        return Path(self.private_key_path).read_text(encoding="utf-8")
