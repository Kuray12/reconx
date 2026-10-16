"""Configuration loading: .env file, authorization guard, operator identity."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# config.py lives in <root>/reconx/core/, so the project root is two levels up.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
OUTPUT_DIR = PROJECT_ROOT / "output"


@dataclass
class Config:
    """Runtime configuration assembled from environment variables."""

    operator: str = "unknown"

    telegram_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""
    email_to: str = ""

    @classmethod
    def load(cls) -> "Config":
        load_dotenv(ENV_FILE)
        return cls(
            operator=os.getenv("OPERATOR_NAME", "").strip() or "unknown",
            telegram_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
            smtp_host=os.getenv("SMTP_HOST", "").strip(),
            smtp_port=int(os.getenv("SMTP_PORT", "587") or 587),
            smtp_user=os.getenv("SMTP_USER", "").strip(),
            smtp_password=os.getenv("SMTP_PASSWORD", ""),
            email_from=os.getenv("EMAIL_FROM", "").strip(),
            email_to=os.getenv("EMAIL_TO", "").strip(),
        )

    # -- notification availability ------------------------------------------
    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_host and self.email_from and self.email_to)


class ScopeError(RuntimeError):
    """Raised when a target cannot be parsed into a usable hostname."""


def normalize_target(target: str) -> str:
    """Turn a URL or hostname into a bare lowercase hostname."""
    target = target.strip().lower()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix) :]
    target = target.split("/")[0].split("?")[0].split(":")[0]
    return target.rstrip(".")
