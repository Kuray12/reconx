"""Telegram delivery to the operator's own bot chat."""

from __future__ import annotations

import requests

from reconx.core import console
from reconx.core.config import Config

API = "https://api.telegram.org/bot{token}/sendMessage"
MAX_LEN = 4000


def _chunks(text: str, size: int = MAX_LEN):
    for start in range(0, len(text), size):
        yield text[start : start + size]


def send_telegram_message(config: Config, text: str, markdown: bool = True) -> bool:
    """Push a message to the configured chat. Never raises."""
    if not config.telegram_enabled:
        return False

    url = API.format(token=config.telegram_token)
    sent = True

    for part in _chunks(text):
        payload = {"chat_id": config.telegram_chat_id, "text": part}
        if markdown:
            payload["parse_mode"] = "Markdown"
        try:
            resp = requests.post(url, data=payload, timeout=20)
            if resp.status_code != 200:
                # Retry without markdown: unbalanced characters are the usual cause.
                payload.pop("parse_mode", None)
                resp = requests.post(url, data=payload, timeout=20)
            if resp.status_code != 200:
                sent = False
                console.fail(f"Telegram menolak pesan (HTTP {resp.status_code})")
        except requests.RequestException as exc:
            sent = False
            console.fail(f"Gagal kirim ke Telegram: {exc}")

    if sent:
        console.ok("Laporan dikirim ke Telegram.")
    return sent
