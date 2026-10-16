"""SMTP report delivery, optionally with a file attachment."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from reconx.core import console
from reconx.core.config import Config


def send_report_email(
    config: Config,
    subject: str,
    body: str,
    attachment: Path | None = None,
) -> bool:
    """Send the report via SMTP. Never raises; returns True on success."""
    if not config.email_enabled:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.email_from
    msg["To"] = config.email_to
    msg.set_content(body)

    if attachment and attachment.exists():
        msg.add_attachment(
            attachment.read_bytes(),
            maintype="application",
            subtype=attachment.suffix.lstrip(".") or "octet-stream",
            filename=attachment.name,
        )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as server:
            server.starttls(context=context)
            if config.smtp_user:
                server.login(config.smtp_user, config.smtp_password)
            server.send_message(msg)
        console.ok(f"Laporan dikirim ke email {config.email_to}.")
        return True
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        console.fail(f"Gagal kirim email: {exc}")
        return False
