"""Notification dispatcher.

Design decision (important): this tool only ever delivers to the operator's
own Telegram chat/channel or mailbox, both configured in .env. There is no
code path that lets a scan result be pushed to an arbitrary third party.
"""

from __future__ import annotations

from reconx.core import console
from reconx.core.config import Config
from reconx.core.report import ScanReport
from reconx.notify.email import send_report_email
from reconx.notify.telegram import send_telegram_message


def build_summary(report: ScanReport, limit: int = 25) -> str:
    """Compact, CLI-and-Telegram friendly summary of a scan."""
    lines: list[str] = []
    lines.append(f"ReconX report - {report.target}")
    lines.append(f"Operator : {report.operator}")
    lines.append(f"Duration : {report.duration_seconds:.0f}s")
    lines.append("")
    lines.append("Ringkasan:")
    for label, count in report.summary_counts().items():
        lines.append(f"  - {label}: {count}")

    if report.nuclei_findings:
        lines.append("")
        lines.append(f"Nuclei findings (top {limit}):")
        for item in report.nuclei_findings[:limit]:
            lines.append(f"  {item}")

    if report.nmap_findings:
        lines.append("")
        lines.append(f"Nmap open ports (top {limit}):")
        for item in report.nmap_findings[:limit]:
            lines.append(f"  {item}")

    if report.xray_findings:
        lines.append("")
        lines.append(f"Xray findings (top {limit}):")
        for item in report.xray_findings[:limit]:
            lines.append(f"  {item}")

    if report.zone_transfer:
        lines.append("")
        lines.append("ZONE TRANSFER BERHASIL (temuan serius):")
        for item in report.zone_transfer[:limit]:
            lines.append(f"  {item}")

    if report.content_findings:
        lines.append("")
        lines.append(f"Content menarik (top {limit}):")
        for item in report.content_findings[:limit]:
            lines.append(f"  {item}")

    if report.parameter_findings:
        lines.append("")
        lines.append(f"Parameter tersembunyi (top {limit}):")
        for item in report.parameter_findings[:limit]:
            lines.append(f"  {item}")

    if report.sqli_findings:
        lines.append("")
        lines.append(f"SQL Injection (top {limit}):")
        for item in report.sqli_findings[:limit]:
            lines.append(f"  {item}")

    if report.xss_findings:
        lines.append("")
        lines.append(f"XSS (top {limit}):")
        for item in report.xss_findings[:limit]:
            lines.append(f"  {item}")

    if report.cloud_findings:
        lines.append("")
        lines.append(f"Cloud storage (top {limit}):")
        for item in report.cloud_findings[:limit]:
            lines.append(f"  {item}")

    if report.takeover_candidates:
        lines.append("")
        lines.append("Subdomain takeover candidates:")
        for item in report.takeover_candidates[:limit]:
            lines.append(f"  {item}")

    if report.sensitive_hits:
        lines.append("")
        lines.append(f"Potensi data sensitif (top {limit}):")
        for item in report.sensitive_hits[:limit]:
            lines.append(f"  {item}")

    if report.errors:
        lines.append("")
        lines.append("Catatan:")
        for item in report.errors[:limit]:
            lines.append(f"  {item}")

    return "\n".join(lines)


def dispatch(report: ScanReport, config: Config, channels: list[str] | None = None) -> None:
    """Send the report to the requested channels, if configured.

    channels: subset of {"telegram", "email"}. None means "all configured".
    """
    channels = channels or ["telegram", "email"]
    body = build_summary(report)

    if "telegram" in channels:
        if config.telegram_enabled:
            send_telegram_message(config, f"```\n{body}\n```")
        else:
            console.warn(
                "Telegram belum dikonfigurasi (opsional) -> laporan tetap "
                "tersimpan di folder output/"
            )

    if "email" in channels:
        if config.email_enabled:
            send_report_email(
                config,
                subject=f"[ReconX] {report.target} - scan report",
                body=body,
            )
        else:
            console.warn(
                "Email belum dikonfigurasi (opsional) -> laporan tetap "
                "tersimpan di folder output/"
            )
