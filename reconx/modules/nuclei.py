"""Vulnerability scanning with nuclei."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "Nuclei Vulnerability Scan"

_SPEED_PRESETS = {
    "1": {"concurrency": "10", "rate": "50"},
    "2": {"concurrency": "25", "rate": "150"},
    "3": {"concurrency": "50", "rate": "300"},
}


def run_nuclei(
    hosts: list[str],
    report: ScanReport,
    speed: str = "2",
    severity: str = "low,medium,high,critical",
    silent: bool = False,
) -> list[str]:
    """Run nuclei templates against live hosts."""
    if not hosts:
        console.fail("Tidak ada host aktif -> nuclei dilewati")
        return []

    console.info("Menjalankan Nuclei untuk subdomain yang aktif...")
    preset = _SPEED_PRESETS.get(speed, _SPEED_PRESETS["2"])

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "hosts.txt"
        out = Path(tmp) / "nuclei.txt"
        src.write_text("\n".join(hosts), encoding="utf-8")

        args = [
            "-l", str(src),
            "-severity", severity,
            "-silent",
            "-no-color",
            "-concurrency", preset["concurrency"],
            "-rate-limit", preset["rate"],
            "-o", str(out),
        ]
        if shutil.which("nuclei-templates"):
            args += ["-update-templates"]

        res = run("nuclei", args, timeout=3600)
        if res.missing:
            report.record_tool("nuclei", "tidak terpasang", 0)
            return []
        findings = dedupe(load_lines(out) or res.lines)

    report.nuclei_findings = findings
    report.record_tool("nuclei", "selesai", len(findings))

    if findings:
        console.warn(f"Nuclei menemukan {len(findings)} temuan")
        for item in findings[:25]:
            console.warn(item)
    else:
        console.ok("Nuclei tidak menemukan kerentanan")
    return findings
