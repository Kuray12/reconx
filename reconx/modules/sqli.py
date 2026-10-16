"""SQL injection scanning with sqlmap."""

from __future__ import annotations

import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, have, run

NAME = "SQL Injection Scan"

# Conservative defaults: detect only, never dump or take over the DB.
_RISK = {"1": "1", "2": "1", "3": "2"}
_LEVEL = {"1": "1", "2": "2", "3": "3"}


def run_sqlmap(
    urls: list[str],
    report: ScanReport,
    speed: str = "3",
    silent: bool = False,
) -> list[str]:
    """Test parameterized URLs for SQL injection.

    Runs sqlmap in detection mode (`--batch --smart`) so it stays non-intrusive
    and never prompts. Deep Scan only.
    """
    targets = dedupe([u for u in urls if "?" in u])[:15]
    if not targets:
        console.info("Tidak ada URL berparameter -> sqlmap dilewati")
        return []

    if not have("sqlmap"):
        console.fail("sqlmap tidak ditemukan di PATH -> SQLi scan dilewati")
        report.record_tool("sqlmap", "tidak terpasang", 0)
        report.errors.append("sqlmap tidak terpasang -> SQLi scan dilewati")
        return []

    console.info(f"Menjalankan sqlmap pada {len(targets)} URL (detection mode)...")
    findings: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "urls.txt"
        src.write_text("\n".join(targets), encoding="utf-8")

        res = run(
            "sqlmap",
            [
                "-m", str(src),
                "--batch", "--smart",
                "--level", _LEVEL.get(speed, "2"),
                "--risk", _RISK.get(speed, "1"),
                "--flush-session",
                "--output-dir", tmp,
            ],
            timeout=3600,
        )

        if res.missing:
            return []

        findings = _parse(res.lines)

    findings = dedupe(findings)
    report.sqli_findings = findings
    report.record_tool("sqlmap", "selesai", len(findings))

    if findings:
        console.warn(f"sqlmap menemukan {len(findings)} indikasi SQLi")
        for item in findings[:25]:
            console.warn(item)
    else:
        console.ok("sqlmap tidak menemukan indikasi SQL injection")
    return findings


def _parse(lines: list[str]) -> list[str]:
    """Extract injectable/parameter lines from sqlmap's console output."""
    hits: list[str] = []
    for line in lines:
        low = line.lower()
        if "is vulnerable" in low or "injectable" in low:
            hits.append(line.strip("[] "))
        elif "parameter" in low and "is vulnerable" in low:
            hits.append(line.strip("[] "))
    return hits
