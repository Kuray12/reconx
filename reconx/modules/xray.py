"""Web vulnerability scanning with Xray (projectdiscovery).

Xray needs a running instance of its web UI / API server to be usable from the
command line. This module therefore targets the common `xray webscan` flow and
degrades gracefully when the binary or its config is absent.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "Xray Vulnerability Scan"

_SEVERITY = {
    "1": "low",
    "2": "medium",
    "3": "high",
}


def run_xray(
    targets: list[str],
    report: ScanReport,
    speed: str = "3",
    silent: bool = False,
) -> list[str]:
    """Run a xray webscan over the given target URLs.

    Kept to Deep Scan by the orchestrator because it is slow and needs config.
    """
    if not targets:
        console.fail("Tidak ada target -> xray dilewati")
        return []

    console.info("Menjalankan xray webscan...")
    with tempfile.TemporaryDirectory() as tmp:
        urls = Path(tmp) / "targets.json"
        out = Path(tmp) / "xray.json"

        # xray expects a JSON list of {"url": ...} objects.
        import json

        urls.write_text(
            json.dumps([{"url": t} for t in targets], ensure_ascii=False),
            encoding="utf-8",
        )

        res = run(
            "xray",
            [
                "webscan",
                "--json-output", str(out),
                "--url-file", str(urls),
                "--level", _SEVERITY.get(speed, "high"),
            ],
            timeout=3600,
        )

        if res.missing:
            report.record_tool("xray", "tidak terpasang", 0)
            report.errors.append(
                "xray tidak terpasang / tidak dikonfigurasi -> webscan dilewati"
            )
            return []

        findings = dedupe(load_lines(out) or _parse_stdout(res.lines))

    report.xray_findings = findings
    report.record_tool("xray", "selesai", len(findings))

    if findings:
        console.warn(f"xray menemukan {len(findings)} temuan")
        for item in findings[:25]:
            console.warn(item)
    else:
        console.ok("xray tidak menemukan kerentanan")
    return findings


def _parse_stdout(lines: list[str]) -> list[str]:
    """Best-effort extraction of vulnerability lines from xray's console output."""
    hits: list[str] = []
    for line in lines:
        low = line.lower()
        if any(tag in low for tag in ("vuln", "found", "[high]", "[medium]", "poc")):
            hits.append(line.strip())
    return hits
