"""XSS scanning with dalfox."""

from __future__ import annotations

import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, have, run

NAME = "XSS Scan"

_SPEED = {"1": "10", "2": "30", "3": "60"}


def run_dalfox(
    urls: list[str],
    report: ScanReport,
    speed: str = "3",
    silent: bool = False,
) -> list[str]:
    """Scan parameterized URLs for reflected XSS with dalfox. Deep Scan only."""
    targets = dedupe([u for u in urls if "?" in u])[:30]
    if not targets:
        console.info("Tidak ada URL berparameter -> dalfox dilewati")
        return []

    if not have("dalfox"):
        console.fail("dalfox tidak ditemukan di PATH -> XSS scan dilewati")
        report.record_tool("dalfox", "tidak terpasang", 0)
        report.errors.append("dalfox tidak terpasang -> XSS scan dilewati")
        return []

    console.info(f"Menjalankan dalfox pada {len(targets)} URL...")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "urls.txt"
        out = Path(tmp) / "dalfox.txt"
        src.write_text("\n".join(targets), encoding="utf-8")

        res = run(
            "dalfox",
            [
                "file", str(src),
                "--silence",
                "--no-color",
                "--worker", _SPEED.get(speed, "30"),
                "--output", str(out),
                "--only-poc", "r",
            ],
            timeout=2400,
        )

        if res.missing:
            return []

        findings = dedupe(_scan_results(out) or _parse(res.lines))

    report.xss_findings = findings
    report.record_tool("dalfox", "selesai", len(findings))

    if findings:
        console.warn(f"dalfox menemukan {len(findings)} indikasi XSS")
        for item in findings[:25]:
            console.warn(item)
    else:
        console.ok("dalfox tidak menemukan XSS")
    return findings


def _scan_results(path: Path) -> list[str]:
    """dalfox is usually run with --output; read it plainly."""
    if not path.exists():
        return []
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _parse(lines: list[str]) -> list[str]:
    """Fallback parser for dalfox console output."""
    hits: list[str] = []
    for line in lines:
        low = line.lower()
        if "[v]" in low or "poc" in low or "verified" in low:
            hits.append(line.strip())
    return hits
