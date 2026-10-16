"""Hidden-parameter discovery with arjun."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, have, run
from reconx.core.wordlists import default_wordlist

NAME = "Parameter Discovery"


def run_arjun(
    urls: list[str],
    report: ScanReport,
    speed: str = "3",
    silent: bool = False,
) -> list[str]:
    """Find hidden GET/POST parameters on interesting URLs.

    Input is the parameterized-URL set already gathered during crawling.
    """
    targets = dedupe([u for u in urls if "?" in u])[:20]
    if not targets:
        console.info("Tidak ada URL berparameter -> arjun dilewati")
        return []

    if not have("arjun"):
        console.fail("arjun tidak ditemukan di PATH -> parameter discovery dilewati")
        report.record_tool("arjun", "tidak terpasang", 0)
        report.errors.append("arjun tidak terpasang -> parameter discovery dilewati")
        return []

    console.info(f"Menjalankan arjun pada {len(targets)} URL...")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "urls.txt"
        out = Path(tmp) / "arjun.json"
        src.write_text("\n".join(targets), encoding="utf-8")

        res = run(
            "arjun",
            ["-i", str(src), "-oJ", str(out), "-t", "10", "-q"],
            timeout=1800,
        )

        if res.missing:
            return []

        findings = _parse(out, res.lines)

    findings = dedupe(findings)
    report.parameter_findings = findings
    report.record_tool("arjun", "selesai", len(findings))

    if findings:
        console.ok(f"arjun menemukan {len(findings)} parameter tersembunyi")
        for item in findings[:25]:
            console.plain(f"      [dim]{item}[/]")
    else:
        console.fail("arjun tidak menemukan parameter tambahan")
    return findings


def _parse(json_path: Path, stdout: list[str]) -> list[str]:
    """Pull 'url -> params' entries from arjun's JSON output."""
    hits: list[str] = []
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
            for url, params in data.items():
                if isinstance(params, list) and params:
                    hits.append(f"{url} -> {', '.join(params)}")
            return hits
        except (json.JSONDecodeError, OSError, AttributeError):
            pass
    return [line.strip() for line in stdout if "parameter" in line.lower()]
