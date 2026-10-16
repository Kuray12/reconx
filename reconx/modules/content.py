"""Content discovery with ffuf, with soft-404 suppression.

Two-layer false-positive control:

  1. ffuf's own `-ac` auto-calibration, which learns the server's wildcard
     response and filters matching results as it runs.
  2. A verification pass: each surviving hit is fetched once, and its body
     size + hash are compared against the other results. Anything sharing a
     signature with many other paths is a soft-404 and is dropped.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import requests

from reconx.core import console
from reconx.core.fp_filter import (
    SOFT_404_MARKERS,
    FilterOutcome,
    collect,
    filter_results,
)
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, have, run
from reconx.core.wordlists import default_wordlist

NAME = "Content Discovery"

_MATCH_CODES = "200,204,301,302,307,401,403,405,500"

_SPEED = {
    "1": {"threads": "20", "rate": "50"},
    "2": {"threads": "40", "rate": "120"},
    "3": {"threads": "80", "rate": "300"},
}


def run_ffuf(
    live_hosts: list[str],
    report: ScanReport,
    speed: str = "3",
    wordlist: str | None = None,
    extensions: str = "php,html,js,txt,json,bak,zip",
    silent: bool = False,
) -> list[str]:
    """Bruteforce directories/files, then filter soft-404 noise."""
    if not live_hosts:
        console.fail("Tidak ada live host -> ffuf dilewati")
        return []

    if not have("ffuf"):
        console.fail("ffuf tidak ditemukan di PATH -> content discovery dilewati")
        report.record_tool("ffuf", "tidak terpasang", 0)
        report.errors.append("ffuf tidak terpasang -> content discovery dilewati")
        return []

    wl = Path(wordlist) if wordlist else default_wordlist()
    if wl is None or not wl.exists():
        console.fail("Tidak ada wordlist. Jalankan install.sh atau taruh file di wordlists/")
        report.record_tool("ffuf", "wordlist tidak ada", 0)
        report.errors.append("wordlist tidak ditemukan -> content discovery dilewati")
        return []

    console.info(f"Menjalankan ffuf dengan wordlist {wl.name} (auto-calibrate + verifikasi)...")
    preset = _SPEED.get(speed, _SPEED["3"])
    raw_hits: list[dict] = []

    for host in live_hosts[:15]:
        url = host if "://" in host else f"https://{host}"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ffuf.json"
            res = run(
                "ffuf",
                [
                    "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", str(wl),
                    "-mc", _MATCH_CODES,
                    "-e", extensions,
                    "-t", preset["threads"],
                    "-rate", preset["rate"],
                    "-ac",              # ffuf auto-calibration: drops wildcards
                    "-of", "json",
                    "-o", str(out),
                    "-s",
                ],
                timeout=1800,
            )
            if res.missing:
                break
            raw_hits.extend(_read_json(out, url))

    if not raw_hits:
        console.fail("ffuf tidak menemukan path tambahan")
        report.content_findings = []
        report.record_tool("ffuf", "selesai", 0)
        return []

    # Verification pass: fetch each hit once and hash the body.
    verified = _verify(raw_hits)
    outcome = filter_results(verified)

    findings = dedupe([f"[{r.status}] {r.url} ({r.length} bytes)" for r in outcome.kept])
    report.content_findings = findings
    report.record_tool("ffuf", "selesai", len(findings))

    if outcome.dropped:
        console.plain(
            f"      [dim]{len(outcome.dropped)} hasil dibuang sebagai false positive "
            "(soft-404 / halaman template)[/]"
        )

    if findings:
        console.ok(f"ffuf menemukan {len(findings)} path menarik")
        for item in findings[:25]:
            console.plain(f"      [dim]{item}[/]")
    else:
        console.fail("Semua hasil ffuf terindikasi soft-404 -> tidak ada temuan")
    return findings


def _read_json(json_path: Path, base: str) -> list[dict]:
    """Read ffuf's JSON results into plain dicts."""
    if not json_path.exists():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    hits: list[dict] = []
    for item in data.get("results", []):
        hits.append(
            {
                "url": item.get("url") or f"{base}/{item.get('input', {}).get('FUZZ', '')}",
                "status": int(item.get("status") or 0),
                "length": int(item.get("length") or 0),
                "redirect": item.get("redirectlocation") or "",
            }
        )
    return hits


def _verify(hits: list[dict]) -> list:
    """Fetch each hit once to capture body length + content hash."""
    session = requests.Session()
    session.headers.update({"User-Agent": "ReconX/1.0"})
    results = []

    for hit in hits:
        body = ""
        try:
            resp = session.get(hit["url"], timeout=10, verify=False, allow_redirects=True)
            # Only read bodies that are small enough to hash cheaply.
            if len(resp.content) <= 500_000:
                body = resp.text
            status = resp.status_code
            length = len(resp.content)
            redirect = resp.url if resp.history else hit.get("redirect", "")
        except requests.RequestException:
            status = hit["status"]
            length = hit["length"]
            redirect = hit.get("redirect", "")

        results.append(collect(hit["url"], status, length, body, redirect))

    return results
