"""URL discovery: waybackurls, gau and katana crawling."""

from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import urlparse

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "URL Crawling"

_SPEED_DEPTH = {"1": "2", "2": "3", "3": "4"}


def collect_urls(
    domain: str,
    hosts: list[str],
    report: ScanReport,
    speed: str = "2",
    silent: bool = False,
) -> list[str]:
    """Gather historical and crawler-discovered URLs for the target."""
    targets = hosts or [domain]
    collected: list[str] = []

    collected.extend(_wayback(domain, report))
    collected.extend(_gau(domain, report))
    collected.extend(_katana(targets, report, speed))

    if not collected:
        console.fail("Tidak ada URL yang berhasil dikumpulkan")
        return []

    urls = dedupe(collected)
    report.crawled_urls = urls

    report.parameterized_urls = dedupe([u for u in urls if "?" in u])
    report.js_urls = dedupe(
        [u for u in urls if urlparse(u).path.lower().endswith(".js")]
    )

    console.ok(f"Ditemukan {len(report.parameterized_urls)} URL berparameter")
    console.ok(f"Ditemukan {len(report.js_urls)} URL .js")
    console.ok(f"Total {len(urls)} URL unik terkumpul")
    return urls


def _wayback(domain: str, report: ScanReport) -> list[str]:
    console.info("Memulai proses crawling dengan Waybackurls...")
    res = run("waybackurls", [domain], timeout=600)
    if res.missing:
        report.record_tool("waybackurls", "tidak terpasang", 0)
        report.wayback_urls = []
        return []
    urls = dedupe(res.lines)
    report.wayback_urls = urls
    report.record_tool("waybackurls", "selesai", len(urls))
    console.ok(f"waybackurls menemukan {len(urls)} url")
    return urls


def _gau(domain: str, report: ScanReport) -> list[str]:
    console.info("Memulai proses crawling dengan Gau...")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "gau.txt"
        res = run("gau", ["--threads", "5", "--o", str(out), domain], timeout=600)
        if res.missing:
            report.record_tool("gau", "tidak terpasang", 0)
            report.gau_urls = []
            return []
        urls = dedupe(load_lines(out) or res.lines)
    report.gau_urls = urls
    report.record_tool("gau", "selesai", len(urls))
    console.ok(f"gau menemukan {len(urls)} url")
    return urls


def _katana(targets: list[str], report: ScanReport, speed: str) -> list[str]:
    console.info("Memulai proses crawling dengan Katana...")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "targets.txt"
        out = Path(tmp) / "katana.txt"
        src.write_text("\n".join(targets), encoding="utf-8")
        res = run(
            "katana",
            [
                "-list", str(src),
                "-silent",
                "-depth", _SPEED_DEPTH.get(speed, "3"),
                "-jc",
                "-o", str(out),
            ],
            timeout=1200,
        )
        if res.missing:
            report.record_tool("katana", "tidak terpasang", 0)
            return []
        urls = dedupe(load_lines(out) or res.lines)
    report.record_tool("katana", "selesai", len(urls))
    console.ok(f"Katana menemukan {len(urls)} url")
    return urls
