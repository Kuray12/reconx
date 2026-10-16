"""Subdomain enumeration via subfinder + assetfinder."""

from __future__ import annotations

import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "Subdomain Enumeration"


def enumerate_subdomains(domain: str, report: ScanReport, silent: bool = False) -> list[str]:
    """Collect subdomains from multiple public sources and merge them."""
    found: list[str] = []

    console.info(f"Mencari subdomain dengan Subfinder, Assetfinder, dan Amass untuk: {domain}")

    # --- subfinder -- with a temp file so large result sets stream to disk ---
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "subfinder.txt"
        console.info("Menjalankan Subfinder...")
        res = run(
            "subfinder",
            ["-d", domain, "-silent", "-all", "-o", str(out)],
            timeout=600,
        )
        if res.missing:
            report.record_tool("subfinder", "tidak terpasang", 0)
        else:
            found.extend(load_lines(out))
            report.record_tool("subfinder", "selesai", len(load_lines(out)))

    # --- assetfinder ---------------------------------------------------------
    console.info("Menjalankan Assetfinder...")
    res = run("assetfinder", ["--subs-only", domain], timeout=300)
    if res.missing:
        report.record_tool("assetfinder", "tidak terpasang", 0)
    else:
        # Assetfinder emits the apex domain too; drop it.
        found.extend(line for line in res.lines if line != domain)
        report.record_tool("assetfinder", "selesai", len(res.lines))

    # --- amass (passive) -----------------------------------------------------
    found.extend(_amass(domain, report))

    subdomains = dedupe(found)
    report.subdomains = subdomains

    if subdomains:
        console.ok(f"Ditemukan total {len(subdomains)} Subdomain")
    else:
        console.fail("Tidak ada subdomain ditemukan")
    return subdomains


def _amass(domain: str, report: ScanReport) -> list[str]:
    """Passive Amass enumeration; enum subcommand is used when available."""
    console.info("Menjalankan Amass (passive)...")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "amass.txt"

        # Amass v4 uses `enum -passive`; v3 used `-passive -d`.
        # Try the modern invocation first, fall back to the legacy one.
        res = run(
            "amass",
            ["enum", "-passive", "-d", domain, "-o", str(out)],
            timeout=900,
        )
        if res.missing:
            report.record_tool("amass", "tidak terpasang", 0)
            return []

        lines = load_lines(out) or res.lines
        if not lines:
            res = run("amass", ["-passive", "-d", domain], timeout=900)
            lines = res.lines

    subs = dedupe(line for line in lines if domain in line)
    report.record_tool("amass", "selesai", len(subs))
    console.ok(f"Amass menemukan {len(subs)} subdomain")
    return subs
