"""Scan orchestration: Deep Scan (Fast / Standard / Deep) and helpers."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from reconx.core import console
from reconx.core.config import OUTPUT_DIR, Config, normalize_target
from reconx.core.report import ScanReport
from reconx.core.reportgenerator import generate as generate_report
from reconx.core.runner import have, missing_hint
from reconx.modules import (
    cloud,
    content,
    crawl,
    dns_enum,
    dorking,
    nmap_scan,
    nuclei,
    params,
    probe,
    sensitive,
    sqli,
    subdomains,
    takeover,
    xray,
    xss,
)

# Scan speed chosen after the target is entered.
#   1 = Fast      -> recon cepat, tanpa nmap
#   2 = Standard  -> recon penuh + nuclei
#   3 = Deep      -> semua modul + nmap scan banyak port (paling lama)
SPEED_LABELS = {
    "1": ("Fast", "subdomain + DNS + live host (cepat)"),
    "2": ("Standard", "Fast + crawl + nuclei"),
    "3": ("Deep", "semua modul + ffuf/arjun + sqlmap/dalfox + cloud_enum + xray + nmap (paling lama)"),
}


def choose_speed() -> str:
    console.plain("")
    console.plain("Pilih mode scanning:")
    for key, (label, desc) in SPEED_LABELS.items():
        console.plain(f"  {key}. {label:<9} - {desc}")
    try:
        choice = console.console.input("[bold cyan]> [/]").strip()
    except EOFError:
        choice = ""
    return choice if choice in SPEED_LABELS else "2"


def choose_target() -> str:
    console.plain("")
    console.plain("Masukkan URL target (contoh: example.com):")
    try:
        raw = console.console.input("[bold cyan]> [/]").strip()
    except EOFError:
        raw = ""
    host = normalize_target(raw)
    if not host:
        raise ValueError("Target kosong atau tidak valid.")
    return host


def doctor() -> None:
    """Report which external tools are available."""
    from reconx.modules.cloud import _resolve_binary

    console.rule("Tool Check")
    for tool in (
        "subfinder",
        "assetfinder",
        "amass",
        "dnsrecon",
        "dnsx",
        "httpx",
        "katana",
        "nuclei",
        "xray",
        "ffuf",
        "arjun",
        "sqlmap",
        "dalfox",
        "gau",
        "waybackurls",
        "nmap",
    ):
        if have(tool):
            console.ok(f"{tool} tersedia")
        else:
            console.fail(f"{tool} TIDAK ditemukan -> {missing_hint(tool)}")

    # cloud_enum ships under two possible names.
    if _resolve_binary() is not None:
        console.ok("cloud_enum tersedia")
    else:
        console.fail(f"cloud_enum TIDAK ditemukan -> {missing_hint('cloud_enum')}")


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------
def _finish(report: ScanReport, config: Config, auto_notify: bool) -> ScanReport:
    report.finished_at = datetime.now(timezone.utc).isoformat()

    console.rule("Ringkasan")
    for label, value in report.summary_counts().items():
        console.plain(f"  {label:<20}: [bold]{value}[/]")
    console.plain(f"  {'Durasi':<20}: [bold]{report.duration_seconds:.0f} detik[/]")

    report.save(OUTPUT_DIR)

    if auto_notify:
        generate_report(report, OUTPUT_DIR)
        from reconx.notify import dispatch

        dispatch(report, config, channels=["telegram", "email"])
    return report


def deep_scan(target: str, speed: str, config: Config) -> ScanReport:
    """Full recon chain; the chosen speed decides which modules run.

    speed: "1" Fast | "2" Standard | "3" Deep (adds nmap many-port scan)
    """
    report = ScanReport(
        target=target,
        operator=config.operator,
        speed=SPEED_LABELS.get(speed, SPEED_LABELS["2"])[0],
    )
    started = time.monotonic()
    label = SPEED_LABELS.get(speed, SPEED_LABELS["2"])[0]
    console.rule(f"Deep Scan ({label}) - {target}")

    # 1. subdomain enumeration (all speeds)
    subdomains.enumerate_subdomains(target, report)

    # 1b. DNS records + resolution (all speeds)
    dns_enum.enumerate_dns(target, report)

    # 2. live host probing (all speeds)
    live = probe.probe_live_hosts(report.subdomains, report, speed)

    # --- Fast stops here ----------------------------------------------------
    if speed == "1":
        report.duration_seconds = time.monotonic() - started
        return _finish(report, config, auto_notify=False)

    # 3. crawling (Standard + Deep)
    urls = crawl.collect_urls(target, live, report, speed)

    # --- Standard adds nuclei ----------------------------------------------
    if speed == "2":
        nuclei.run_nuclei(live, report, speed)
        report.duration_seconds = time.monotonic() - started
        return _finish(report, config, auto_notify=False)

    # --- Deep adds everything else -----------------------------------------
    sensitive.scan_urls(urls, report)
    sensitive.fetch_and_scan(urls, report)
    takeover.check_takeover(report.subdomains or [target], report)

    # content + hidden-parameter discovery (Deep only, traffic-heavy)
    content.run_ffuf(live, report, speed)
    params.run_arjun(urls, report, speed)

    # injection + XSS + cloud storage (Deep only)
    sqli.run_sqlmap(urls, report, speed)
    xss.run_dalfox(urls, report, speed)
    cloud.run_cloud_enum(target, report)

    nuclei.run_nuclei(live, report, speed)

    # xray webscan (slow, Deep only)
    xray.run_xray(live, report, speed)

    # nmap many-port scan, the point of "Deep"
    nmap_scan.run_nmap(live or [target], report, speed)

    report.duration_seconds = time.monotonic() - started
    return _finish(report, config, auto_notify=False)


def dork_only(domain: str, config: Config) -> None:
    report = ScanReport(target=domain, operator=config.operator)
    started = time.monotonic()
    console.rule(f"Manual Dorking - {domain}")
    dorking.generate_dorks(domain, report)
    report.duration_seconds = time.monotonic() - started
    _finish(report, config, auto_notify=False)
