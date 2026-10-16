"""Live-host probing with httpx, including a graceful fallback."""

from __future__ import annotations

import tempfile
from pathlib import Path

import requests

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "HTTP Probing"

_SPEED_PRESETS = {
    "1": {"threads": 10, "rate": 20},
    "2": {"threads": 50, "rate": 150},
    "3": {"threads": 150, "rate": 500},
}


def probe_live_hosts(
    hosts: list[str],
    report: ScanReport,
    speed: str = "2",
    silent: bool = False,
) -> list[str]:
    """Determine which hosts actually respond over HTTP/HTTPS."""
    if not hosts:
        return []

    console.info("Mengecek Subdomain yang aktif...")
    preset = _SPEED_PRESETS.get(speed, _SPEED_PRESETS["2"])

    if run_have_httpx():
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "hosts.txt"
            dst = Path(tmp) / "live.txt"
            src.write_text("\n".join(hosts), encoding="utf-8")
            console.info("Menjalankan httpx...")
            res = run(
                "httpx",
                [
                    "-l", str(src),
                    "-silent",
                    "-threads", str(preset["threads"]),
                    "-rate-limit", str(preset["rate"]),
                    "-o", str(dst),
                ],
                timeout=900,
            )
            if not res.missing:
                live = dedupe(load_lines(dst))
                report.record_tool("httpx", "selesai", len(live))
            else:
                live = []
        if live:
            console.ok(f"httpx berhasil menemukan {len(live)} subdomain")
            report.live_hosts = live
            return live
        console.warn("httpx tidak menghasilkan host -> mencoba probe Python")

    live = _python_probe(hosts, preset, silent, report)
    report.live_hosts = live
    if live:
        console.ok(f"Probe Python menemukan {len(live)} host aktif")
    else:
        console.fail("Tidak ada host aktif yang bisa diverifikasi")
    return live


def run_have_httpx() -> bool:
    from reconx.core.runner import have

    return have("httpx")


def _python_probe(
    hosts: list[str],
    preset: dict[str, int],
    silent: bool,
    report: ScanReport,
) -> list[str]:
    """Minimal fallback prober used when the httpx binary is unavailable."""
    from concurrent.futures import ThreadPoolExecutor

    session = requests.Session()
    session.headers.update({"User-Agent": "ReconX/1.0"})

    def check(host: str) -> str | None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = session.get(url, timeout=8, allow_redirects=True, verify=False)
                if not silent:
                    console.ok(f"Http berhasil menemukan -> {url} [{resp.status_code}]")
                report.record_tool("python-probe", url, resp.status_code)
                return url
            except requests.RequestException:
                continue
        return None

    console.info("Menggunakan prober Python sebagai fallback...")
    with ThreadPoolExecutor(max_workers=preset["threads"]) as pool:
        results = pool.map(check, hosts)
    return dedupe([r for r in results if r])
