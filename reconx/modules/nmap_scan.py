"""Port and service scanning with nmap (used by Deep Scan)."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "Nmap Port Scan"

# Profile per speed. "Deep" is intentionally broad (all TCP ports).
PROFILES: dict[str, dict[str, object]] = {
    "2": {
        "label": "top 1000 ports",
        "args": ["--top-ports", "1000", "-sV", "-T4"],
        "timeout": 1800,
    },
    "3": {
        "label": "semua port TCP (1-65535)",
        "args": ["-p-", "-sV", "-T4", "--min-rate", "1000"],
        "timeout": 7200,
    },
}

# A discovered service line inside nmap's normal output.
_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$")


def _host_of(entry: str) -> str:
    """Accept a URL or a bare host and return the hostname."""
    if "://" in entry:
        return urlparse(entry).hostname or entry
    return entry.split("/")[0]


def run_nmap(
    targets: list[str],
    report: ScanReport,
    speed: str = "3",
    silent: bool = False,
) -> list[str]:
    """Scan the given hosts and record open ports/services.

    Missing nmap is a soft failure so a Deep scan still completes.
    """
    if not targets:
        console.fail("Tidak ada host untuk di-scan nmap")
        return []

    profile = PROFILES.get(speed, PROFILES["3"])
    hosts = dedupe([_host_of(t) for t in targets if _host_of(t)])

    console.info(f"Menjalankan Nmap ({profile['label']}) pada {len(hosts)} host...")

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "hosts.txt"
        out = Path(tmp) / "nmap.txt"
        src.write_text("\n".join(hosts), encoding="utf-8")

        args = [
            "-iL", str(src),
            *profile["args"],  # type: ignore[list-item]
            "-oN", str(out),
            "--open",
        ]
        result = run("nmap", args, timeout=int(profile["timeout"]))

        if result.missing:
            report.record_tool("nmap", "tidak terpasang", 0)
            report.errors.append("nmap tidak terpasang -> port scan dilewati")
            return []

        raw_lines = load_lines(out) or result.lines

    findings = _parse(raw_lines)
    report.nmap_findings = findings
    report.record_tool("nmap", "selesai", len(findings))

    if findings:
        console.ok(f"Nmap menemukan {len(findings)} port terbuka")
        for item in findings[:30]:
            console.plain(f"      [dim]{item}[/]")
    else:
        console.fail("Nmap tidak menemukan port terbuka")
    return findings


def _parse(lines: list[str]) -> list[str]:
    """Turn raw nmap output into compact 'host:port/service' strings."""
    findings: list[str] = []
    current = ""

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for"):
            # "Nmap scan report for example.com (93.184.216.34)"
            host = stripped.replace("Nmap scan report for", "").strip()
            match = re.match(r"^(.*?)\s*\(([\d.:a-fA-F]+)\)\s*$", host)
            current = match.group(1).strip() if match else host
            continue

        match = _PORT_RE.match(stripped)
        if match and current:
            port, proto, state, service, version = match.groups()
            if state != "open":
                continue
            detail = f"{current}:{port}/{proto} {service}"
            if version:
                detail += f" {version.strip('| ').strip()}"
            findings.append(detail)

    return dedupe(findings)
