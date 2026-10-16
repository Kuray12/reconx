"""DNS enumeration with dnsrecon and dnsx.

dnsrecon: DNS records, zone-transfer checks, and reverse lookups.
dnsx:     fast bulk DNS resolution/validation of a subdomain list.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, load_lines, run

NAME = "DNS Enumeration"

# Zone-transfer success markers differ between nameservers; these cover the
# common BIND / NSD / dnsrecon phrasings.
_AXFR_MARKERS = ("zone transfer successful", "axfr", "succeeded")
_RECORD_RE = re.compile(r"^\s*(\S+)\s+\d+\s+IN\s+(\w+)\s+(.+)$")


def enumerate_dns(domain: str, report: ScanReport) -> None:
    """Run dnsrecon and dnsx, recording findings on the report."""
    console.info(f"Memeriksa DNS records untuk: {domain}")
    _dnsrecon(domain, report)
    _dnsx(report.subdomains, report)


def _dnsrecon(domain: str, report: ScanReport) -> None:
    console.info("Menjalankan dnsrecon (records + zone transfer)...")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "dnsrecon.json"
        res = run(
            "dnsrecon",
            ["-d", domain, "-t", "std", "--json", str(out)],
            timeout=600,
        )
        if res.missing:
            report.record_tool("dnsrecon", "tidak terpasang", 0)
            return

        # dnsrecon prints its findings to stdout in a readable table.
        findings: list[str] = []
        for line in res.lines:
            match = _RECORD_RE.match(line)
            if match:
                name, rtype, value = match.groups()
                findings.append(f"{name} {rtype} {value.strip()}")
            elif "zone transfer" in line.lower():
                findings.append(f"[AXFR] {line.strip()}")

    # Flag any successful zone transfer explicitly: that is a real finding.
    for line in res.lines:
        low = line.lower()
        if "zone transfer" in low and any(m in low for m in ("success", "succeeded")):
            report.zone_transfer.append(line.strip())

    report.dns_records = dedupe(findings)
    report.record_tool("dnsrecon", "selesai", len(report.dns_records))

    if report.dns_records:
        console.ok(f"dnsrecon menemukan {len(report.dns_records)} DNS record")
    if report.zone_transfer:
        console.warn("ZONE TRANSFER BERHASIL -> temuan serius:")
        for item in report.zone_transfer:
            console.warn(f"      {item}")


def _dnsx(subdomains: list[str], report: ScanReport) -> None:
    """Resolve a subdomain list quickly; unresolved hosts are dropped."""
    if not subdomains:
        return

    console.info("Menjalankan dnsx (validasi resolusi)...")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "subs.txt"
        out = Path(tmp) / "resolved.txt"
        src.write_text("\n".join(subdomains), encoding="utf-8")

        res = run(
            "dnsx",
            ["-l", str(src), "-silent", "-a", "-resp", "-o", str(out)],
            timeout=600,
        )
        if res.missing:
            report.record_tool("dnsx", "tidak terpasang", 0)
            return

        resolved = dedupe(load_lines(out) or res.lines)

    report.resolved_hosts = resolved
    report.record_tool("dnsx", "selesai", len(resolved))
    if resolved:
        console.ok(f"dnsx memvalidasi {len(resolved)} host yang resolve")
