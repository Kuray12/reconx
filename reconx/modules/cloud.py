"""Cloud storage enumeration with cloud_enum (S3 / Azure / GCP)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from reconx.core import console
from reconx.core.report import ScanReport
from reconx.core.runner import dedupe, have, run

NAME = "Cloud Storage Enumeration"


def run_cloud_enum(
    domain: str,
    report: ScanReport,
    silent: bool = False,
) -> list[str]:
    """Search for open S3/Azure/GCP buckets matching the domain name.

    cloud_enum is a Python tool shipped as `cloud_enum` (or `cloud-enum`).
    Deep Scan only: it makes many DNS/HTTP lookups across providers.
    """
    binary = _resolve_binary()
    if binary is None:
        console.fail("cloud_enum tidak ditemukan di PATH -> cloud enum dilewati")
        report.record_tool("cloud_enum", "tidak terpasang", 0)
        report.errors.append("cloud_enum tidak terpasang -> cloud enum dilewati")
        return []

    keyword = domain.split(".")[0]
    console.info(f"Mencari cloud storage terbuka untuk keyword: {keyword}")

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "cloud.txt"
        res = run(
            binary,
            ["-k", keyword, "-l", str(out)],
            timeout=1800,
        )

        if res.missing:
            return []

        findings = dedupe(_parse(out) or _parse_lines(res.lines))

    report.cloud_findings = findings
    report.record_tool("cloud_enum", "selesai", len(findings))

    if findings:
        console.warn(f"cloud_enum menemukan {len(findings)} bucket/endpoint")
        for item in findings[:25]:
            console.warn(item)
    else:
        console.ok("cloud_enum tidak menemukan storage terbuka")
    return findings


def _resolve_binary() -> str | None:
    """cloud_enum ships under two possible command names."""
    for name in ("cloud_enum", "cloud-enum"):
        if have(name):
            return name
    return None


def _parse(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _parse_lines(lines: list[str]) -> list[str]:
    """Keep only lines that look like an open-resource finding."""
    hits: list[str] = []
    for line in lines:
        low = line.lower()
        if any(tag in low for tag in ("open", "public", "found", "s3.amazonaws", "blob.core", "storage.googleapis")):
            hits.append(line.strip())
    return hits
