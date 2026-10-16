"""In-memory collection of everything a scan discovers, plus persistence."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from reconx.core import console


@dataclass
class ScanReport:
    """All artefacts produced by a single scan run."""

    target: str
    operator: str = "unknown"
    speed: str = "2"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = ""
    duration_seconds: float = 0.0

    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    gau_urls: list[str] = field(default_factory=list)
    wayback_urls: list[str] = field(default_factory=list)
    parameterized_urls: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    sensitive_hits: list[str] = field(default_factory=list)
    nuclei_findings: list[str] = field(default_factory=list)
    takeover_candidates: list[str] = field(default_factory=list)
    dorking_results: list[str] = field(default_factory=list)
    nmap_findings: list[str] = field(default_factory=list)
    xray_findings: list[str] = field(default_factory=list)
    dns_records: list[str] = field(default_factory=list)
    resolved_hosts: list[str] = field(default_factory=list)
    zone_transfer: list[str] = field(default_factory=list)
    content_findings: list[str] = field(default_factory=list)
    parameter_findings: list[str] = field(default_factory=list)
    sqli_findings: list[str] = field(default_factory=list)
    xss_findings: list[str] = field(default_factory=list)
    cloud_findings: list[str] = field(default_factory=list)

    tool_log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # -- helpers ------------------------------------------------------------
    def record_tool(self, tool: str, status: str, count: int = 0) -> None:
        self.tool_log.append(f"{tool}: {status} ({count} items)")

    def summary_counts(self) -> dict[str, int]:
        return {
            "Subdomain": len(self.subdomains),
            "Live host": len(self.live_hosts),
            "URL crawled": len(self.crawled_urls),
            "URL (gau)": len(self.gau_urls),
            "URL (wayback)": len(self.wayback_urls),
            "URL berparameter": len(self.parameterized_urls),
            "File .js": len(self.js_urls),
            "Sensitive data": len(self.sensitive_hits),
            "Nuclei findings": len(self.nuclei_findings),
            "Xray findings": len(self.xray_findings),
            "Nmap port terbuka": len(self.nmap_findings),
            "DNS record": len(self.dns_records),
            "Zone transfer": len(self.zone_transfer),
            "Content ditemukan": len(self.content_findings),
            "Parameter tersembunyi": len(self.parameter_findings),
            "SQLi": len(self.sqli_findings),
            "XSS": len(self.xss_findings),
            "Cloud bucket": len(self.cloud_findings),
            "Takeover candidate": len(self.takeover_candidates),
        }

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, directory: Path) -> Path:
        """Write a JSON copy of the report and return its path."""
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = directory / f"{self.target}-{stamp}.json"
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.ok(f"Data mentah disimpan: {path}")
        return path
