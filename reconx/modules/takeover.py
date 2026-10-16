"""Subdomain-takeover detection based on dangling-DNS fingerprints."""

from __future__ import annotations

import socket
from dataclasses import dataclass

import requests

from reconx.core import console
from reconx.core.report import ScanReport

NAME = "Subdomain Takeover"


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cname: str
    body: str = ""


# Minimal but high-precision subset of the public "can-i-take-over-xyz" list.
FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    Fingerprint("Heroku", "herokuapp.com", "No such app"),
    Fingerprint("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
    Fingerprint("Azure", "azurewebsites.net", ""),
    Fingerprint("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    Fingerprint("Zendesk", "zendesk.com", "Help Center Closed"),
    Fingerprint("Fastly", "fastly.net", "Fastly error: unknown domain"),
    Fingerprint("Tumblr", "tumblr.com", "There's nothing here"),
    Fingerprint("Pantheon", "pantheonsite.io", "The gods are wise"),
    Fingerprint("Netlify", "netlify.app", "Not Found - Request ID"),
    Fingerprint("Surge.sh", "surge.sh", "project not found"),
    Fingerprint("Read the Docs", "readthedocs.io", "unknown to Read the Docs"),
    Fingerprint("Bitbucket", "bitbucket.io", ""),
    Fingerprint("Unbounce", "unbouncepages.com", ""),
)


def _resolve_cname(host: str) -> str:
    try:
        return socket.gethostbyname_ex(host)[0].lower()
    except socket.gaierror:
        return ""


def check_takeover(hosts: list[str], report: ScanReport, timeout: int = 10) -> list[str]:
    """Flag hosts whose CNAME points at an unclaimed third-party service."""
    console.info("Memeriksa indikasi subdomain takeover...")
    session = requests.Session()
    session.headers.update({"User-Agent": "ReconX/1.0"})
    candidates: list[str] = []

    for host in hosts:
        resolved = _resolve_cname(host)
        service = next((fp for fp in FINGERPRINTS if fp.cname in resolved), None)

        for fp in FINGERPRINTS:
            if fp.cname not in resolved:
                continue
            # Dangling CNAME is suspicious; a matching error body confirms it.
            verdict = f"[{fp.service}] {host} -> CNAME {resolved} (kandidat)"
            if fp.body:
                for scheme in ("https", "http"):
                    try:
                        resp = session.get(f"{scheme}://{host}", timeout=timeout, verify=False)
                        if fp.body.lower() in resp.text.lower():
                            verdict = (
                                f"[{fp.service}] {host} -> DIAMBIL ALIH "
                                f"(fingerprint '{fp.body}' ditemukan)"
                            )
                            break
                    except requests.RequestException:
                        continue
            candidates.append(verdict)
            break
        else:
            _ = service  # service unused when no fingerprint matched

    candidates = list(dict.fromkeys(candidates))
    report.takeover_candidates = candidates
    report.record_tool("takeover-check", "selesai", len(candidates))

    if candidates:
        console.warn(f"Ditemukan {len(candidates)} kandidat takeover")
        for item in candidates:
            console.warn(item)
    else:
        console.fail("Tidak ada kandidat subdomain takeover")
    return candidates
