"""Sensitive-data scanning: regex triage over discovered URLs and bodies."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse

import requests

from reconx.core import console
from reconx.core.report import ScanReport

NAME = "Sensitive Data Scan"

# Patterns deliberately biased toward high-signal, low-false-positive shapes.
PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Password in URL": re.compile(r"[?&](?:password|passwd|pwd)=([^&\s]+)", re.I),
    "Email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "Internal IP": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    "S3 Bucket": re.compile(r"[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"),
}

# Query keys commonly leaking secrets when left in a URL.
INTERESTING_KEYS = {
    "token", "api_key", "apikey", "key", "secret", "password", "passwd",
    "pwd", "auth", "session", "sessionid", "access_token", "id_token",
    "signature", "sig", "credential", "aws_access_key_id",
}

# Values that look like secrets but are placeholders / documentation samples.
# Matching these is the single biggest source of false positives in regex-based
# secret scanning, so they are dropped outright.
PLACEHOLDER_RE = re.compile(
    r"(example|sample|dummy|placeholder|changeme|change_me|your[_-]?key|"
    r"xxxx|yyyy|zzzz|test[_-]?key|fake|redacted|todo|insert[_-]?here|"
    r"<[^>]+>|\$\{[^}]+\}|%[sd]\b)",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """True when a matched value is clearly a non-secret placeholder."""
    stripped = value.strip()
    if len(stripped) <= 6:
        return True
    if stripped.isdigit():
        return True
    if re.fullmatch(r"(.)\1+", stripped):  # aaaaa / 11111
        return True
    return bool(PLACEHOLDER_RE.search(stripped))


def scan_urls(urls: list[str], report: ScanReport) -> list[str]:
    """Pattern-match a list of URLs and return de-duplicated hits."""
    console.info("Mencari data sensitif pada URL yang terkumpul...")
    hits: list[str] = []
    seen: set[str] = set()

    for url in urls:
        decoded = unquote(url)
        for label, pattern in PATTERNS.items():
            for match in pattern.findall(decoded):
                # findall returns groups for grouped patterns.
                value = match if isinstance(match, str) else "".join(match)
                if _is_placeholder(value):
                    continue  # example/sample/test value, not a real secret
                sig = f"{label}: {value[:120]}"
                if sig not in seen:
                    seen.add(sig)
                    hits.append(f"[{label}] {url[:160]} -> {value[:80]}")

        keys = {k.lower() for k in parse_qs(urlparse(url).query)}
        leaked = keys & INTERESTING_KEYS
        if leaked:
            sig = f"keys:{url}"
            if sig not in seen:
                seen.add(sig)
                hits.append(f"[Menarik] parameter {sorted(leaked)} pada {url[:160]}")

    report.sensitive_hits = hits
    report.record_tool("sensitive-scan", "selesai", len(hits))

    if hits:
        console.ok(f"Ditemukan {len(hits)} potensi data sensitif")
        for item in hits[:20]:
            console.warn(item)
    else:
        console.fail("Tidak menemukan data sensitif")
    return hits


def fetch_and_scan(
    urls: list[str],
    report: ScanReport,
    limit: int = 40,
    timeout: int = 50,
) -> list[str]:
    """Optional deeper pass: pull JS/JSON bodies and pattern-match content."""
    console.info("Mengambil beberapa file .js/.json untuk analisis isi...")
    session = requests.Session()
    session.headers.update({"User-Agent": "ReconX/1.0"})

    candidates = report.js_urls[:limit]
    hits: list[str] = []

    for url in candidates:
        try:
            resp = session.get(url, timeout=timeout / 10, verify=False)
            if resp.status_code != 200 or len(resp.text) > 3_000_000:
                continue
            body = resp.text
        except requests.RequestException:
            continue

        for label, pattern in PATTERNS.items():
            for match in pattern.findall(body):
                value = match if isinstance(match, str) else "".join(match)
                if _is_placeholder(value):
                    continue
                hits.append(f"[{label}] {url[:120]} -> {value[:80]}")

    hits = list(dict.fromkeys(hits))
    report.sensitive_hits.extend(hits)
    report.sensitive_hits = list(dict.fromkeys(report.sensitive_hits))
    if hits:
        console.ok(f"Analisis isi JS menemukan {len(hits)} petunjuk tambahan")
    return hits
