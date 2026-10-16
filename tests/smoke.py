"""Local test suite - no network, no external binaries required.

Run with:  python -m tests.smoke     (or)   python tests/smoke.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reconx.core.config import Config, normalize_target
from reconx.core.report import ScanReport
from reconx.core.reportgenerator import generate
from reconx.core.runner import dedupe
from reconx.modules.dns_enum import _RECORD_RE
from reconx.modules.nmap_scan import _parse
from reconx.notify import build_summary

PASSED = 0
FAILED = 0


def check(name: str, condition: bool) -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"[+] PASS  {name}")
    else:
        FAILED += 1
        print(f"[-] FAIL  {name}")


def test_normalize() -> None:
    check("normalize strips scheme/path/port", normalize_target("https://A.test:443/x?y=1") == "a.test")
    check("normalize keeps bare host", normalize_target("sub.example.com.") == "sub.example.com")
    check("normalize handles empty", normalize_target("   ") == "")


def test_config() -> None:
    cfg = Config.load()
    check("config loads without scope gate", isinstance(cfg.operator, str))
    check("telegram disabled by default", cfg.telegram_enabled is False)


def test_nmap_parsing() -> None:
    raw = [
        "Nmap scan report for example.com (93.184.216.34)",
        "22/tcp   open  ssh     OpenSSH 8.2p1",
        "80/tcp   open  http    nginx 1.18.0",
        "443/tcp  closed https",
        "Nmap scan report for www.example.com (93.184.216.35)",
        "8080/tcp open  http-proxy",
    ]
    findings = _parse(raw)
    check("nmap finds open 22", any(":22/tcp ssh" in f for f in findings))
    check("nmap finds open 80", any(":80/tcp http" in f for f in findings))
    check("nmap skips closed", not any("443" in f for f in findings))
    check("nmap tracks second host", any("www.example.com:8080" in f for f in findings))


def test_dns_parsing() -> None:
    """The dnsrecon record regex must pull name/type/value from a table row."""
    row = "www.demo.test.       3600    IN      A       93.184.216.34"
    match = _RECORD_RE.match(row)
    check("dns record parsed", match is not None)
    check("dns type extracted", match is not None and match.group(2) == "A")


def test_report() -> None:
    r = ScanReport(target="demo.test", operator="ci", duration_seconds=1.0)
    r.finished_at = "2026-01-01T00:00:00Z"
    r.subdomains = ["a.demo.test", "a.demo.test"]
    r.nuclei_findings = ["[medium] https://a.demo.test xss"]
    r.nmap_findings = ["a.demo.test:22/tcp ssh OpenSSH 8.2"]
    r.xray_findings = ["[high] https://a.demo.test/sqli"]
    r.dns_records = ["a.demo.test A 93.184.216.34"]
    r.zone_transfer = ["[AXFR] Zone transfer successful on ns1.demo.test"]
    r.content_findings = ["[200] https://a.demo.test/admin (1234 bytes)"]
    r.parameter_findings = ["https://a.demo.test/?id=1 -> debug, token"]
    r.sqli_findings = ["Parameter 'id' is vulnerable to SQL injection"]
    r.xss_findings = ["[V] https://a.demo.test/?q=<script> POC"]
    r.cloud_findings = ["open: demo-test.s3.amazonaws.com"]
    paths = generate(r)
    check("markdown written", paths["markdown"].exists())
    check("html written", paths["html"].exists())
    summary = build_summary(r)
    check("summary contains target", "demo.test" in summary)
    check("summary contains nuclei finding", "xss" in summary)
    check("summary contains nmap port", "22/tcp" in summary)
    check("summary contains xray finding", "sqli" in summary)
    check("summary contains zone transfer", "ZONE TRANSFER" in summary)
    md = paths["markdown"].read_text(encoding="utf-8")
    check("md includes nmap section", "Nmap Open Ports" in md)
    check("md includes xray section", "Xray Findings" in md)
    check("md includes dns section", "DNS Records" in md)
    check("md includes content section", "Content Discovery" in md)
    check("md includes parameter section", "Parameter Tersembunyi" in md)
    check("md includes sqli section", "SQL Injection" in md)
    check("md includes xss section", "XSS" in md)
    check("md includes cloud section", "Cloud Storage" in md)
    check("summary contains sqli", "SQL Injection" in summary)
    check("summary contains xss", "XSS" in summary)
    check("summary contains cloud", "Cloud storage" in summary)
    paths["markdown"].unlink(missing_ok=True)
    paths["html"].unlink(missing_ok=True)


def test_wordlists() -> None:
    from reconx.core.wordlists import DEFAULT_ORDER, WORDLISTS, default_wordlist

    check("wordlists are small curated set", 0 < len(WORDLISTS) <= 10)
    check("default order references known lists", all(n in WORDLISTS for n in DEFAULT_ORDER))
    # default_wordlist must not raise even when the folder is empty.
    result = default_wordlist()
    check("default_wordlist returns None or Path", result is None or hasattr(result, "name"))


def test_runner_utils() -> None:
    check("dedupe preserves order", dedupe(["b", "a", "b", "c"]) == ["b", "a", "c"])
    check("dedupe drops blanks", dedupe(["a", "", "  "]) == ["a"])


def test_fp_filter() -> None:
    """Soft-404 suppression: identical/repeated responses must be dropped."""
    from reconx.core.fp_filter import collect, filter_results, is_soft_404_text

    tmpl = "<html><body>Page not found</body></html>"
    results = [
        # Real findings: distinct sizes, real content.
        collect("https://t/admin", 200, 5120, "<html>Admin panel</html>"),
        collect("https://t/backup.zip", 200, 204800, "PK\x03\x04 binary"),
        # Soft-404 noise: same size AND same body repeated many times.
        collect("https://t/aaa", 200, 200, tmpl),
        collect("https://t/bbb", 200, 200, tmpl),
        collect("https://t/ccc", 200, 200, tmpl),
        collect("https://t/ddd", 200, 200, tmpl),
    ]
    outcome = filter_results(results)
    kept_urls = {r.url for r in outcome.kept}
    check("fp: keeps distinct real findings", "https://t/admin" in kept_urls)
    check("fp: keeps backup file", "https://t/backup.zip" in kept_urls)
    check("fp: drops soft-404 aaa", "https://t/aaa" not in kept_urls)
    check("fp: drops soft-404 ddd", "https://t/ddd" not in kept_urls)
    check("fp: reports drop reasons", len(outcome.dropped) == 4)
    check("fp: detects not-found text", is_soft_404_text("OOPS page not found"))


def test_fp_filter_keeps_small_set() -> None:
    """A repeated size in a SMALL set must not be dropped (avoid over-filtering)."""
    from reconx.core.fp_filter import collect, filter_results

    results = [
        collect("https://t/a", 200, 42, "aaa"),
        collect("https://t/b", 200, 42, "bbb"),
    ]
    outcome = filter_results(results)
    check("fp: keeps results when only 2 share a size", len(outcome.kept) == 2)


def test_placeholder_filter() -> None:
    """Regex secret scanning must ignore obvious placeholders."""
    from reconx.modules.sensitive import _is_placeholder

    check("placeholder: drops EXAMPLE key", _is_placeholder("AKIAIOSFODNN7EXAMPLE"))
    check("placeholder: drops changeme", _is_placeholder("changeme"))
    check("placeholder: drops repeated", _is_placeholder("aaaaaaaaaaaa"))
    check("placeholder: drops template var", _is_placeholder("${API_KEY}"))
    check("placeholder: keeps real-looking key", not _is_placeholder("AKIAIOSFODNN7REALKEY9"))
    check("placeholder: keeps jwt-ish", not _is_placeholder("eyJhbGciOiJIUzI1NiJ9xyz"))


def main() -> int:
    print("Running ReconX smoke tests\n")
    test_normalize()
    test_config()
    test_nmap_parsing()
    test_dns_parsing()
    test_report()
    test_wordlists()
    test_runner_utils()
    test_fp_filter()
    test_fp_filter_keeps_small_set()
    test_placeholder_filter()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
