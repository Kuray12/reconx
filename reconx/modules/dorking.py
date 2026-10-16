"""Manual dorking helper.

This module only *builds* search queries and prints copy-paste links for the
operator. It deliberately does not automate querying a search engine, which
would violate most engines' terms of service.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from reconx.core import console
from reconx.core.report import ScanReport

NAME = "Manual Dorking"

ENGINES = {
    "Google": "https://www.google.com/search?q={q}",
    "Bing": "https://www.bing.com/search?q={q}",
    "DuckDuckGo": "https://duckduckgo.com/?q={q}",
    "GitHub": "https://github.com/search?q={q}",
}

TEMPLATES = [
    'site:{d} -www',
    'site:{d} inurl:admin',
    'site:{d} intitle:"index of"',
    'site:{d} ext:log OR ext:bak OR ext:sql',
    'site:{d} inurl:.env',
    'site:{d} "api_key" OR "apikey" OR "password"',
    '"{d}" -site:{d}',
]


def generate_dorks(domain: str, report: ScanReport) -> list[str]:
    """Build and display dork queries for the operator to run manually."""
    console.info(f"Membuat Google Dork untuk: {domain}")
    queries = [t.format(d=domain) for t in TEMPLATES]
    report.dorking_results = queries
    report.record_tool("dorking", "dibuat", len(queries))

    for query in queries:
        console.plain(f"      [bold]{query}[/]")
        for engine, url in ENGINES.items():
            console.plain(f"        [dim]{engine}: {url.format(q=quote_plus(query))}[/]")

    console.ok("Dork siap dijalankan manual di browser.")
    return queries
