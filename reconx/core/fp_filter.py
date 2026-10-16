"""False-positive suppression helpers.

The biggest source of noise in content discovery is the "soft 404": a server
that answers 200 OK with an identical boilerplate page for every unknown path.
Ffuf's `-ac` (auto-calibrate) catches some of it, but not all. This module adds
a second layer:

  * collect the body size + content hash of every result,
  * treat any size/hash shared by many different paths as a soft-404 signature,
  * drop those.

Rules live here in code (no external config) so the behaviour is predictable.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field

# A response size shared by this many distinct paths is almost certainly a
# template/soft-404 rather than a real finding.
SOFT_404_MIN_HITS = 3

# Wildcard responses often come back with a generic body; these phrases on a
# page that many paths share confirm it is noise.
SOFT_404_MARKERS = (
    "not found",
    "page not found",
    "404",
    "does not exist",
    "cannot be found",
    "no such file",
    "not available",
    "default page",
    "welcome to nginx",
    "apache2 ubuntu default",
    "index of /",
)

# Redirects that just bounce everything to the same place are noise too.
BORING_REDIRECT_TARGETS = ("/login", "/index.php", "/home")

# Paths matching these are known framework/system noise.
NOISE_PATH_RE = re.compile(
    r"/(?:\.git/|\.svn/|\.hg/|node_modules/|vendor/|\.DS_Store$|"
    r"__pycache__/|\.idea/|\.vscode/)",
    re.IGNORECASE,
)


@dataclass
class ContentResult:
    """One ffuf hit before filtering."""

    url: str
    status: int
    length: int
    body_hash: str = ""
    redirect: str = ""
    soft_marker: bool = False


@dataclass
class FilterOutcome:
    kept: list[ContentResult] = field(default_factory=list)
    dropped: list[tuple[ContentResult, str]] = field(default_factory=list)


def _hash_body(body: str) -> str:
    normalised = " ".join(body.split()).lower()
    return hashlib.sha1(normalised.encode("utf-8", "replace")).hexdigest()


def collect(url: str, status: int, length: int, body: str = "", redirect: str = "") -> ContentResult:
    """Build a ContentResult, hashing the body when one is available."""
    return ContentResult(
        url=url,
        status=status,
        length=length,
        body_hash=_hash_body(body) if body else "",
        redirect=redirect,
        soft_marker=is_soft_404_text(body) if body else False,
    )


def filter_results(results: list[ContentResult]) -> FilterOutcome:
    """Split results into real findings and suppressed false positives."""
    outcome = FilterOutcome()
    if not results:
        return outcome

    # Signature-based soft-404 detection.
    size_counter: Counter[int] = Counter(r.length for r in results)
    hash_counter: Counter[str] = Counter(r.body_hash for r in results if r.body_hash)
    wildcard_sizes = {size for size, n in size_counter.items() if n >= SOFT_404_MIN_HITS}
    wildcard_hashes = {h for h, n in hash_counter.items() if n >= SOFT_404_MIN_HITS}

    for result in results:
        reason = _why_drop(result, wildcard_sizes, wildcard_hashes)
        if reason:
            outcome.dropped.append((result, reason))
        else:
            outcome.kept.append(result)

    return outcome


def _why_drop(
    result: ContentResult,
    wildcard_sizes: set[int],
    wildcard_hashes: set[str],
) -> str | None:
    if NOISE_PATH_RE.search(result.url):
        return "path sistem/framework"

    # Identical body shared across many paths -> template/soft-404.
    if result.body_hash and result.body_hash in wildcard_hashes:
        return "soft-404 (body identik)"

    # Same byte size repeated across many paths -> wildcard response.
    if result.length in wildcard_sizes:
        # A generic not-found body confirms it beyond doubt.
        if result.soft_marker:
            return "soft-404 (ukuran seragam + teks 'not found')"
        return "soft-404 (ukuran seragam)"

    if result.redirect and any(
        result.redirect.rstrip("/").endswith(t) for t in BORING_REDIRECT_TARGETS
    ):
        return f"redirect seragam ke {result.redirect}"

    return None


def is_soft_404_text(text: str) -> bool:
    """True when a body looks like a generic not-found page."""
    lowered = text.lower()
    return any(marker in lowered for marker in SOFT_404_MARKERS)
