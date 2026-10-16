"""Wordlist management.

Downloads only the high-value SecLists files (a few MB total) instead of
cloning the whole ~1 GB repository. Resolves a sensible default wordlist for
content discovery, and creates the folder layout if it is missing.
"""

from __future__ import annotations

from pathlib import Path

from reconx.core import console
from reconx.core.config import PROJECT_ROOT

WORDLIST_DIR = PROJECT_ROOT / "wordlists"

# name -> raw URL. Kept small on purpose; each is a well-known SecLists file.
WORDLISTS: dict[str, str] = {
    "common.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/common.txt"
    ),
    "raft-small-directories.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/raft-small-directories.txt"
    ),
    "raft-medium-directories.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/raft-medium-directories.txt"
    ),
    "dirbuster-small.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"
    ),
    "burp-parameter-names.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/burp-parameter-names.txt"
    ),
}

# Prefer these, in order, when the user has not specified a wordlist.
DEFAULT_ORDER = [
    "raft-small-directories.txt",
    "common.txt",
    "dirbuster-small.txt",
]


def default_wordlist() -> Path | None:
    """Return the first available default wordlist, or None."""
    for name in DEFAULT_ORDER:
        path = WORDLIST_DIR / name
        if path.exists() and path.stat().st_size > 0:
            return path

    # Fall back to any file the user dropped into the folder.
    if WORDLIST_DIR.exists():
        for candidate in sorted(WORDLIST_DIR.glob("*.txt")):
            if candidate.stat().st_size > 0:
                return candidate
    return None


def download_wordlists(force: bool = False) -> int:
    """Download the curated wordlists. Returns how many were fetched."""
    import requests

    WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    fetched = 0

    for name, url in WORDLISTS.items():
        target = WORDLIST_DIR / name
        if target.exists() and target.stat().st_size > 0 and not force:
            console.ok(f"{name} sudah ada, dilewati")
            continue

        try:
            console.info(f"Mengunduh {name}...")
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                target.write_bytes(resp.content)
                fetched += 1
                console.ok(f"{name} ({target.stat().st_size // 1024} KB)")
            else:
                console.fail(f"{name} gagal (HTTP {resp.status_code})")
        except requests.RequestException as exc:
            console.fail(f"{name} gagal: {exc}")

    return fetched


def status() -> None:
    """Print which wordlists are present."""
    console.rule("Wordlists")
    if not WORDLIST_DIR.exists():
        console.warn("Folder wordlists/ belum ada. Jalankan install.sh atau menu download.")
        return
    found = sorted(WORDLIST_DIR.glob("*.txt"))
    if not found:
        console.warn("Belum ada file wordlist di wordlists/")
        return
    for path in found:
        console.ok(f"{path.name} ({path.stat().st_size // 1024} KB)")
