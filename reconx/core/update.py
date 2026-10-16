"""Tool updater: refresh nuclei templates and local repository code."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from reconx.core import console
from reconx.core.config import PROJECT_ROOT, ENV_FILE
from reconx.core.runner import have


def update_tool() -> None:
    """Update nuclei templates and pull the latest tool source if it is a repo."""
    console.rule("Update Tool")

    if have("nuclei"):
        console.info("Memperbarui nuclei templates...")
        try:
            subprocess.run(
                ["nuclei", "-update-templates"],
                check=False,
                timeout=900,
                shell=(sys.platform == "win32"),
            )
            console.ok("Template nuclei diperbarui.")
        except (OSError, subprocess.TimeoutExpired) as exc:
            console.fail(f"Gagal memperbarui template: {exc}")
    else:
        console.fail("nuclei belum terpasang, template tidak bisa diperbarui.")

    if (PROJECT_ROOT / ".git").exists():
        console.info("Menarik pembaruan kode (git pull)...")
        try:
            subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=PROJECT_ROOT,
                check=False,
                timeout=300,
                shell=(sys.platform == "win32"),
            )
            console.ok("Repositori diperbarui.")
        except (OSError, subprocess.TimeoutExpired) as exc:
            console.fail(f"git pull gagal: {exc}")
    else:
        console.plain("      [dim]Bukan repositori git -> lewati git pull.[/]")

    if not ENV_FILE.exists():
        console.warn("File .env belum ada. Jalankan menu [9] Setup Configuration.")
