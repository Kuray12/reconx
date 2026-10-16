"""Runner for external recon binaries (subfinder, httpx, katana, ...).

Every external tool call funnels through here so that:
  * a missing binary produces a clear hint instead of a traceback,
  * timeouts never kill the whole scan,
  * stdout is streamed line-by-line back to the caller,
  * the exact command is recorded for the audit log.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from reconx.core import console

# What each tool does and how to install it, shown when it is missing.
TOOL_INFO: dict[str, str] = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "dnsrecon": "pip install dnsrecon   (or: sudo apt install dnsrecon)",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "xray": "download from https://github.com/chaitin/xray/releases (needs config)",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
    "arjun": "pip install arjun",
    "sqlmap": "sudo apt install sqlmap   (or: pip install sqlmap)",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "cloud_enum": "pip install cloud-enum   (or: git clone github.com/initstring/cloud_enum)",
    "nmap": "sudo apt install nmap   (Debian/Ubuntu)  |  sudo dnf install nmap  (Fedora)",
}


@dataclass
class ToolResult:
    """Outcome of one external command."""

    tool: str
    command: list[str]
    lines: list[str] = field(default_factory=list)
    returncode: int | None = None
    missing: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return not self.missing and not self.timed_out and self.returncode == 0

    @property
    def count(self) -> int:
        return len(self.lines)


def have(tool: str) -> bool:
    """True when the binary is resolvable on PATH."""
    return shutil.which(tool) is not None


def missing_hint(tool: str) -> str:
    return TOOL_INFO.get(tool, f"pasang '{tool}' lalu pastikan ada di PATH")


def run(
    tool: str,
    args: list[str],
    timeout: int = 300,
    stream: bool = False,
) -> ToolResult:
    """Execute an external tool and collect its stdout lines.

    Missing binaries and timeouts are reported as soft failures so a scan can
    continue with whatever tooling is actually installed.
    """
    command = [tool, *args]
    result = ToolResult(tool=tool, command=command)

    if not have(tool):
        result.missing = True
        console.fail(f"{tool} tidak ditemukan di PATH -> dilewati")
        console.plain(f"      [dim]install: {missing_hint(tool)}[/]")
        return result

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            shell=(sys.platform == "win32"),
        )
    except OSError as exc:  # pragma: no cover - platform dependent
        result.missing = True
        console.fail(f"gagal menjalankan {tool}: {exc}")
        return result

    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.strip()
            if not line:
                continue
            result.lines.append(line)
            if stream:
                console.plain(f"      [dim]{line}[/]")
        proc.wait(timeout=timeout)
        result.returncode = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        result.timed_out = True
        console.warn(f"{tool} melebihi batas waktu {timeout}s -> dihentikan")
    finally:
        if proc.poll() is None:
            proc.kill()

    return result


def dedupe(items: list[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return dedupe(path.read_text(encoding="utf-8", errors="replace").splitlines())
