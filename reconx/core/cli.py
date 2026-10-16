"""ReconX command-line interface - streamlined menu."""

from __future__ import annotations

import sys
import time

from reconx.core import console
from reconx.core.config import OUTPUT_DIR, Config
from reconx.core.report import ScanReport
from reconx.core.reportgenerator import generate as generate_report
from reconx.core.scanner import choose_speed, choose_target, deep_scan, doctor
from reconx.core.setup_wizard import run_setup
from reconx.core.update import update_tool

MENU = """
Choose Feature:

[1] Deep Scan
[2] Generate Report -> Send To Telegram
[3] Generate Report -> Send To Email Target
[4] Setup Configuration
[5] Update Tool
[6] Download Wordlists
[9] Out
"""


def _print_menu() -> None:
    console.plain(MENU)


def _ask(prompt: str) -> str:
    try:
        return console.console.input(prompt).strip()
    except EOFError:
        return ""


def _prompt_target() -> str | None:
    """Ask for a target, returning None when it is empty."""
    try:
        return choose_target()
    except ValueError as exc:
        console.fail(str(exc))
        return None


def _send_to(channel: str, config: Config) -> None:
    """Run a scan-sized report from the most recent result, then send it.

    If no previous scan exists, the operator is asked to run a Deep Scan first.
    """
    last = _load_last_report()
    if last is None:
        console.warn("Belum ada hasil scan. Jalankan [1] Deep Scan dulu.")
        return

    report, path = last
    generate_report(report, OUTPUT_DIR)

    from reconx.notify import dispatch

    console.info(f"Mengirim laporan '{report.target}' ke {channel}...")
    dispatch(report, config, channels=[channel])
    _ = path


def _load_last_report() -> tuple[ScanReport, str] | None:
    """Load the newest JSON report from the output directory."""
    import json

    if not OUTPUT_DIR.exists():
        return None
    files = sorted(OUTPUT_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None

    path = files[0]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    report = ScanReport(target=data.get("target", "unknown"))
    for key, value in data.items():
        if hasattr(report, key):
            setattr(report, key, value)
    return report, str(path)


def main() -> int:
    console.banner()
    config = Config.load()

    console.plain(f"        Operator : [bold]{config.operator}[/]")
    console.plain(
        f"        Telegram : {'aktif' if config.telegram_enabled else 'nonaktif'}"
        f"   Email : {'aktif' if config.email_enabled else 'nonaktif'}"
    )
    doctor()

    while True:
        _print_menu()
        try:
            choice = console.console.input(
                "[bold cyan]Choose Feature (1-6, or 9): [/]"
            ).strip()
        except EOFError:
            console.plain("")
            console.ok("Input berakhir. Keluar.")
            return 0

        try:
            if choice == "1":
                target = _prompt_target()
                if target is None:
                    continue
                speed = choose_speed()
                label = {"1": "Fast", "2": "Standard", "3": "Deep"}[speed]
                console.plain("")
                console.info(f"Memulai Deep Scan ({label}) untuk [bold]{target}[/]")
                started = time.monotonic()
                report = deep_scan(target, speed, config)

                # Offer to push the result to the configured channel.
                if config.telegram_enabled or config.email_enabled:
                    answer = _ask(
                        "\nKirim laporan ke Telegram/Email sekarang? (y/n): "
                    ).lower()
                    if answer in {"y", "yes"}:
                        from reconx.notify import dispatch

                        generate_report(report, OUTPUT_DIR)
                        dispatch(report, config)
                _ = started

            elif choice == "2":
                _send_to("telegram", config)

            elif choice == "3":
                _send_to("email", config)

            elif choice == "4":
                run_setup()
                config = Config.load()

            elif choice == "5":
                update_tool()

            elif choice == "6":
                from reconx.core.wordlists import download_wordlists, status

                status()
                answer = _ask("\nUnduh wordlist yang belum ada? (y/n): ").lower()
                if answer in {"y", "yes"}:
                    download_wordlists()
                    status()

            elif choice == "9":
                console.ok("Keluar. Sampai jumpa.")
                return 0

            else:
                console.fail("Pilihan tidak dikenal.")

        except KeyboardInterrupt:
            console.warn("Dibatalkan oleh pengguna.")
            return 130
        except Exception as exc:  # keep the loop alive on unexpected errors
            console.fail(f"Error tak terduga: {exc}")
            if "--debug" in sys.argv:
                raise


if __name__ == "__main__":
    raise SystemExit(main())
