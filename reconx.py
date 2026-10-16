#!/usr/bin/env python3
"""ReconX launcher.

    python reconx.py

Runs the interactive CLI. Installs nothing automatically; use
`pip install -r requirements.txt` first.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reconx.core.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
