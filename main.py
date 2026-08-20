#!/usr/bin/env python3
"""Convenience launcher so the project runs with ``python main.py``.

The real entry point is :mod:`firewall.cli`; this only makes sure the project
directory is importable when the script is run from elsewhere. With no
arguments it runs the ten-packet demo described in the README.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from firewall.cli import main  # noqa: E402  (import needs the path set above)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["simulate", "--seed", "1"]))
