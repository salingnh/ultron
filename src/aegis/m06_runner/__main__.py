"""`python -m aegis.m06_runner` - the runner loop (see `loop.py`)."""

from __future__ import annotations

import sys

from aegis.m06_runner.loop import main

if __name__ == "__main__":
    sys.exit(main())
