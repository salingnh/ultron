"""`python -m aegis.m23_graph` - the operator CLI of the graph projector (see `cli.py`)."""

from __future__ import annotations

import sys

from aegis.m23_graph.cli import main

if __name__ == "__main__":
    sys.exit(main())
