"""Spike configuration. All values come from the environment; no secrets are stored."""

from __future__ import annotations

import os

DSN = os.environ.get("SPIKE_PG_DSN", "postgresql://spike:spike@127.0.0.1:58101/aegis")
TEMPORAL_ADDRESS = os.environ.get("SPIKE_TEMPORAL_ADDRESS", "127.0.0.1:7233")
TEMPORAL_NAMESPACE = os.environ.get("SPIKE_TEMPORAL_NAMESPACE", "default")

# Task queues fixed by contracts/interfaces/README.md §7.
ORCHESTRATOR_QUEUE = "aegis-orchestrator"
AGENT_QUEUE = "aegis-agent"

# LangGraph checkpoint tables live in their own schema (contracts/db/postgres/0001_init.sql:17).
CHECKPOINT_SCHEMA = "langgraph"


def checkpoint_dsn() -> str:
    """DSN that puts the checkpointer's tables in CHECKPOINT_SCHEMA instead of public."""
    separator = "&" if "?" in DSN else "?"
    return f"{DSN}{separator}options=-c%20search_path%3D{CHECKPOINT_SCHEMA}"
