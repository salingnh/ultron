"""M18 intel feeds (G1.6 slice C): sync the public vulnerability catalogues into PostgreSQL.

`python -m aegis.m18_intel sync --feed <nvd|kev|epss> --version <v> --source <path|url>`

This is the only place in the slice that may use the host network, and only when `--source` is an
`http(s)` URL: the bytes are stored untouched in S3, so everything downstream (matching, the
projector, tests) works from a snapshot and never from the network.
"""

from __future__ import annotations

from aegis.m18_intel.feeds import FEEDS, FeedError, VulnRecord
from aegis.m18_intel.sync import FeedSync, FeedSyncError, SnapshotConflict, SyncReport

__all__ = [
    "FEEDS",
    "FeedError",
    "FeedSync",
    "FeedSyncError",
    "SnapshotConflict",
    "SyncReport",
    "VulnRecord",
]
