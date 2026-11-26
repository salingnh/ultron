"""M18 intel feeds (G1.6 slice C + full NVD 2.0): sync public vulnerability catalogues.

`python -m aegis.m18_intel sync --feed <nvd|kev|epss> --version <v> --source <path|url>`
`python -m aegis.m18_intel sync-nvd --mode <auto|full|incremental>`

This is the only place in the slice that may use the host network: the bytes are stored untouched
in S3, so everything downstream (matching, the projector, tests) works from a snapshot and never
from the network.
"""

from __future__ import annotations

from aegis.m18_intel.feeds import FEEDS, FeedError, VulnRecord
from aegis.m18_intel.nvd_api import NvdApiSync, NvdCorpusReport, load_nvd_api_key
from aegis.m18_intel.sync import FeedSync, FeedSyncError, SnapshotConflict, SyncReport

__all__ = [
    "FEEDS",
    "FeedError",
    "FeedSync",
    "FeedSyncError",
    "NvdApiSync",
    "NvdCorpusReport",
    "SnapshotConflict",
    "SyncReport",
    "VulnRecord",
    "load_nvd_api_key",
]
