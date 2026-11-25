"""M20-lite CVE matcher (G1.6 slice C): candidate AFFECTED_BY rows from a pinned intel snapshot.

Feeds and snapshots are M18's (`aegis.m18_intel`); this package only matches the current
observations against `vulnerability_current` and records candidates, never findings.
"""

from __future__ import annotations

from aegis.m20_vuln.cpe import Cpe, CpeError, CpeMatch, compare_versions, parse_cpe, parse_version
from aegis.m20_vuln.matching import Candidate, Matcher, MatchReport, Target

__all__ = [
    "Candidate",
    "Cpe",
    "CpeError",
    "CpeMatch",
    "MatchReport",
    "Matcher",
    "Target",
    "compare_versions",
    "parse_cpe",
    "parse_version",
]
