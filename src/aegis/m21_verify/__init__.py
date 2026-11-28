"""M21 - deterministic decision of one dynamic verification run (G2-B).

M21 answers one question per `verify.check` job: does the evidence of this run show the condition,
and do both negative controls show that the observation is specific? The answer is a table, not a
judgement:

* the *inputs* are all server-side (the signed run, the deployment's control map, the expected
  value M21 holds) and the *evidence* only records what was seen (`verification-result.v2`);
* an unexpected positive result is **not** a failed check: a patched twin that reproduces, a benign
  control that matches, a catch-all that answers every path the same way, or an extracted value that
  looks like a canary but is not this run's canary all make the run **INCONCLUSIVE** - never
  VERIFIED, and never a weaker verdict the operator could read as "not vulnerable";
* `NOT_REPRODUCED` never closes a finding: FIXED still needs a new scan observing a version outside
  the affected range (`finding/transitions.v2.yaml`), and FALSE_POSITIVE stays the operator's
  decision;
* internet runs have no twin, so an E1 observation there is `OBSERVED` - evidence attached, no
  status change (the internet pack does not even carry an L1 check).

The module is split by responsibility:

    oracle.py    the decision table (pure: result document + expectation -> outcome)
    result.py    the result document as a contract object (parse, validate, sha check)
    controls.py  the deployment control map and the canary hashes M21 holds
    evidence.py  reading the stored evidence object of the job
    writer.py    the one transaction that records the run and, when VERIFIED, the transition
    __main__.py  the operator/CLI entry (`decide --job`, `decide --campaign`, `list`)

The transition it writes goes through `aegis.common.finding_write`, the same writer M20 and the
operator API use, so the three producers cannot drift on the sequence guard, the history row or the
`finding.changed.v2` event.
"""

from __future__ import annotations

from aegis.m21_verify.oracle import (
    Decision,
    Expectation,
    OracleError,
    decide,
)
from aegis.m21_verify.result import ResultDocument, load_result, validate_result

__all__ = [
    "Decision",
    "Expectation",
    "OracleError",
    "ResultDocument",
    "decide",
    "load_result",
    "validate_result",
]
