#!/usr/bin/env python3
"""Migration-chain hygiene: the README gate and the files on disk must describe the same chain.

This is the cheap, offline half of the OI-1/OI-2 fix. The behaviour is proved by the database tests
(tests/search_path_pinning.sql, tests/dispatch_hold.sql, tests/upgrade_assertions.sql); this file
proves that those tests and the migrations they cover are actually part of the documented gate, so a
new migration, fixture or SQL test cannot be added to the directory and silently skipped by
`contracts/README.md §Kiểm tra` (the gate PR #14's scripts/ci/contracts-gate.sh reads).

    python3 -I contracts/tests/test_migration_hygiene.py
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / "db/postgres"
README = (ROOT / "README.md").read_text()
MIGRATIONS = sorted(p.name for p in PG.glob("[0-9][0-9][0-9][0-9]_*.sql"))
SQL_TESTS = sorted(p.name for p in (PG / "tests").glob("*.sql"))
FIXTURES = sorted(p.name for p in (PG / "tests/fixtures").glob("*.sql"))
# smoke.sql and tool_orchestration.sql build their own campaign on the fresh database and would collide
# with the upgrade fixtures; upgrade_assertions.sql runs on the upgraded database only. Every other
# SQL test must be in both chains.
CLEAN_ONLY = {"smoke.sql", "tool_orchestration.sql"}
UPGRADE_ONLY = {"upgrade_assertions.sql"}


def clean_chain() -> list[str]:
    """Paths after -f on the psql line of §Kiểm tra (the fresh-database chain)."""
    line = next(l for l in README.splitlines() if l.startswith("psql -v ON_ERROR_STOP=1"))
    return re.findall(r"-f contracts/db/postgres/(\S+)", line)


def upgrade_chain() -> list[str]:
    """The inline upgrade order: `0001_init.sql` → `tests/fixtures/...` → ..."""
    paragraph = next(l for l in README.splitlines()
                     if "Test nâng cấp trên DB riêng theo thứ tự" in l)
    return re.findall(r"`([0-9]{4}_[A-Za-z0-9_]+\.sql|tests/[A-Za-z0-9_./-]+\.sql)`", paragraph)


class ChainOnDisk(unittest.TestCase):
    def test_every_migration_is_documented_in_ascending_order(self):
        first_seen = []
        for name in MIGRATIONS:
            with self.subTest(migration=name):
                self.assertIn(f"`{name}`", README, f"{name} is not described in contracts/README.md")
            first_seen.append(README.index(f"`{name}`"))
        self.assertEqual(first_seen, sorted(first_seen),
                         "migrations are described out of order in contracts/README.md")

    def test_clean_chain_applies_every_migration_then_every_sql_test(self):
        chain = clean_chain()
        applied = [p for p in chain if p[0].isdigit()]
        self.assertEqual(applied, MIGRATIONS,
                         "the psql chain must apply 0001..NNNN in ascending order")
        for name in SQL_TESTS:
            if name in UPGRADE_ONLY:
                continue
            with self.subTest(sql_test=name):
                self.assertIn(f"tests/{name}", chain,
                              f"tests/{name} is not part of the psql gate")

    def test_upgrade_chain_applies_every_migration_and_fixture(self):
        chain = upgrade_chain()
        applied = [p for p in chain if p[0].isdigit()]
        self.assertEqual(applied, MIGRATIONS,
                         "the documented upgrade chain must apply every migration in order")
        for name in FIXTURES:
            with self.subTest(fixture=name):
                self.assertIn(f"tests/fixtures/{name}", chain,
                              f"tests/fixtures/{name} is not part of the upgrade chain")
        # The fixture that reproduces probe P1 has to be inserted before the actor rule it violates.
        self.assertLess(chain.index("tests/fixtures/post-0009-agent-actor.sql"),
                        chain.index("0010_job_actor_attribution.sql"),
                        "the post-0009 agent-actor fixture must load before 0010")
        self.assertIn("tests/upgrade_assertions.sql", chain)
        for name in SQL_TESTS:
            if name in CLEAN_ONLY:
                continue
            with self.subTest(sql_test=name):
                self.assertIn(f"tests/{name}", chain,
                              f"tests/{name} is not part of the upgrade gate")
        self.assertLess(chain.index("0011_dispatch_hold_and_search_path.sql"),
                        chain.index("tests/upgrade_assertions.sql"),
                        "0011 must run before the assertions that check its backfill")


FUNCTION_RE = re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+aegis\.([a-z0-9_]+)", re.I)
PIN_SWEEP = "ALTER FUNCTION %s SET search_path = aegis, pg_temp"


class SearchPathPinning(unittest.TestCase):
    """Every function a migration creates after the 0011 sweep must be pinned by itself or by a later sweep.

    The runtime invariant is checked from the catalog by tests/search_path_pinning.sql, which runs at the
    end of both psql chains, so an unpinned function fails the gate. This is the cheaper, earlier
    version of the same rule: a migration numbered above 0011 that creates a function must either put
    `SET search_path` in the function header or run the generic sweep itself.
    """

    def test_functions_created_after_the_sweep_are_pinned(self):
        checked = 0
        for path in sorted(PG.glob("[0-9][0-9][0-9][0-9]_*.sql")):
            if int(path.name[:4]) < 11:
                continue
            text = path.read_text()
            sweep = PIN_SWEEP in text
            for match in FUNCTION_RE.finditer(text):
                header = text[match.start():text.find("$$", match.start())]
                checked += 1
                with self.subTest(migration=path.name, function=match.group(1)):
                    self.assertTrue(
                        "SET search_path" in header or sweep,
                        f"{path.name}: aegis.{match.group(1)} has no search_path pin "
                        f"(add `SET search_path = aegis, pg_temp` or the generic sweep to the migration)")
        self.assertGreater(checked, 0, "no function-creating migration was checked; the rule is vacuous")


class FollowUpContract(unittest.TestCase):
    def test_0011_states_the_three_rules(self):
        text = (PG / "0011_dispatch_hold_and_search_path.sql").read_text()
        for fragment in [
            "SET search_path = aegis, pg_temp",
            "NOT aegis.is_initiator(j.requested_by)",
            "'LEGACY_ACTOR'",
            "OLD.dispatch_block_reasons IS NOT NULL",
            "cannot be reopened",
            "ALTER FUNCTION %s SET search_path = aegis, pg_temp",
        ]:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_the_actor_hold_is_published_where_the_claim_was_made(self):
        job = (ROOT / "capability/job.v2.schema.json").read_text()
        self.assertIn("LEGACY_ACTOR", job)
        self.assertNotIn("không có pin/proposed_by", job)
        spec = (ROOT.parent / "docs/living/dac-ta-ky-thuat/04-module-ket-noi-oss.md").read_text()
        self.assertIn("LEGACY_ACTOR", spec)
        self.assertIn("0011", spec)
        readme = README
        for name in ["tests/search_path_pinning.sql", "tests/dispatch_hold.sql",
                     "tests/fixtures/post-0009-agent-actor.sql"]:
            with self.subTest(artifact=name):
                self.assertIn(name, readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
