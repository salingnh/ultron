#!/usr/bin/env python3
"""Migration hygiene: the README gate and the files on disk must describe the same chain.

The chain is `0001_baseline.sql` plus one numbered file per later slice. This file proves that
every migration and every SQL test in `db/postgres/tests` are part of the documented gate, so a file
cannot be added to the directory and silently skipped by `contracts/README.md §Kiểm tra` (the gate
that scripts/ci/read-contract-gate.py reads and `python -m aegis.migrations` applies).

    python3 -I contracts/tests/test_migration_hygiene.py
"""
from __future__ import annotations

import re
import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PG = ROOT / "db/postgres"
README = (ROOT / "README.md").read_text()
MIGRATIONS = sorted(p.name for p in PG.glob("[0-9][0-9][0-9][0-9]_*.sql"))
SQL_TESTS = sorted(p.name for p in (PG / "tests").glob("*.sql"))


def clean_chain() -> list[str]:
    """Paths after -f on the psql line of §Kiểm tra (the fresh-database chain)."""
    line = next(l for l in README.splitlines() if l.startswith("psql -v ON_ERROR_STOP=1"))
    return re.findall(r"-f contracts/db/postgres/(\S+)", line)


class ChainOnDisk(unittest.TestCase):
    def test_the_chain_is_the_baseline_then_its_sequenced_migrations(self):
        # 0001 is the catalog dump of the locked schema; a later slice appends one numbered file
        # (0004 adds the CVE matching columns and the vulnerability.matched.v2 outbox type), and
        # the order is the version. The chain still has no upgrade path: a database built by the
        # replaced chain is reset, not upgraded.
        self.assertEqual(MIGRATIONS[0], "0001_baseline.sql",
                         "the chain must start with the baseline migration")
        versions = [int(name[:4]) for name in MIGRATIONS]
        self.assertEqual(versions, sorted(versions), f"migrations out of order: {MIGRATIONS}")
        self.assertEqual(len(versions), len(set(versions)), f"duplicate migration: {MIGRATIONS}")

    def test_every_migration_is_documented(self):
        for name in MIGRATIONS:
            with self.subTest(migration=name):
                self.assertIn(f"`{name}`", README, f"{name} is not described in contracts/README.md")

    def test_clean_chain_applies_the_migration_then_every_sql_test(self):
        chain = clean_chain()
        applied = [p for p in chain if p[0].isdigit()]
        self.assertEqual(applied, MIGRATIONS, "the psql chain must apply the migration(s) in order")
        for name in SQL_TESTS:
            with self.subTest(sql_test=name):
                self.assertIn(f"tests/{name}", chain, f"tests/{name} is not part of the psql gate")

    def test_the_documented_chain_has_no_upgrade_path(self):
        # A database carrying the old chain is reset, not upgraded: the README must not publish an
        # upgrade order, and the migration runner refuses such a database (src/aegis/migrations.py).
        self.assertNotIn("Test nâng cấp", README)
        self.assertNotIn("tests/fixtures", README)


FUNCTION_RE = re.compile(r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+aegis\.([a-z0-9_]+)", re.I)
PIN_SWEEP = "ALTER FUNCTION %s SET search_path = aegis, pg_temp"


def _slug(heading: str) -> str:
    """GitHub heading anchor: lowercase, drop punctuation, spaces to hyphens (Unicode letters kept)."""
    kept = "".join(ch for ch in heading.strip().lower()
                   if ch.isalnum() or ch in "-_ " or unicodedata.category(ch).startswith("L"))
    return kept.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    return {_slug(line.lstrip("#").strip()) for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("#")}


class DocLinks(unittest.TestCase):
    """No dead cross-file anchors: the contract narrative is cited by anchor (OI-14).

    The gate review found anchors that survived a heading edit (C04 "còn cần chứng minh" became
    "đã khóa ở S1.3", the C05 heading lost "cần khóa"); a reader following them lands nowhere. Only
    relative links into Markdown files are checked, which is what the docs use.
    """

    def test_cross_file_anchors_resolve(self):
        roots = [ROOT, ROOT.parent / "docs"]
        broken = []
        seen = 0
        for root in roots:
            for md in root.rglob("*.md"):
                text = md.read_text(encoding="utf-8")
                for match in re.finditer(r"\]\(([^)\s]+)\)", text):
                    target = match.group(1)
                    if target.startswith(("http://", "https://", "mailto:", "#")) or "#" not in target:
                        continue
                    file_part, _, anchor = target.partition("#")
                    if not file_part.endswith(".md"):
                        continue
                    target_path = (md.parent / file_part).resolve()
                    seen += 1
                    if not target_path.exists():
                        broken.append(f"{md}: {target} (missing file)")
                    elif anchor and anchor not in _anchors(target_path):
                        broken.append(f"{md}: {target} (missing anchor)")
        self.assertGreater(seen, 20, "no cross-file anchor was checked; the rule is vacuous")
        self.assertEqual(broken, [], "dead cross-file anchors:\n" + "\n".join(broken[:10]))


class SearchPathPinning(unittest.TestCase):
    """Every migration that creates a function must pin it inline or run the generic sweep.

    The runtime invariant is checked from the catalog by tests/search_path_pinning.sql, which runs at
    the end of the chain, so an unpinned function fails the gate. This is the cheaper, earlier
    version of the same rule.
    """

    def test_functions_are_pinned_by_their_migration(self):
        checked = 0
        for path in MIGRATIONS:
            text = (PG / path).read_text()
            sweep = PIN_SWEEP in text
            for match in FUNCTION_RE.finditer(text):
                header = text[match.start():text.find("$$", match.start())]
                checked += 1
                with self.subTest(migration=path, function=match.group(1)):
                    self.assertTrue(
                        "SET search_path" in header or sweep,
                        f"{path}: aegis.{match.group(1)} has no search_path pin "
                        f"(add `SET search_path = aegis, pg_temp` or the generic sweep to the migration)")
        self.assertGreater(checked, 0, "no function-creating migration was checked; the rule is vacuous")

    def test_the_baseline_asserts_its_own_pinning(self):
        text = (PG / MIGRATIONS[0]).read_text()
        self.assertIn("SET search_path = aegis, pg_temp", text)
        self.assertIn("were created without a pinned search_path", text)


class BaselineContract(unittest.TestCase):
    """The invariants the baseline must keep, stated where a reader looks for them."""

    def test_baseline_keeps_the_dispatch_and_actor_rules(self):
        text = (PG / MIGRATIONS[0]).read_text()
        for fragment in [
            "IF NOT aegis.is_initiator(NEW.requested_by) THEN",
            "aegis.require_job_decision_consistency",
            "aegis.outbox_publication_alloc",
            "aegis.outbox_watermark_refresh",
            "aegis.consumer_advance",
            "aegis.graph_revision_allocate_seq",
            "aegis.forbid_value_update",
        ]:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, text)

    def test_baseline_has_no_legacy_machinery(self):
        # The header says what was removed; the schema it creates must not carry any of it.
        text = (PG / MIGRATIONS[0]).read_text().split("BEGIN;", 1)[1]
        for fragment in [
            "legacy_contract_snapshot",
            "policy_snapshot_migration",
            "dispatch_block_reasons",
            "LEGACY_",
        ]:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, text)

    def test_job_contract_publishes_no_hold_codes(self):
        job = (ROOT / "capability/job.v2.schema.json").read_text()
        self.assertNotIn("DispatchBlockReason", job)
        self.assertNotIn("LegacyRequestedBy", job)
        self.assertNotIn("LEGACY_", job)


if __name__ == "__main__":
    unittest.main(verbosity=2)
