"""M23's contract bindings: the committed Cypher, the kind/label and edge tables, `batched()`.

These tests fail when the contract moves under the projector: the statements are loaded from
`contracts/graph/projector-upserts.cypher` (never copied), and the tables `contract.py` keeps are
compared with `contracts/graph/model.md` and the `aegis.relationship` CHECK of migration 0001.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegis.common.repo import contract_path, repository_root
from aegis.m23_graph import contract


def _model_markdown() -> str:
    return contract_path("graph/model.md").read_text(encoding="utf-8")


def _kind_table() -> dict[str, str]:
    match = re.search(r"Bảng kind → nhãn phụ:([^\n]+)", _model_markdown())
    assert match is not None, "model.md lost its kind → label table"
    return dict(re.findall(r"(\w+) `:(\w+)`", match.group(1)))


def _edge_table() -> set[str]:
    rows = re.findall(r"^\| `([A-Z][A-Z_]+)` \|", _model_markdown(), re.MULTILINE)
    assert rows, "model.md lost its edge table"
    return set(rows)


def _relationship_check() -> set[str]:
    path = repository_root() / "contracts/db/postgres/0001_baseline.sql"
    ddl = path.read_text(encoding="utf-8")
    block = re.search(r"CREATE TABLE aegis\.relationship \((.*?)\n\);", ddl, re.DOTALL)
    assert block is not None, "0001_baseline.sql lost the relationship table"
    check = re.search(
        r"relationship_type_check CHECK \(\(type = ANY \(ARRAY\[(.*?)\]\)\)\)",
        block.group(1),
        re.DOTALL,
    )
    assert check is not None, "the relationship.type CHECK moved; update this parser"
    return set(re.findall(r"'([A-Z_]+)'", check.group(1)))


def test_kind_labels_are_the_model_table() -> None:
    assert contract.KIND_LABELS == _kind_table()


def test_relationship_types_are_the_model_edges_stored_by_postgres() -> None:
    assert set(contract.RELATIONSHIP_TYPES) == _edge_table() & _relationship_check()
    assert len(contract.RELATIONSHIP_TYPES) == len(set(contract.RELATIONSHIP_TYPES))


def test_statements_come_from_the_committed_file() -> None:
    statements = contract.cypher_statements(
        contract_path(contract.PROJECTOR_FILE).read_text(encoding="utf-8")
    )
    templates = contract.templates()
    assert templates.asset in statements
    assert templates.relationship in statements
    assert templates.finding in statements
    assert templates.evidence in statements


def test_every_kind_gets_its_own_label_and_statement() -> None:
    for kind, label in contract.KIND_LABELS.items():
        statement = contract.asset_upsert(kind)
        assert f"SET a:{label}," in statement
        assert "a:Domain" not in statement or label == "Domain"
        assert "$canonical_key" in statement


def test_every_edge_type_gets_its_own_statement() -> None:
    for edge_type in contract.RELATIONSHIP_TYPES:
        statement = contract.relationship_upsert(edge_type)
        assert f"MERGE (f)-[r:{edge_type} {{relationship_id: $relationship_id}}]->(t)" in statement
        assert statement.count("SUBDOMAIN_OF") == (1 if edge_type == "SUBDOMAIN_OF" else 0)


def test_unknown_kind_or_edge_type_is_refused() -> None:
    with pytest.raises(contract.ContractMismatch):
        contract.asset_upsert("quantum_thing")
    with pytest.raises(contract.ContractMismatch):
        contract.relationship_upsert("KNOWS")


def test_constraints_cover_the_file_and_every_edge_type() -> None:
    statements = contract.constraint_statements()
    text = "\n".join(statements)
    for edge_type in contract.RELATIONSHIP_TYPES:
        if edge_type == "SUBDOMAIN_OF":
            assert "()-[r:SUBDOMAIN_OF]-()" in text
        else:
            assert f"CREATE CONSTRAINT relationship_id_{edge_type} IF NOT EXISTS" in text
    for label in ("Asset", "Finding", "Evidence", "Campaign", "Observation", "Job"):
        assert re.search(rf"FOR \(\w:{label}\)", text), label
    assert "REQUIRE r.relationship_id IS UNIQUE" in text


def test_batched_rewrites_every_parameter_and_nothing_else() -> None:
    for statement in (
        contract.asset_upsert("domain"),
        contract.relationship_upsert("SUBDOMAIN_OF"),
        contract.finding_upsert(),
        contract.evidence_upsert(),
    ):
        batched = contract.batched(statement)
        assert batched.startswith("UNWIND $rows AS row\n")
        body = batched.split("\n", 1)[1]
        assert body == re.sub(r"\$([A-Za-z_]\w*)", r"row.\1", statement)
        assert "$" not in body.replace("row.", "")


def test_batched_refuses_a_statement_that_already_uses_the_row_alias() -> None:
    with pytest.raises(contract.ContractMismatch):
        contract.batched("MATCH (n) RETURN row.x")


def test_a_contract_edit_that_removes_a_statement_fails_loudly(tmp_path: Path) -> None:
    """`_only_one` is what turns "the template lost a statement" into a start-up failure."""
    empty: list[str] = []
    with pytest.raises(contract.ContractMismatch):
        contract._only_one(empty, "MERGE (a:Asset {canonical_key:", "asset")
