"""M23's binding to the committed graph contract (G1.4b).

The projector never carries its own copy of the Cypher: the statements are read from
`contracts/graph/projector-upserts.cypher` at runtime and the per-kind/per-edge-type variants are
derived from them. `contracts/graph/model.md` fixes the node labels (kind → secondary label) and
the edge types; this module keeps those two tables and the file is the statement source, so a
contract edit lands in exactly one place.

Two substitutions are applied, both over **contract constants**, never over caller data:

* the asset statement's secondary label token `a:Domain` becomes `a:<label>` for the asset's kind
  ("mỗi kind một câu lệnh riêng");
* the edge statement's type token `:SUBDOMAIN_OF` becomes `:<TYPE>` for each type the
  `aegis.relationship` table can store (0001 CHECK), which is also how `constraints.cypher`'
  comment describes relationship schemas: "projector sinh từ danh sách loại cạnh".

`statement()` fails loudly when a template is missing or a token appears more than once, so a
contract edit that changes the statements breaks the projector's start-up instead of silently
projecting nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

from aegis.common.repo import contract_path

__all__ = [
    "CONSTRAINTS_FILE",
    "ContractMismatch",
    "KIND_LABELS",
    "PROJECTOR_FILE",
    "AFFECTED_BY_SOURCE_KINDS",
    "RELATIONSHIP_TYPES",
    "Templates",
    "asset_label",
    "asset_upsert",
    "batched",
    "constraint_statements",
    "cypher_statements",
    "evidence_upsert",
    "finding_upsert",
    "observation_upsert",
    "relationship_upsert",
    "templates",
    "vulnerability_retract",
    "vulnerability_upsert",
]

PROJECTOR_FILE: Final = "graph/projector-upserts.cypher"
CONSTRAINTS_FILE: Final = "graph/constraints.cypher"

#: model.md "Bảng kind → nhãn phụ": the secondary label of an `:Asset` node.
KIND_LABELS: Final[dict[str, str]] = {
    "domain": "Domain",
    "ip": "IP",
    "service": "Service",
    "application": "Application",
    "url": "Endpoint",
    "email": "Email",
    "oci_image": "Image",
    "repo": "Repo",
    "repo_snapshot": "RepoSnapshot",
    "artifact": "Artifact",
    "package": "Package",
    "cloud_resource": "CloudResource",
    "k8s_workload": "K8sWorkload",
}

#: model.md edge table, restricted to the types `aegis.relationship` stores (0001 CHECK): those are
#: the edges the projector reads from PostgreSQL. `HAS_FINDING`/`SUPPORTED_BY` come from the
#: finding template instead, and `AFFECTED_BY` is an M20 candidate edge with no projector statement.
RELATIONSHIP_TYPES: Final[tuple[str, ...]] = (
    "SUBDOMAIN_OF",
    "RESOLVES_TO",
    "EXPOSES",
    "SERVES",
    "HAS_ENDPOINT",
    "HAS_ARTIFACT",
    "CONTAINS_PACKAGE",
    "DISCOVERED_FROM",
    "SNAPSHOT_OF",
    "ALIAS_OF",
)

#: model.md edge table: `AFFECTED_BY` is a candidate edge from an affected asset to a
#: `:Vulnerability`. This slice extends the sources from package to the two discovery kinds; the
#: projector refuses any other kind instead of MERGEing an edge the model does not allow.
AFFECTED_BY_SOURCE_KINDS: Final[tuple[str, ...]] = ("service", "application", "package")

_ASSET_LABEL_TOKEN: Final = "a:Domain"
_EDGE_TYPE_TOKEN: Final = ":SUBDOMAIN_OF"


class ContractMismatch(RuntimeError):
    """The committed Cypher no longer has the shape M23 derives statements from."""


_PARAMETER = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def batched(statement: str) -> str:
    """The same committed statement applied to many parameter rows in one round trip.

    The derivation is mechanical and total: `UNWIND $rows AS row` puts each row in scope and every
    `$parameter` becomes `row.parameter`, so the statement text (MERGE clauses, `CASE`, `coalesce`,
    `datetime(...)`) is the committed text, unchanged. It exists because the per-statement client
    cost of the driver, not Neo4j, is the projector's ceiling: one round trip per entity measured
    ~2 250 statements/s on this host, the batched form ~5 600 rows/s, and the two are proven
    equivalent by `tests/test_m23_plan.py` (same fixture, same snapshot).

    Rows are processed in list order inside one transaction, so per-key order is preserved as long
    as the caller keeps a key's rows in publication order (the projector does: see `plan.py`).
    """
    if "row." in statement or "$rows" in statement:
        raise ContractMismatch(
            "a committed statement already uses the row alias; the batched form would collide"
        )
    body = _PARAMETER.sub(r"row.\1", statement)
    return f"UNWIND $rows AS row\n{body}"


def cypher_statements(text: str) -> list[str]:
    """Split a committed Cypher file the way contracts/graph/tests/cypher_smoke.py does.

    `//` comment lines are dropped and statements are separated by `;`; there is no free-form
    parsing, so the projector executes the same bytes the CI smoke test executes.
    """
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("//")]
    return [part.strip() for part in "\n".join(lines).split(";") if part.strip()]


@dataclass(frozen=True, slots=True)
class Templates:
    """The seven statement groups of `projector-upserts.cypher`, in file order."""

    asset: str
    relationship: str
    finding: str
    evidence: str
    vulnerability: str
    vulnerability_retract: str
    observation: str


def _only_one(statements: list[str], marker: str, name: str) -> str:
    found = [statement for statement in statements if marker in statement]
    if len(found) != 1:
        raise ContractMismatch(
            f"contracts/{PROJECTOR_FILE}: expected exactly one {name} statement "
            f"(marker {marker!r}), found {len(found)}"
        )
    return found[0]


@lru_cache(maxsize=1)
def templates() -> Templates:
    """The committed statements, re-read once per process."""
    statements = cypher_statements(contract_path(PROJECTOR_FILE).read_text(encoding="utf-8"))
    asset = _only_one(statements, "MERGE (a:Asset {canonical_key:", "asset")
    if asset.count(_ASSET_LABEL_TOKEN) != 1:
        raise ContractMismatch(
            f"contracts/{PROJECTOR_FILE}: the asset statement must name the label token "
            f"{_ASSET_LABEL_TOKEN!r} exactly once"
        )
    relationship = _only_one(statements, "MERGE (f)-[r:", "relationship")
    if relationship.count(_EDGE_TYPE_TOKEN) != 1:
        raise ContractMismatch(
            f"contracts/{PROJECTOR_FILE}: the relationship statement must name the type token "
            f"{_EDGE_TYPE_TOKEN!r} exactly once"
        )
    return Templates(
        asset=asset,
        relationship=relationship,
        finding=_only_one(statements, "MERGE (fd:Finding", "finding"),
        evidence=_only_one(statements, "MERGE (e:Evidence", "evidence"),
        vulnerability=_only_one(statements, "MERGE (v:Vulnerability", "vulnerability"),
        vulnerability_retract=_only_one(statements, "DELETE r", "vulnerability retraction"),
        observation=_only_one(statements, "MERGE (o:Observation", "observation"),
    )


def asset_label(kind: str) -> str:
    """The secondary label of `kind`; an unknown kind is a contract gap, not a silent no-op."""
    try:
        return KIND_LABELS[kind]
    except KeyError as error:
        raise ContractMismatch(
            f"asset kind {kind!r} has no label in contracts/graph/model.md"
        ) from error


def asset_upsert(kind: str) -> str:
    """Statement 1 of the template, labelled for `kind`."""
    return templates().asset.replace(_ASSET_LABEL_TOKEN, f"a:{asset_label(kind)}")


def relationship_upsert(edge_type: str) -> str:
    """Statement 2 of the template, typed for `edge_type`."""
    if edge_type not in RELATIONSHIP_TYPES:
        raise ContractMismatch(f"{edge_type!r} is not an aegis.relationship type of the contract")
    return templates().relationship.replace(_EDGE_TYPE_TOKEN, f":{edge_type}")


def finding_upsert() -> str:
    """Statement 3a: the `:Finding` node and its `HAS_FINDING` edge."""
    return templates().finding


def evidence_upsert() -> str:
    """Statement 3b: the `:Evidence` node and its `SUPPORTED_BY` edge."""
    return templates().evidence


def vulnerability_upsert() -> str:
    """Statement 4: the `:Vulnerability` node and the candidate `AFFECTED_BY` edge."""
    return templates().vulnerability


def vulnerability_retract() -> str:
    """Statement 4b: drop the `AFFECTED_BY` edge of a pair whose newest decision is a retraction."""
    return templates().vulnerability_retract


def affected_by_source(kind: str) -> str:
    """The asset kind of an `AFFECTED_BY` start, or a contract gap (never a silent skip).

    model.md's edge table names the allowed sources; a kind outside it is a producer/contract
    mismatch the projector must refuse, because MERGEing the edge would publish a graph shape the
    contract does not describe.
    """
    if kind not in AFFECTED_BY_SOURCE_KINDS:
        raise ContractMismatch(
            f"AFFECTED_BY from {kind!r}: contracts/graph/model.md allows "
            f"{', '.join(AFFECTED_BY_SOURCE_KINDS)}"
        )
    return kind


def observation_upsert() -> str:
    """Statement 5: one `:Observation` node for a `graph: true` predicate (G1.6b)."""
    return templates().observation


@lru_cache(maxsize=1)
def constraint_statements() -> tuple[str, ...]:
    """`constraints.cypher` plus the per-edge-type `relationship_id` schema it asks for.

    The file declares the `relationship_id` uniqueness constraint for `SUBDOMAIN_OF` only and
    says every edge type from PostgreSQL gets one; the extra types are generated here with a
    per-type constraint name (the file's name is already taken, and `IF NOT EXISTS` would
    silently skip the other types under a shared name). All statements are idempotent, so the
    projector applies them on every start.
    """
    statements = list(
        cypher_statements(contract_path(CONSTRAINTS_FILE).read_text(encoding="utf-8"))
    )
    declared = {
        edge_type
        for statement in statements
        for edge_type in RELATIONSHIP_TYPES
        if f"()-[r:{edge_type}]-()" in statement
    }
    if "SUBDOMAIN_OF" not in declared:
        raise ContractMismatch(
            f"contracts/{CONSTRAINTS_FILE}: the SUBDOMAIN_OF relationship_id constraint is gone"
        )
    for edge_type in RELATIONSHIP_TYPES:
        if edge_type in declared:
            continue
        statements.append(
            f"CREATE CONSTRAINT relationship_id_{edge_type} IF NOT EXISTS "
            f"FOR ()-[r:{edge_type}]-() REQUIRE r.relationship_id IS UNIQUE"
        )
    return tuple(statements)
