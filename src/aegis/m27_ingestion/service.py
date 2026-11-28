"""M27 ingestion: `/ingestion/results` and the internal `Ingestion` port (owner: G1.4a).

One submission is one PostgreSQL transaction (contracts/interfaces/README.md §6):

1. the envelope is validated against `ingestion/result-envelope.v2.schema.json` with the shared
   semantic validator (`aegis.validation`), so contract shape and formats are checked once;
2. `payload_hash` = sha256 of `aegis-c14n/1` over the envelope minus event_id/dedup_key/trace;
3. the job/campaign/scope/capability/provider/policy pins and the seed refs of the job are checked
   (G2/G5 envelope-level, spec 05:83–89) — a mismatch refuses the whole envelope and records it in
   `dead_letter`, never silently;
4. `ingestion_inbox` claims the dedup_key (0006). A replay of the same content returns the first
   committed receipt with `duplicate=true`; different content returns 409 after committing an
   `ingestion_attempt` row, so a conflict is auditable; nothing already accepted is overwritten;
5. one `graph_revision` is drawn from the C04 allocator (0008), then the results pass the G1–G7
   gates. A record that fails a gate is quarantined (`quarantine_record`) with the gate and a stable
   reason; the rest of the envelope is still accepted (`partial`);
6. assets/aliases/detail rows/observations/relationships and their provenance are upserted, and the
   matching `asset.discovered.v2` / `observation.changed.v2` events are written to `outbox_event` in
   the same transaction. Neo4j is only written later by the projector (M23);
7. the receipt is written once on the inbox row and returned to the caller.

G6 (untrusted data) is structural: every value is bound as a parameter, nothing is interpreted or
executed, and raw evidence stays in the object store (M28). The findings of an envelope are
quarantined as deferred: M20 turns candidates into findings (G2.2), M27 must not invent rows the
contract has no producer for at G1.

The service does not terminalize the job: the collector (M06/G1.3a) owns the C06 callback
(`aegis.record_job_callback`) and passes the receipt's event_id as `envelope_event_id`.

The generated DTOs are `RootModel` wrappers (`Id`, `CanonicalKey`, `Timestamp`, `Sha256`). Their
`str()` is `root=...`, so every value crossing into SQL/JSON goes through `_value`/`_text`; a raw
`str()` here would store garbage that still looks like a string.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from aegis import validation
from aegis.common.ports import Ingestion
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import (
    Gate,
    IngestReceipt,
    QuarantinedItem,
)
from aegis.contracts_gen.ingestion.result_envelope_v2_schema import (
    Asset,
    Evidence,
    ResultEnvelope,
)
from aegis.m27_ingestion import canonical, normalize, predicates
from aegis.m27_ingestion.errors import EnvelopeRejected, IdempotencyConflict
from aegis.m27_ingestion.ids import uuid7

__all__ = ["Connect", "IngestionService", "RESULT_ENVELOPE_SCHEMA", "is_ingestion"]

RESULT_ENVELOPE_SCHEMA = "ingestion/result-envelope.v2.schema.json"
PRODUCER = "M27"
TRACE_TYPES = {"asset.discovered.v2", "observation.changed.v2"}

Connection = psycopg.Connection[tuple[object, ...]]
Connect = Callable[[], Connection]

#: Gate codes of `quarantine_record` / `ingest-receipt.v2#/properties/quarantined`.
GATE_IDENTITY = "G1"
GATE_PROVENANCE = "G2"
GATE_EVIDENCE = "G3"
GATE_SCHEMA = "G4"
GATE_SOURCE = "G5"
GATE_UNTRUSTED = "G6"
GATE_DEDUP = "G7"

#: Stable M27 gate reasons that the normalization/predicate registries do not own.
UNKNOWN_SUBJECT = "unknown_subject_asset"
UNKNOWN_ENDPOINT = "unknown_relationship_endpoint"
SELF_RELATIONSHIP = "self_relationship"
DETAIL_CONFLICT = "canonical_detail_conflict"
EVIDENCE_NOT_STORED = "evidence_reference_not_stored"
#: G3 owns secret scanning/verification; a secret candidate is kept in quarantine, never dropped.
SECRET_CANDIDATES_DEFERRED = "finding_secret_candidates_deferred_to_g3"


# --------------------------------------------------------------------------- value helpers


def _value(value: object) -> object:
    """Unwrap generated `RootModel` wrappers (`Id`, `CanonicalKey`, `Timestamp`, `Sha256`)."""
    current = value
    while hasattr(current, "root"):
        current = current.root
    return current


def _text(value: object) -> str:
    """The wire string of an id/key/version wrapper."""
    return str(_value(value))


def _moment(value: object) -> datetime:
    """The aware datetime of a `Timestamp` wrapper."""
    resolved = _value(value)
    if not isinstance(resolved, datetime):
        raise TypeError(f"expected a contract Timestamp, got {type(value).__name__}")
    return resolved


def _iso_z(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _enum_text(value: object, default: str) -> str:
    """Enum member (or the plain string a codegen default may leave) as its wire value."""
    if value is None:
        return default
    return str(getattr(value, "value", value))


def _json_safe(value: object) -> object:
    """Make audit JSON storable: PostgreSQL jsonb has no NaN/Infinity and no bytes."""
    if isinstance(value, float):
        finite = value == value and value not in (float("inf"), float("-inf"))
        return value if finite else str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return repr(value)


def _uuid_or_none(value: object) -> str | None:
    try:
        return str(UUID(str(value)))
    except ValueError, TypeError, AttributeError:
        return None


def _dump(model: object) -> dict[str, Any]:
    dumped = getattr(model, "model_dump", None)
    if dumped is None:  # pragma: no cover - callers pass generated DTOs
        raise TypeError(f"{type(model).__name__} is not a contract model")
    return cast(dict[str, Any], dumped(mode="json", by_alias=True, exclude_none=True))


def _coverage_document(envelope: ResultEnvelope) -> dict[str, Any]:
    """The envelope's `coverage` as the column stores it, with `complete` always answered.

    `result-envelope.v2` makes `complete` optional and M06 always sets it, but the column's
    consumer (M02 finalising a campaign, the API) must not have to guess: an absent `complete`
    with limitations is incomplete by the contract's own rule, and an absent `complete` without
    them can only mean the run finished. `subjects` and `limitations` stay byte-identical to the
    accepted envelope.
    """
    document = _dump(envelope.coverage)
    document.setdefault("complete", not document.get("limitations"))
    return document


@dataclass(frozen=True, slots=True)
class _Conflict:
    existing_payload_hash: str
    reason: str


@dataclass(slots=True)
class _AssetEntry:
    """One envelope asset: its identity, the id M27 mints for it and what the DB accepted."""

    asset: Asset
    normalized: normalize.Normalized
    asset_id: str
    index: int
    inserted: bool = False
    new_in_campaign: bool = False
    sources: list[tuple[str | None, str | None]] = field(default_factory=list)

    @property
    def pointer(self) -> str:
        return f"/results/assets/{self.index}"


@dataclass(frozen=True, slots=True)
class _Source:
    asset_id: str | None = None
    target_id: str | None = None


# --------------------------------------------------------------------------- service


class IngestionService(Ingestion):
    """The M27 endpoint. One psycopg connection per submission; one transaction per decision."""

    def __init__(
        self,
        connect: Connect,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._connect = connect
        self._now = now or (lambda: datetime.now(UTC))

    @classmethod
    def from_dsn(cls, dsn: str) -> IngestionService:
        return cls(lambda: psycopg.connect(dsn))

    def _open(self) -> Connection:
        """Open a connection pinned to the schema M27 writes; caller-owned sessions may differ."""
        connection = self._connect()
        connection.execute("SET search_path = aegis, public")
        return connection

    # -- port -----------------------------------------------------------------

    def submit(self, envelope: ResultEnvelope) -> IngestReceipt:
        """Internal caller path: the payload is the wire form of exactly the fields it set."""
        payload = envelope.model_dump(mode="json", by_alias=True, exclude_unset=True)
        return self.submit_payload(payload)

    # -- REST caller path -----------------------------------------------------

    def submit_payload(self, payload: Mapping[str, Any]) -> IngestReceipt:
        """Validate, decide and commit one envelope submitted as JSON."""
        rejected_error: EnvelopeRejected | None = None
        with self._open() as connection:
            try:
                envelope = self._validate(payload)
                try:
                    payload_hash = canonical.payload_hash(payload)
                except canonical.CanonicalizationError as error:
                    raise EnvelopeRejected(
                        "INPUT_INVALID", f"envelope has no canonical form: {error}"
                    ) from error
                with connection.transaction():
                    outcome = self._submit(
                        connection, cast(dict[str, Any], payload), envelope, payload_hash
                    )
            except EnvelopeRejected as rejected:
                # The envelope is not accepted; keep the payload and the reason for reprocessing.
                # Roll the failed decision back, write the dead letter, then let the connection
                # context commit it (raising inside the context would roll the letter back too).
                rejected_error = rejected
                connection.rollback()
                self._record_dead_letter(connection, payload, rejected)
        if rejected_error is not None:
            raise rejected_error
        if isinstance(outcome, _Conflict):
            raise IdempotencyConflict(
                envelope.dedup_key, outcome.existing_payload_hash, outcome.reason
            )
        return outcome

    # -- pipeline -------------------------------------------------------------

    def _validate(self, payload: Mapping[str, Any]) -> ResultEnvelope:
        try:
            validation.validate(RESULT_ENVELOPE_SCHEMA, dict(payload))
            envelope = ResultEnvelope.model_validate(payload)
        except validation.ContractViolation as violation:
            first = violation.errors[0] if violation.errors else ""
            raise EnvelopeRejected(
                "INPUT_INVALID",
                f"ResultEnvelope does not satisfy the contract: {first}",
                field=first.split(":", 1)[0] or None,
            ) from violation
        except ValueError as error:
            raise EnvelopeRejected(
                "INPUT_INVALID", f"ResultEnvelope is invalid: {error}"
            ) from error
        return envelope

    def _submit(
        self,
        connection: Connection,
        payload: dict[str, Any],
        envelope: ResultEnvelope,
        payload_hash: str,
    ) -> IngestReceipt | _Conflict:
        self._check_job_and_seeds(connection, envelope)
        outcome = self._claim(connection, envelope, payload_hash)
        if isinstance(outcome, (_Conflict, IngestReceipt)):
            return outcome

        revision = self._revision(connection, envelope)
        quarantined = self._apply_results(connection, envelope, revision)
        return self._finish(connection, envelope, payload_hash, revision, quarantined)

    # -- G2/G5 envelope-level checks -----------------------------------------

    def _check_job_and_seeds(self, connection: Connection, envelope: ResultEnvelope) -> None:
        job_id = _text(envelope.job_id)
        row = connection.execute(
            "SELECT campaign_id, scope_id, capability, provider, provider_version, policy_version,"
            " target_refs FROM scan_job WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if row is None:
            raise EnvelopeRejected("INPUT_INVALID", f"job {job_id} does not exist", field="/job_id")
        campaign_id, scope_id, capability, provider, provider_version, policy_version, refs = row
        checks = (
            ("/campaign_id", _text(envelope.campaign_id), str(campaign_id)),
            ("/scope_id", _text(envelope.scope_id), str(scope_id)),
            ("/capability", _text(envelope.capability), str(capability)),
            ("/provider/name", envelope.provider.name, str(provider)),
            ("/provider/version", envelope.provider.version, str(provider_version)),
            ("/policy_version", _text(envelope.policy_version), str(policy_version)),
        )
        for pointer, supplied, pinned in checks:
            if supplied != pinned:
                raise EnvelopeRejected(
                    "INPUT_INVALID",
                    f"{pointer} is {supplied!r} but the job is pinned to {pinned!r}",
                    field=pointer,
                )
        expected_key = f"job:{job_id}:envelope"
        if envelope.dedup_key != expected_key:
            raise EnvelopeRejected(
                "INPUT_INVALID",
                f"dedup_key must be {expected_key!r} for this job, got {envelope.dedup_key!r}",
                field="/dedup_key",
            )
        if refs is None:
            raise EnvelopeRejected(
                "INPUT_INVALID",
                f"job {job_id} predates target_refs and cannot carry provenance",
                field="/provenance/seed_targets",
            )

        provided = [
            ref.model_dump(mode="json", by_alias=True) for ref in envelope.provenance.seed_targets
        ]
        if provided != list(cast(list[dict[str, Any]], refs)):
            raise EnvelopeRejected(
                "INPUT_INVALID",
                "provenance.seed_targets must be the job's TargetRef list, unchanged",
                field="/provenance/seed_targets",
            )
        for index, ref in enumerate(provided):
            known: object | None
            if "seed_id" in ref:
                row = connection.execute(
                    "SELECT 1 FROM campaign_target ct JOIN scope_snapshot s"
                    " ON s.scope_id = ct.scope_id"
                    " WHERE ct.target_id = %s AND s.campaign_id = %s AND ct.scope_id = %s",
                    (ref["seed_id"], str(campaign_id), str(scope_id)),
                ).fetchone()
                known = row
            else:
                known = self._source_for(connection, str(campaign_id), str(ref["canonical_key"]))
            if known is None:
                raise EnvelopeRejected(
                    "INPUT_INVALID",
                    f"seed at index {index} is not a target or asset of campaign {campaign_id}",
                    field=f"/provenance/seed_targets/{index}",
                )

    # -- C03 claim / receipt --------------------------------------------------

    def _claim(
        self, connection: Connection, envelope: ResultEnvelope, payload_hash: str
    ) -> IngestReceipt | _Conflict | None:
        """Claim the dedup_key. None means first acceptance; the caller must finish the decision."""
        event_id = _text(envelope.event_id)
        inserted = connection.execute(
            "INSERT INTO ingestion_inbox (event_id, dedup_key, job_id, payload_hash, hash_version,"
            " coverage, status) VALUES (%s, %s, %s, %s, %s, %s, 'received')"
            " ON CONFLICT DO NOTHING RETURNING event_id",
            (
                event_id,
                envelope.dedup_key,
                _text(envelope.job_id),
                payload_hash,
                canonical.HASH_VERSION,
                Jsonb(_coverage_document(envelope)),
            ),
        ).fetchone()
        if inserted is not None:
            self._record_attempt(
                connection, event_id, envelope.dedup_key, event_id, payload_hash, "first"
            )
            return None

        existing = connection.execute(
            "SELECT event_id, payload_hash, hash_version, receipt FROM ingestion_inbox"
            " WHERE dedup_key = %s FOR UPDATE",
            (envelope.dedup_key,),
        ).fetchone()
        if existing is None:
            # No row for this dedup_key but the event_id is taken by another logical result.
            raise EnvelopeRejected(
                "INPUT_INVALID",
                f"event_id {event_id} was already used for another dedup_key",
                field="/event_id",
            )
        committed_event, committed_hash, committed_version, receipt = existing

        if committed_version != canonical.HASH_VERSION:
            reason = "hash_version_mismatch"
        elif committed_hash != payload_hash:
            reason = "hash_mismatch"
        else:
            reason = ""

        if reason:
            self._record_attempt(
                connection,
                event_id,
                envelope.dedup_key,
                str(committed_event),
                payload_hash,
                "conflict",
                Jsonb({"existing_payload_hash": str(committed_hash), "reason": reason}),
            )
            return _Conflict(str(committed_hash), reason)

        self._record_attempt(
            connection,
            event_id,
            envelope.dedup_key,
            str(committed_event),
            payload_hash,
            "duplicate",
        )
        if not isinstance(receipt, Mapping):  # pragma: no cover - receipt_once keeps it shaped
            raise EnvelopeRejected("INTERNAL_ERROR", "committed receipt is missing")
        replay = dict(receipt)
        replay["duplicate"] = True
        return IngestReceipt.model_validate(replay)

    def _record_attempt(
        self,
        connection: Connection,
        event_id: str,
        dedup_key: str,
        inbox_event_id: str,
        payload_hash: str,
        outcome: str,
        detail: Jsonb | None = None,
    ) -> None:
        """Audit one submission; a resend of the same event_id (crash retry) is already audited."""
        seen = connection.execute(
            "SELECT 1 FROM ingestion_attempt WHERE event_id = %s", (event_id,)
        ).fetchone()
        if seen is not None:
            return
        try:
            # A savepoint keeps a lost race on the same event_id from aborting the decision: the
            # unique index, not the pre-check, is what makes two concurrent retries safe.
            with connection.transaction():
                connection.execute(
                    "INSERT INTO ingestion_attempt (event_id, dedup_key, inbox_event_id,"
                    " payload_hash, hash_version, outcome, detail)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        event_id,
                        dedup_key,
                        inbox_event_id,
                        payload_hash,
                        canonical.HASH_VERSION,
                        outcome,
                        detail if detail is not None else Jsonb({}),
                    ),
                )
        except psycopg.errors.UniqueViolation:
            return

    def _revision(self, connection: Connection, envelope: ResultEnvelope) -> int:
        row = connection.execute(
            "INSERT INTO graph_revision (campaign_id, causal_job_id, envelope_event_id)"
            " VALUES (%s, %s, %s) RETURNING revision",
            (
                _text(envelope.campaign_id),
                _text(envelope.job_id),
                _text(envelope.event_id),
            ),
        ).fetchone()
        if row is None:  # pragma: no cover - the trigger always returns a row
            raise EnvelopeRejected("INTERNAL_ERROR", "graph revision allocation returned nothing")
        return int(cast(int, row[0]))

    def _finish(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        payload_hash: str,
        revision: int,
        quarantined: list[QuarantinedItem],
    ) -> IngestReceipt:
        receipt = IngestReceipt.model_validate(
            {
                "event_id": _text(envelope.event_id),
                "dedup_key": envelope.dedup_key,
                "accepted": True,
                "duplicate": False,
                "revision": revision,
                "quarantined": [
                    item.model_dump(mode="json", by_alias=True) for item in quarantined
                ],
                "payload_hash": payload_hash,
                "hash_version": canonical.HASH_VERSION,
                "decided_at": _iso_z(self._now()),
            }
        )
        connection.execute(
            "UPDATE ingestion_inbox SET status = %s, revision = %s, receipt = %s,"
            " processed_at = now() WHERE event_id = %s",
            (
                "partially_quarantined" if quarantined else "accepted",
                revision,
                Jsonb(receipt.model_dump(mode="json", by_alias=True)),
                _text(envelope.event_id),
            ),
        )
        return receipt

    # -- G1..G7 record pipeline ----------------------------------------------

    def _apply_results(
        self, connection: Connection, envelope: ResultEnvelope, revision: int
    ) -> list[QuarantinedItem]:
        finished_at = _moment(envelope.provenance.finished_at)
        quarantined: list[QuarantinedItem] = []

        entries = self._identities(connection, envelope, quarantined)
        self._resolve_sources(connection, envelope, entries, quarantined)
        self._upsert_assets(connection, envelope, entries, quarantined, finished_at)
        self._write_asset_details(connection, envelope, entries, quarantined, revision, finished_at)
        self._write_observations(connection, envelope, entries, quarantined, revision)
        self._write_relationships(connection, envelope, entries, quarantined)
        self._check_coverage(connection, envelope, entries, quarantined)
        self._write_findings(connection, envelope, entries, quarantined, revision)
        return quarantined

    def _identities(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        quarantined: list[QuarantinedItem],
    ) -> dict[str, _AssetEntry]:
        entries: dict[str, _AssetEntry] = {}
        for index, asset in enumerate(envelope.results.assets):
            pointer = f"/results/assets/{index}"
            try:
                normalized = normalize.validate_key(_text(asset.canonical_key), asset.kind.value)
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    _text(envelope.event_id),
                    GATE_IDENTITY,
                    pointer,
                    _dump(asset),
                    error.reason,
                    quarantined,
                )
                continue
            existing = entries.get(normalized.canonical_key)
            if existing is not None:
                if existing.asset.kind != asset.kind:
                    self._quarantine(
                        connection,
                        _text(envelope.event_id),
                        GATE_DEDUP,
                        pointer,
                        _dump(asset),
                        "canonical_key_declared_with_two_kinds",
                        quarantined,
                    )
                continue
            entries[normalized.canonical_key] = _AssetEntry(
                asset=asset,
                normalized=normalized,
                asset_id=str(uuid7()),
                index=index,
            )
        return entries

    def _resolve_sources(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: dict[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
    ) -> None:
        campaign_id = _text(envelope.campaign_id)
        seeds = envelope.provenance.seed_targets
        for key, entry in list(entries.items()):
            sources: list[tuple[str | None, str | None]] = []
            discovered = entry.asset.discovered_from or []
            try:
                if discovered:
                    for source_key in discovered:
                        normalized = normalize.validate_key(_text(source_key))
                        source = self._source_for(
                            connection, campaign_id, normalized.canonical_key, entries
                        )
                        if source is None:
                            raise _SourceFailure(
                                GATE_SOURCE,
                                f"discovered_from {normalized.canonical_key} is not an asset or"
                                " seed of this campaign",
                            )
                        sources.append((source.asset_id, source.target_id))
                else:
                    for ref in seeds:
                        seed_id = getattr(ref.root, "seed_id", None)
                        seed_key = getattr(ref.root, "canonical_key", None)
                        if seed_id is not None:
                            row = connection.execute(
                                "SELECT ct.target_id FROM campaign_target ct"
                                " JOIN scope_snapshot s ON s.scope_id = ct.scope_id"
                                " WHERE ct.target_id = %s AND s.campaign_id = %s",
                                (_text(seed_id), campaign_id),
                            ).fetchone()
                            if row is None:
                                raise _SourceFailure(
                                    GATE_SOURCE, f"seed {_text(seed_id)} is not in this campaign"
                                )
                            sources.append((None, str(row[0])))
                        else:
                            source = self._source_for(
                                connection, campaign_id, _text(seed_key), entries
                            )
                            if source is None:
                                raise _SourceFailure(
                                    GATE_SOURCE, f"seed asset {_text(seed_key)} is not known"
                                )
                            sources.append((source.asset_id, source.target_id))
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    _text(envelope.event_id),
                    GATE_IDENTITY,
                    entry.pointer,
                    _dump(entry.asset),
                    error.reason,
                    quarantined,
                )
                del entries[key]
                continue
            except _SourceFailure as failure:
                self._quarantine(
                    connection,
                    _text(envelope.event_id),
                    failure.gate,
                    entry.pointer,
                    _dump(entry.asset),
                    failure.reason,
                    quarantined,
                )
                del entries[key]
                continue
            entry.sources = sources

    def _source_for(
        self,
        connection: Connection,
        campaign_id: str,
        key: str,
        entries: Mapping[str, _AssetEntry] | None = None,
    ) -> _Source | None:
        """Resolve an asset key to a known asset of this campaign, or to a campaign_target seed."""
        entry = entries.get(key) if entries is not None else None
        if entry is not None:
            return _Source(asset_id=entry.asset_id)
        row = connection.execute(
            "SELECT a.asset_id FROM asset a JOIN asset_campaign ac ON ac.asset_id = a.asset_id"
            " WHERE a.canonical_key = %s AND ac.campaign_id = %s",
            (key, campaign_id),
        ).fetchone()
        if row is not None:
            return _Source(asset_id=str(row[0]))
        row = connection.execute(
            "SELECT ct.target_id FROM campaign_target ct"
            " JOIN scope_snapshot s ON s.scope_id = ct.scope_id"
            " WHERE ct.canonical_key = %s AND s.campaign_id = %s",
            (key, campaign_id),
        ).fetchone()
        if row is not None:
            return _Source(target_id=str(row[0]))
        return None

    def _upsert_assets(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: dict[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
        seen_at: datetime,
    ) -> None:
        event_id = _text(envelope.event_id)
        campaign_id = _text(envelope.campaign_id)
        job_id = _text(envelope.job_id)
        for key, entry in list(entries.items()):
            stored = connection.execute(
                "SELECT kind FROM asset WHERE canonical_key = %s", (key,)
            ).fetchone()
            if stored is not None and str(stored[0]) != entry.asset.kind.value:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_DEDUP,
                    entry.pointer,
                    _dump(entry.asset),
                    "canonical_key_kind_conflict",
                    quarantined,
                )
                del entries[key]
                continue
            row = connection.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                " first_job_id, normalization_version)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (canonical_key) DO UPDATE SET"
                " last_seen = greatest(asset.last_seen, EXCLUDED.last_seen)"
                " WHERE asset.kind = EXCLUDED.kind"
                " RETURNING asset_id, (xmax = 0) AS inserted",
                (
                    entry.asset_id,
                    key,
                    entry.asset.kind.value,
                    seen_at,
                    seen_at,
                    job_id,
                    normalize.NORM_VERSION,
                ),
            ).fetchone()
            if row is None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_DEDUP,
                    entry.pointer,
                    _dump(entry.asset),
                    "canonical_key_kind_conflict",
                    quarantined,
                )
                del entries[key]
                continue
            entry.asset_id = str(row[0])
            entry.inserted = bool(row[1])
            membership = connection.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen, first_job_id)"
                " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING asset_id",
                (entry.asset_id, campaign_id, seen_at, job_id),
            ).fetchone()
            entry.new_in_campaign = membership is not None

    def _write_asset_details(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: dict[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
        revision: int,
        seen_at: datetime,
    ) -> None:
        event_id = _text(envelope.event_id)
        campaign_id = _text(envelope.campaign_id)
        job_id = _text(envelope.job_id)
        provider = envelope.provider.name
        for entry in entries.values():
            try:
                # A savepoint keeps a constraint failure local: without it the failed statement
                # would abort the whole envelope transaction and the quarantine could not commit.
                with connection.transaction():
                    self._write_provenance(
                        connection, entry, campaign_id, job_id, provider, seen_at
                    )
            except psycopg.errors.ForeignKeyViolation:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    entry.pointer,
                    _dump(entry.asset),
                    "provenance_foreign_seed",
                    quarantined,
                )
                continue
            except psycopg.errors.CheckViolation:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    entry.pointer,
                    _dump(entry.asset),
                    "provenance_source_missing",
                    quarantined,
                )
                continue
            for alias in entry.asset.aliases or []:
                connection.execute(
                    "INSERT INTO asset_alias (alias_id, asset_id, namespace, alias_value, reason,"
                    " source_job_id, observed_at) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    " ON CONFLICT DO NOTHING",
                    (
                        str(uuid7()),
                        entry.asset_id,
                        alias.namespace.value,
                        alias.value,
                        alias.reason,
                        job_id,
                        seen_at,
                    ),
                )
            try:
                self._write_detail(connection, entry)
            except _DetailConflict as conflict:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_DEDUP,
                    entry.pointer,
                    _dump(entry.asset),
                    conflict.reason,
                    quarantined,
                )
            for from_asset, _from_target in entry.sources:
                if from_asset is None or from_asset == entry.asset_id:
                    continue
                relationship_id = self._open_relationship(
                    connection,
                    "DISCOVERED_FROM",
                    from_asset,
                    entry.asset_id,
                    seen_at,
                    1.0,
                    job_id,
                    campaign_id,
                )
                connection.execute(
                    "INSERT INTO relationship_sighting (relationship_id, scan_id, observed_at,"
                    " confidence, evidence_ids) VALUES (%s, %s, %s, %s, '{}')"
                    " ON CONFLICT DO NOTHING",
                    (relationship_id, job_id, seen_at, 1.0),
                )
            if entry.inserted or entry.new_in_campaign:
                self._emit_asset_discovered(connection, envelope, entry, revision, seen_at)

    def _write_provenance(
        self,
        connection: Connection,
        entry: _AssetEntry,
        campaign_id: str,
        job_id: str,
        provider: str,
        seen_at: datetime,
    ) -> None:
        for from_asset, from_target in entry.sources:
            connection.execute(
                "INSERT INTO asset_provenance (provenance_id, asset_id, campaign_id, from_asset_id,"
                " from_target_id, source_job_id, provider, observed_at)"
                " SELECT %s, %s, %s, %s, %s, %s, %s, %s"
                " WHERE NOT EXISTS (SELECT 1 FROM asset_provenance WHERE asset_id = %s"
                "   AND source_job_id = %s"
                "   AND from_asset_id IS NOT DISTINCT FROM %s"
                "   AND from_target_id IS NOT DISTINCT FROM %s)",
                (
                    str(uuid7()),
                    entry.asset_id,
                    campaign_id,
                    from_asset,
                    from_target,
                    job_id,
                    provider,
                    seen_at,
                    entry.asset_id,
                    job_id,
                    from_asset,
                    from_target,
                ),
            )

    def _write_detail(self, connection: Connection, entry: _AssetEntry) -> None:
        # The detail row comes from the canonical key's own rule output, never from the adapter's
        # free-form `attributes`: those cannot override the identity they claim to describe.
        detail = entry.normalized.detail
        if detail is None:
            return
        if entry.normalized.kind == "service":
            ip, port, transport = detail["ip"], detail["port"], detail["transport"]
            owner = connection.execute(
                "SELECT asset_id FROM asset_service WHERE ip = %s AND port = %s AND transport = %s",
                (ip, port, transport),
            ).fetchone()
            if owner is not None and str(owner[0]) != entry.asset_id:
                raise _DetailConflict(DETAIL_CONFLICT, f"{entry.pointer} collides with {owner[0]}")
            connection.execute(
                "INSERT INTO asset_service (asset_id, ip, port, transport)"
                " VALUES (%s, %s, %s, %s) ON CONFLICT (asset_id) DO NOTHING",
                (entry.asset_id, ip, port, transport),
            )
        elif entry.normalized.kind == "url":
            connection.execute(
                "INSERT INTO asset_url (asset_id, scheme, host, port, path, query)"
                " VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (asset_id) DO NOTHING",
                (
                    entry.asset_id,
                    detail["scheme"],
                    detail["host"],
                    detail["port"],
                    detail["path"],
                    detail["query"],
                ),
            )
        elif entry.normalized.kind == "package":
            purl = str(detail["purl"])
            owner = connection.execute(
                "SELECT asset_id FROM asset_package WHERE purl = %s", (purl,)
            ).fetchone()
            if owner is not None and str(owner[0]) != entry.asset_id:
                raise _DetailConflict(DETAIL_CONFLICT, f"{entry.pointer} collides with {owner[0]}")
            connection.execute(
                "INSERT INTO asset_package (asset_id, purl, ecosystem, name, version)"
                " VALUES (%s, %s, %s, %s, %s) ON CONFLICT (asset_id) DO NOTHING",
                (
                    entry.asset_id,
                    purl,
                    detail["ecosystem"],
                    detail["name"],
                    detail["version"],
                ),
            )

    def _write_observations(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: Mapping[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
        revision: int,
    ) -> None:
        event_id = _text(envelope.event_id)
        campaign_id = _text(envelope.campaign_id)
        job_id = _text(envelope.job_id)
        provider = envelope.provider.name
        trace = envelope.trace.model_dump(mode="json", exclude_none=True)
        for index, observation in enumerate(envelope.results.observations):
            pointer = f"/results/observations/{index}"
            try:
                normalized = normalize.validate_key(_text(observation.subject))
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_IDENTITY,
                    pointer,
                    _dump(observation),
                    error.reason,
                    quarantined,
                )
                continue
            subject_id = self._asset_id(connection, entries, normalized.canonical_key)
            if subject_id is None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    pointer,
                    _dump(observation),
                    UNKNOWN_SUBJECT,
                    quarantined,
                )
                continue
            value = observation.value
            reason = predicates.check_value(observation.predicate, value, normalized.kind)
            if reason is not None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SCHEMA,
                    pointer,
                    _dump(observation),
                    reason,
                    quarantined,
                )
                continue
            evidence_ids, verified = self._evidence_ids(
                connection, envelope, observation.evidence_refs
            )
            if not verified:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_EVIDENCE,
                    pointer,
                    _dump(observation),
                    EVIDENCE_NOT_STORED,
                    quarantined,
                )
                continue
            observed_at = _moment(observation.observed_at)
            previous = connection.execute(
                "SELECT observation_id, value FROM observation WHERE subject_asset_id = %s"
                " AND predicate = %s ORDER BY observed_at DESC, ingested_at DESC LIMIT 1",
                (subject_id, observation.predicate),
            ).fetchone()
            inserted = connection.execute(
                "INSERT INTO observation (observation_id, campaign_id, scan_id, envelope_event_id,"
                " revision, subject_asset_id, predicate, value, value_hash, polarity, confidence,"
                " provider, provider_version, evidence_ids, observed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT DO NOTHING RETURNING observation_id",
                (
                    str(uuid7()),
                    campaign_id,
                    job_id,
                    event_id,
                    revision,
                    subject_id,
                    observation.predicate,
                    Jsonb(value),
                    canonical.sha256_hex(value),
                    _enum_text(observation.polarity, "present"),
                    None if observation.confidence is None else _value(observation.confidence),
                    provider,
                    envelope.provider.version,
                    evidence_ids,
                    observed_at,
                ),
            ).fetchone()
            if inserted is None:
                continue  # the same observation already exists: G7 dedup, not a new change
            payload: dict[str, Any] = {
                "observation_id": str(inserted[0]),
                "subject_id": subject_id,
                "subject_key": normalized.canonical_key,
                "predicate": observation.predicate,
                "new_value": value,
                "causal_job_id": job_id,
                "campaign_id": campaign_id,
                "observed_at": _iso_z(observed_at),
                "polarity": _enum_text(observation.polarity, "present"),
            }
            if previous is not None:
                payload["old_value"] = previous[1]
                payload["old_observation_id"] = str(previous[0])
            self._emit(
                connection,
                "observation.changed.v2",
                str(inserted[0]),
                payload,
                trace,
                campaign_id,
            )

    def _write_relationships(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: Mapping[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
    ) -> None:
        event_id = _text(envelope.event_id)
        campaign_id = _text(envelope.campaign_id)
        job_id = _text(envelope.job_id)
        for index, relationship in enumerate(envelope.results.relationships):
            pointer = f"/results/relationships/{index}"
            try:
                source_key = normalize.validate_key(_text(relationship.from_)).canonical_key
                target_key = normalize.validate_key(_text(relationship.to)).canonical_key
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_IDENTITY,
                    pointer,
                    _dump(relationship),
                    error.reason,
                    quarantined,
                )
                continue
            source_id = self._asset_id(connection, entries, source_key)
            target_id = self._asset_id(connection, entries, target_key)
            if source_id is None or target_id is None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    pointer,
                    _dump(relationship),
                    UNKNOWN_ENDPOINT,
                    quarantined,
                )
                continue
            if source_id == target_id:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SCHEMA,
                    pointer,
                    _dump(relationship),
                    SELF_RELATIONSHIP,
                    quarantined,
                )
                continue
            evidence_ids, verified = self._evidence_ids(
                connection, envelope, relationship.evidence_refs
            )
            if not verified:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_EVIDENCE,
                    pointer,
                    _dump(relationship),
                    EVIDENCE_NOT_STORED,
                    quarantined,
                )
                continue
            observed_at = _moment(relationship.observed_at)
            relationship_id = self._open_relationship(
                connection,
                relationship.type.value,
                source_id,
                target_id,
                observed_at,
                _value(relationship.confidence),
                job_id,
                campaign_id,
                attributes=relationship.attributes,
            )
            connection.execute(
                "INSERT INTO relationship_sighting (relationship_id, scan_id, observed_at,"
                " confidence, evidence_ids) VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (
                    relationship_id,
                    job_id,
                    observed_at,
                    _value(relationship.confidence),
                    evidence_ids,
                ),
            )

    def _open_relationship(
        self,
        connection: Connection,
        relationship_type: str,
        source_id: str,
        target_id: str,
        observed_at: datetime,
        confidence: object,
        job_id: str,
        campaign_id: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> str:
        inserted = connection.execute(
            "INSERT INTO relationship (relationship_id, type, from_asset_id, to_asset_id,"
            " observed_at, valid_from, source_job_id, confidence, campaign_id, attributes)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (type, from_asset_id, to_asset_id) WHERE valid_to IS NULL DO NOTHING"
            " RETURNING relationship_id",
            (
                str(uuid7()),
                relationship_type,
                source_id,
                target_id,
                observed_at,
                observed_at,
                job_id,
                1.0 if confidence is None else float(cast(float, confidence)),
                campaign_id,
                Jsonb(dict(attributes or {})),
            ),
        ).fetchone()
        if inserted is not None:
            return str(inserted[0])
        row = connection.execute(
            "SELECT relationship_id FROM relationship WHERE type = %s AND from_asset_id = %s"
            " AND to_asset_id = %s AND valid_to IS NULL",
            (relationship_type, source_id, target_id),
        ).fetchone()
        if row is None:  # pragma: no cover - the partial unique index guarantees a row
            raise EnvelopeRejected("INTERNAL_ERROR", "open relationship vanished")
        return str(row[0])

    def _check_coverage(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: Mapping[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
    ) -> None:
        event_id = _text(envelope.event_id)
        for index, key in enumerate(envelope.coverage.subjects):
            pointer = f"/coverage/subjects/{index}"
            try:
                normalized = normalize.validate_key(_text(key))
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_IDENTITY,
                    pointer,
                    _text(key),
                    error.reason,
                    quarantined,
                )
                continue
            if self._asset_id(connection, entries, normalized.canonical_key) is None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    pointer,
                    _text(key),
                    UNKNOWN_SUBJECT,
                    quarantined,
                )

    def _write_findings(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entries: Mapping[str, _AssetEntry],
        quarantined: list[QuarantinedItem],
        revision: int,
    ) -> None:
        """Keep every validated scanner finding as a `finding_candidate` (M20 decides findings).

        M27 does not invent a `finding` row: the fingerprint, provider merge, status and severity
        are M20's (`aegis.m20_vuln.candidates`). What it does enforce here is the same evidence
        contract as for an observation - a candidate is stored only when its subject is an asset
        this campaign knows and every evidence ref resolves to stored bytes - so a finding can
        never cite output nobody kept.
        """
        event_id = _text(envelope.event_id)
        campaign_id = _text(envelope.campaign_id)
        job_id = _text(envelope.job_id)
        provider = envelope.provider.name
        provider_version = str(envelope.provider.version)
        for index, finding in enumerate(envelope.results.findings):
            pointer = f"/results/findings/{index}"
            if finding.category is not None and finding.category.value == "secret":
                # G2-D covers SBOM/vulnerability analysis; secret scanning and its fingerprint
                # policy are G3's. Quarantine keeps the candidate for that slice (no data loss).
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SCHEMA,
                    pointer,
                    _dump(finding),
                    SECRET_CANDIDATES_DEFERRED,
                    quarantined,
                )
                continue
            try:
                normalized = normalize.validate_key(_text(finding.subject))
            except (normalize.NormalizationError, normalize.KeyRejection) as error:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_IDENTITY,
                    pointer,
                    _dump(finding),
                    error.reason,
                    quarantined,
                )
                continue
            subject_id = self._asset_id(connection, entries, normalized.canonical_key)
            if subject_id is None:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_SOURCE,
                    pointer,
                    _dump(finding),
                    UNKNOWN_SUBJECT,
                    quarantined,
                )
                continue
            evidence_ids, verified = self._evidence_ids(connection, envelope, finding.evidence_refs)
            if not verified or not evidence_ids:
                self._quarantine(
                    connection,
                    event_id,
                    GATE_EVIDENCE,
                    pointer,
                    _dump(finding),
                    EVIDENCE_NOT_STORED,
                    quarantined,
                )
                continue
            location = {} if finding.location is None else finding.location.model_dump(mode="json")
            observed_at = _moment(envelope.provenance.finished_at)
            connection.execute(
                "INSERT INTO finding_candidate (candidate_id, campaign_id, scan_id,"
                " envelope_event_id, revision, subject_asset_id, provider, provider_version,"
                " rule_id, category, title, description, location, location_hash,"
                " vulnerability_ids, cwe_ids, scanner_severity, fingerprint_context, confidence,"
                " evidence_ids, observed_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
                "         %s, %s, %s, %s)"
                " ON CONFLICT DO NOTHING",
                (
                    str(uuid7()),
                    campaign_id,
                    job_id,
                    event_id,
                    revision,
                    subject_id,
                    provider,
                    provider_version,
                    _text(finding.rule_id),
                    "vulnerability" if finding.category is None else finding.category.value,
                    _text(finding.title),
                    None if finding.description is None else _text(finding.description),
                    Jsonb(location),
                    canonical.sha256_hex(location),
                    [_text(item) for item in finding.vulnerability_ids or ()],
                    [_text(item) for item in finding.cwe_ids or ()],
                    None if finding.scanner_severity is None else finding.scanner_severity.value,
                    Jsonb(dict(finding.fingerprint_context)),
                    None if finding.confidence is None else _value(finding.confidence),
                    evidence_ids,
                    observed_at,
                ),
            )

    # -- evidence (G3) --------------------------------------------------------

    def _evidence_ids(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        refs: Sequence[object] | None,
    ) -> tuple[list[str], bool]:
        if not refs:
            return [], True
        local: dict[str, Evidence] = {
            evidence.local_ref: evidence for evidence in envelope.evidence
        }
        resolved: list[str] = []
        for ref in refs:
            local_ref = getattr(ref, "local_ref", None)
            evidence_id = getattr(ref, "evidence_id", None)
            if local_ref is not None:
                evidence = local.get(str(local_ref))
                if evidence is None:
                    return [], False
                row = connection.execute(
                    "SELECT evidence_id FROM evidence WHERE storage_uri = %s AND sha256 = %s"
                    " AND size_bytes = %s AND campaign_id = %s AND job_id = %s",
                    (
                        evidence.uri,
                        _text(evidence.sha256),
                        evidence.size_bytes,
                        _text(envelope.campaign_id),
                        _text(envelope.job_id),
                    ),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT evidence_id FROM evidence WHERE evidence_id = %s AND campaign_id = %s",
                    (_text(evidence_id), _text(envelope.campaign_id)),
                ).fetchone()
            if row is None:
                return [], False
            resolved.append(str(row[0]))
        return resolved, True

    # -- helpers --------------------------------------------------------------

    def _asset_id(
        self,
        connection: Connection,
        entries: Mapping[str, _AssetEntry],
        key: str,
    ) -> str | None:
        entry = entries.get(key)
        if entry is not None:
            return entry.asset_id
        row = connection.execute(
            "SELECT asset_id FROM asset WHERE canonical_key = %s", (key,)
        ).fetchone()
        return None if row is None else str(row[0])

    def _emit(
        self,
        connection: Connection,
        event_type: str,
        dedup_key: str,
        payload: Mapping[str, Any],
        trace: Mapping[str, Any],
        campaign_id: str,
    ) -> None:
        if event_type not in TRACE_TYPES:  # pragma: no cover - only the two types above are emitted
            raise ValueError(f"M27 does not emit {event_type!r}")
        connection.execute(
            "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload,"
            " trace) VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (type, dedup_key) DO NOTHING",
            (
                str(uuid7()),
                event_type,
                PRODUCER,
                dedup_key,
                campaign_id,
                Jsonb(dict(payload)),
                Jsonb(dict(trace)),
            ),
        )

    def _emit_asset_discovered(
        self,
        connection: Connection,
        envelope: ResultEnvelope,
        entry: _AssetEntry,
        revision: int,
        seen_at: datetime,
    ) -> None:
        payload: dict[str, Any] = {
            "asset_id": entry.asset_id,
            "canonical_key": entry.normalized.canonical_key,
            "kind": entry.normalized.kind,
            "revision": revision,
            "causal_job_id": _text(envelope.job_id),
            "campaign_id": _text(envelope.campaign_id),
            "discovered_from": [_text(key) for key in (entry.asset.discovered_from or [])],
            "first_seen": _iso_z(seen_at),
        }
        self._emit(
            connection,
            "asset.discovered.v2",
            f"{entry.asset_id}:{revision}",
            payload,
            envelope.trace.model_dump(mode="json", exclude_none=True),
            _text(envelope.campaign_id),
        )

    def _quarantine(
        self,
        connection: Connection,
        event_id: str,
        gate: str,
        pointer: str,
        record: object,
        reason: str,
        quarantined: list[QuarantinedItem],
    ) -> None:
        connection.execute(
            "INSERT INTO quarantine_record (quarantine_id, event_id, gate, record_pointer, record,"
            " reason) VALUES (%s, %s, %s, %s, %s, %s)",
            (str(uuid7()), event_id, gate, pointer, Jsonb(record), reason),
        )
        quarantined.append(QuarantinedItem(pointer=pointer, gate=Gate(gate), reason=reason))

    def _record_dead_letter(
        self, connection: Connection, payload: Mapping[str, Any], rejected: EnvelopeRejected
    ) -> None:
        error: dict[str, Any] = {
            "code": rejected.code,
            "message": rejected.message[:2000],
            "next_action": rejected.next_action,
        }
        if rejected.field is not None:
            error["field"] = rejected.field
        connection.execute(
            "INSERT INTO aegis.dead_letter (dlq_id, source, event_id, payload, error)"
            " VALUES (%s, 'ingestion', %s, %s, %s)",
            (
                str(uuid7()),
                _uuid_or_none(payload.get("event_id")),
                Jsonb(cast(dict[str, Any], _json_safe(payload))),
                Jsonb(error),
            ),
        )


class _SourceFailure(Exception):
    def __init__(self, gate: str, reason: str) -> None:
        super().__init__(reason)
        self.gate = gate
        self.reason = reason


class _DetailConflict(Exception):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def is_ingestion(candidate: object) -> bool:
    """True when `candidate` implements the M27 port (used by wiring/tests)."""
    return isinstance(candidate, Ingestion)
