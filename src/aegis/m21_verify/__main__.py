"""Operator CLI of M21 (G2-B): `python -m aegis.m21_verify <decide|list>`.

* `decide --job <id>` - decide one completed `verify.check` job and record its run row (idempotent:
  a second call returns the committed row and writes nothing).
* `decide --campaign <id>` - decide every completed, undecided `verify.check` job of a campaign;
  this is what the M02 activity calls at the end of a dispatch tick and at campaign finalize, and
  what an operator runs if the dispatcher was down for the completion.
* `list --finding <id>` - the recorded runs of a finding, newest first (the same rows
  `GET /findings/{id}/verifications` serves).

Environment: `AEGIS_PG_DSN`; the evidence store (`AEGIS_S3_ENDPOINT`, `AEGIS_S3_BUCKET`) unless
`--evidence-file` points at a stored result document (a replay of an operator's recorded file).
`AEGIS_VERIFY_CONTROLS` overrides the lab control map path.

No network of its own besides the object store; no container.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from aegis.m21_verify import controls as control_map
from aegis.m21_verify.evidence import EvidenceError, MemoryEvidenceReader, reader_from_env
from aegis.m21_verify.writer import VerificationError, decide_campaign, decide_job


def _connect() -> Any:
    import psycopg

    dsn = os.environ.get("AEGIS_PG_DSN")
    if not dsn:
        raise SystemExit("AEGIS_PG_DSN is required")
    connection = psycopg.connect(dsn, autocommit=True, row_factory=psycopg.rows.dict_row)
    connection.execute("SET search_path = aegis, public")
    return connection


def _reader(argv: argparse.Namespace) -> Any:
    if argv.evidence_file is not None:
        content = Path(argv.evidence_file).read_bytes()

        uri = argv.evidence_uri or "s3://evidence/replay/result"
        return MemoryEvidenceReader({uri: content})
    return reader_from_env()


def _decide(argv: argparse.Namespace) -> int:
    reader = _reader(argv)
    mapping = control_map.load_controls(argv.controls)
    connection = _connect()
    try:
        if argv.job is not None:
            record = decide_job(connection, argv.job, reader=reader, controls=mapping)
            if record is None:
                print(json.dumps({"job_id": argv.job, "decidable": False}))
                return 1
            print(json.dumps(record.as_dict()))
            return 0
        records = decide_campaign(connection, argv.campaign, reader=reader, controls=mapping)
        print(json.dumps([record.as_dict() for record in records]))
        return 0
    except (VerificationError, EvidenceError, ValueError) as error:
        print(f"m21: {error}", file=sys.stderr)
        return 2
    finally:
        connection.close()


def _list(argv: argparse.Namespace) -> int:
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT verification_id, job_id, check_id, check_class, network_profile, outcome,"
            " requests_sent, request_cap, matched, transition_seq, created_at"
            "  FROM verification_run WHERE finding_id = %s"
            " ORDER BY created_at DESC, verification_id DESC LIMIT %s",
            (argv.finding, argv.limit),
        ).fetchall()
    finally:
        connection.close()
    print(
        json.dumps(
            [
                {
                    **{key: row[key] for key in row if key != "created_at"},
                    "created_at": row["created_at"].isoformat(),
                    "reason": (row["matched"] or {}).get("reason"),
                }
                for row in rows
            ],
            default=str,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M21 verification decision")
    sub = parser.add_subparsers(dest="command", required=True)
    decide = sub.add_parser("decide", help="decide one job or a campaign's completed verify jobs")
    group = decide.add_mutually_exclusive_group(required=True)
    group.add_argument("--job")
    group.add_argument("--campaign")
    decide.add_argument("--controls", help="path of the lab control map")
    decide.add_argument(
        "--evidence-file",
        help="replay: read the result document from this file instead of the evidence store",
    )
    decide.add_argument("--evidence-uri", help="the URI the replay file stands in for")
    listing = sub.add_parser("list", help="the recorded runs of one finding")
    listing.add_argument("--finding", required=True)
    listing.add_argument("--limit", type=int, default=50)
    arguments = parser.parse_args(argv)
    if arguments.command == "list":
        return _list(arguments)
    return _decide(arguments)


if __name__ == "__main__":
    sys.exit(main())
