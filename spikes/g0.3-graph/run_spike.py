#!/usr/bin/env python3
"""G0.3b spike CLI. See README.md; all runs use throwaway databases in the g03b-pg container."""

from __future__ import annotations

import argparse
import json
import sys
import time

import spike_common as common
from spike_concurrent import run as run_concurrent
from spike_pipeline import run_alloc, run_load, run_pipeline

OUT = common.OUT_DIR


def _stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _summary(results: dict) -> dict:
    out: dict = {}
    if "concurrent" in results:
        c = results["concurrent"]
        out["concurrent"] = {
            "no_retry_outcomes": c["no_retry"]["outcomes"],
            "retry": c["retry"],
            "checks": c["checks"],
            "distinct_keys_ops_per_second": c["distinct_keys"]["ops_per_second"],
        }
    if "alloc" in results:
        out["alloc"] = [
            {k: r[k] for k in ("allocator", "writers", "median_transactions_per_second", "errors")}
            for r in results["alloc"]
        ]
    if "load" in results:
        out["load"] = [
            {k: r[k] for k in ("allocator", "writers", "median_events_per_second")}
            for r in results["load"]
        ]
    if "pipeline" in results:
        out["pipeline_runs"] = []
        groups: dict[tuple[str, str], list[dict]] = {}
        for p in results["pipeline"]:
            groups.setdefault((p["allocator"], p["watermark"]), []).append(p)
            out["pipeline_runs"].append({
                "allocator": p["allocator"], "watermark": p["watermark"],
                "producers": {
                    "events": p["producers"]["events_committed_total"],
                    "wall_seconds": p["producers"]["wall_seconds"],
                    "events_per_second": p["producers"]["producer_events_per_second"],
                },
                "projector": {
                    "lag_events": p["projector"]["max_publication_lag"],
                    "refresh_attempts": p["projector"]["refresh_attempts"],
                    "refresh_blocked": p["projector"]["refresh_blocked_with_pending"],
                    "drain_seconds": p["projector"]["drain_seconds"],
                    "end_to_end_events_per_second": p["projector"]["end_to_end_events_per_second"],
                },
                "original_reconcile_ok": p["original_reconcile"]["ok"],
                "redelivery": p.get("redelivery", {}).get("graph_unchanged"),
                "rebuild_equals": p.get("rebuild", {}).get("equals_original"),
                "rebuild_reconcile_ok": p.get("rebuild", {}).get("reconcile_ok"),
                "rebuild_events_per_second": p.get("rebuild", {}).get("events_per_second"),
                "cursors": p.get("rebuild", {}).get("cursors"),
            })
        out["pipeline_medians"] = []
        for (allocator, watermark), runs in sorted(groups.items()):
            out["pipeline_medians"].append({
                "allocator": allocator, "watermark": watermark, "runs": len(runs),
                "producer_events_per_second": _med([r["producers"]["producer_events_per_second"] for r in runs]),
                "end_to_end_events_per_second": _med([r["projector"]["end_to_end_events_per_second"] for r in runs]),
                "drain_seconds": _med([r["projector"]["drain_seconds"] for r in runs]),
                "rebuild_events_per_second": _med([r["rebuild"]["events_per_second"] for r in runs]),
                "refresh_blocked": _med([r["projector"]["refresh_blocked_with_pending"] for r in runs]),
                "all_checks_pass": all(
                    r["original_reconcile"]["ok"]
                    and r.get("redelivery", {}).get("graph_unchanged", True)
                    and r.get("rebuild", {}).get("equals_original", True)
                    and r.get("rebuild", {}).get("reconcile_ok", True)
                    for r in runs
                ),
            })
    return out


def _med(values: list[float]) -> float:
    import statistics

    return round(statistics.median(values), 1) if values else 0.0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("concurrent-upsert", help="100 writers, one canonical_key, template upsert")
    p.add_argument("--writers", type=int, default=100)

    p = sub.add_parser("pipeline", help="produce -> project -> redeliver -> rebuild")
    p.add_argument("--label", default="pipeline")
    p.add_argument("--allocator", choices=["counter", "nextval"], default="counter")
    p.add_argument("--watermark", choices=["try", "blocking"], default="try")
    p.add_argument("--writers", type=int, default=100)
    p.add_argument("--events-per-writer", type=int, default=20)
    p.add_argument("--no-rebuild", action="store_true")
    p.add_argument("--no-redelivery", action="store_true")

    p = sub.add_parser("alloc", help="allocator-only throughput, identical writer transactions")
    p.add_argument("--allocator", choices=["counter", "nextval"], default="counter")
    p.add_argument("--writers", type=int, default=100)
    p.add_argument("--events", type=int, default=1000)
    p.add_argument("--runs", type=int, default=3)

    p = sub.add_parser("load", help="real writer transactions without a consumer")
    p.add_argument("--allocator", choices=["counter", "nextval"], default="counter")
    p.add_argument("--writers", type=int, default=100)
    p.add_argument("--events-per-writer", type=int, default=20)
    p.add_argument("--runs", type=int, default=3)

    p = sub.add_parser("all", help="concurrent upsert, allocator matrix, pipeline matrix")
    p.add_argument("--writers", type=int, default=100)
    p.add_argument("--events-per-writer", type=int, default=20)
    p.add_argument("--alloc-events", type=int, default=1000)
    p.add_argument("--alloc-runs", type=int, default=3)
    p.add_argument("--load-runs", type=int, default=3)
    p.add_argument("--pipeline-runs", type=int, default=1)

    args = parser.parse_args(argv)
    results: dict = {"started_at": _stamp(), "env": {
        "pg": common.PG_DSN, "neo4j": common.NEO4J_URI,
        "template_db": common.TEMPLATE_DB,
    }}

    if args.cmd == "concurrent-upsert":
        results["concurrent"] = run_concurrent(writers=args.writers)
    elif args.cmd == "pipeline":
        results["pipeline"] = [run_pipeline(
            label=f"{args.label}_{args.allocator}_{args.watermark}",
            allocator=args.allocator, watermark=args.watermark, writers=args.writers,
            events_per_writer=args.events_per_writer,
            rebuild=not args.no_rebuild, redelivery=not args.no_redelivery,
        )]
    elif args.cmd == "alloc":
        results["alloc"] = [run_alloc(
            allocator=args.allocator, writers=args.writers, total_events=args.events, runs=args.runs,
        )]
    elif args.cmd == "load":
        results["load"] = [run_load(
            allocator=args.allocator, writers=args.writers,
            events_per_writer=args.events_per_writer, runs=args.runs,
        )]
    elif args.cmd == "all":
        results["concurrent"] = run_concurrent(writers=args.writers)
        results["alloc"] = []
        for allocator in ("counter", "nextval"):
            for writers in (args.writers, 16):
                results["alloc"].append(run_alloc(
                    allocator=allocator, writers=writers, total_events=args.alloc_events, runs=args.alloc_runs,
                ))
        results["load"] = []
        for allocator in ("counter", "nextval"):
            results["load"].append(run_load(
                allocator=allocator, writers=args.writers,
                events_per_writer=args.events_per_writer, runs=args.load_runs,
            ))
        results["pipeline"] = []
        for allocator, watermark in (
            ("counter", "try"), ("nextval", "try"), ("counter", "blocking"), ("nextval", "blocking"),
        ):
            for run_index in range(args.pipeline_runs):
                results["pipeline"].append(run_pipeline(
                    label=f"all_{allocator}_{watermark}_{run_index}",
                    allocator=allocator, watermark=watermark, writers=args.writers,
                    events_per_writer=args.events_per_writer,
                ))

    results["finished_at"] = _stamp()
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"results-{results['started_at']}.json"
    common.write_json(path, results)
    common.write_json(OUT / "latest.json", results)
    print(json.dumps(_summary(results), indent=1, sort_keys=True))
    print(f"\nfull results: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
