"""Helper for Playwright live status change test: creates fresh job, moves to RUNNING, and triggers real M06 terminal callback + outbox event."""
import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import psycopg
from tests.db_support import SeededCampaign
from tests.g15a_support import emit_event, job_completed_payload
from tests.m02_support import accept_job, run_job, service


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python terminalise.py <dsn> <prepare|terminalise> [job_id_or_campaign_id]")
        sys.exit(1)

    dsn = sys.argv[1]
    action = sys.argv[2]
    target_id = sys.argv[3] if len(sys.argv) > 3 else None

    if action == "prepare":
        with psycopg.connect(dsn) as conn:
            if target_id:
                row = conn.execute(
                    "SELECT campaign_id, current_policy_version, scope_id FROM aegis.campaign WHERE campaign_id = %s",
                    (target_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT campaign_id, current_policy_version, scope_id FROM aegis.campaign ORDER BY created_at LIMIT 1"
                ).fetchone()

            if not row:
                print("CAMPAIGN_NOT_FOUND")
                sys.exit(2)

            target_row = conn.execute(
                "SELECT raw_value FROM campaign_target WHERE scope_id = %s AND kind = 'domain' LIMIT 1",
                (row[2],),
            ).fetchone()
            seed_domain = target_row[0] if target_row else "internal.example"

            campaign = SeededCampaign(
                campaign_id=str(row[0]),
                policy_version=row[1],
                scope_id=str(row[2]),
                seed_domain=seed_domain,
                seed_ip="10.20.0.0/24",
                known_asset="",
            )

        with service(dsn) as jobs_service:
            job_id = accept_job(jobs_service, campaign)
        run_job(dsn, job_id)
        print(f"PREPARED_JOB_ID {job_id}")
        return

    if action == "terminalise":
        if not target_id:
            print("Missing job_id for terminalise")
            sys.exit(3)

        with psycopg.connect(dsn) as conn, conn.transaction():
            row = conn.execute(
                "SELECT job_id, campaign_id, generation, attempt, status FROM aegis.scan_job WHERE job_id = %s",
                (target_id,),
            ).fetchone()
            if not row:
                print("JOB_NOT_FOUND")
                sys.exit(4)
            if row[4] == "RUNNING":
                conn.execute(
                    "SELECT aegis.record_job_callback(%s, %s, %s, 'SUCCEEDED')",
                    (row[0], row[2], row[3]),
                )
                job_dict = {
                    "job_id": str(row[0]),
                    "campaign_id": str(row[1]),
                    "generation": row[2],
                    "attempt": row[3],
                }
                seq = emit_event(
                    dsn,
                    campaign_id=str(row[1]),
                    event_type="job.completed.v2",
                    dedup_key=str(row[0]),
                    payload=job_completed_payload(job_dict, "SUCCEEDED"),
                    connection=conn,
                )
                print(f"TERMINALISE_OK seq={seq}")
            else:
                print(f"JOB_NOT_RUNNING current_status={row[4]}")
        return

    if action == "get_asset":
        with psycopg.connect(dsn) as conn:
            row = conn.execute(
                """
                SELECT a.asset_id, ac.campaign_id
                FROM asset a
                JOIN asset_campaign ac ON a.asset_id = ac.asset_id
                ORDER BY a.first_seen LIMIT 1
                """
            ).fetchone()
            if row:
                print(f"ASSET_ID {row[0]}")
                print(f"CAMPAIGN_ID {row[1]}")
            else:
                print("ASSET_NOT_FOUND")
        return

    print(f"UNKNOWN_ACTION {action}")
    sys.exit(5)


if __name__ == "__main__":
    main()
