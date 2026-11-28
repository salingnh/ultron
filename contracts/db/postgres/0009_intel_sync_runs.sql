-- 0009_intel_sync_runs.sql
--
-- Scheduled intel refresh (item 80): the schedule is only half of "the intel is refreshed daily".
-- `intel_snapshot` records what was loaded, never whether the *attempt* worked: a failed NVD leg
-- writes nothing, and the next successful snapshot can be days away. The operator then sees old
-- data without being able to tell "the feed has not changed" from "every run has failed since
-- Tuesday".
--
-- `intel_sync_run` is that missing record: one row per refresh attempt, inserted as `RUNNING`
-- before the first network call and finished as `SUCCEEDED` or `FAILED` with the per-feed legs and
-- the error. `started_at` on a row that never finished is the visible sign of a worker that died
-- mid-sync (staleness still follows from the snapshots; this row says when the attempt began).
--
-- `legs` is the M18 refresh summary (`{"nvd": {...}, "kev": {...}, "epss": {...}}`) so a failed
-- feed and its error survive in PostgreSQL, not only in a log line. A `RUNNING` row never has a
-- finish time and a finished row always does; the two halves are one CHECK with three-valued NULL
-- as the thing it catches (same rule as `package_vuln_match.retraction_reason`, 0008).

BEGIN;

CREATE TABLE aegis.intel_sync_run (
    run_id uuid NOT NULL,
    trigger text NOT NULL,
    status text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    legs jsonb DEFAULT '{}'::jsonb NOT NULL,
    error text,
    CONSTRAINT intel_sync_run_pkey PRIMARY KEY (run_id),
    CONSTRAINT intel_sync_run_trigger_check CHECK (
        trigger = ANY (ARRAY['schedule'::text, 'manual'::text])
    ),
    CONSTRAINT intel_sync_run_status_check CHECK (
        status = ANY (ARRAY['RUNNING'::text, 'SUCCEEDED'::text, 'FAILED'::text])
    ),
    CONSTRAINT intel_sync_run_finish_check CHECK (
        (status = 'RUNNING') = (finished_at IS NULL)
    )
);

COMMENT ON TABLE aegis.intel_sync_run IS
    'M18. Mỗi lần chạy sync-intel (schedule hoặc tay): RUNNING rồi SUCCEEDED/FAILED, kèm legs và lỗi.';

COMMENT ON COLUMN aegis.intel_sync_run.legs IS
    'M18. Kết quả từng feed của lần chạy (legs của sync-intel), kể cả feed lỗi.';

CREATE INDEX intel_sync_run_latest
    ON aegis.intel_sync_run (started_at DESC, run_id DESC);

COMMIT;
