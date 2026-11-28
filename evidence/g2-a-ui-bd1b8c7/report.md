# G2-A Findings UI: Real-Stack Recheck on `integ/g2-findings` `@83f0129` (PR #130)

## Status: COMPLETE
PR: https://github.com/salingnh/ultron/pull/130 (kept Draft, base `integ/g2-findings`, head `bd1b8c7`) · checks: CI 3/3 green (`contracts` 3m16s, `python` 37s, `ui` 1m35s).

## Root cause (390px Findings table overflow)
- **Root cause:** `ui/src/screens/FindingsScreen.tsx:621-729` rendered `table.findings-table` as a 5-column horizontal table with `white-space: nowrap` on `th` (`ui/src/index.css:294`), giving it a minimum intrinsic width (~650–750px) wider than the 364px `.table-container` at 390px viewport, clipping columns 2–5 outside the container viewport.
- **Fix:** Added `data-label` attributes to all 5 `<td>` cells in `ui/src/screens/FindingsScreen.tsx:644-725` and stacked `table.findings-table` rows into vertical cards inside `@media (max-width: 768px)` (`ui/src/index.css:921-975`), keeping all 5 columns visible with `tableScroll=364 <= tableClient=364` and `docScroll=390 <= docClient=390`. Added `mobileTableOverflow` assertion in `ui/e2e/screens.spec.ts:374-379`.

## Acceptance (Real stack: `m26_api` + PostgreSQL 18, `VITE_USE_MOCK=false`)
| Criterion | Result | Evidence |
| --- | --- | --- |
| Rebase PR #130 onto `origin/integ/g2-findings @83f0129` + `codegen:check` | PASS | `feat/g2-a-findings-ui @bd1b8c7`; `npm run codegen` / `codegen:check` clean |
| 390px Findings table overflow fix | PASS | Real-stack 390px: `tableScroll=364, tableClient=364, docScroll=390, docClient=390`; `real-390-findings-light.png` |
| 401 before token -> token modal -> list loads | PASS | Unauth `GET /api/v2/findings` -> `401`; token modal (`op-soc-1`) -> `200` with 3 findings (`REAL API` badge) |
| Detail: provider sources, evidence metadata, timeline | PASS | `CVE-2021-41773` (`01a220a5-c08b-706a-93fa-80496d1c2901`): `subfinder`, `cpe_range`, `70%`, Evidence ID `01a220a5-bf03-7a7c-b5f3-06c2b3bbdd69`, SHA-256 `8f6d98c0dcb98b4f33fb662d3210e4a10700a0f409243d257f4dc6a3403aed54`. **Evidence signed download URL is not implemented** (UI shows `Chưa có signed download URL`). |
| UI transition -> 200 + DB `finding_transition` + `finding.changed.v2` outbox | PASS | `01a220a5-c08b-706a-93fa-80496d1c2901` -> `FALSE_POSITIVE` (`200`); `finding_transition` `seq=2`, `actor={"id":"op-soc-1","kind":"operator"}`; `outbox_event` `seq=18`, `type=finding.changed.v2`, `producer=M26`, `dedup_key=01a220a5-c08b-706a-93fa-80496d1c2901:2` |
| Same `Idempotency-Key` replay | PASS | `01a220a5-c078-7c34-9672-0d5a18c3c8cc` (`CVE-2022-22965`, `Idempotency-Key: accept-replay-key-001`): Call 1 -> `200` (`replayed=null`), Call 2 -> `200` (`Idempotent-Replayed: true`); `outbox_event` `seq=19` |
| Invalid token & second operator permissions | PASS | Invalid token -> `401`; `op-soc-2` transitioned `01a220a5-c092-716c-a03a-88a5dcc0ea83` (`CVE-2021-23017`) -> `ACCEPTED_RISK` (`200`, `seq=2`, `outbox_event` `seq=20`) |
| Stale `expected_seq` -> 409 message in UI | PASS | Browser holding `seq=1` on `01a220a5-c092-716c-a03a-88a5dcc0ea83` got `409 INPUT_INVALID` (`expected_seq 1 does not match the current transition_seq 2`), showed stale-seq banner + preserved reason |
| CI 3/3 green on PR #130 `@bd1b8c7` | PASS | `contracts` 3m16s, `python` 37s, `ui` 1m35s |

## Seeded & Verified DB Records (Campaign `01900000-0000-7000-8000-0000000c0001`)
- `finding`:
  - `01a220a5-c092-716c-a03a-88a5dcc0ea83` (`CVE-2021-23017`): `status=ACCEPTED_RISK`, `severity=UNRATED`, `transition_seq=2` (`op-soc-2`)
  - `01a220a5-c08b-706a-93fa-80496d1c2901` (`CVE-2021-41773`): `status=FALSE_POSITIVE`, `severity=UNRATED`, `transition_seq=2` (`op-soc-1`)
  - `01a220a5-c078-7c34-9672-0d5a18c3c8cc` (`CVE-2022-22965`): `status=FALSE_POSITIVE`, `severity=UNRATED`, `transition_seq=2` (`op-soc-1`)
- `outbox_event` (`finding.changed.v2`, `producer=M26`): `seq=18` (`...:2`), `seq=19` (`...:2`), `seq=20` (`...:2`).

## Change map (on PR #130 `@bd1b8c7`)
- `ui/src/screens/FindingsScreen.tsx:644-725` — add `data-label` and semantic classes for mobile stacked cards
- `ui/src/index.css:468-476,921-975` — stack `table.findings-table` rows at `<=768px`
- `ui/e2e/screens.spec.ts:374-379` — assert 390px `.table-container` `scrollWidth <= clientWidth + 2`
- `ui/screenshots/10b-mobile-390-findings-{light,dark}.png` — updated mock 390px screenshots

## Verification
- `cd ui && npm run codegen:check && npm run typecheck && npm run lint && npm test && npm run build && npm run test:e2e`: all pass (74/74 unit tests; 5 E2E passed, 1 skipped `AEGIS_E2E_THROWAWAY_DSN`).
- Real-stack Playwright acceptance (`VITE_USE_MOCK=false`, `m26_api` + PG 18 `ultron-g2a-accept-pg` as `uid:gid`): all checks passed, 0 page errors.
- Real-stack light-theme screenshots (on branch `evidence/g2-a-ui-bd1b8c7`):
  - `evidence/g2-a-ui-bd1b8c7/screenshots/real-1440-findings-detail-light.png`
  - `evidence/g2-a-ui-bd1b8c7/screenshots/real-1440-after-transition-light.png`
  - `evidence/g2-a-ui-bd1b8c7/screenshots/real-1440-stale-seq-409-light.png`
  - `evidence/g2-a-ui-bd1b8c7/screenshots/real-390-findings-light.png`

## Contract changes
none

## Choices made
- Stacked `table.findings-table` rows into cards at `<=768px` instead of hiding columns, preserving all 5 columns required by the spec.

## Look closely
- `ui/src/index.css:921-975` — mobile stacked table layout for `table.findings-table`

## Remaining / questions
- Evidence signed download URL is not yet implemented on backend (`m26_api/findings.py`); PR #130 kept Draft per instruction.

## Out-of-scope proposals
none

## Self-initiated actions
- Added `mobileTableOverflow` check in `ui/e2e/screens.spec.ts:374-379` and updated mock `10b-mobile-390-findings-{light,dark}.png` to match the 390px fix.
