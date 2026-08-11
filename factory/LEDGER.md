# Factory ledger

One line per trip through the production line. Full records in `runs/`.

**Regenerated from `runs/*.json` — do not hand-edit.** Two production lines running in parallel both
append here, so an append-only file conflicts on every merge. Rebuild instead of resolving:

    ~/.claude/scripts/factory_record.py --rebuild-ledger --go

Cache reads are shown separately from output because they are billed differently; summing them into one
number would misrepresent cost.

| when (UTC) | run | status | issue | commits | CI | elapsed | tokens | outcome |
|---|---|---|---|---|---|---|---|---|
| 2026-08-01T05:01:53Z | issue-6 | done | #6 | 1 commits | failure | 414m | out 127,776 - cache-read 14,918,374 - agents 468,804 total across 11 spawns | bounces=0 breaker_verdict=no-defect-found findings_deferred=4 findings_fixed=1 guard_tests=1 laps=2 reviewer_blocking=0 seraph_unsure=0 slices=3 tests_added=3 |
