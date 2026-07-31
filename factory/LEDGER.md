# Factory ledger

One line per trip through the production line. Full records in `runs/`.

**Regenerated from `runs/*.json` — do not hand-edit.** Two production lines running in parallel both
append here, so an append-only file conflicts on every merge. Rebuild instead of resolving:

    ~/.claude/scripts/factory_record.py --rebuild-ledger --go

Cache reads are shown separately from output because they are billed differently; summing them into one
number would misrepresent cost.

| when (UTC) | run | status | issue | commits | CI | elapsed | tokens | outcome |
|---|---|---|---|---|---|---|---|---|
