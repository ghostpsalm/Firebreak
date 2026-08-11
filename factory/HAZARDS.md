## Held — found once, now guarded by a test
| hazard | path | test that holds it | commit |
| A reviewed mark could appear without ever being stored (#6) | src/ui.rs (toggle_reviewed) | ui::tests::a_failed_write_leaves_the_row_unmarked_and_says_so, ::a_mark_follows_its_rule_when_the_table_is_rebuilt_underneath | 67644f2 |
| One event's four upserts could half-apply, so the retry #7 enables would double-count them (#15) | src/store.rs (record_event) | store::tests::a_failed_event_write_leaves_no_half_written_row | 8a7b264 |
| A crafted bundle could decompress without bound on an analyst's machine (#8) | src/collect.rs (read_bundle) | collect::tests::oversize_rules_entry_is_refused, ::oversize_events_entry_leaves_no_partial_extraction | add61c9 |
| Scratch paths were guessable, inviting a symlink pre-plant on the one path that handles another machine's file (#10) | src/syspath.rs, src/collect.rs | syspath::tests::scratch_paths_differ_every_time | 5c01332 |

## Ruled out — probed with evidence, no defect found
| hypothesis | path | evidence | established at |

## Unprobed — no oracle available
| hypothesis | path | what would settle it |
| 5156/5157 direction tokens could be swapped, silently inverting every event's direction (#9) | src/event_query.rs (decode_direction) | Documentation corroborates %%14592 = Inbound (MS event 5156 schema + two DFIR references) and a test pins the mapping, but no live capture has confirmed it. `firebreak --export-support` on a real Windows host now prints a CONSISTENT/INVERTED verdict from an independent port-shape check — that closes it either way. |

## Superseded — an approach that was tried and rejected, with why
| approach | why it was rejected | what shipped instead |
|---|---|---|
| Freeze the ingest checkpoint at the last successfully-written event (drafted on `pipeline/write-safety`, never committed) | Events *after* the first failure that wrote successfully are still committed by the batch, so re-reading from the frozen point re-applies them — trading #7's under-count for the double-count #15 was filed about | Discard the whole batch on any write failure (8a7b264): the ingest is already one transaction, so nothing commits, the checkpoint does not move, and the next run re-reads the same span exactly once |
