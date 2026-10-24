# Evaluation report

Produced by `python3 code/evaluation/main.py` (public samples + custom cases). The full 518-case run has no ground truth, so it was checked structurally (518 rows, sorted, valid JSON, consecutive step numbers, phase order, no evidence captured after `audit_at`, every COMPLETE case has cited verification evidence).

## Public samples (32 cases, `sample_output.csv`)

| Metric | Result |
|---|---|
| Case-level deletion-status accuracy | 32/32 = 100.0% |
| Sequence accuracy (exact ordered step list) | 29/32 = 90.6% |
| Step-level accuracy (all 6 compared fields match at same position) | 186/193 = 96.4% |
| Field-level accuracy (incl. step_no) | 1320/1351 = 97.7% |

Full run: INCOMPLETE 355, COMPLETE 153, NOT_APPLICABLE 10.

## Custom evaluation cases (8, all pass)

1. Compliant account + retained legal hold -> COMPLETE, verification-only, includes `VERIFY_RECORD_PRESENT`.
2. Active data flow + restorable backup + leftover account -> INCOMPLETE; `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` precede `DELETE_RECORD`; remediation/verification have empty evidence.
3. Tombstone still carrying identifiers -> `REDACT_RECORD` (never delete); a clean tombstone -> COMPLETE.
4. Intent: access request -> NOT_APPLICABLE; explicit deletion accepted; negated ("do not delete") refused; Spanish deletion accepted.

## Failures found and improvements made

- Bundle scopes overrode explicit observations (case_15) -> bundle scopes made non-declared.
- Stale replica copy hidden by a later primary snapshot (case_05) -> per-copy-family state, worst case across families.
- Support replica record mapped as message/REDACT instead of DELETE -> now a secondary record.
- Identifier-less resources (404 accounts, anonymised analytics, redacted support, tombstones) -> linked via `system_activity.csv` account events and policy/failure chains with exact-second preference and best-case assignment.
- Wrong account assigned by naming-convention fallback -> ownership check added.
- Legal hold wrongly inferred ABSENT from omission -> omission inference limited to deletable categories.
- COMPLETE cases lacking account verification evidence -> primary scope covers every system in the SQL schema.
- Sibling cases with identical reported time/status -> tie-break by record order in shared snapshots (reduced account-less cases 18 -> 14).

## Known remaining errors

- case_18, case_20: gold includes `audit_record_*` ids that appear in no participant file (unobservable).
- case_04: cites a different but equivalent evidence file (tie).
- 14 non-NA cases have no account step (ambiguous sibling accounts or image/PDF-only artifacts whose account id is not discoverable).
- Chain linking can tie within ±1 s for a few analytics records (cases 284/286, 455/457).
