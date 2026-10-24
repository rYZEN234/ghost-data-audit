#!/usr/bin/env python3
"""Evaluation harness: scores the pipeline on the public samples and runs custom cases.

Usage: python3 code/evaluation/main.py [--dataset dataset]
Writes evaluation/ metrics to stdout (copy into evaluation_report.md).
"""
import argparse, csv, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))

from ghostaudit.pipeline import audit  # noqa: E402
from ghostaudit import intent, model as M  # noqa: E402
from ghostaudit.plan import build_steps  # noqa: E402
from ghostaudit.resolve import Resource  # noqa: E402

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def key(s):
    return tuple(s[f] for f in FIELDS)


def score_samples(dataset: Path):
    got = {c: (st, json.loads(sj)) for c, st, sj in audit(dataset, "sample_deletion_requests.csv")}
    gold = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(dataset / "sample_output.csv", encoding="utf-8"))}
    n = len(gold)
    status = sum(got[c][0] == gold[c][0] for c in gold)
    seq = sum([key(s) for s in got[c][1]] == [key(s) for s in gold[c][1]] for c in gold)
    steps_tot = steps_ok = fields_tot = fields_ok = 0
    for c in gold:
        g, p = gold[c][1], got[c][1]
        for i, gs in enumerate(g):
            steps_tot += 1
            ps = p[i] if i < len(p) else None
            steps_ok += ps is not None and key(ps) == key(gs)
            for f in FIELDS + ["step_no"]:
                fields_tot += 1
                fields_ok += ps is not None and ps.get(f) == gs.get(f)
    return dict(cases=n, status=status, seq=seq, steps=steps_tot, steps_ok=steps_ok,
                fields=fields_tot, fields_ok=fields_ok)


def custom_cases():
    """Hand-built scenarios exercising the policy engine and intent classifier."""
    res = []
    R = Resource
    # 1: everything compliant, legal hold retained -> COMPLETE with only verification
    st, steps = build_steps([R("account_1", "account_service", M.ACCOUNT, M.ABSENT, "evidence_1"),
                             R("legal_hold_1", "legal_service", M.LEGAL, M.PRESENT, "evidence_2")], "2026-01-01T00:00:00Z")
    res.append(("compliant + legal hold retained", st == "COMPLETE" and all(s.phase == "VERIFICATION" for s in steps)
                and any(s.operation == "VERIFY_RECORD_PRESENT" for s in steps)))
    # 2: active flow + restorable backup + leftover account -> INCOMPLETE, flows disabled before delete
    st, steps = build_steps([R("account_1", "account_service", M.ACCOUNT, M.PRESENT, "e1"),
                             R("data_flow_1", "integration_service", M.FLOW, M.ACTIVE, "e2"),
                             R("backup_1", "backup_service", M.BACKUP, M.RESTORABLE, "e3")], "2026-01-01T00:00:00Z")
    ops = [s.operation for s in steps if s.phase == "REMEDIATION"]
    res.append(("remediation order: flow/backup before delete",
                st == "INCOMPLETE" and ops.index("DISABLE_DATA_FLOW") < ops.index("DELETE_RECORD")
                and ops.index("BLOCK_RESTORE") < ops.index("DELETE_RECORD")
                and all(s.evidence_id == "" for s in steps if s.phase != "FINDING")))
    # 3: tombstone with identifiers must be redacted, not deleted; clean tombstone fine
    st, steps = build_steps([R("tombstone_1", "identity_service", M.TOMBSTONE, M.IDENTIFIABLE, "e1")], "2026-01-01T00:00:00Z")
    res.append(("tombstone with PII -> REDACT not DELETE",
                st == "INCOMPLETE" and any(s.operation == "REDACT_RECORD" for s in steps)
                and not any(s.operation == "DELETE_RECORD" for s in steps)))
    st, steps = build_steps([R("tombstone_1", "identity_service", M.TOMBSTONE, M.CLEAN, "e1")], "2026-01-01T00:00:00Z")
    res.append(("clean tombstone -> COMPLETE", st == "COMPLETE"))
    # 4: non-deletion requests / multilingual deletion
    res.append(("access request is NOT_APPLICABLE", not intent.authorizes_deletion("Please send me a copy of my data.")))
    res.append(("explicit deletion authorised", intent.authorizes_deletion("Please delete my account and all my data.")))
    res.append(("negated deletion refused", not intent.authorizes_deletion("Do not delete my account, just update my address.")))
    res.append(("Spanish deletion authorised", intent.authorizes_deletion("Por favor elimine mi cuenta y todos mis datos personales.")))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "dataset"))
    a = ap.parse_args()
    m = score_samples(Path(a.dataset))
    print("== public samples ==")
    print(f"case-level status accuracy : {m['status']}/{m['cases']} = {m['status']/m['cases']:.1%}")
    print(f"exact sequence accuracy    : {m['seq']}/{m['cases']} = {m['seq']/m['cases']:.1%}")
    print(f"step-level accuracy        : {m['steps_ok']}/{m['steps']} = {m['steps_ok']/m['steps']:.1%}")
    print(f"field-level accuracy       : {m['fields_ok']}/{m['fields']} = {m['fields_ok']/m['fields']:.1%}")
    print("== custom cases ==")
    ok = 0
    for name, passed in custom_cases():
        ok += passed
        print(("PASS " if passed else "FAIL ") + name)
    print(f"{ok}/{len(custom_cases())} custom cases pass")


if __name__ == "__main__":
    main()
