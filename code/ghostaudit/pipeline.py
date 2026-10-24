"""End-to-end deletion audit: dataset directory -> output rows."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

from . import intent
from .data import ActivityIndex, IdentityIndex, read_csv
from .plan import build_steps
from .resolve import Case, Resolver
from .store import EvidenceStore


def serialize(steps) -> str:
    return json.dumps([s.to_json(i + 1) for i, s in enumerate(steps)], separators=(",", ":"), ensure_ascii=False)


def audit(dataset: Path, requests_file: str = "deletion_requests.csv") -> List[Tuple[str, str, str]]:
    activity_rows = read_csv(dataset / "system_activity.csv")
    identities = read_csv(dataset / "user_identities.csv")
    audit_log = read_csv(dataset / "user_audit_log.csv")
    requests = read_csv(dataset / requests_file)

    store = EvidenceStore(dataset, activity_rows, identities, audit_log)
    idx = IdentityIndex(identities, audit_log)
    act = ActivityIndex(activity_rows)
    resolver = Resolver(store, idx, act)

    intake_non_deletion = {r["resource_id"] for r in activity_rows if r["event_type"] == "CLASSIFY_REQUEST"}

    cases = [Case(row, idx.resolve(row["email"])) for row in requests]
    for c in cases:
        resolver.direct(c)
    authorized: Dict[str, bool] = {}
    for c in cases:
        flagged = any(r in intake_non_deletion for r in c.direct)
        authorized[c.row["case_id"]] = intent.authorizes_deletion(c.row["request_text"], flagged)
    live = [c for c in cases if authorized[c.row["case_id"]]]
    resolver.link_all(live)

    rows = []
    for c in cases:
        cid = c.row["case_id"]
        if not authorized[cid]:
            rows.append((cid, "NOT_APPLICABLE", "[]"))
            continue
        resolver.build(c)
        status, steps = build_steps(c.resources, c.row["audit_at"])
        rows.append((cid, status, serialize(steps)))
    rows.sort(key=lambda r: r[0])
    return rows


def write_output(rows, path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["case_id", "deletion_status", "steps_json"])
        w.writerows(rows)
