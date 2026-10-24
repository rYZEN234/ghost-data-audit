"""Policy engine: resolved resource states -> deletion status and ordered steps."""
from __future__ import annotations

from typing import List, Optional, Tuple

from . import model as M
from .resolve import Resource

DELETE_CATS = {M.ACCOUNT, M.SECONDARY, M.SEARCH, M.CACHE, M.EXPORT,
               M.MARKETING, M.SUPPORT_ATT}
REDACT_CATS = {M.SUPPORT_MSG, M.EMAIL_LOG, M.TOMBSTONE}
ANON_CATS = {M.ANALYTICS, M.TELEMETRY}

# finding op / remediation op / verification op per policy action
ACTIONS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "BLOCK": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
}


def judge(r: Resource, audit_at: str) -> Optional[Tuple[str, bool]]:
    """Return (policy action, violation?) for a resolved resource, or None if not applicable."""
    c, s = r.cat, r.state
    if c in DELETE_CATS:
        return "DELETE", s in (M.PRESENT, M.IDENTIFIABLE)
    if c in REDACT_CATS:
        if s == M.ABSENT:
            return None
        return "REDACT", s in (M.PRESENT, M.IDENTIFIABLE)
    if c in ANON_CATS:
        if s == M.ABSENT:
            return None
        return "ANONYMIZE", s in (M.PRESENT, M.IDENTIFIABLE)
    if c == M.FLOW:
        return "DISABLE", s == M.ACTIVE
    if c == M.BACKUP:
        return "BLOCK", s == M.RESTORABLE
    if c in (M.SECURITY, M.LEGAL):
        return "RETAIN", False
    return None


def build_steps(resources: List[Resource], audit_at: str) -> Tuple[str, List[M.Step]]:
    items = []
    for r in resources:
        j = judge(r, audit_at)
        if j is not None:
            items.append((r, j[0], j[1]))
    violations = [(r, a) for r, a, v in items if v]
    complete = not violations
    steps: List[M.Step] = []

    def verify_op(r: Resource, action: str) -> str:
        return "VERIFY_RECORD_PRESENT" if action == "RETAIN" else ACTIONS[action][2]

    if complete:
        for r, a, v in items:
            steps.append(M.Step(M.VERIFICATION, r.system, r.rid, verify_op(r, a), r.evidence))
        status = "COMPLETE"
    else:
        for r, a in violations:
            steps.append(M.Step(M.FINDING, r.system, r.rid, ACTIONS[a][0], r.evidence))
            steps.append(M.Step(M.REMEDIATION, r.system, r.rid, ACTIONS[a][1], ""))
        for r, a, v in items:
            steps.append(M.Step(M.VERIFICATION, r.system, r.rid, verify_op(r, a), ""))
        status = "INCOMPLETE"

    order = {op: i for i, op in enumerate(M.OP_ORDER)}
    phase_rank = {M.FINDING: 0, M.REMEDIATION: 1, M.VERIFICATION: 2}
    steps.sort(key=lambda s: (phase_rank[s.phase], order[s.operation], s.system_id, s.resource_id))
    return status, steps
