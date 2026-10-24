"""Vocabulary and data classes shared by every module."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

# ---------------------------------------------------------------- categories
# These match deletion_rules.csv data_category values.
ACCOUNT = "USER_PROFILE"
SECONDARY = "SECONDARY_IDENTIFIER"
SEARCH = "SEARCH_INDEX_ENTRY"
CACHE = "CACHE_ENTRY"
SUPPORT_MSG = "SUPPORT_MESSAGE"
SUPPORT_ATT = "SUPPORT_ATTACHMENT"
ANALYTICS = "ANALYTICS_PROFILE"
TELEMETRY = "PRODUCT_TELEMETRY"
EXPORT = "USER_EXPORT"
MARKETING = "MARKETING_PROFILE"
EMAIL_LOG = "EMAIL_DELIVERY_LOG"
SECURITY = "SECURITY_AUDIT_LOG"
LEGAL = "LEGAL_HOLD_RECORD"
BACKUP = "BACKUP_ARCHIVE"
TOMBSTONE = "ACCOUNT_TOMBSTONE"
FLOW = "DATA_FLOW"

# ------------------------------------------------------------ observed state
PRESENT = "PRESENT"            # the record exists
ABSENT = "ABSENT"              # the record does not exist
IDENTIFIABLE = "IDENTIFIABLE"  # record exists and still carries direct identifiers
CLEAN = "CLEAN"                # record exists with identifiers removed / anonymised
ACTIVE = "ACTIVE"              # data flow is running
DISABLED = "DISABLED"          # data flow is stopped
RESTORABLE = "RESTORABLE"      # backup can still restore the user's data
BLOCKED = "BLOCKED"            # backup restore is blocked

# ---------------------------------------------------------------- operations
FINDING, REMEDIATION, VERIFICATION = "FINDING", "REMEDIATION", "VERIFICATION"

OP_STATE = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

# Order of operations inside a phase (problem statement table order).
OP_ORDER = list(OP_STATE.keys())

# resource-id prefix -> owning system
PREFIX_SYSTEM = {
    "account": "account_service",
    "search": "search_service",
    "support": "support_platform",
    "analytics": "analytics_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "marketing": "marketing_platform",
    "email_delivery": "email_delivery_service",
    "cache": "cache_service",
    "object": "object_storage",
}


def rid_prefix(rid: str) -> str:
    for p in sorted(PREFIX_SYSTEM, key=len, reverse=True):
        if rid.startswith(p + "_"):
            return p
    return rid.split("_")[0]


@dataclass(frozen=True)
class Obs:
    """One observation of one resource inside one evidence file."""

    fid: str                 # evidence file_id
    cap: str                 # file captured_at (citation cut-off)
    t: str                   # time the state was observed (<= cap normally)
    system: str
    rid: str
    cat: str
    state: str
    emails: FrozenSet[str] = frozenset()
    hashes: FrozenSet[str] = frozenset()
    refs: FrozenSet[str] = frozenset()
    phones: FrozenSet[str] = frozenset()
    link: str = ""           # related resource id (e.g. search doc -> account)
    copy: str = ""           # primary / replica table name
    retention_until: str = ""
    note: str = ""           # free text kept for debugging
    fam: str = "primary"     # copy family: "primary" (authoritative views) or a replica key
    ord: tuple = ()          # (snapshot group, position): records are written in request order


@dataclass(frozen=True)
class Scope:
    """A snapshot that covers an entire system: absence-by-omission proof."""

    fid: str
    cap: str
    t: str
    system: str
    declared: bool = True    # coverage explicitly declared (SQL scope tables / primaries)
    fam: str = "primary"


@dataclass
class Step:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    evidence_id: str = ""

    @property
    def state(self) -> str:
        return OP_STATE[self.operation][1]

    def to_json(self, n: int) -> dict:
        return {
            "step_no": n,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }
