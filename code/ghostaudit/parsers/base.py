"""Shared parser plumbing: parse results and collection -> observation mapping."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .. import model as M
from ..util import EMAIL_RE, extract_ids, flatten_strings, is_null, norm_email, norm_phone


@dataclass
class FileCtx:
    fid: str
    cap: str          # manifest captured_at
    path: str
    origin: str = ""


@dataclass
class ParseResult:
    obs: List[M.Obs] = field(default_factory=list)
    scopes: List[M.Scope] = field(default_factory=list)


def mk(ctx: FileCtx, t: str, system: str, rid: str, cat: str, state: str, *,
       emails=(), hashes=(), refs=(), phones=(), link: str = "", copy: str = "",
       retention_until: str = "", note: str = "", fam: str = "primary", ord: tuple = ()) -> M.Obs:
    return M.Obs(
        fid=ctx.fid, cap=ctx.cap, t=t, system=system, rid=rid, cat=cat, state=state,
        emails=frozenset(norm_email(e) for e in emails if not is_null(e)),
        hashes=frozenset(h.lower() for h in hashes if not is_null(h)),
        refs=frozenset(r for r in refs if not is_null(r)),
        phones=frozenset(norm_phone(p) for p in phones if not is_null(p)),
        link=link, copy=copy, retention_until=retention_until, note=note, fam=fam, ord=ord,
    )


def ids_of(rec: dict, phone_keys: Iterable[str] = ("phone", "requester_phone", "owner_phone")):
    """Generic identifier extraction from a JSON-like record."""
    emails, hashes, refs = extract_ids(flatten_strings(rec))
    phones = []
    stack = [rec]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in phone_keys and isinstance(v, str) and not is_null(v):
                    phones.append(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return emails, hashes, refs, phones


def _has_any(rec: dict, keys: Iterable[str]) -> bool:
    return any(not is_null(rec.get(k)) for k in keys)


def collection_obs(ctx: FileCtx, t: str, store: str, coll: str, rec: dict,
                   copy: str = "", fam: str = "primary", ord: tuple = ()) -> Optional[M.Obs]:
    """Map a record of a (data_store, collection) pair to a normalised Obs.

    Used both for snapshot bundles and for the record_json SQL topologies,
    which share the same collection schemas.
    """
    rid = rec.get("resource_id")
    if not rid:
        return None
    emails, hashes, refs, phones = ids_of(rec)
    kw = dict(emails=emails, hashes=hashes, refs=refs, phones=phones, copy=copy, fam=fam, ord=ord)

    if coll == "customer_profiles":
        return mk(ctx, t, "account_service", rid, M.ACCOUNT, M.PRESENT,
                  note=str(rec.get("account_status", "")), **kw)
    if coll == "deleted_customer_references":
        # direct identifiers (name/email/phone/hash) must be gone, user ref may stay
        exposed = _has_any(rec, ("name", "email", "phone", "email_hash"))
        return mk(ctx, t, "identity_service", rid, M.TOMBSTONE,
                  M.IDENTIFIABLE if exposed else M.CLEAN, **kw)
    if coll == "customer_analytics_reports":
        exposed = _has_any(rec, ("email", "phone", "email_hash", "user_id"))
        return mk(ctx, t, "analytics_platform", rid, M.ANALYTICS,
                  M.IDENTIFIABLE if exposed else M.CLEAN, **kw)
    if coll == "customer_search_documents":
        return mk(ctx, t, "search_service", rid, M.SEARCH, M.PRESENT, **kw)
    if coll == "support_conversations":
        text = str(rec.get("message_text", ""))
        exposed = bool(EMAIL_RE.search(text)) and "[REDACTED]" not in text
        return mk(ctx, t, "support_platform", rid, M.SUPPORT_MSG,
                  M.IDENTIFIABLE if exposed else M.CLEAN, **kw)
    if coll == "ticket_attachments":
        return mk(ctx, t, "support_platform", rid, M.SUPPORT_ATT, M.PRESENT, **kw)
    if coll == "customer_export_jobs":
        return mk(ctx, t, "export_service", rid, M.EXPORT, M.PRESENT,
                  note="available" if rec.get("download_available") else "unavailable", **kw)
    if coll == "backup_catalog":
        return mk(ctx, t, "backup_service", rid, M.BACKUP,
                  M.RESTORABLE if rec.get("restore_allowed") else M.BLOCKED, **kw)
    if coll == "connector_configurations":
        return mk(ctx, t, "integration_service", rid, M.FLOW,
                  M.ACTIVE if rec.get("enabled") else M.DISABLED, **kw)
    if coll == "security_audit_events":
        return mk(ctx, t, "security_service", rid, M.SECURITY, M.PRESENT, **kw)
    if coll == "retained_order_records":
        return mk(ctx, t, "legal_service", rid, M.LEGAL, M.PRESENT,
                  retention_until=str(rec.get("retained_until", "")), **kw)
    return None


# ledger record_type/result vocabulary -----------------------------------
LEDGER_CAT = {
    "USER_PROFILE": M.ACCOUNT, "SEARCH_INDEX_ENTRY": M.SEARCH, "ANALYTICS_PROFILE": M.ANALYTICS,
    "SUPPORT_MESSAGE": M.SUPPORT_MSG, "SUPPORT_ATTACHMENT": M.SUPPORT_ATT, "USER_EXPORT": M.EXPORT,
    "DATA_FLOW": M.FLOW, "BACKUP_ARCHIVE": M.BACKUP, "SECURITY_AUDIT_LOG": M.SECURITY,
    "LEGAL_HOLD_RECORD": M.LEGAL, "ACCOUNT_TOMBSTONE": M.TOMBSTONE, "MARKETING_PROFILE": M.MARKETING,
    "EMAIL_DELIVERY_LOG": M.EMAIL_LOG, "CACHE_ENTRY": M.CACHE,
    "SECONDARY_IDENTIFIER": M.SECONDARY, "PRODUCT_TELEMETRY": M.TELEMETRY,
}
LEDGER_STATE = {
    "FOUND": M.PRESENT, "NOT_FOUND": M.ABSENT, "IDENTIFIABLE": M.IDENTIFIABLE,
    "ANONYMIZED": M.CLEAN, "REDACTED": M.CLEAN, "ACTIVE": None, "DISABLED": M.DISABLED,
    "BLOCKED": M.BLOCKED,
}


def ledger_obs(ctx: FileCtx, t: str, system: str, rid: str, rtype: str, result: str,
               subject: str) -> Optional[M.Obs]:
    cat = LEDGER_CAT.get(rtype)
    if cat is None:
        return None
    st = LEDGER_STATE.get(result, "?")
    if result == "ACTIVE":
        st = M.RESTORABLE if cat == M.BACKUP else M.ACTIVE
    if st == "?":
        return None
    emails, hashes, refs = extract_ids([subject])
    return mk(ctx, t, system, rid, cat, st, emails=emails, hashes=hashes, refs=refs)
