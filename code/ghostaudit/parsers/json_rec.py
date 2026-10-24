"""JSON evidence: snapshot bundles, service exports, single-collection dumps, ledgers."""
from __future__ import annotations

import json

from .. import model as M
from ..util import is_null
from .base import FileCtx, ParseResult, collection_obs, ledger_obs, mk


def _service_export(d: dict, ctx: FileCtx, res: ParseResult) -> None:
    for system, groups in d["service_exports"].items():
        for kind, rows in groups.items():
            for r in rows:
                t = r["observed_at"]
                rid = r["resource_id"]
                if system == "account_service":
                    if r.get("status_code") == 404 or r.get("profile") is None:
                        res.obs.append(mk(ctx, t, system, rid, M.ACCOUNT, M.ABSENT))
                    else:
                        p = r["profile"]
                        res.obs.append(mk(ctx, t, system, rid, M.ACCOUNT, M.PRESENT, emails=[p.get("email")],
                                          hashes=[p.get("email_hash")], refs=[p.get("customer_reference")],
                                          phones=[p.get("phone")]))
                elif system == "search_service":
                    for doc in r["hits"]["documents"]:
                        res.obs.append(mk(ctx, t, system, doc["resource_id"], M.SEARCH, M.PRESENT,
                                          emails=[doc.get("email")], hashes=[doc.get("email_hash")],
                                          refs=[doc.get("customer_reference")], phones=[doc.get("phone")]))
                    if not r["hits"]["documents"]:
                        res.obs.append(mk(ctx, t, system, rid, M.SEARCH, M.ABSENT))
                elif system == "analytics_platform":
                    exposed = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
                    res.obs.append(mk(ctx, t, system, rid, M.ANALYTICS, M.IDENTIFIABLE if exposed else M.CLEAN,
                                      emails=[r.get("email")], hashes=[r.get("email_hash")],
                                      refs=[r.get("customer_reference")], phones=[r.get("phone")]))
                elif system == "support_platform":
                    exposed = any(not is_null(r.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
                    res.obs.append(mk(ctx, t, system, rid, M.SUPPORT_MSG, M.IDENTIFIABLE if exposed else M.CLEAN,
                                      emails=[r.get("requester_email")], refs=[r.get("customer_reference")],
                                      phones=[r.get("requester_phone")]))
                elif system == "export_service":
                    res.obs.append(mk(ctx, t, system, rid, M.EXPORT, M.PRESENT, emails=[r.get("owner_email")],
                                      refs=[r.get("customer_reference")], phones=[r.get("owner_phone")]))
                elif system == "integration_service":
                    res.obs.append(mk(ctx, t, system, rid, M.FLOW, M.ACTIVE if r["enabled"] else M.DISABLED,
                                      emails=[r.get("customer_email")], refs=[r.get("customer_reference")]))
                elif system == "backup_service":
                    res.obs.append(mk(ctx, t, system, rid, M.BACKUP,
                                      M.RESTORABLE if r["restore_allowed"] else M.BLOCKED,
                                      emails=[r.get("customer_email")], refs=[r.get("customer_reference")]))
                elif system == "security_service":
                    res.obs.append(mk(ctx, t, system, rid, M.SECURITY, M.PRESENT, refs=[r.get("subject_reference")],
                                      retention_until=r.get("retention_until", "")))


def parse_json(text: str, ctx: FileCtx) -> ParseResult:
    res = ParseResult()
    d = json.loads(text)
    if "snapshots" in d:
        for s in d["snapshots"]:
            t = s["captured_at"]
            res.scopes.append(M.Scope(ctx.fid, ctx.cap, t, s["data_store"], declared=False))
            for i, rec in enumerate(s["records"]):
                o = collection_obs(ctx, t, s["data_store"], s["collection"], rec,
                                   ord=(f"{ctx.fid}|{t}|{s['collection']}", i))
                if o is not None:
                    res.obs.append(o)
    elif "service_exports" in d:
        _service_export(d, ctx, res)
    elif "collection" in d:
        t = d["captured_at"]
        for rec in d["records"]:
            o = collection_obs(ctx, t, "", d["collection"], rec)
            if o is not None:
                res.obs.append(o)
    elif "records" in d:   # ledger
        for r in d["records"]:
            o = ledger_obs(ctx, r["recorded_at"], r["system"], r["resource_id"], r["record_type"],
                           r["result"], r.get("subject_reference", ""))
            if o is not None:
                res.obs.append(o)
    return res


def parse_handover(text: str, ctx: FileCtx) -> ParseResult:
    res = ParseResult()
    for line in text.splitlines():
        parts = [p.strip() for p in line.lstrip("- ").split("|")]
        if len(parts) == 6 and parts[0].endswith("Z"):
            o = ledger_obs(ctx, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
            if o is not None:
                res.obs.append(o)
    return res
