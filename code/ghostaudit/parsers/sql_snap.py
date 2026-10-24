"""SQLite-compatible SQL snapshot exports (inventory, replicas, failover...)."""
from __future__ import annotations

import json
import re
import sqlite3
from typing import List

from .. import model as M
from ..util import is_null
from .base import FileCtx, ParseResult, collection_obs, mk


def _fam(ctx: FileCtx, table: str) -> str:
    """Primary tables are the authoritative view; replica tables are separate stale-able copies."""
    if table.endswith("primary") or "replica" not in table:
        return "primary"
    return f"{ctx.origin}:{table}"


def _rows(con, table):
    cur = con.execute(f'SELECT * FROM "{table}"')
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def parse_sql(text: str, ctx: FileCtx) -> ParseResult:
    res = ParseResult()
    con = sqlite3.connect(":memory:")
    con.executescript(text)
    m = re.search(r"Captured at:\s*(\S+)", text) or re.search(r"snapshot_completed_at=(\S+)", text)
    file_t = m.group(1) if m else ctx.cap
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    all_systems = set()

    # ---- inventory style: one table per data category + snapshot_scope
    scope_t = {}
    if "snapshot_scope" in tables:
        for r in _rows(con, "snapshot_scope"):
            scope_t[r["origin_system"]] = r["captured_at"]
            res.scopes.append(M.Scope(ctx.fid, ctx.cap, r["captured_at"], r["origin_system"]))

    def t_for(system: str) -> str:
        return scope_t.get(system, file_t)

    for table in tables:
        rows = _rows(con, table)
        if table == "customer_profiles":
            for r in rows:
                res.obs.append(mk(ctx, t_for("account_service"), "account_service", r["resource_id"],
                                  M.ACCOUNT, M.PRESENT, emails=[r["email"]], hashes=[r["email_hash"]],
                                  refs=[r["customer_reference"]], phones=[r["phone"]], copy=table,
                                  note=str(r["account_status"])))
        elif table == "customer_search_documents":
            for r in rows:
                res.obs.append(mk(ctx, t_for("search_service"), "search_service", r["resource_id"],
                                  M.SEARCH, M.PRESENT, emails=[r["email"]], hashes=[r["email_hash"]],
                                  refs=[r["customer_reference"]], phones=[r["phone"]], copy=table))
        elif table == "customer_analytics_profiles":
            for r in rows:
                exposed = any(not is_null(r[k]) for k in ("email", "phone", "email_hash", "customer_reference"))
                res.obs.append(mk(ctx, t_for("analytics_platform"), "analytics_platform", r["resource_id"],
                                  M.ANALYTICS, M.IDENTIFIABLE if exposed else M.CLEAN,
                                  emails=[r["email"]], hashes=[r["email_hash"]],
                                  refs=[r["customer_reference"]], phones=[r["phone"]], copy=table))
        elif table == "support_records":
            for r in rows:
                exposed = any(not is_null(r[k]) for k in ("requester_name", "requester_email", "requester_phone"))
                res.obs.append(mk(ctx, t_for("support_platform"), "support_platform", r["resource_id"],
                                  M.SUPPORT_MSG, M.IDENTIFIABLE if exposed else M.CLEAN,
                                  emails=[r["requester_email"]], refs=[r["customer_reference"]],
                                  phones=[r["requester_phone"]], copy=table, note=r["message_excerpt"]))
        elif table == "customer_exports":
            for r in rows:
                res.obs.append(mk(ctx, t_for("export_service"), "export_service", r["resource_id"],
                                  M.EXPORT, M.PRESENT, emails=[r["owner_email"]],
                                  refs=[r["customer_reference"]], phones=[r["owner_phone"]], copy=table))
        elif table == "connector_subscriptions":
            for r in rows:
                res.obs.append(mk(ctx, t_for("integration_service"), "integration_service", r["resource_id"],
                                  M.FLOW, M.ACTIVE if int(r["enabled"]) else M.DISABLED,
                                  emails=[r["customer_email"]], refs=[r["customer_reference"]], copy=table,
                                  note=r["last_delivery_status"]))
        elif table == "backup_restore_entries":
            for r in rows:
                res.obs.append(mk(ctx, t_for("backup_service"), "backup_service", r["resource_id"],
                                  M.BACKUP, M.RESTORABLE if int(r["restore_allowed"]) else M.BLOCKED,
                                  emails=[r["customer_email"]], refs=[r["customer_reference"]], copy=table))
        elif table == "security_audit_records":
            for r in rows:
                res.obs.append(mk(ctx, t_for("security_service"), "security_service", r["resource_id"],
                                  M.SECURITY, M.PRESENT, refs=[r["subject_reference"]], copy=table,
                                  retention_until=r["retention_until"], note=r["event_code"]))
        # ---- failover accounts
        elif table in ("customer_profiles_primary", "customer_profiles_failover_replica"):
            res.scopes.append(M.Scope(ctx.fid, ctx.cap, file_t, "account_service", True, _fam(ctx, table)))
            for r in rows:
                res.obs.append(mk(ctx, file_t, "account_service", r["resource_id"], M.ACCOUNT, M.PRESENT,
                                  emails=[r["email"]], refs=[r["user_id"]], phones=[r["phone"]], copy=table,
                                  note=str(r["account_status"]), fam=_fam(ctx, table)))
        # ---- search primary
        elif table == "search_documents_primary":
            res.scopes.append(M.Scope(ctx.fid, ctx.cap, file_t, "search_service"))
            for r in rows:
                res.obs.append(mk(ctx, file_t, "search_service", r["resource_id"], M.SEARCH, M.PRESENT,
                                  emails=[r["email"]], link=r["source_resource_id"] or "", copy=table))
        # ---- generic primary / replica topologies (record_json)
        elif table.startswith("customer_data_"):
            systems = set()
            fam = _fam(ctx, table)
            for i, r in enumerate(rows):
                rec = json.loads(r["record_json"])
                o = collection_obs(ctx, file_t, r["origin_system"], r["collection_name"], rec, copy=table, fam=fam,
                                   ord=(f"{ctx.fid}|{table}|{r['collection_name']}", i))
                systems.add(r["origin_system"])
                if o is not None:
                    res.obs.append(o)
            for s in systems:
                res.scopes.append(M.Scope(ctx.fid, ctx.cap, file_t, s, True, fam))
            all_systems |= systems
    # the primary database covers every system the schema holds, even when it lists no rows for one
    if "customer_data_primary" in tables:
        have = {(s.system, s.fam) for s in res.scopes}
        for s in all_systems:
            if (s, "primary") not in have:
                res.scopes.append(M.Scope(ctx.fid, ctx.cap, file_t, s, True, "primary"))
    return res
