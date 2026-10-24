"""Service log evidence (key=value, quoted, JSON, pipe, bracket, syslog, cloud runtime)."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Dict, List

from .. import model as M
from ..util import extract_ids, is_null
from .base import FileCtx, ParseResult, ledger_obs, mk

KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S+)')
TS = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.*)$")
KEY_FIELDS = ("lookup_key", "match_key", "subject_key", "owner_key", "scan_key", "subject_ref",
              "correlation_key")


def _unq(v: str) -> str:
    if v.startswith('"') and v.endswith('"'):
        v = v[1:-1].replace('\\"', '"')
    return v


def _kv(text: str, d: dict) -> None:
    for k, v in KV.findall(text):
        d[k] = _unq(v)


def parse_line(line: str):
    m = TS.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    d = {"_ts": ts}
    if rest.startswith("{"):
        try:
            d.update({k: str(v) for k, v in json.loads(rest).items()})
            return d
        except ValueError:
            pass
    mm = re.search(r'message="((?:[^"\\]|\\.)*)"', rest)
    if mm:                                       # cloud runtime export
        _kv(rest[:mm.start()], d)
        _kv(mm.group(1).replace('\\"', '"'), d)
        if "requestId" in d:
            d.setdefault("trace_id", d["requestId"])
        return d
    rest = rest[2:] if rest.startswith("| ") else rest
    if " | " in rest and re.match(r"(DEBUG|INFO|WARN|ERROR)\s+\|", rest):
        parts = [p.strip() for p in rest.split(" | ")]
        d["level"], d["service"], d["trace_id"], d["event"] = parts[:4]
        _kv(" ".join(parts[4:]), d)
        return d
    mb = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\w+):\s*(.*)$", rest)
    if mb:
        d["level"], d["service"], d["trace_id"], d["event"] = mb.groups()[:4]
        _kv(mb.group(5), d)
        return d
    ms = re.match(r"<\d+>1\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$", rest)
    if ms:
        d["service"], d["trace_id"] = ms.group(2), ms.group(3)
        _kv(ms.group(4), d)
        return d
    _kv(rest, d)
    return d


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def parse_log(text: str, ctx: FileCtx) -> ParseResult:
    res = ParseResult()
    lines: List[dict] = []
    for ln in text.splitlines():
        if ln.strip():
            d = parse_line(ln)
            if d:
                lines.append(d)
    keys: Dict[str, set] = defaultdict(set)
    for d in lines:
        tid = d.get("trace_id")
        if tid:
            for f in KEY_FIELDS:
                if not is_null(d.get(f)):
                    keys[tid].add(d[f])

    for d in lines:
        ev = d.get("event")
        rid = d.get("resource_id")
        if not ev:
            continue
        t = d["_ts"]
        vals = set(keys.get(d.get("trace_id", ""), ()))
        for f in KEY_FIELDS:
            if not is_null(d.get(f)):
                vals.add(d[f])
        idvals = list(vals) + [d.get(f, "") for f in (
            "email", "customer_email", "owner_email", "requester_email", "customer_reference",
            "subject_reference", "email_hash", "matched_value")]
        emails, hashes, refs = extract_ids(idvals)
        phones = [d.get(f) for f in ("phone", "requester_phone") if not is_null(d.get(f))]
        mv = d.get("matched_value", "")
        if mv.startswith("+"):
            phones.append(mv)
        kw = dict(emails=emails, hashes=hashes, refs=refs, phones=phones)
        sysid = M.PREFIX_SYSTEM.get(M.rid_prefix(rid), "") if rid else ""

        def add(cat, state, system=None, **extra):
            res.obs.append(mk(ctx, t, system or sysid, rid, cat, state, **kw, **extra))

        if ev == "profile_lookup_completed":
            gone = d.get("rows") == "0" or d.get("http_status") == "404"
            add(M.ACCOUNT, M.ABSENT if gone else M.PRESENT)
        elif ev == "index_query_completed":
            add(M.SEARCH, M.PRESENT if d.get("result") == "hit" else M.ABSENT)
        elif ev == "analytics_profile_read_completed":
            exposed = any(not is_null(d.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
            add(M.ANALYTICS, M.IDENTIFIABLE if exposed else M.CLEAN)
        elif ev in ("analytics_profile_read", "analytics_identity_scan"):
            add(M.ANALYTICS, M.IDENTIFIABLE if _truthy(d.get("direct_identifiers")) else M.CLEAN)
        elif ev == "message_pii_scan":
            add(M.SUPPORT_MSG, M.IDENTIFIABLE)
        elif ev == "attachment_pii_scan":
            add(M.SUPPORT_ATT, M.PRESENT)
        elif ev == "message_read":
            txt = d.get("message_text", "")
            exposed = bool(extract_ids([txt])[0]) and "[REDACTED]" not in txt
            add(M.SUPPORT_MSG, M.IDENTIFIABLE if exposed else M.CLEAN)
        elif ev == "support_ticket_read_completed":
            exposed = any(not is_null(d.get(k)) for k in ("requester_name", "requester_email", "requester_phone"))
            add(M.SUPPORT_MSG, M.IDENTIFIABLE if exposed else M.CLEAN)
        elif ev in ("export_metadata_read_completed", "export_download_check_completed"):
            add(M.EXPORT, M.PRESENT, note="available" if _truthy(d.get("available")) else "unavailable")
        elif ev == "connector_config_read_completed":
            add(M.FLOW, M.ACTIVE if _truthy(d.get("enabled")) else M.DISABLED)
        elif ev in ("connector_config_loaded", "connector_heartbeat"):
            live = _truthy(d.get("enabled")) and d.get("scheduler_registered", "true") != "false"
            add(M.FLOW, M.ACTIVE if live else M.DISABLED)
        elif ev == "restore_policy_read_completed":
            ok = _truthy(d.get("restore_allowed")) and d.get("archive_present", "true") != "false"
            add(M.BACKUP, M.RESTORABLE if ok else M.BLOCKED)
        elif ev == "restore_candidate_evaluated":
            ok = _truthy(d.get("eligible")) and not _truthy(d.get("deletion_block"))
            add(M.BACKUP, M.RESTORABLE if ok else M.BLOCKED)
        elif ev == "restore_authorization_completed":
            add(M.BACKUP, M.BLOCKED if d.get("decision") == "deny" else M.RESTORABLE)
        elif ev == "audit_record_read_completed":
            add(M.SECURITY, M.PRESENT, retention_until=d.get("retention_until", ""))
        elif ev == "contact_lookup_completed":
            add(M.MARKETING, M.PRESENT, system="analytics_platform")
        elif ev == "deletion_marker_check" and d.get("marker_found") == "false":
            add(M.SECONDARY, M.PRESENT, note="replica_no_marker")
        elif ev == "record_lookup":
            o = ledger_obs(ctx, t, d.get("system", ""), rid, d.get("record_type", ""),
                           d.get("result", ""), d.get("subject_reference", ""))
            if o is not None:
                res.obs.append(o)
    return res
