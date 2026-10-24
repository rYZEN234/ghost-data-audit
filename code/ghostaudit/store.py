"""Evidence store: loads every file in the manifest into observations + scopes."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from . import model as M
from .data import read_csv
from .parsers.artifacts import Universe, link_rows, parse_artifact
from .parsers.base import FileCtx, ParseResult
from .parsers.json_rec import parse_handover, parse_json
from .parsers.logs import parse_log
from .parsers.sql_snap import parse_sql


class EvidenceStore:
    def __init__(self, dataset: Path, activity_rows: List[dict], identities: List[dict], audit: List[dict]):
        self.dataset = dataset
        self.obs: List[M.Obs] = []
        self.scopes: List[M.Scope] = []
        self.files: Dict[str, dict] = {}
        rids = {a["resource_id"] for a in activity_rows}
        emails = {r["email"].lower() for r in identities}
        for a in audit:
            for v in (a["old_value"], a["new_value"]):
                if "@" in v:
                    emails.add(v.lower())
        self.universe = Universe(rids, emails, link_rows(activity_rows))
        for row in read_csv(dataset / "evidence_files.csv"):
            self._load(row)
        self.by_rid: Dict[str, List[M.Obs]] = defaultdict(list)
        for o in self.obs:
            self.by_rid[o.rid].append(o)
        self.by_ident: Dict[str, List[M.Obs]] = defaultdict(list)
        for o in self.obs:
            for k in (*o.emails, *o.hashes, *o.refs, *o.phones):
                self.by_ident[k].append(o)

    def _load(self, row: dict) -> None:
        ctx = FileCtx(row["file_id"], row["captured_at"], row["file_path"], row["origin"])
        self.files[ctx.fid] = row
        path = self.dataset / row["file_path"]
        suffix = path.suffix.lower()
        if suffix in (".png", ".pdf"):
            res = parse_artifact(path, ctx, self.universe)
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
            if suffix == ".sql":
                res = parse_sql(text, ctx)
            elif suffix == ".json":
                res = parse_json(text, ctx)
            elif suffix == ".log":
                res = parse_log(text, ctx)
            elif suffix == ".txt":
                res = parse_handover(text, ctx)
            else:
                res = ParseResult()
        self.obs.extend(res.obs)
        self.scopes.extend(res.scopes)

    # --------------------------------------------------------------- queries
    def for_idents(self, idents, audit_at: str, since: str = "") -> List[M.Obs]:
        """Observations carrying any identifier, observed within [since, audit_at]."""
        seen, out = set(), []
        for k in idents:
            for o in self.by_ident.get(k, ()):
                if since <= o.t <= audit_at and id(o) not in seen:
                    seen.add(id(o))
                    out.append(o)
        return out
