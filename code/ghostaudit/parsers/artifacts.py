"""PDF and screenshot evidence: text extraction (pdftotext / tesseract OCR) + record views.

Each artifact is a single-record view of one subject.  Text is extracted at
run time; a JSON cache (text_cache.json) is used only when the extractor is
missing.  OCR output is noisy, so resource ids and emails are snapped to the
universe of identifiers that exist in the supplied dataset files.
"""
from __future__ import annotations

import difflib
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from .. import model as M
from ..util import EMAIL_RE, PHONE_RE, USER_RE, extract_ids
from .base import FileCtx, ParseResult, mk

CACHE_PATH = Path(__file__).resolve().parent.parent / "text_cache.json"
RID_LOOSE = re.compile(
    r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|"
    r"legal_hold|object|marketing)_(\d+)\b")


def _load_cache() -> Dict[str, str]:
    try:
        return json.loads(CACHE_PATH.read_text())
    except (OSError, ValueError):
        return {}


def extract_text(path: Path, key: str) -> str:
    text = ""
    try:
        if path.suffix.lower() == ".pdf":
            text = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True,
                                  text=True, timeout=120).stdout
        else:
            from PIL import Image
            import pytesseract
            img = Image.open(path).convert("L")
            img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
            text = pytesseract.image_to_string(img, config="--psm 6")
    except Exception:  # extractor missing -> fall back to cache
        text = ""
    if len(text.strip()) < 40:
        text = _load_cache().get(key, text)
    return text


def build_cache(dataset: Path) -> None:
    import csv
    cache = {}
    for r in csv.DictReader(open(dataset / "evidence_files.csv")):
        if r["file_path"].endswith((".png", ".pdf")):
            cache[r["file_path"]] = extract_text(dataset / r["file_path"], r["file_path"])
    CACHE_PATH.write_text(json.dumps(cache, indent=1, sort_keys=True))


# ------------------------------------------------------------------ snapping
class Universe:
    def __init__(self, rids: Iterable[str], emails: Iterable[str], links: List[dict]):
        self.rids: Set[str] = set(rids)
        self.emails: Set[str] = set(emails)
        self.links = links     # parsed LINK_RESOURCE_IDENTITY activity rows

    def snap_rid(self, prefix: str, num: str) -> Optional[str]:
        cand = f"{prefix}_{num}"
        if cand in self.rids:
            return cand
        pool = [r for r in self.rids if r.startswith(prefix + "_") and len(r) == len(cand)]
        close = [r for r in pool if sum(a != b for a, b in zip(r, cand)) == 1]
        return close[0] if len(close) == 1 else None

    def snap_email(self, e: str) -> Optional[str]:
        e = e.lower()
        if e in self.emails:
            return e
        m = difflib.get_close_matches(e, list(self.emails), n=1, cutoff=0.92)
        return m[0] if m else None


LINK_RE = re.compile(r"linked (\S+) \(([^)]*)\) to (\S+) and (user_\d+)")
BELONGS_RE = re.compile(r"confirmed (\S+) \(([^)]*)\) belongs only to (\S+) and (user_\d+)")


def link_rows(activity_rows: Iterable[dict]) -> List[dict]:
    out = []
    for r in activity_rows:
        if r["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        m = LINK_RE.search(r["details"]) or BELONGS_RE.search(r["details"])
        if m:
            out.append(dict(rid=m.group(1), token=m.group(2), email=m.group(3).strip(";,.").lower(),
                            user=m.group(4), activity=r["activity_id"], t=r["event_time"],
                            sole="belongs only" in r["details"]))
    return out


# ---------------------------------------------------------------- the parser
def parse_artifact(path: Path, ctx: FileCtx, uni: Universe) -> ParseResult:
    res = ParseResult()
    text = extract_text(path, ctx.path)
    text = re.sub(r"\buser[\s_]+(\d+)", r"user_\1", text, flags=re.I)
    low = text.lower()
    is_pdf = path.suffix.lower() == ".pdf"
    rids = []
    for pre, num in RID_LOOSE.findall(text):
        s = uni.snap_rid(pre, num) or (f"{pre}_{num}" if is_pdf else None)
        if s and s not in rids:
            rids.append(s)
    emails = {s for s in (uni.snap_email(e) for e in EMAIL_RE.findall(text)) if s}
    refs = set(USER_RE.findall(text))
    phones = [p for p in PHONE_RE.findall(text)]

    def fuzzy_has(rid: str) -> bool:
        pre, num = rid.rsplit("_", 1)
        conf = {"7": "[7/1]", "1": "[1lI|7]", "0": "[0Oo]", "5": "[5S]", "8": "[8B]", "6": "[6b]"}
        pat = pre + r"[_\s]*" + "".join(conf.get(c, c) for c in num)
        return re.search(pat, text) is not None

    # subject records: resources tied to an identity by the data catalog, else self-identifying
    entries = []   # (rid, emails, refs, link)
    seen = set()
    for lk in uni.links:
        by_rid = lk["rid"] in rids or fuzzy_has(lk["rid"])
        by_token = (lk["token"] and lk["token"] != lk["rid"] and lk["token"].lower() in low
                    and not (is_pdf and M.rid_prefix(lk["rid"]) == "tombstone"))
        if by_rid or by_token:
            entries.append((lk["rid"], {lk["email"]}, {lk["user"]}, lk))
            seen.add(lk["rid"])
            if M.rid_prefix(lk["rid"]) == "account":      # customer overview lists the customer's tickets etc.
                for r in rids:
                    if r not in seen and M.rid_prefix(r) in ("support", "export", "backup"):
                        entries.append((r, {lk["email"]}, {lk["user"]}, lk))
                        seen.add(r)
    if not entries and emails:
        for r in rids:
            entries.append((r, set(emails), refs, None))

    for rid, em, rf, lk in entries:
        pre = M.rid_prefix(rid)
        system = M.PREFIX_SYSTEM.get(pre, "")
        kw = dict(emails=em, refs=rf)
        t = ctx.cap
        if pre == "account":
            o = mk(ctx, t, system, rid, M.ACCOUNT, M.PRESENT, **kw)
        elif pre == "search":
            o = mk(ctx, t, system, rid, M.SEARCH, M.PRESENT, **kw)
        elif pre == "data_flow":
            live = not re.search(r"disabled|paused|stopped|inactive", low)
            o = mk(ctx, t, system, rid, M.FLOW, M.ACTIVE if live else M.DISABLED, **kw)
        elif pre == "analytics":
            o = mk(ctx, t, system, rid, M.ANALYTICS, M.IDENTIFIABLE if (em and any(e in text.lower() for e in em)) else M.CLEAN, **kw)
        elif pre == "export":
            o = mk(ctx, t, system, rid, M.EXPORT, M.PRESENT, **kw)
        elif pre == "support":
            kind = M.SUPPORT_ATT if re.search(r"attachment|uploader", low) else M.SUPPORT_MSG
            o = mk(ctx, t, system, rid, kind, M.PRESENT if kind == M.SUPPORT_ATT else M.IDENTIFIABLE,
                   phones=phones, **kw)
        elif pre == "backup":
            blocked = re.search(r"restore blocked|blocked", low) is not None
            o = mk(ctx, t, system, rid, M.BACKUP, M.BLOCKED if blocked else M.RESTORABLE, **kw)
        elif pre == "object":
            o = mk(ctx, t, system, rid, M.SUPPORT_ATT, M.PRESENT, **kw)
        elif pre == "marketing":
            o = mk(ctx, t, system, rid, M.MARKETING, M.PRESENT, phones=phones, **kw)
        elif pre == "audit_record":
            ret = re.search(r"retain until\s+(\d{1,2}) (\w{3}) (\d{4})", text, re.I)
            until = ""
            if ret:
                import datetime
                d = datetime.datetime.strptime(" ".join(ret.groups()), "%d %b %Y")
                until = d.strftime("%Y-%m-%dT00:00:00Z")
            o = mk(ctx, t, system, rid, M.SECURITY, M.PRESENT, retention_until=until, **kw)
        elif pre == "tombstone":
            exposed = bool(EMAIL_RE.search(text))
            o = mk(ctx, t, system, rid, M.TOMBSTONE, M.IDENTIFIABLE if exposed else M.CLEAN, **kw)
        else:
            continue
        res.obs.append(o)
    return res


if __name__ == "__main__":
    import sys
    build_cache(Path(sys.argv[1]))
