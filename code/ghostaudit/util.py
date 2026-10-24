"""Small shared helpers."""
from __future__ import annotations

import re
from datetime import datetime, timezone

ISO_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
USER_RE = re.compile(r"\buser_\d+\b")
PHONE_RE = re.compile(r"\+\d[\d\s().\-]{6,}\d")
RID_RE = re.compile(
    r"\b(account|search|support|analytics|export|data_flow|backup|audit_record|"
    r"tombstone|legal_hold|email_delivery|cache|object|marketing|secondary)_\w+\b"
)


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def norm_email(e: str) -> str:
    return e.strip().lower()


def norm_phone(p: str) -> str:
    """Digits with a leading '+' kept: '+1 (202) 555-0103' -> '+12025550103'."""
    p = p.strip()
    digits = re.sub(r"\D", "", p)
    return ("+" if p.startswith("+") else "") + digits


def is_null(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip().lower() in ("", "null", "none"))


def extract_ids(values):
    """Scan an iterable of scalar values and return (emails, hashes, refs).

    Phones are only taken from explicitly phone-typed fields, so they are
    handled by the callers.
    """
    emails, hashes, refs = set(), set(), set()
    for v in values:
        if not isinstance(v, str):
            continue
        for m in EMAIL_RE.findall(v):
            emails.add(norm_email(m))
        for m in HASH_RE.findall(v.lower()):
            hashes.add(m)
        for m in USER_RE.findall(v):
            refs.add(m)
    return emails, hashes, refs


def flatten_strings(obj):
    """Yield every scalar string found anywhere inside a JSON-like object."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from flatten_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from flatten_strings(v)
    elif isinstance(obj, str):
        yield obj
