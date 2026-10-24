"""CSV loaders, identity resolution and the activity-stream index."""
from __future__ import annotations

import csv
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from .util import norm_email, norm_phone


def read_csv(path: Path) -> List[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ------------------------------------------------------------------ identity
@dataclass
class Person:
    user_id: str
    name: str = ""
    emails: Set[str] = field(default_factory=set)       # current + historical
    hashes: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    current_email: str = ""
    history: List[dict] = field(default_factory=list)   # audit rows

    def identifiers(self) -> dict:
        return {
            "user_id": self.user_id,
            "emails": sorted(self.emails),
            "hashes": sorted(self.hashes),
            "phones": sorted(self.phones),
        }


class IdentityIndex:
    """Resolves any current or historical email to a user and all identifiers."""

    def __init__(self, identities: List[dict], audit: List[dict]):
        self.people: Dict[str, Person] = {}
        self.by_email: Dict[str, Set[str]] = defaultdict(set)
        for r in identities:
            p = Person(user_id=r["user_id"], name=r["name"])
            e = norm_email(r["email"])
            p.current_email = e
            p.emails.add(e)
            p.hashes.add(r["email_hash"].lower())
            p.hashes.add(hashlib.sha256(e.encode()).hexdigest())
            if r["phone"]:
                p.phones.add(norm_phone(r["phone"]))
            self.people[p.user_id] = p
        for a in audit:
            p = self.people.get(a["user_id"])
            if p is None:
                continue
            p.history.append(a)
            f = a["field_name"]
            for v in (a["old_value"], a["new_value"]):
                if not v:
                    continue
                if f == "email":
                    p.emails.add(norm_email(v))
                    p.hashes.add(hashlib.sha256(norm_email(v).encode()).hexdigest())
                elif f == "email_hash":
                    p.hashes.add(v.lower())
                elif f == "phone":
                    p.phones.add(norm_phone(v))
        for p in self.people.values():
            for e in p.emails:
                self.by_email[e].add(p.user_id)

    def resolve(self, email: str) -> Person | None:
        users = self.by_email.get(norm_email(email), set())
        if not users:
            return None
        if len(users) == 1:
            return self.people[next(iter(users))]
        # an address that is historical for one user and current for another:
        # prefer the user it is currently registered to
        for u in users:
            if self.people[u].current_email == norm_email(email):
                return self.people[u]
        return self.people[sorted(users)[0]]


# ------------------------------------------------------------------ activity
@dataclass
class Event:
    activity_id: str
    t: str
    event_type: str
    source: str
    target: str
    rid: str
    result: str
    details: str


class ActivityIndex:
    def __init__(self, rows: List[dict]):
        self.events: List[Event] = [
            Event(r["activity_id"], r["event_time"], r["event_type"], r["source_system"],
                  r["target_system"], r["resource_id"], r["reported_result"], r["details"])
            for r in rows
        ]
        self.events.sort(key=lambda e: (e.t, e.activity_id))
        self.by_rid: Dict[str, List[Event]] = defaultdict(list)
        for e in self.events:
            self.by_rid[e.rid].append(e)

    def for_rid(self, rid: str) -> List[Event]:
        return self.by_rid.get(rid, [])
