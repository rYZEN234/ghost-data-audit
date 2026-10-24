"""Per-case resource attribution and state reconstruction at audit_at."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import model as M
from .data import ActivityIndex, IdentityIndex, Person
from .linker import Linker
from .store import EvidenceStore

# "worse" = the state that keeps a case INCOMPLETE; used to merge copies
WORST = {M.PRESENT: 3, M.IDENTIFIABLE: 3, M.ACTIVE: 3, M.RESTORABLE: 3,
         M.CLEAN: 1, M.DISABLED: 1, M.BLOCKED: 1, M.ABSENT: 0}


SINGLETON = {"analytics", "data_flow", "backup", "tombstone"}
OMISSION_OK = {"account", "search", "export", "marketing", "object", "support"}


@dataclass
class Resource:
    rid: str
    system: str
    cat: str
    state: str
    evidence: str = ""        # citable file_id (captured <= audit_at), "" if none
    retention_until: str = ""
    source: str = ""          # how the resource was attributed
    activity: str = ""        # fallback citation (activity id)


@dataclass
class Case:
    row: dict
    person: Optional[Person]
    keys: Set[str] = field(default_factory=set)
    direct: Dict[str, str] = field(default_factory=dict)       # rid -> source
    linked: Dict[str, str] = field(default_factory=dict)       # rid -> source
    resources: List[Resource] = field(default_factory=list)


class Resolver:
    def __init__(self, store: EvidenceStore, idx: IdentityIndex, act: ActivityIndex):
        self.store, self.idx, self.act = store, idx, act
        self.linker = Linker(act)
        self.rid_users = self._rid_owners()

    def _rid_owners(self) -> Dict[str, Set[str]]:
        owners: Dict[str, Set[str]] = defaultdict(set)
        for o in self.store.obs:
            for k in (*o.emails, *o.refs):
                for u in self.idx.by_email.get(k, ()):
                    owners[o.rid].add(u)
                if k.startswith("user_"):
                    owners[o.rid].add(k)
            for h in o.hashes:
                for p in self.idx.people.values():
                    if h in p.hashes:
                        owners[o.rid].add(p.user_id)
        return owners

    # ------------------------------------------------------------------
    def direct(self, case: Case) -> None:
        p = case.person
        if p is None:
            return
        case.keys = set(p.emails) | set(p.hashes) | set(p.phones) | {p.user_id}
        since = case.row["requested_at"]
        for o in self.store.for_idents(case.keys, case.row["audit_at"], since):
            if M.rid_prefix(o.rid) == "object" and False:
                continue
            owners = self.rid_users.get(o.rid, set())
            if owners and p.user_id not in owners:
                continue
            case.direct.setdefault(o.rid, "identity")

    def link_all(self, cases: List[Case]) -> None:
        """Attribute identifier-less resources through the deletion worker's activity."""
        todo = [c for c in cases if c.person is not None]
        claimed_acct: Dict[str, str] = {}
        for c in todo:
            for r in c.direct:
                if M.rid_prefix(r) == "account":
                    claimed_acct[r] = c.row["case_id"]
        # accounts known to belong to someone (identity-bearing evidence)
        foreign = {r for r, u in self.rid_users.items() if M.rid_prefix(r) == "account" and u}
        pending = [c for c in todo if not any(M.rid_prefix(r) == "account" for r in c.direct)]
        for round_ in range(4):
            progress = False
            for c in list(pending):
                cand = self._account_candidates(c, claimed_acct, foreign, strict=(round_ < 3))
                if len(cand) == 1:
                    e = cand[0]
                    c.linked[e.rid] = "activity:" + e.activity_id
                    claimed_acct[e.rid] = c.row["case_id"]
                    pending.remove(c)
                    progress = True
            if not progress and round_ >= 1:
                break
        pending = [c for c in todo if not any(M.rid_prefix(r) == "account" for r in list(c.direct) + list(c.linked))]
        self._order_resolve(pending, claimed_acct, foreign)
        # hand-written worker rows close to reported_at and naming-convention accounts
        for c in todo:
            for e in self.linker.hand_events(c.row["reported_at"]):
                owners = self.rid_users.get(e.rid, set())
                if owners and c.person.user_id not in owners:
                    continue
                if any(e.rid in o.direct for o in todo if o is not c):
                    continue
                c.linked.setdefault(e.rid, "hand:" + e.activity_id)
            if not any(M.rid_prefix(r) == "account" for r in list(c.direct) + list(c.linked)):
                uid = c.person.user_id
                if uid[5:].isdigit() and len(uid[5:]) <= 2:
                    guess = "account_%03d" % int(uid[5:])
                    owners = self.rid_users.get(guess, set())
                    if owners and uid not in owners:
                        continue
                    if self.state_of(guess, c.row["audit_at"], c.row["requested_at"], c.row["reported_at"]) is not None:
                        c.linked[guess] = "convention"
        # chains
        claimed_chain: Dict[int, str] = {}
        for c in todo:
            for r in list(c.direct) + list(c.linked):
                for ch in self.linker.chain_of_rid.get(r, ()):
                    if r in c.direct:
                        claimed_chain.setdefault(id(ch), c.row["case_id"])
        proposals: Dict[int, List] = defaultdict(list)       # chain id -> [(diff, case)]
        for c in todo:
            R = c.row["reported_at"]
            accts = [r for r in list(c.direct) + list(c.linked) if M.rid_prefix(r) == "account"]
            for r in accts:
                evs = [e for e in self.linker.acct_events if e.rid == r]
                if not evs:
                    continue
                for ch, diff in self.linker.chains_for_account(evs[0], R):
                    owner = claimed_chain.get(id(ch))
                    if owner and owner != c.row["case_id"]:
                        continue
                    proposals[id(ch)].append((diff, c, ch))
        for plist in proposals.values():
            best = min(d for d, _, _ in plist)
            for d, c, ch in plist:
                if d != best:
                    continue
                for rid in ch.rids:
                    owners = self.rid_users.get(rid, set())
                    if owners and c.person.user_id not in owners:
                        continue
                    pre = M.rid_prefix(rid)
                    if pre in SINGLETON and any(M.rid_prefix(x) == pre for x in c.direct):
                        continue          # the person already has this kind of record
                    if rid not in c.direct:
                        c.linked.setdefault(rid, "chain:" + ch.kind)

    def _order_resolve(self, pending: List[Case], claimed_acct, foreign) -> None:
        """Break ties between sibling requests (same reported_at and status).

        Snapshot exports write their records in request order, so the order of the siblings'
        anonymised analytics records in a shared snapshot gives the order of their cases.
        """
        groups: Dict[tuple, List[Case]] = defaultdict(list)
        for c in pending:
            groups[(c.row["reported_at"], c.row["reported_status"])].append(c)
        for (rep, _st), cs in groups.items():
            if len(cs) < 2:
                continue
            cs.sort(key=lambda c: int(c.row["case_id"].split("_")[1]))
            cands = {}
            for c in cs:
                for e in self._account_candidates(c, claimed_acct, foreign, True):
                    cands[e.rid] = e
            keyed = []
            for rid, e in cands.items():
                an = [r for ch, _d in self.linker.chains_for_account(e, rep) for r in ch.rids
                      if M.rid_prefix(r) == "analytics"]
                ords = [o.ord for r in an for o in self.store.by_rid.get(r, ()) if o.ord]
                if ords:
                    keyed.append((e, ords))
            if len(keyed) != len(cs):
                continue
            common = set.intersection(*[{g for g, _ in o} for _, o in keyed])
            if not common:
                continue
            g = sorted(common)[0]
            keyed.sort(key=lambda k: min(i for gg, i in k[1] if gg == g))
            for c, (e, _o) in zip(cs, keyed):
                c.linked[e.rid] = "order:" + e.activity_id
                claimed_acct[e.rid] = c.row["case_id"]

    def _account_candidates(self, c: Case, claimed, foreign, strict: bool):
        row = c.row
        cands = self.linker.account_candidates(row["reported_at"], row["reported_status"])
        if not cands:     # hand-written worker rows do not follow the status mapping
            cands = self.linker.account_candidates(row["reported_at"], "", "hand")
        out = []
        for e in cands:
            if e.rid in claimed and claimed[e.rid] != row["case_id"]:
                continue
            owners = self.rid_users.get(e.rid, set())
            if owners and c.person.user_id not in owners:
                continue
            out.append(e)
        if len(out) > 1:
            secs = self.linker.anchor_seconds(list(c.direct), row["reported_at"])
            if secs:
                f = [e for e in out if int(e.t[17:19]) in secs]
                if f:
                    out = f
        return out

    # ------------------------------------------------------------------
    CAT_BY_PREFIX = {"account": M.ACCOUNT, "search": M.SEARCH, "analytics": M.ANALYTICS, "export": M.EXPORT,
                     "data_flow": M.FLOW, "backup": M.BACKUP, "audit_record": M.SECURITY,
                     "tombstone": M.TOMBSTONE, "support": M.SUPPORT_MSG, "marketing": M.MARKETING,
                     "legal_hold": M.LEGAL, "object": M.SUPPORT_ATT}

    def state_of(self, rid: str, audit_at: str, since: str, reported_at: str = "") -> Optional[Resource]:
        """State of one resource at audit_at.

        Each copy family (the authoritative view, and every replica table) contributes its latest
        view at or before audit_at -- an explicit record observation or a declared snapshot that
        no longer lists the record.  Copies combine worst-case, so a stale replica keeps a record
        alive even after the primary stopped listing it.
        """
        pre = M.rid_prefix(rid)
        system = M.PREFIX_SYSTEM.get(pre, "")
        obs = [o for o in self.store.by_rid.get(rid, ()) if since <= o.t <= audit_at]
        if obs:
            system = obs[0].system
        scopes = [s for s in self.store.scopes if s.system == system and since <= s.t <= audit_at and s.declared]
        fams = {o.fam for o in obs} | {s.fam for s in scopes}
        if not obs and not scopes:
            # a bundle snapshot that does not list the record is the only proof of absence
            weak = [s for s in self.store.scopes if s.system == system and since <= s.t <= audit_at]
            if not weak or pre not in OMISSION_OK:
                return None
            scopes = weak
            fams = {"primary"}
        views = []      # (family, time, state, cat, obs-or-scope list)
        for f in fams:
            fo = [o for o in obs if o.fam == f]
            fs = [s for s in scopes if s.fam == f]
            to = max((o.t for o in fo), default="")
            ts = max((s.t for s in fs), default="")
            if not fo and f != "primary":
                continue                                    # a replica snapshot never mentioning it says nothing
            if ts > to:
                views.append((f, ts, M.ABSENT, None, [s for s in fs if s.t == ts]))
            elif fo:
                latest = [o for o in fo if o.t == to]
                w = max(latest, key=lambda o: WORST.get(o.state, 0))
                views.append((f, to, w.state, w.cat, [o for o in latest if o.state == w.state]))
        if not views:
            if pre == "account" and not obs:
                # attributed through activity, never observed as a record: not present anywhere we can see
                return Resource(rid, system, M.ACCOUNT, M.ABSENT, "")
            return None
        top = max(views, key=lambda v: (WORST.get(v[2], 0), v[1]))
        state = top[2]
        cat = next((v[3] for v in views if v[3]), self.CAT_BY_PREFIX.get(pre, ""))
        ev = ""
        if state == M.ABSENT:
            explicit = [o for o in obs if o.state == M.ABSENT and o.cap <= audit_at]
            if explicit:
                ev = max(explicit, key=lambda o: (o.cap, o.t)).fid
            else:
                cites = [s for s in self.store.scopes if s.system == system and s.cap <= audit_at
                         and s.t >= since and s.fam == "primary"]
                if cites:
                    ev = max(cites, key=lambda s: (s.cap, s.fid)).fid
        else:
            cites = [o for o in obs if o.state == state and o.cap <= audit_at]
            if cites:
                ev = max(cites, key=lambda o: (o.cap, o.t)).fid
        ret = max((o.retention_until for o in obs if o.retention_until), default="")
        return Resource(rid, system, cat, state, ev, ret)

    def build(self, case: Case) -> None:
        since, audit = case.row["requested_at"], case.row["audit_at"]
        seen = set()
        for src, group in (("direct", case.direct), ("linked", case.linked)):
            for rid, how in group.items():
                if rid in seen:
                    continue
                seen.add(rid)
                r = self.state_of(rid, audit, since, case.row['reported_at'])
                if r is not None:
                    r.source = how
                    case.resources.append(r)
