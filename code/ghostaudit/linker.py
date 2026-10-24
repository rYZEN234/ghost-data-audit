"""Activity-stream linking for resources that carry no identifier in the evidence.

Accounts that return 404, anonymised analytics profiles, redacted support
tickets and clean tombstones cannot be matched by e-mail or hash.  They are
tied to a request through the deletion worker's activity: the account
delete event sits shortly before the reported time, and the downstream
policy / follow-up chains are timed relative to it.  Candidates are
eliminated against resources already attributed to other people.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Set

from .data import ActivityIndex, Event
from .util import parse_ts

POLICY_GAPS = (390, 449)      # seconds between consecutive policy-chain events
FAIL_GAPS = (1110, 1169)      # seconds between consecutive failure-chain events
POLICY_SEC_OFFSET = 41        # chain start second = account event second + 41
FAIL_SEC_OFFSET = 52
RESULT_FOR_STATUS = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def _t(e: Event) -> float:
    return parse_ts(e.t).timestamp()


def _build_chains(evs: List[Event], gaps, tol: float = 1.5) -> List[List[Event]]:
    evs = sorted(evs, key=_t)
    used: Set[int] = set()
    out = []
    for i, e in enumerate(evs):
        if i in used:
            continue
        used.add(i)
        ch, cur = [e], e
        while True:
            nxt = None
            for j in range(i + 1, len(evs)):
                if j in used:
                    continue
                d = _t(evs[j]) - _t(cur)
                if d > max(gaps) + tol + 1:
                    break
                if any(abs(d - g) <= tol for g in gaps):
                    nxt = j
                    break
            if nxt is None:
                break
            used.add(nxt)
            cur = evs[nxt]
            ch.append(cur)
        out.append(ch)
    return out


def _sec(e: Event) -> int:
    return int(e.t[17:19])


class Chain:
    def __init__(self, kind: str, events: List[Event]):
        self.kind = kind
        self.events = events
        self.start = _t(events[0])
        self.sec = _sec(events[0])
        self.rids = [e.rid for e in events]


class Linker:
    def __init__(self, act: ActivityIndex):
        self.act = act
        ev = act.events
        self.acct_events = [e for e in ev if e.event_type == "DELETE_RECORD" and e.target == "account_service"
                            and e.rid.startswith("account_")]
        policy = [e for e in ev if e.details.startswith("Policy action completed")]
        fail = [e for e in ev if (e.source == "deletion_worker" and e.target != "account_service"
                                  and (e.details.startswith("Deletion worker received the final result")
                                       or e.event_type.startswith("CHECK_")))
                or (e.event_type in ("SYNC_RECORD", "RESTORE_BACKUP") and "repopulated downstream" in e.details)]
        self.chains: List[Chain] = ([Chain("policy", c) for c in _build_chains(policy, POLICY_GAPS)]
                                    + [Chain("fail", c) for c in _build_chains(fail, FAIL_GAPS)])
        self.chain_of_rid: Dict[str, List[Chain]] = defaultdict(list)
        for c in self.chains:
            for r in c.rids:
                self.chain_of_rid[r].append(c)

    # ------------------------------------------------------------ accounts
    def account_candidates(self, reported_at: str, status: str, template: str = "submitted"):
        """Account delete events around reported_at.

        Two wordings exist: "submitted primary profile" events sit 45-75 minutes before
        reported_at and carry a result that mirrors the reported status; hand-written
        "reported the requested operation" events sit within a few minutes of it.
        """
        R = parse_ts(reported_at).timestamp()
        want = RESULT_FOR_STATUS.get(status)
        out = []
        for e in self.acct_events:
            d = (_t(e) - R) / 60
            if template == "submitted":
                ok = "submitted primary profile" in e.details and -76 <= d <= -44 and (want is None or e.result == want)
            else:
                ok = "Target resource" in e.details and -10 <= d <= 10
            if ok:
                out.append(e)
        return out

    def chains_for_account(self, e: Event, reported_at: str):
        """(chain, seconds-diff) pairs timed from an account event; diff 0 is an exact match."""
        R = parse_ts(reported_at).timestamp()
        out = []
        for c in self.chains:
            off = POLICY_SEC_OFFSET if c.kind == "policy" else FAIL_SEC_OFFSET
            if not self._in_window(c, R):
                continue
            diff = (c.sec - (_sec(e) + off)) % 60
            if diff in (0, 1, 59):
                out.append((c, 0 if diff == 0 else 1))
        # a near match is only acceptable when no exact chain of the same kind exists
        for kind in ("policy", "fail"):
            if any(c.kind == kind and d == 0 for c, d in out):
                out = [(c, d) for c, d in out if not (c.kind == kind and d == 1)]
        return out

    @staticmethod
    def _in_window(c: "Chain", R: float) -> bool:
        d = (c.start - R) / 60
        return (-31 <= d <= -26) if c.kind == "policy" else (36 <= d <= 65)

    def hand_events(self, reported_at: str, minutes: float = 15):
        """Directly reported worker events (non-chain wording) close to reported_at."""
        R = parse_ts(reported_at).timestamp()
        return [e for e in self.act.events
                if e.source == "deletion_worker" and "Target resource:" in e.details
                and e.target != "account_service" and abs(_t(e) - R) <= minutes * 60]

    def anchor_seconds(self, rids, reported_at: str):
        """Account-event seconds implied by chains that contain the person's known resources."""
        R = parse_ts(reported_at).timestamp()
        secs = set()
        for r in rids:
            for c in self.chain_of_rid.get(r, ()):
                if self._in_window(c, R):
                    off = POLICY_SEC_OFFSET if c.kind == "policy" else FAIL_SEC_OFFSET
                    for d in (0, -1, 1):
                        secs.add((c.sec - off + d) % 60)
        return secs
