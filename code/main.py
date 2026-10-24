#!/usr/bin/env python3
"""Ghost Data Still Exists -- deletion-audit agent.

Usage:  python3 code/main.py [--dataset dataset] [--output output.csv]

Reads the participant-facing files under dataset/ and writes output.csv at the repo root.
Fully deterministic; makes no model calls.
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ghostaudit.pipeline import audit, write_output  # noqa: E402


def main() -> int:
    root = HERE.parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=str(root / "dataset"))
    ap.add_argument("--requests", default="deletion_requests.csv")
    ap.add_argument("--output", default=str(root / "output.csv"))
    args = ap.parse_args()
    rows = audit(Path(args.dataset), args.requests)
    write_output(rows, Path(args.output))
    counts = {}
    for _, status, _ in rows:
        counts[status] = counts.get(status, 0) + 1
    print(f"wrote {len(rows)} rows to {args.output}: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
