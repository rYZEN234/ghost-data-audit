# Ghost Data Still Exists — deletion-audit agent

Deterministic Python pipeline (no LLM calls, no API keys needed).

## Setup
- Python 3.10+ (tested 3.13), standard library only for the core.
- Optional, for PNG/PDF evidence: `tesseract` + `pytesseract` + `Pillow`, and `pdftotext` (poppler). Without them the
  extractor falls back to a bundled text cache if present.

## Run
```
python3 code/main.py                 # reads dataset/, writes output.csv at repo root
python3 code/evaluation/main.py      # scores public samples + custom cases
```

## Layout
- `ghostaudit/parsers/` SQL, JSON, log, PDF/image evidence parsers -> observations
- `ghostaudit/data.py` identity resolution (current + historical emails, hashes, phones)
- `ghostaudit/linker.py` links identifier-less resources through `system_activity.csv`
- `ghostaudit/resolve.py` state of each resource at `audit_at` (no evidence after the cutoff)
- `ghostaudit/plan.py` policy engine -> status and ordered FINDING/REMEDIATION/VERIFICATION steps
- `ghostaudit/intent.py` multilingual deletion-intent classifier (NOT_APPLICABLE otherwise)
- `evaluation/` reports and harness
