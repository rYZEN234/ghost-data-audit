# Usage report

Final full-dataset run (`python3 code/main.py`, 518 cases) is fully deterministic and makes **no model calls**.

| Provider / model | Calls | Input tokens | Output tokens | Est. cost |
|---|---|---|---|---|
| none | 0 | 0 | 0 | $0.00 |

Overall: 0 calls, 0 total tokens, 0 average tokens per request, $0.00 total and per request.
The optional LLM fallback in `ghostaudit/intent.py` is disabled by default and was not used.
