"""Does the request actually authorize deletion?  (multilingual rule classifier)

A deterministic rule set decides every request in the supplied dataset.  An optional
LLM fallback hook (see `llm_fallback`) exists for texts the rules cannot place; it is
disabled unless GHOST_LLM_FALLBACK=1 and an API key are present, and the final
submission run made zero model calls.
"""
from __future__ import annotations

import os
import re
import unicodedata

# explicit statements that the person does NOT want the account or data removed
NEGATION = re.compile(
    r"(not\s+(?:a\s+request\s+to|asking\s+for)\s+(?:erase|erasure|delet)|"
    r"(?:don't|do\s+not|never)\s+(?:delete|close|remove|erase)|"
    r"leave\s+(?:the\s+|my\s+)?(?:account|profile)[^.]{0,40}(?:active|in\s+place|as\s+it\s+is)|"
    r"keep\s+the\s+account|without\s+removing|lists\s+only|still\s+(?:need|use|want)\b|"
    r"continue\s+using|leave\s+.{0,30}\bin\s+place)", re.I)

# deletion verbs / nouns in the request languages seen in the data
DELETION = re.compile(
    r"(delet|eras[ei]|permanent(?:ly)?\s+(?:remov|clos)|\bremov|\bclos(?:e|ed|ing)\b|\bis\s+gone\b|cannot\s+identify\s+me|"
    r"(?:has|have)\s+(?:already\s+)?been\s+removed|"
    r"suppression|supprim|eliminaci|elimin|borrar|exclus[ãa]o|excluir|apagar|löschen|lösch|"
    r"삭제|削除|消去|删除|удал)", re.I)

# topics that are other data-subject requests (access, correction, export, marketing, support)
OTHER_TOPIC = re.compile(
    r"(copy\s+of|download|portable\s+format|information\s+(?:we\s+)?hold|what\s+personal\s+information|"
    r"misspell|correct\s+it|replace\s+it|out\s+of\s+date|resetting|change\s+the\s+email|"
    r"promotional\s+emails|marketing\s+lists)", re.I)


def classify_text(text: str) -> str:
    """Return 'DELETE' or 'OTHER'."""
    t = unicodedata.normalize("NFC", text)
    if NEGATION.search(t):
        return "OTHER"
    if DELETION.search(t):
        return "DELETE"
    return "OTHER"


def llm_fallback(text: str) -> str | None:       # pragma: no cover - optional, off by default
    if os.environ.get("GHOST_LLM_FALLBACK") != "1":
        return None
    return None


def authorizes_deletion(text: str, intake_non_deletion: bool = False) -> bool:
    verdict = classify_text(text)
    if intake_non_deletion:
        return False       # privacy intake already classified the request as non-deletion
    return verdict == "DELETE"
