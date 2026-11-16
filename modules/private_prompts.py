"""Operator-private prompt text, swapped in at run time.

Prompt text distilled from the operator's own solves never enters the tree,
because this repository has a remote. It lives in
`<DATA_DIR>/private-prompts/<name>.md` (`data/` is untracked and bind-mounted
at /data), and every call site carries a generic fallback:

    text = private_prompt("<name>") or "<generic text>"

A deployment that has the file renders exactly what it rendered before the
text moved; one without it renders the fallback. This module imports nothing
heavier than `modules.storage`, so light modules can use it too.
"""
from __future__ import annotations

import os
from pathlib import Path

from modules.storage import DATA_DIR


def private_prompt(name: str) -> str:
    """Operator-private prompt text, or "" when there is none.

    Read from `$HEXTECH_PRIVATE_PROMPTS/<name>.md` when that variable is set (a
    test points it at its own directory), else from
    `<DATA_DIR>/private-prompts/<name>.md`. A missing, empty or unreadable file
    counts as absent, and the caller falls back to the generic text in the tree.
    The text is returned byte for byte, so a slot inside a sentence keeps its
    spacing.
    """
    base = os.environ.get("HEXTECH_PRIVATE_PROMPTS")
    root = Path(base) if base else DATA_DIR / "private-prompts"
    try:
        text = (root / f"{name}.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    return text if text.strip() else ""
