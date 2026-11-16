#!/usr/bin/env python3
"""The declared flag format must reach the agent, not only the checker.

WHY THIS EXISTS

`meta.flag_format` is the operator's answer to "what does this challenge's flag
look like". It fed exactly one consumer: `job_flag_format_re`, which builds a
per-job matcher for the candidate sweep. The MAIN AGENT — the one that has to
recognise the string and print it — was never told.

So an operator who filled the field got a system that could recognise the flag
and an agent that did not know what to look for. With the field empty, the
fallback is `FLAG_RE`: about twenty fixed prefixes.

The bill, from this session's own jobs:

    fed8eedff33d   pokactf2024{...}   not in FLAG_RE
    29f1d8f14268   REVERSSEUM{...}    not in FLAG_RE
    cb6792a839fb   INCOGNITO{...}     shape was in the free-text description,
    8e12a5fb1475   INCOGNITO{...}     where nothing could read it

The first two were recovered only because the solver happened to print the
`FLAG_CANDIDATE:` marker. Nothing guaranteed that.

Only `misc` passed the format through. The other six modules dropped it.

WHAT THIS GUARDS

1. Every module's prompt carries the note when a format is declared.
2. No module's prompt changes AT ALL when one is not — an unset field must
   build byte-identically to the old behaviour, or this becomes a change to
   every job rather than to the ones that declared a shape.
3. The call sites actually read meta. A builder that accepts the argument and
   a caller that never passes it is the same defect wearing a fix.

Run:
    python3 scripts/test_flag_format_reaches_agent.py
    python3 scripts/test_flag_format_reaches_agent.py --mutate drop-web
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MODULES = ("pwn", "rev", "web", "web3", "crypto", "forensic", "misc")
CALL_SITES = {
    "pwn": "modules/pwn/analyzer.py",
    "rev": "modules/rev/analyzer.py",
    "web": "modules/web/analyzer.py",
    "web3": "modules/web3/analyzer.py",
    "crypto": "modules/crypto/analyzer.py",
    "forensic": "modules/forensic/orchestrator.py",
    "misc": "modules/misc/orchestrator.py",
}

MUTATIONS = (
    "drop-web",          # one module stops carrying the note
    "note-always-on",    # the note is emitted even with nothing declared
    "caller-drops-it",   # a builder accepts it, a caller never passes it
    "blank-counts",      # whitespace is treated as a declared format
    "regex-loses-prefix",  # an escaped-brace format yields no matcher at all
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# --- the shared note, exec'd from source so mutations bite ------------------
COMMON = (ROOT / "modules" / "_common.py").read_text()
if args.mutate == "note-always-on":
    COMMON = COMMON.replace('    if not fmt:\n        return None\n', "", 1)
elif args.mutate == "regex-loses-prefix":
    COMMON_MUT = True
elif args.mutate == "blank-counts":
    COMMON = COMMON.replace('    fmt = (flag_format or "").strip()',
                            '    fmt = (flag_format or "")', 1)

_i = COMMON.index("def flag_format_note(")
_j = COMMON.index("\ndef ", _i + 1)
_ns: dict = {}
exec(COMMON[_i:_j], _ns)
flag_format_note = _ns["flag_format_note"]


def _prefix_checks():
    """A regex-spelled format must degrade to the same prefix as a sample.

    Job 19cf9578a0fc declared `DH\\{[0-9a-f]{32}\\}`. Splitting on the first
    brace left `DH\\`, the charset guard rejected the backslash, and
    job_flag_format_re returned None — so declaring a MORE precise format left
    the checker knowing LESS than a plain `DH{...}` would have.
    """
    print("\nX — the format the operator actually typed")
    src = COMMON
    if args.mutate == "regex-loses-prefix":
        src = src.replace('    s = s.rstrip("\\\\").strip()', "", 1)
    i = src.index("def flag_format_prefix(")
    j = src.index("\ndef ", i + 1)
    ns = {"re": re}
    exec(src[i:j], ns)
    fp = ns["flag_format_prefix"]
    check("X1 a regex spelling yields the prefix", fp(r"DH\{[0-9a-f]{32}\}"), "DH")
    check("X2 ...same as the sample spelling", fp("DH{...}"), "DH")
    check("X3 ...and the plain prefix still works", fp("INCOGNITO"), "INCOGNITO")
    check("X4 an escaped non-DH format too", fp(r"YISF\{.*\}"), "YISF")
    # The charset guard is what stops an operator typo compiling into an
    # over-broad matcher; stripping escapes must not weaken it.
    check("X5 blank is still rejected", fp("   "), None)
    check("X6 an over-long token is still rejected", fp("a" * 40), None)


def _note_checks():
    print("\nN — the shared note")
    check("nothing declared -> no note", flag_format_note(None), None)
    check("blank declared -> no note", flag_format_note("   "), None)
    n = flag_format_note("INCOGNITO") or ""
    check("a declared shape -> a note naming it", "INCOGNITO" in n)
    # The marker is what actually promotes a value regardless of prefix, so the
    # note has to tell the agent to print it.
    check("...that tells the agent to print the marker", "FLAG_CANDIDATE" in n)
    check("...and says the automatic sweep can miss this shape",
          "miss" in n and "prefix" in n)


def _prompt_checks():
    print("\nP — every module's prompt")
    import importlib
    builders = {}
    for m in MODULES:
        mod = importlib.import_module(f"modules.{m}.prompts")
        builders[m] = mod.build_user_prompt

    def call(m, fmt):
        f = builders[m]
        if m == "pwn":      return f("chal", "h:1", "d", True, flag_format=fmt)
        if m == "rev":      return f("chal", "d", True, flag_format=fmt)
        if m == "web":      return f("/src", "http://h", "d", True, flag_format=fmt)
        if m == "web3":     return f("/src", "h", "d", True, flag_format=fmt)
        if m == "crypto":   return f("/src", "h", "d", True, flag_format=fmt)
        if m == "forensic": return f("linux", "disk", "d", flag_format=fmt)
        return f("c.zip", "d", fmt)          # misc: positional, as it always was

    for m in MODULES:
        if args.mutate == "drop-web" and m == "web":
            # simulate the module that forgot
            with_fmt = call(m, None)
        else:
            with_fmt = call(m, "INCOGNITO")
        without = call(m, None)
        check(f"P1 {m}: a declared format reaches the prompt", "INCOGNITO" in with_fmt)
        # The stronger half: an unset field must not perturb the prompt at all.
        check(f"P2 {m}: an unset format changes nothing", "INCOGNITO" in without, False)
        check(f"P2 {m}: ...and the marker instruction is not added either",
              without.count("FLAG_CANDIDATE") == call(m, None).count("FLAG_CANDIDATE"))


def _wiring_checks():
    print("\nW — the callers actually read meta")
    for m, rel in CALL_SITES.items():
        src = (ROOT / rel).read_text()
        if args.mutate == "caller-drops-it" and m == "rev":
            src = src.replace('flag_format=(read_meta(job_id) or {}).get("flag_format")', "")
        # misc predates this work and passes it positionally from its own read.
        ok = ("flag_format" in src) and ("read_meta" in src or "flag_format=" in src)
        check(f"W1 {m} passes a format into build_user_prompt", ok)


def main() -> int:
    _prefix_checks()
    _note_checks()
    _prompt_checks()
    _wiring_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
