#!/usr/bin/env python3
"""run.log must stay text, or the tools everyone reads it with go silent.

WHY THIS EXISTS

Agent tool output carries raw bytes: serial consoles, hexdumps, killed
processes. Job 549fcc1195ff wrote 998 NUL bytes into its run.log and
a2fcb3c313ab wrote 115. GNU grep classifies a file containing a NUL as binary
and then prints nothing for a match — with `-c` it prints nothing at all and
exits 1, which is indistinguishable from "that line is not there".

That is not hypothetical tidiness. Twice in one session a search of a real job
log returned empty and the honest reading was "the agent never did this",
when the agent had done it 26 times. An operator tailing their own job hits
exactly the same wall.

Run:
    python3 scripts/test_run_log_is_text.py
    python3 scripts/test_run_log_is_text.py --mutate no-sanitiser
"""
from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

COMMON = ROOT / "modules" / "_common.py"
C = COMMON.read_text()

MUTATIONS = ("no-sanitiser", "drops-instead-of-escaping", "eats-newlines",
             "line-writer-unsanitised", "block-writer-unsanitised",
             "sanitiser-can-raise")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_C0 = C

if args.mutate == "no-sanitiser":
    C = C.replace(r'_LOG_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")',
                  '_LOG_CTRL_RE = re.compile(r"(?!x)x")', 1)
elif args.mutate == "drops-instead-of-escaping":
    # A NUL that becomes nothing silently joins the bytes on either side.
    C = C.replace('lambda m: "\\\\x%02x" % ord(m.group()), raw',
                  'lambda m: "", raw', 1)
elif args.mutate == "eats-newlines":
    C = C.replace(r'_LOG_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")',
                  r'_LOG_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")', 1)
elif args.mutate == "line-writer-unsanitised":
    C = C.replace("    line = _log_safe(redact_job_value(job_id, str(line)))",
                  "    line = str(redact_job_value(job_id, str(line)))", 1)
elif args.mutate == "block-writer-unsanitised":
    C = C.replace("    body = _log_safe(redact_job_value(job_id, str(body or \"\")))",
                  "    body = str(redact_job_value(job_id, str(body or \"\")))", 1)
elif args.mutate == "sanitiser-can-raise":
    # Let an unprintable object escape. Logging must never be the thing that
    # ends a turn.
    C = C.replace('    except Exception:\n        return "<unloggable object>"',
                  "    except Exception:\n        raise", 1)

if args.mutate and C == _C0:
    raise SystemExit(
        f"MUTATION {args.mutate!r} DID NOT APPLY — its anchor is gone. "
        "Fix the anchor; do not delete the mutation."
    )

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}\n        want={want!r}")


# Exec just the sanitiser from the (possibly mutated) source, so a mutation is
# what runs — importing modules._common would test the shipped file instead.
NS: dict = {"re": re}
for node in ast.parse(C).body:
    if isinstance(node, ast.FunctionDef) and node.name == "_log_safe":
        exec(compile(ast.get_source_segment(C, node), str(COMMON), "exec"), NS)
    elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_LOG_CTRL_RE" for t in node.targets):
        exec(compile(ast.get_source_segment(C, node), str(COMMON), "exec"), NS)
_safe = NS.get("_log_safe", lambda x: x)


def _grep_shows(body: str, needle: str) -> bool:
    """Does a plain `grep` actually SHOW the matching line?

    Printing mode, not `-c`, and the distinction is the whole bug: measured on
    GNU grep here, a file containing a NUL still COUNTS matches with `-c` but
    prints NOTHING without it — rc=0 and empty stdout. That is what fooled two
    searches in one session, because an empty result reads as "not there".
    """
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fp:
        fp.write(body)
        path = fp.name
    try:
        r = subprocess.run(["grep", needle, path], capture_output=True, text=True)
        return bool(r.stdout.strip())
    finally:
        Path(path).unlink(missing_ok=True)


def _reproduce_the_bug() -> None:
    """First prove the failure is real, or the fix is guarding nothing."""
    poisoned = "[00:01:02] [main] TOOL_RESULT: boot\x00ok\n[00:01:03] delegate round: 3 agents\n"
    check("R1 grep prints NOTHING for a match in a log with a NUL",
          _grep_shows(poisoned, "delegate round"), False)
    check("R1 ...and shows the line once it is sanitised",
          _grep_shows(_safe(poisoned), "delegate round"), True)


def _sanitiser_checks() -> None:
    check("S1 a NUL is escaped, not dropped", _safe("a\x00b"), "a\\x00b")
    check("S1 ...so nothing silently joins across it",
          "ab" in _safe("a\x00b"), False)
    check("S2 other C0 controls are escaped too",
          _safe("\x01\x07\x1b\x7f"), "\\x01\\x07\\x1b\\x7f")
    # Newlines and tabs are the callers' business — log_block splits on them.
    check("S3 newline and tab survive untouched", _safe("a\nb\tc"), "a\nb\tc")
    check("S4 ordinary text is unchanged",
          _safe("[main] AGENT: 판정: 계산 불가"), "[main] AGENT: 판정: 계산 불가")
    check("S5 a sanitiser never breaks logging",
          _safe(object()).startswith("<object"), True)

    class _Hostile:
        def __str__(self): raise RuntimeError("this object refuses to render")

    # The fallback used to be `return str(text)` — the very call that fails
    # here. A rescue path that re-runs the failing call is not a rescue path.
    try:
        _out = _safe(_Hostile())
        check("S5 ...even when the object itself refuses to render",
              isinstance(_out, str) and _out != "", True)
    except Exception as _e:
        check("S5 ...even when the object itself refuses to render",
              f"raised {type(_e).__name__}", True)


def _wiring_checks() -> None:
    """Both writers, or the un-sanitised one poisons the same file."""
    for fn_name, field in (("log_line", "line"), ("log_block", "body")):
        src = next(
            (ast.get_source_segment(C, n) for n in ast.parse(C).body
             if isinstance(n, ast.FunctionDef) and n.name == fn_name), "")
        check(f"W1 {fn_name} sanitises before writing",
              f"{field} = _log_safe(" in src, True)
        check(f"W1 ...and still writes to run.log", '"run.log"' in src, True)
    check("W2 log_block sanitises its prefix as well",
          "prefix = _log_safe(" in C, True)


def main() -> int:
    _reproduce_the_bug()
    _sanitiser_checks()
    _wiring_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
