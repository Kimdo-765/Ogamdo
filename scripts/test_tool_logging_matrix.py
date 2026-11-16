#!/usr/bin/env python3
"""Every provider branch must log tool ARGUMENTS and tool RESULTS.

WHY THIS EXISTS

run.log is the only artifact a post-mortem reads. An agent's tool calls reach
it through a per-provider `async for msg in client.receive_response()` loop,
and there are nine such branches: three providers (GPT, Grok, Claude) x three
modules (_common.run_pre_recon, misc/, forensic/).

The instrumentation was written for Claude and then only partly copied:

    module                      GPT              Grok             Claude
    _common.run_pre_recon       args -  res -    args OK res -    OK
    misc/orchestrator           args -  res -    args OK res -    OK
    forensic/orchestrator       args -  res -    args OK res -    OK

Measured, not inferred. Job 7d409c40249e (misc, GPT backend) produced 126 KB
of gpt-events.jsonl — 41 tool calls carrying their full command text and 46
completions carrying ~69 KB of output — and its run.log received 3 KB of it:
a column of bare "TOOL Bash" lines, not one command, not one result. The
operator's report was "출력이 너무 없다", and they were right.

The same hole had already been found once, in run_pre_recon's Claude branch
(job 62531f9da538: 18 TOOL calls, 0 TOOL_RESULT). That fix never reached the
GPT and Grok branches beside it, and the un-fixed shape was later copied into
misc/ and forensic/. That is the actual failure mode this file guards: not
"a branch is wrong" but "a branch was fixed and its siblings were not".

So the matrix check below is the point of the suite. The behavioural checks
verify the shared helpers; the matrix check verifies that every branch is
WIRED to them, which is the part that historically rots.

Run:
    python3 scripts/test_tool_logging_matrix.py
    python3 scripts/test_tool_logging_matrix.py --mutate gpt-name-only
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

COMMON = ROOT / "modules" / "_common.py"
MISC = ROOT / "modules" / "misc" / "orchestrator.py"
FORENSIC = ROOT / "modules" / "forensic" / "orchestrator.py"

C = COMMON.read_text()
M = MISC.read_text()
F = FORENSIC.read_text()

MUTATIONS = (
    "gpt-name-only",          # GPT branch logs the tool name, drops the args
    "no-result-branch-gpt",   # GPT branch stops handling UserMessage
    "no-result-branch-grok",  # Grok branch stops handling UserMessage
    "forensic-forgotten",     # misc fixed, forensic left behind — the real bug
    "args-drop-input",        # helper returns the name only
    "result-swallows-all",    # helper returns no lines
    "result-uncapped",        # helper bypasses the 200 KB valve
    "result-eats-errors",     # helper loses the is_error distinction
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_C0, _M0, _F0 = C, M, F


def _in_function(src: str, fn: str, old: str, new: str) -> str:
    """Replace inside ONE function body.

    A bare src.replace(x, y, 1) hits the FIRST occurrence in a 10k-line file,
    which for `out: list[str] = []` and `bool(getattr(block, "is_error", ...))`
    is some unrelated function — the mutation then "applies", the stale-anchor
    guard stays quiet, and the suite reports a clean escape while the code it
    meant to break was never touched. Two mutations in this very file failed
    that way before this helper existed.
    """
    i = src.index(f"def {fn}(")
    head, body = src[:i], src[i:]
    assert old in body, f"anchor {old!r} not found inside {fn}"
    return head + body.replace(old, new, 1)


def _drop_branch(src: str, nth: int) -> str:
    """Delete the nth `elif ... UserMessage:` branch, CONDITION AND BODY.

    Deleting only the condition line leaves a dangling body — a SyntaxError,
    which aborts the suite instead of failing a check and so proves nothing.
    Making the condition unreachable (`elif False and ...`) is no better: the
    call to tool_result_lines survives textually, so the matrix check, which
    reads source, still sees it and passes. The faithful mutation is the one
    that reproduces the original defect: the branch is simply not there.
    """
    lines = src.splitlines(keepends=True)
    hits = [i for i, l in enumerate(lines)
            if l.lstrip().startswith('elif type(msg).__name__ == "UserMessage":')]
    if nth >= len(hits):
        return src
    start = hits[nth]
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines):
        stripped = lines[end].strip()
        if stripped and (len(lines[end]) - len(lines[end].lstrip())) <= indent:
            break
        end += 1
    return "".join(lines[:start] + lines[end:])

if args.mutate == "gpt-name-only":
    C = C.replace('log_line(job_id, f"[{tag}] {tool_use_line(block)}")',
                  'log_line(job_id, f"[{tag}] TOOL {getattr(block, \'name\', \'?\')}")', 1)
    M = M.replace("_log(job_id, tool_use_line(block))",
                  "_log(job_id, f\"TOOL {getattr(block, 'name', '?')}\")", 1)
    F = F.replace("_log(job_id, tool_use_line(block))",
                  "_log(job_id, f\"TOOL {getattr(block, 'name', '?')}\")", 1)
elif args.mutate in ("no-result-branch-gpt", "no-result-branch-grok"):
    nth = 0 if args.mutate == "no-result-branch-gpt" else 1
    C, M, F = _drop_branch(C, nth), _drop_branch(M, nth), _drop_branch(F, nth)
elif args.mutate == "forensic-forgotten":
    # misc/ repaired, forensic/ left as it was — the exact shape in which this
    # defect survived its first fix. BOTH halves must apply: _drop_branch
    # alone would change F, satisfy the stale-anchor guard below, and hide a
    # dead args anchor. Assert the args edit separately rather than trusting
    # "F differs from _F0".
    _F_ARGS = "_log(job_id, tool_use_line(block))"
    assert _F_ARGS in F, "forensic-forgotten: args anchor is stale"
    F = F.replace(_F_ARGS, "_log(job_id, f\"TOOL {getattr(block, 'name', '?')}\")", 1)
    _F_mid = F
    F = _drop_branch(F, 0)
    assert F != _F_mid, "forensic-forgotten: result branch not found in forensic/"
elif args.mutate == "args-drop-input":
    C = C.replace('    return f"TOOL {name}: {preview}"', '    return f"TOOL {name}"', 1)
elif args.mutate == "result-swallows-all":
    C = _in_function(C, "tool_result_lines",
                     "    out: list[str] = []", "    return []\n    out: list[str] = []")
elif args.mutate == "result-uncapped":
    C = _in_function(
        C, "tool_result_lines",
        "                format_tool_result(\n"
        "                    getattr(block, \"content\", None),\n"
        "                    bool(getattr(block, \"is_error\", False)),\n"
        "                )",
        "                \"TOOL_RESULT: \" + str(getattr(block, \"content\", None))")
elif args.mutate == "result-eats-errors":
    # Scope the edit to the HELPER. The identical expression also appears in
    # run_pre_recon's Claude branch, earlier in the file, and a bare
    # replace(..., 1) would silently mutate that instead — testing a branch
    # this mutation was not aimed at.
    C = _in_function(C, "tool_result_lines",
                     'bool(getattr(block, "is_error", False)),', "False,")

if args.mutate and (C, M, F) == (_C0, _M0, _F0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor no longer "
        "matches the source. A mutation that does not apply proves nothing; "
        "fix the anchor before trusting this suite."
    )

PASSED = FAILED = 0


def first(lines) -> str:
    """First rendered line, or "" — so a helper that returns NOTHING fails a
    check with a readable message instead of raising IndexError. A suite that
    dies on the mutation it was written to catch reports a crash, not a bite.
    """
    return lines[0] if lines else ""


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# ---------------------------------------------------------------------------
# The helpers, exec'd from the (possibly mutated) source.
#
# Importing modules._common would load the REAL file and quietly ignore every
# mutation above — the class of mistake that made earlier suites look green
# while testing nothing. Pull the three functions out by AST and run those.
# ---------------------------------------------------------------------------
def _load_helpers(src: str):
    tree = ast.parse(src)
    wanted = {"format_tool_result", "tool_use_line", "tool_result_lines"}
    segs = [ast.get_source_segment(src, n) for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name in wanted]
    if len(segs) != len(wanted):
        raise SystemExit(f"expected {sorted(wanted)}, found {len(segs)} definitions")
    ns: dict = {"json": json, "Any": object}
    exec("\n\n".join(segs), ns)
    return ns["tool_use_line"], ns["tool_result_lines"]


tool_use_line, tool_result_lines = _load_helpers(C)


class TRB:
    """Duck-typed ToolResultBlock — every provider's class is shaped this way
    and the production code matches on type(block).__name__, not on import."""
    def __init__(self, content=None, is_error=False):
        self.content, self.is_error = content, is_error


TRB.__name__ = "ToolResultBlock"


class TUB:
    def __init__(self, name, input):
        self.name, self.input = name, input


class Msg:
    def __init__(self, content):
        self.content = content


# ---------------------------------------------------------------------------
def _reproduce_the_bug() -> None:
    """The exact events job 7d409c40249e recorded, replayed through the fix.

    These two are verbatim from its gpt-events.jsonl. Before the fix the GPT
    branch turned the first into "TOOL Bash" and dropped the second entirely.
    """
    print("\nR — the job that started this")
    line = tool_use_line(TUB("Bash", {"command": "/bin/bash -lc \"sed -n '1,240p' findings.json\""}))
    check("R1 the command reaches run.log, not just the word Bash",
          "findings.json" in line, True)
    check("R1 ...and it is still a TOOL line", line.startswith("TOOL Bash:"), True)

    out = tool_result_lines(Msg([TRB(content='{"size": 6807, "filetype": "zip"}')]))
    check("R2 a GPT tool result produces a line", len(out), 1)
    check("R2 ...carrying the output", "6807" in first(out), True)

    # If the live job's events are still on disk, replay ALL of them: a
    # synthetic fixture cannot prove the adapter's real shapes are handled.
    ev = ROOT / "data" / "jobs" / "7d409c40249e" / "gpt-events.jsonl"
    if ev.exists():
        starts = results = empty = 0
        for raw in ev.read_text(errors="replace").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                d = json.loads(raw)
            except Exception:
                continue
            if d.get("kind") == "tool_started":
                if "TOOL " in tool_use_line(TUB(d.get("tool"), d.get("input") or {})):
                    starts += 1
            elif d.get("kind") == "tool_completed":
                got = tool_result_lines(Msg([TRB(content=d.get("detail") or "",
                                                 is_error=d.get("status") == "failed")]))
                results += len(got)
                empty += (not got)
        check("R3 every real tool_started renders", starts > 0, True)
        check("R3 every real tool_completed renders", results > 0, True)
        check("R3 ...and none render as nothing", empty, 0)


def _helper_checks() -> None:
    print("\nH — the shared helpers")
    check("H1 arguments are included",
          "ls -la" in tool_use_line(TUB("Bash", {"command": "ls -la"})), True)
    check("H2 a missing name degrades, never raises",
          tool_use_line(TUB(None, {})).startswith("TOOL ?"), True)

    class Hostile:
        def __repr__(self): raise RuntimeError("refuses to render")
    # json.dumps raises on this; str() on the DICT still works, so the first
    # fallback must be tried before giving up.
    check("H3 non-serialisable input does not kill the message loop",
          tool_use_line(TUB("Bash", {"x": Hostile()})).startswith("TOOL Bash:"), True)

    check("H4 errors are marked as errors",
          first(tool_result_lines(Msg([TRB("boom", True)]))).startswith("TOOL_ERROR"), True)
    check("H4 ...and successes are not",
          first(tool_result_lines(Msg([TRB("fine", False)]))).startswith("TOOL_RESULT"), True)

    # Claude sends a list of {type,text} dicts; GPT sends a bare string. One
    # helper serves both because format_tool_result already normalises them.
    check("H5 Claude's list shape renders",
          "hello" in first(tool_result_lines(Msg([TRB([{"type": "text", "text": "hello"}])]))), True)
    check("H5 GPT's string shape renders",
          "hello" in first(tool_result_lines(Msg([TRB("hello")]))), True)

    check("H6 non-result blocks are ignored", tool_result_lines(Msg([TUB("Bash", {})])), [])
    check("H7 an empty message is not an error", tool_result_lines(Msg(None)), [])

    # The 200 KB valve lives in format_tool_result. Wiring a branch to the
    # helper must inherit it — misc jobs run WebSearch heavily and a raw
    # result can be far larger than run.log should ever take in one line.
    big = first(tool_result_lines(Msg([TRB("A" * 400_000)])))
    check("H8 the 200 KB disaster valve still applies", len(big) < 250_000, True)


def _matrix_checks() -> None:
    """The point of the suite: is every branch WIRED to the helpers?

    Slices each provider branch out of its own function by the `# ---- X path`
    markers, so a fix landing in one provider and not its siblings fails here
    — which is precisely how this bug survived its first repair.
    """
    print("\nM — the 3x3 provider/module matrix")
    targets = (("_common.run_pre_recon", C, "run_pre_recon"),
               ("misc/orchestrator", M, "_claude_summary"),
               ("forensic/orchestrator", F, "_claude_summary"))
    for label, src, fn_name in targets:
        fn = next((ast.get_source_segment(src, n) for n in ast.parse(src).body
                   if isinstance(n, ast.FunctionDef) and n.name == fn_name), None)
        if fn is None:
            fn = next((ast.get_source_segment(src, n)
                       for n in ast.walk(ast.parse(src))
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and n.name == fn_name), None)
        check(f"M0 {label}: {fn_name} found", fn is not None, True)
        if fn is None:
            continue
        lines = fn.splitlines()
        marks = [i for i, l in enumerate(lines) if "path ---" in l]
        check(f"M0 {label}: three provider branches", len(marks), 3)
        if len(marks) != 3:
            continue
        bounds = marks + [len(lines)]
        for k, prov in enumerate(("GPT", "Grok", "Claude")):
            seg = "\n".join(lines[bounds[k]:bounds[k + 1]])
            check(f"M1 {label}/{prov} logs tool ARGUMENTS",
                  ("tool_use_line(" in seg) or ("preview}" in seg) or ("args_preview}" in seg),
                  True)
            check(f"M2 {label}/{prov} logs tool RESULTS",
                  ("tool_result_lines(" in seg) or ("format_tool_result(" in seg),
                  True)


def main() -> int:
    _reproduce_the_bug()
    _helper_checks()
    _matrix_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
