#!/usr/bin/env python3
"""The judge advises. It does not gate, and it is not a ritual.

WHY THIS EXISTS — TWO MEASURED COSTS, ONE OPERATOR DECISION (2026-09-03)

Job cc38cfa29161 ran to completion in 37.1 min and never shipped anything to
the sandbox. Two separate judge mechanisms fired on their own:

  1. Main's own JUDGE GATE was written as "mandatory before you finalize".
     Under Codex it had never actually run — the prompt told main to call
     `mcp__team__spawn_subagent`, which does not exist there — so the
     obligation was inert until the delegate-file channel gave main a working
     way to obey it. Then it obeyed: rounds #4 and #5 of that job were both
     single-judge rounds, 78s and two whole turns, immediately before
     finalize.

  2. `judge_mode=enforce` let prejudge BLOCK the ship at
     flag_likelihood=0.00, so the sandbox was never spawned.

The judge is not useless and this suite does not pretend otherwise: in that
same job it found a prompt wait longer than the sandbox's own limit and a
blocking receive, either of which reads as "exploit failed" rather than "we
waited too long". The decision was to keep the capability and drop the obligation — send
it when you cannot rule the risk out yourself, ship otherwise, and let the
sandbox produce real execution feedback instead of a prediction about it.

Run from the repository root::

    python3 scripts/test_judge_gate_optional.py
    python3 scripts/test_judge_gate_optional.py --mutate gate-mandatory-again
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SHARED = ROOT / "modules" / "_prompts.py"
SETTINGS = ROOT / "modules" / "settings_io.py"
COMMON = ROOT / "modules" / "_common.py"
RUNNER = ROOT / "modules" / "_runner.py"
MODULE_PROMPTS = {
    m: ROOT / "modules" / m / "prompts.py"
    for m in ("pwn", "web", "crypto", "web3", "rev")
}

P = SHARED.read_text()
C = COMMON.read_text()
R = RUNNER.read_text()
S = SETTINGS.read_text()
M = {k: v.read_text() for k, v in MODULE_PROMPTS.items()}

MUTATIONS = ("gate-mandatory-again", "module-step-mandatory-again",
             "retry-hint-mandatory-again", "shadow-gates",
             "gate-has-no-cost", "gate-has-no-trigger",
             "stale-justification-restored", "ship-gate-not-separable",
             "ship-gate-silent-when-off", "ship-gate-defaults-off",
             "ship-gate-fails-open", "ship-gate-accessor-raises")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

_P0, _C0, _R0, _M0, _S0 = P, C, R, dict(M), S

if args.mutate == "gate-mandatory-again":
    P = P.replace("JUDGE GATE (optional — your call, and it costs you a round)",
                  "JUDGE GATE (mandatory before you finalize)", 1)
    P = P.replace("You MAY send your final exploit/solver",
                  "You MUST send your final exploit/solver", 1)
elif args.mutate == "module-step-mandatory-again":
    M["pwn"] = M["pwn"].replace(
        "Pre-finalize: the JUDGE GATE is OPTIONAL",
        "Pre-finalize: invoke the JUDGE GATE", 1)
elif args.mutate == "retry-hint-mandatory-again":
    C = C.replace("The JUDGE GATE is available but OPTIONAL — spend a round",
                  "Re-run the JUDGE GATE (peer subagent) on the script", 1)
elif args.mutate == "shadow-gates":
    R = R.replace('return str(mode) == "enforce"',
                  'return str(mode) in ("enforce", "shadow")', 1)
elif args.mutate == "gate-has-no-cost":
    # Drop the price. An option with no stated cost reads as free, and a
    # free option gets taken every time — which is the behaviour being fixed.
    P = P.replace("It is NOT required, and it is not free: a judge\n"
                  "review is a full round plus a turn of yours.",
                  "It is NOT required.", 1)
elif args.mutate == "gate-has-no-trigger":
    # Drop WHEN to use it. "Optional" with no trigger is just "off", and the
    # too-long-wait class of defect goes back to being found by the sandbox.
    P = re.sub(r"SEND IT when you cannot rule out.*?would have looked like exploit failure\.\n",
               "", P, count=1, flags=re.S)
elif args.mutate == "ship-gate-not-separable":
    # Put the block back under "the judge ran at all", which is the coupling
    # that made silencing prejudge also silence postjudge.
    R = R.replace("                if _ship_gate:", "                if True:", 1)
elif args.mutate == "ship-gate-silent-when-off":
    # A near miss nobody can see. The gate gets blamed or credited for
    # outcomes it had nothing to do with.
    R = R.replace('                    f"[runner] prejudge WOULD have blocked ship (severity=high, "',
                  '                    f"" or (\n'
                  '                    f"[runner] quiet (severity=high, "', 1)
elif args.mutate == "ship-gate-defaults-off":
    # An upgrade must not silently remove a gate a deployment relies on.
    S = S.replace('("prejudge_ship_gate", "PREJUDGE_SHIP_GATE", bool, True)',
                  '("prejudge_ship_gate", "PREJUDGE_SHIP_GATE", bool, False)', 1)
elif args.mutate == "ship-gate-accessor-raises":
    S = S.replace("    try:\n        v = get_setting(\"prejudge_ship_gate\")\n"
                  "    except Exception:",
                  "    if True:\n        v = get_setting(\"prejudge_ship_gate\")\n"
                  "    if False:", 1)
elif args.mutate == "ship-gate-fails-open":
    R = R.replace("                    _ship_gate = True      # unreadable policy keeps the gate",
                  "                    _ship_gate = False", 1)
elif args.mutate == "stale-justification-restored":
    R = R.replace("Main's\n        # own JUDGE GATE was mandatory; as of 2026-09-03 it is OPTIONAL,",
                  "Main\n        # already has its own internal JUDGE GATE turn, so", 1)

if args.mutate and (P, C, R, M, S) == (_P0, _C0, _R0, _M0, _S0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} DID NOT APPLY — its anchor no longer exists. "
        "Fix the anchor; do not delete the mutation."
    )

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}\n        want={want!r}")


def _gate_block() -> str:
    i = P.find("JUDGE GATE (")
    assert i > 0, "the judge gate block is gone entirely"
    j = P.find("\nJudge replies with findings", i)
    return P[i:j if j > i else i + 4000]


def _obligation_checks() -> None:
    """No wording anywhere may make the review a required step."""
    block = _gate_block()
    check("O1 the gate announces itself as optional",
          "optional" in block.splitlines()[0].lower(), True)
    check("O2 ...and no line orders main to send it",
          [l for l in block.splitlines()
           if re.search(r"\bMUST send\b|\byou MUST\b", l)], [])
    check("O2 ...it is offered, not commanded",
          "You MAY send" in block, True)

    # The per-module checklists are what main reads as its running order, so
    # an "invoke the JUDGE GATE" step there reinstates the obligation no
    # matter how the shared block is worded.
    for name, text in sorted(M.items()):
        step = [l for l in text.splitlines() if "JUDGE GATE" in l]
        check(f"O3 {name}: the checklist step exists", bool(step), True)
        check(f"O3 {name}: ...and marks it OPTIONAL",
              all("OPTIONAL" in l for l in step), True)
        check(f"O3 {name}: ...and does not order it invoked",
              [l for l in step if re.search(r"invoke the JUDGE GATE", l)], [])

    # The retry hint is a fresh user turn — it can re-impose the obligation
    # after the fact even when every prompt above is clean.
    check("O4 the retry hint does not re-impose the gate",
          bool(re.search(r"Re-run the JUDGE GATE", C)), False)
    check("O4 ...and says plainly that it is optional there too",
          "JUDGE GATE is available but OPTIONAL" in C, True)


def _usefulness_checks() -> None:
    """Optional must not decay into never. The text has to say WHEN, and
    what it costs — a stated price is what stops 'optional' being taken as
    'free', and a stated trigger is what stops it being taken as 'off'."""
    block = _gate_block()
    check("U1 the price is stated, so the option is not read as free",
          "not free" in block and "round" in block, True)
    check("U2 ...and the trigger is stated, so it is not read as off",
          "SEND IT when you cannot rule out" in block, True)
    check("U3 ...naming the risks judge actually catches",
          all(w in block for w in ("unbounded recv", "parse mismatch",
                                   "longer than the runner")), True)
    # Keep the evidence in the prompt: main complies with reasons, and this
    # one is a measured save, not an assertion.
    check("U4 ...and the measured save is cited, not asserted",
          "prompt wait longer than" in block and "blocking receive" in block, True)
    check("U5 ...against the measured cost of doing it every time",
          "cc38cfa29161" in block and "78 seconds" in block, True)


def _mode_checks() -> None:
    """`shadow` records; only `enforce` gates. The operator moved to shadow
    on 2026-09-03, so the distinction is now load-bearing."""
    from modules.settings_io import JUDGE_MODES, effective_judge_mode

    check("M1 the three modes still exist",
          sorted(JUDGE_MODES), ["enforce", "off", "shadow"])
    # `_judge_gates` is read from source: importing _runner pulls docker.
    m = re.search(r"def _judge_gates\(mode: str\) -> bool:.*?\n    return ([^\n]+)",
                  R, re.S)
    check("M2 the gate predicate exists", bool(m), True)
    check("M2 ...and ONLY enforce gates",
          (m.group(1).strip() if m else ""), 'str(mode) == "enforce"')
    check("M3 shadow stays shadow for every module",
          [effective_judge_mode("shadow", mod)
           for mod in ("pwn", "rev", "web", "crypto", "web3", "misc", "")],
          ["shadow"] * 7)
    check("M4 off never becomes a gate",
          [effective_judge_mode("off", mod) for mod in ("pwn", "")],
          ["off", "off"])
    # An unknown module must not resolve INTO a gate — not knowing what
    # something is, is not a reason to block it.
    check("M5 an unknown module never reaches enforce",
          effective_judge_mode("enforce", "no-such-module"), "shadow")


def _ship_gate_checks() -> None:
    """Blocking the ship is a SEPARATE decision from running the judge.

    `judge_mode` used to be one switch over two different things: prejudge, a
    prediction made before the script has ever run, and postjudge, a reading
    of what a real execution did. Job cc38cfa29161 showed the cost of the
    first firing (flag_likelihood=0.00 blocked the ship; the sandbox never
    ran). Job df05d2ce2710 showed the cost of silencing it via `shadow`: the
    sandbox ran twice and then the retry loop had no verdict to iterate on and
    stopped at 24.7 min of a 58 min budget. Neither is the judge being wrong —
    both are one switch spanning a prediction and a measurement.
    """
    check("G1 the ship gate is its own setting",
          '("prejudge_ship_gate", "PREJUDGE_SHIP_GATE", bool, True)' in S, True)
    # Default ON: an upgrade must never silently remove a gate a deployment
    # depends on. This one turns it off explicitly.
    check("G1 ...defaulting ON, so an upgrade changes nobody's behaviour",
          'bool, True)' in S.split('"PREJUDGE_SHIP_GATE"')[1][:40], True)
    check("G2 ...with a reader that is not captured at import",
          "def prejudge_ship_gate_enabled()" in S, True)

    # The block must be conditional on the gate, not on "a judge ran".
    check("G3 the block is gated by the ship gate, not by enable_judge",
          "if _ship_gate:" in R, True)
    check("G3 ...and the gate is READ, not assumed",
          "prejudge_ship_gate_enabled()" in R, True)
    check("G4 an unreadable policy KEEPS the gate at the call site",
          "_ship_gate = True      # unreadable policy keeps the gate" in R, True)
    # ...and in the accessor itself, because the property belongs to the gate
    # and not to one caller remembering to wrap it.
    import modules.settings_io as _sio
    _real = _sio.get_setting
    try:
        _sio.get_setting = lambda k: (_ for _ in ()).throw(RuntimeError("boom"))
        check("G4 ...and the accessor does not raise it at the next caller",
              _sio.prejudge_ship_gate_enabled(), True)
    finally:
        _sio.get_setting = _real
    # Structural, because the check above imports the REAL module and so can
    # never notice a change to the shipped source. Both layers or neither.
    _acc = next((n for n in ast.parse(S).body
                 if isinstance(n, ast.FunctionDef)
                 and n.name == "prejudge_ship_gate_enabled"), None)
    check("G4 ...and the shipped accessor really has the guard", bool(_acc), True)
    _tries = [t for t in ast.walk(_acc) if isinstance(t, ast.Try)] if _acc else []
    check("G4 ...as a try that catches Exception",
          bool(_tries) and any(
              isinstance(h.type, ast.Name) and h.type.id == "Exception"
              for t in _tries for h in t.handlers), True)
    check("G4 ...whose handler returns the SAFE value",
          any(isinstance(st, ast.Return)
              and isinstance(st.value, ast.Constant) and st.value.value is True
              for t in _tries for h in t.handlers for st in h.body), True)
    check("G4 ...and a key nobody ever set reads as ON",
          _sio.prejudge_ship_gate_enabled.__doc__ is not None
          and "missing key is ON" in _sio.prejudge_ship_gate_enabled.__doc__, True)

    # With the gate off, the near miss has to be visible or it never happened
    # as far as anyone reading the log is concerned.
    check("G5 a bypassed block is announced, not swallowed",
          "prejudge WOULD have blocked ship" in R, True)
    check("G5 ...as its own event, distinguishable from a real block",
          '"prejudge", "would_block"' in R and '"prejudge", "blocked"' in R, True)
    check("G5 ...and says why running anyway is the better bet",
          "better evidence than a prediction" in R, True)

    # THE POINT OF THE SPLIT: postjudge must survive turning the gate off.
    # It lives under `if enable_judge:`, so the mode has to stay `enforce`.
    i = R.find("Stage 1: prejudge (ship gate)")
    note = R[i:i + 2600] if i > 0 else ""
    check("G6 the note records that shadow silenced postjudge too",
          "shadow silences POSTJUDGE too" in note
          or "silences POSTJUDGE" in note, True)
    check("G6 ...naming the job that measured it",
          "df05d2ce2710" in note, True)
    check("G6 ...and the one that measured the other half",
          "cc38cfa29161" in note, True)


def _justification_checks() -> None:
    """A comment that asserts a premise the code no longer has is how the
    next change inherits a false one. The ship-block's own note used to say
    main had already run a mandatory gate before it."""
    i = R.find("Stage 1: prejudge (ship gate)")
    note = R[i:i + 2200] if i > 0 else ""
    check("J1 the ship-block note exists", bool(note), True)
    check("J2 ...and no longer claims a gate main may never run",
          bool(re.search(r"already has its own internal JUDGE GATE turn", note)),
          False)
    check("J3 ...and records that the gate became optional",
          "OPTIONAL" in note and "2026-09-03" in note, True)
    check("J4 ...and that the block only applies under enforce",
          "enforce" in note, True)
    check("J5 ...and names what still backstops a bad ship",
          "postjudge" in note and "timeout" in note, True)


def main() -> int:
    _obligation_checks()
    _usefulness_checks()
    _mode_checks()
    _ship_gate_checks()
    _justification_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
