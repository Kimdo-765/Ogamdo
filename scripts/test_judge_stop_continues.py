#!/usr/bin/env python3
"""A judge STOP is a statement about the size of the work, not the end of it.

WHAT THE CORPUS SHOWED

Several runs on one hard challenge all ended on a judge opinion (a judge
STOP, a missing retry_hint, a concession); none ended because a budget ran out.

Meanwhile INVESTIGATION_BUDGET=0, COST_CAP_USD=0, AUTO_RETRY_MAX=-1 and
job_timeout_seconds=9999999. Nothing was capping anything. The runs had
unlimited road and stopped anyway. "No small fix exists" is the CORRECT
verdict on a target that needs a capability the run has not built yet; it
is the signal that the long work starts, not that the run is over.

Operator decision, 2026-09-03: a CTF runs at most 48 hours and the operator
holds Stop, so an unproductive loop is cheap to end by hand and a premature
halt is not. `judge_stop_halts` is OFF here, default ON for everyone else.

Run:
    python3 scripts/test_judge_stop_continues.py
    python3 scripts/test_judge_stop_continues.py --mutate halt-anyway
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

COMMON = ROOT / "modules" / "_common.py"
SETTINGS = ROOT / "modules" / "settings_io.py"
C = COMMON.read_text()
S = SETTINGS.read_text()

MUTATIONS = ("halt-anyway", "converts-without-hint", "fails-open",
             "default-off", "no-local-hint", "silent-conversion",
             "ignores-dead-remote", "hides-circling",
             "concession-still-ends-it", "ready-gate-still-ends-it",
             "unsolvable-still-ends-it", "converts-a-dead-transport",
             "one-text-for-every-door", "concession-fails-open")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_C0, _S0 = C, S

if args.mutate == "halt-anyway":
    C = C.replace("                    if _stop_becomes_work(_kind):",
                  "                    if False:", 1)
elif args.mutate == "converts-without-hint":
    C = C.replace('                judge_out["retry_hint"] = (\n'
                  '                    "THE RUN CONTINUES.', '                _unused = (\n'
                  '                    "THE RUN CONTINUES.', 1)
elif args.mutate == "fails-open":
    C = C.replace("                except Exception:\n"
                  "                    return False        # unreadable policy keeps the halt",
                  "                except Exception:\n                    return True", 1)
elif args.mutate == "default-off":
    S = S.replace('("judge_stop_halts", "JUDGE_STOP_HALTS", bool, True)',
                  '("judge_stop_halts", "JUDGE_STOP_HALTS", bool, False)', 1)
elif args.mutate == "no-local-hint":
    C = C.replace('                        retry_hint = judge_out["retry_hint"]\n', "", 1)
elif args.mutate == "silent-conversion":
    C = C.replace('                log_fn(\n'
                  '                    f"[orchestrator] judge STOP (kind={_kind}, "', '                _q = (\n'
                  '                    f"[orchestrator] judge STOP (kind={_kind}, "', 1)
elif args.mutate == "ignores-dead-remote":
    C = C.replace('                _dead_remote = verdict == "network_error"',
                  "                _dead_remote = False", 1)
elif args.mutate == "concession-still-ends-it":
    C = C.replace('                if stop_converts("conceded_by_deletion", log_fn):',
                  "                if False:", 1)
elif args.mutate == "ready-gate-still-ends-it":
    C = C.replace('                    if stop_converts("remote_not_ready", log_fn):',
                  "                    if False:", 1)
elif args.mutate == "unsolvable-still-ends-it":
    C = C.replace('                if _concede_unsolvable and stop_converts(\n'
                  '                        "unsolvable_by_analysis", log_fn):',
                  "                if False:", 1)
elif args.mutate == "converts-a-dead-transport":
    # Continuing past a dead transport is a loop that cannot act.
    C = C.replace('_STOP_CONVERTIBLE = ("conceded_by_deletion", "remote_not_ready",\n'
                  '                     "unsolvable_by_analysis")',
                  '_STOP_CONVERTIBLE = ("conceded_by_deletion", "remote_not_ready",\n'
                  '                     "unsolvable_by_analysis", "agent_error",\n'
                  '                     "cost_cap")', 1)
elif args.mutate == "one-text-for-every-door":
    C = C.replace('    if kind == "conceded_by_deletion":', "    if False:", 1)
elif args.mutate == "concession-fails-open":
    C = C.replace("    except Exception:            # unreadable policy keeps the halt\n"
                  "        if log_fn:", "    except Exception:\n        return True\n"
                  "        if log_fn:", 1)
elif args.mutate == "hides-circling":
    C = C.replace("                if _circling:", "                if False:", 1)

if args.mutate and (C, S) == (_C0, _S0):
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


def _fn_src(name: str) -> str:
    for n in ast.walk(ast.parse(C)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(C, n) or ""
    return ""


def _setting_checks() -> None:
    check("S1 the halt is an operator setting",
          '("judge_stop_halts", "JUDGE_STOP_HALTS", bool, True)' in S, True)
    check("S1 ...defaulting ON, so an upgrade changes nobody's behaviour",
          "bool, True)" in S.split('"JUDGE_STOP_HALTS"')[1][:30], True)
    check("S2 ...with a reader that is not captured at import",
          "def judge_stop_halts_enabled()" in S, True)
    # A policy that cannot be read must keep the SAFE historical behaviour.
    import modules.settings_io as sio
    real = sio.get_setting
    try:
        sio.get_setting = lambda k: (_ for _ in ()).throw(RuntimeError("boom"))
        check("S3 an unreadable policy keeps the halt",
              sio.judge_stop_halts_enabled(), True)
    finally:
        sio.get_setting = real
    check("S3 ...and a key nobody set keeps it too",
          "missing key halts" in (sio.judge_stop_halts_enabled.__doc__ or ""), True)


def _converter_checks() -> None:
    src = _fn_src("_stop_becomes_work")
    check("V1 the converter exists", bool(src), True)
    check("V1 ...and refuses to convert while the setting says halt",
          "if judge_stop_halts_enabled():" in src and "return False" in src, True)
    check("V2 an unreadable policy also keeps the halt",
          "except Exception:\n                    return False" in src, True)

    # The whole point: it must hand main SOMETHING to act on.
    check("V3 it writes a retry hint", 'judge_out["retry_hint"] = (' in src, True)
    check("V3 ...and flips the verdict to continue",
          'judge_out["next_action"] = "continue"' in src, True)
    check("V4 the hint says a STOP is about SIZE, not possibility",
          "NO SMALL FIX" in src and "not about" in src, True)
    check("V4 ...and asks for the missing CAPABILITY by name",
          "CAPABILITY you are missing" in src
          and "arbitrary read" in src, True)
    check("V4 ...and demands local proof before a remote attempt",
          "PROVE IT LOCALLY FIRST" in src and "~96" in src, True)
    # A dead target cannot be measured; hammering it is not "more work".
    check("V5 a dead remote gets a different instruction",
          '_dead_remote = verdict == "network_error"' in src
          and "Do NOT keep reconnecting" in src, True)
    # Circling is reported rather than silently fatal.
    # Structural: the text existing proves nothing — a mutation that assigns
    # it to a variable instead of using it leaves every string in place.
    _fn = next((n for n in ast.walk(ast.parse(C))
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == "_stop_becomes_work"), None)
    _guards = [n for n in ast.walk(_fn) if isinstance(n, ast.If)] if _fn else []
    check("V6 a circling run is told so, not killed for it",
          any("_circling" == ast.unparse(g.test) for g in _guards), True)
    check("V6 ...and what it is told names the symptom",
          "stopped reaching states" in src, True)
    check("V6 ...and the evidence budget does not gate the conversion",
          "if not _evidence.evidence_progress" in src, False)
    _logs = [n for n in ast.walk(_fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "log_fn"] if _fn else []
    check("V7 the conversion is LOGGED, not merely spelled out",
          any("CONVERTED to continue" in (ast.unparse(n) or "") for n in _logs),
          True)


def _every_door_checks() -> None:
    """A gate on ONE exit is not a policy.

    With `judge_stop_halts=False`, a run had every judge STOP converted and
    still ended by itself: main deleted exploit.py and left through
    `conceded_by_deletion`. Closing one door only changes which one gets used.
    """
    # EXEC THE MUTATED SOURCE, not the imported module. Three mutations
    # escaped this suite by editing `C` while every check called the real
    # `modules._common` — the checks proved the shipped file was right and
    # said nothing about the file under test.
    _ns = types.ModuleType("_stop_ns")
    _want_fn = {"stop_converts", "stop_becomes_work_text"}
    _pieces = []
    for _n in ast.parse(C).body:
        if isinstance(_n, ast.FunctionDef) and _n.name in _want_fn:
            _pieces.append(ast.get_source_segment(C, _n))
        elif isinstance(_n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_STOP_CONVERTIBLE"
                for t in _n.targets):
            _pieces.append(ast.get_source_segment(C, _n))
    exec(compile("\n\n".join(_pieces), "modules/_common.py", "exec"),
         _ns.__dict__)
    _c = _ns

    # WHICH DOORS CONVERT — and, just as load-bearing, which do not.
    check("D1 a concession by deletion may become work",
          _c.stop_converts.__doc__ is not None
          and "conceded_by_deletion" in _c._STOP_CONVERTIBLE, True)
    check("D1 ...and so may a withheld remote",
          "remote_not_ready" in _c._STOP_CONVERTIBLE, True)
    check("D1 ...and an unsolvable-by-analysis ruling",
          "unsolvable_by_analysis" in _c._STOP_CONVERTIBLE, True)
    # Continuing past a dead transport is not persistence; it is a loop with
    # nothing to act on. A configured ceiling is somebody's real decision.
    for terminal in ("agent_error", "policy_refusal", "sandbox_runner_error",
                     "cost_cap", "budget_exhausted"):
        check(f"D2 {terminal} still ends the run",
              terminal in _c._STOP_CONVERTIBLE, False)
        check(f"D2 ...and stop_converts refuses it",
              _c.stop_converts(terminal), False)

    # The setting is the only thing that opens them.
    import modules.settings_io as sio
    real = sio.get_setting
    try:
        sio.get_setting = lambda k: True          # halts = True
        check("D3 with the halt ON nothing converts",
              [_c.stop_converts(k) for k in _c._STOP_CONVERTIBLE],
              [False] * len(_c._STOP_CONVERTIBLE))
        sio.get_setting = lambda k: False         # halts = False
        check("D3 with it OFF the three convert",
              [_c.stop_converts(k) for k in _c._STOP_CONVERTIBLE],
              [True] * len(_c._STOP_CONVERTIBLE))
    finally:
        sio.get_setting = real

    # `stop_converts` has its OWN guard, and it has to be reachable to matter.
    # Breaking `get_setting` does not reach it — settings_io already fails safe
    # and returns True — so the layer under test here is the accessor itself.
    _real_acc = sio.judge_stop_halts_enabled
    try:
        sio.judge_stop_halts_enabled = (
            lambda: (_ for _ in ()).throw(RuntimeError("policy unreadable")))
        check("D3 an unreadable policy keeps every halt",
              [_c.stop_converts(k) for k in _c._STOP_CONVERTIBLE],
              [False] * len(_c._STOP_CONVERTIBLE))
    finally:
        sio.judge_stop_halts_enabled = _real_acc

    # THREE DOORS, THREE MISTAKES. A generic "keep going" would be noise.
    texts = {k: _c.stop_becomes_work_text(k) for k in _c._STOP_CONVERTIBLE}
    check("D4 each door gets its own instruction",
          len(set(texts.values())), 3)
    check("D4 the concession one says to put the artifact back",
          "Put the artifact back" in texts["conceded_by_deletion"], True)
    check("D4 ...and says a failing exploit that RUNS is evidence",
          "that RUNS is evidence" in texts["conceded_by_deletion"], True)
    check("D5 the ready-gate one explains the manifest, not just the refusal",
          all(w in texts["remote_not_ready"]
              for w in ("REMOTE_READY", "SHA-256", "content-bound")), True)
    check("D5 ...and frames the block as the gate working",
          "the gate working" in texts["remote_not_ready"], True)
    check("D6 the unsolvable one separates artifacts from the target",
          "not about what\nthe target permits" in texts["unsolvable_by_analysis"]
          or "not about what the target permits" in texts["unsolvable_by_analysis"],
          True)
    check("D6 ...and asks for the missing capability",
          "arbitrary read" in texts["unsolvable_by_analysis"], True)
    for k, t in texts.items():
        check(f"D7 {k}: main is told the operator ends runs here",
              "nothing stops it but the operator" in t, True)
    check("D8 recorded detail is carried when supplied",
          "seven attempts" in _c.stop_becomes_work_text(
              "conceded_by_deletion", "seven attempts"), True)

    # Wiring: each door must actually consult the gate and continue.
    for kind in _c._STOP_CONVERTIBLE:
        check(f"D9 {kind} consults stop_converts at its exit",
              f'stop_converts("{kind}"' in C or f'"{kind}", log_fn)' in C, True)
    # The literals wrap across source lines, so count the stable fragment:
    # three new doors plus the original judge-STOP conversion.
    check("D9 ...and each conversion is announced", C.count("CONVERTED to "), 4)


def _wiring_checks() -> None:
    """Every premature exit has to route through the converter, and the local
    `retry_hint` has to be set — the inject tail reads that, not judge_out."""
    # Count CALLS, not occurrences: `def _stop_becomes_work(` would inflate
    # every one of these by one and the number would mean nothing.
    def _calls(name):
        return len([n for n in ast.walk(ast.parse(C))
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == name])

    check("W1 the judge-STOP exits go through the converter",
          _calls("_stop_becomes_work"), 3)
    check("W2 the historical halt is still reachable when the setting says so",
          _calls("_judge_stop_halt") >= 2, True)
    check("W3 every conversion sets the LOCAL retry_hint",
          C.count('retry_hint = judge_out["retry_hint"]'), 3)
    # The absent-hint exit is the same premature end; df05d2ce2710 died there
    # after two real remote runs.
    check("W4 the no-hint exit converts too",
          "_stop_becomes_work(_no_hint_kind)" in C, True)
    check("W4 ...and still writes WHY_STOPPED when it does halt",
          "stop_kind=_no_hint_kind," in C, True)


def main() -> int:
    _setting_checks()
    _converter_checks()
    _every_door_checks()
    _wiring_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
