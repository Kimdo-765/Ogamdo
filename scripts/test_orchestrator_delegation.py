#!/usr/bin/env python3
"""The orchestrator runs the round, because the model cannot spawn one.

WHY THIS EXISTS — PROVEN, NOT ASSUMED

Run outside this platform, `codex exec --json` with Ogamdo's own flags was told
to call `spawn_agent` and to answer NO_SPAWN_TOOL if it had no such tool. It
said "I'm spawning exactly one sub-agent…", emitted only

    {"type":"collab_tool_call","tool":"wait",
     "receiver_thread_ids":[],"agents_states":{}}

and then answered the question itself. Reproduced on gpt-daybreak-blue-latest
AND gpt-5.6-sol. `wait` is registered; `spawn_agent` is not. Codex's own system
prompt describes spawn_agent unconditionally, which is why the model believes
it delegated.

Eliminated as causes first: CLI version (0.147.0 and 0.152.1), the feature flag
(`features.multi_agent_v2` had been set as a TABLE via sub-keys — a real bug,
fixed, and it changed nothing), prompt wording (three attempts), model choice,
and `codex exec` mode. So no further instruction could fix it.

The cost was never small: every "waiting for subagents" figure this platform
measured — 52% / 44% / 39% / 35% of wall-clock — was main blocking on a roster
that could not exist.

THE DESIGN, AND ITS ONE RULE

The orchestrator does NOT decide what to ask. Only main knows the questions,
and a question the orchestrator invented would spend a real spawn on a guess.
Main declares the round in `.scratch/delegate.json` — a channel it demonstrably
uses, tens of Bash and Edit calls per job, rather than a tool it does not have
— and the orchestrator runs those tasks CONCURRENTLY and injects the replies.
Judgement stays with main; only execution moves.

Run from the repository root::

    python3 scripts/test_orchestrator_delegation.py
    python3 scripts/test_orchestrator_delegation.py --mutate serial-round
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import builtins
import importlib
import json
import os
import re
import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
COMMON = ROOT / "modules" / "_common.py"
CODEX = ROOT / "modules" / "codex_cli.py"
EVENTS = ROOT / "modules" / "gpt_run_events.py"
C = COMMON.read_text()
X = CODEX.read_text()
G = EVENTS.read_text()

MUTATIONS = ("serial-round", "no-consume", "one-child-kills-round",
             "unbounded-tasks", "one-task-per-role",
             "worked-example-overfits", "fixed-count", "phantom-global",
             "unguarded-hook", "delegate-preempts-final-draft",
             "bell-ignores-blocked", "bell-matches-text", "bell-never-starts",
             "bell-drops-malformed", "bell-errors-on-early-ring",
             "bell-swallows-failure", "bell-fires-on-request",
             "bell-double-starts", "bell-cancels-round",
             "addendum-drops-ring", "rejection-forgets-ring",
             "leak-round-on-exit", "plural-always", "parallel-claim-for-one",
             "concurrent-claim-for-one", "bell-verb-always-plural",
             "cap-eight-without-expander", "cap-justified-by-dead-measurement",
             "cap-ignores-policy", "warning-advises-spawn-agent",
             "empty-wait-not-corrected", "empty-wait-nags",
             "empty-wait-preempts-final-draft", "empty-wait-false-positive",
             "reframe-never-fires", "reframe-nags", "reframe-on-target-facts",
             "addendum-drops-goal-not-method")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

_C0, _X0 = C, X

if args.mutate == "serial-round":
    C = C.replace("replies = await asyncio.gather(\n"
                  "        *[_one(i, t) for i, t in enumerate(tasks)]\n"
                  "    )",
                  "replies = [await _one(i, t) for i, t in enumerate(tasks)]", 1)
elif args.mutate == "no-consume":
    C = C.replace("path.replace(path.with_suffix(\".json.consumed\"))", "pass", 1)
elif args.mutate == "one-child-kills-round":
    C = C.replace("        except Exception as exc:  # noqa: BLE001 — one child must not end the round\n"
                  "            log_fn(f\"[{tag}] crashed: {exc!r}\")\n"
                  "            reply = f\"(this agent crashed: {type(exc).__name__})\"\n",
                  "        except Exception:\n            raise\n", 1)
elif args.mutate == "worked-example-overfits":
    # Put challenge-specific subject matter back into the example, which is
    # what makes the next job copy the SHAPE of the last one.
    X = X.replace('"<ONE self-contained question: name the',
                  '"check the SLUB hardening options first (name the', 1)
elif args.mutate == "fixed-count":
    X = X.replace("HOW MANY: as many as the work genuinely has.",
                  "HOW MANY: always send exactly three.", 1)
elif args.mutate == "one-task-per-role":
    # Teach the shape that made this read as a per-role tool again: two
    # different roles, one task each, and no word that a role may repeat.
    X = X.replace('{"role": "recon", "question": "<a second question',
                  '{"role": "debugger", "question": "<a second question', 1)
    X = X.replace('{"role": "recon", "question": "<...and so on',
                  '{"role": "triage", "question": "<...and so on', 1)
    X = X.replace("THE SAME ROLE MAY REPEAT, AND USUALLY SHOULD.", "", 1)
elif args.mutate == "phantom-global":
    # Job 2aa7b80fd9b2 verbatim: the round called time.monotonic() and the
    # module imported no `time`. It cost a whole run, at t+2min.
    C = C.replace("import threading\nimport time\nimport traceback",
                  "import threading\nimport traceback", 1)
elif args.mutate == "unguarded-hook":
    # Take the guard off the turn-boundary call — replace the whole
    # try/except with the bare await. This is the mutation that matters most:
    # with it, ANY defect inside the round fails the job, which is exactly
    # what happened to 2aa7b80fd9b2.
    _i = C.find("                try:\n"
                "                    _dtext = await run_delegate_round(")
    _j = C.find("                await client.query(_dtext)", _i)
    assert _i > 0 and _j > _i, "unguarded-hook: the guarded block moved"
    C = C[:_i] + ("                _dtext = await run_delegate_round(\n"
                  "                    job_id=job_id, work_dir=work_dir,\n"
                  "                    model=summary.get(\"model\"),\n"
                  "                    log_fn=log_fn, tasks=_dtasks,\n"
                  "                )\n") + C[_j:]
elif args.mutate == "reframe-never-fires":
    C = C.replace("        state[\"fired\"] = True", "        return text", 1)
elif args.mutate == "reframe-nags":
    C = C.replace('        if state.get("fired") or not text or not _DEAD_END_VERDICT.search(text):',
                  '        if not text or not _DEAD_END_VERDICT.search(text):', 1)
elif args.mutate == "reframe-on-target-facts":
    # Widen on ANY negative sentence: now a correct abandonment gets argued
    # with, and the nudge becomes noise nobody reads.
    C = C.replace('r"|(?<![A-Za-z])REFUTED"', 'r"|없다|없음|않는다"', 1)
elif args.mutate == "addendum-drops-goal-not-method":
    X = X.replace("ASK FOR THE GOAL, NOT FOR ONE METHOD OF REACHING IT.",
                  "Be precise.", 1)
elif args.mutate == "empty-wait-not-corrected":
    C = C.replace("                await client.query(EMPTY_WAIT_CORRECTION)\n", "", 1)
elif args.mutate == "empty-wait-nags":
    C = C.replace('            if empty_wait_state["seen"] and not empty_wait_state["corrected"]:',
                  '            if empty_wait_state["seen"]:', 1)
elif args.mutate == "empty-wait-preempts-final-draft":
    # Move the correction above the last-chance draft.
    _blk = C[C.find("            # ---- EMPTY WAIT correction ----"):
             C.find("            # ---- Contrarian reframe injection (Tooth 1) ----")]
    C = C.replace(_blk, "", 1)
    C = C.replace("            # ---- FINAL_DRAFT last-chance injection ----",
                  _blk + "            # ---- FINAL_DRAFT last-chance injection ----", 1)
elif args.mutate == "empty-wait-false-positive":
    # Fire on any roster, populated or not: spends a turn telling main it did
    # nothing when it actually delegated.
    C = C.replace('        if not (body.get("receiver_thread_ids") or body.get("agents_states")):\n'
                  "            return True",
                  "        return True", 1)
elif args.mutate == "warning-advises-spawn-agent":
    X = X.replace('+ " `spawn_agent` is not registered "\n'
                  '                                        "here — main should write "',
                  '+ " Call spawn_agent before wait, or "\n'
                  '                                        "here — main should write "', 1)
elif args.mutate == "cap-eight-without-expander":
    # Eight with no ladder under it: 5.5 GB into a 4.29 GB slot.
    C = C.replace("        default = 8 if dynamic_enabled() else 4",
                  "        default = 8", 1)
elif args.mutate == "cap-ignores-policy":
    # Degrade to the LARGE cap when the policy cannot be read — the unsafe
    # direction to fail in.
    C = C.replace("    except Exception:\n        default = 4",
                  "    except Exception:\n        default = 8", 1)
elif args.mutate == "cap-justified-by-dead-measurement":
    C = C.replace("Job cc38cfa29161 measured it: 448 cgroup samples",
                  "Nothing has measured this, but assume", 1)
elif args.mutate == "bell-verb-always-plural":
    C = C.replace('                + ("they run" if len(tasks) > 1 else "it runs")',
                  '                + "they run"', 1)
elif args.mutate == "plural-always":
    C = C.replace('return "1 agent" if n == 1 else f"{n} agents"',
                  'return f"{n} agents"', 1)
elif args.mutate == "parallel-claim-for-one":
    C = C.replace('           + (" IN PARALLEL" if len(tasks) > 1 else "")',
                  '           + " IN PARALLEL"', 1)
elif args.mutate == "concurrent-claim-for-one":
    C = C.replace('    _ran = (f"ran these {_agents_phrase(len(tasks))} concurrently"\n'
                  '            if len(tasks) > 1 else f"ran {_agents_phrase(len(tasks))}")',
                  '    _ran = f"ran these {_agents_phrase(len(tasks))} concurrently"', 1)
elif args.mutate == "leak-round-on-exit":
    C = C.replace("                    cancel_delegate_round(state=delegate_state, log_fn=log_fn)\n",
                  "", 1)
elif args.mutate == "rejection-forgets-ring":
    C = C.replace('f"tasks, then write `.scratch/{DELEGATE_RING_FILE}` again "\n'
                  '                    "to ring it — a rewritten request with no new ring waits "\n'
                  '                    "for the end of your turn instead of starting now."',
                  '"tasks, then continue."', 1)
elif args.mutate == "addendum-drops-ring":
    # The machinery works and nobody rings it: every round waits for the turn
    # boundary again, silently, with no log line saying so.
    X = X.replace("then RING THE BELL by writing `.scratch/delegate.ring` (any content — it is a\n"
                  "signal, not data), and END YOUR TURN.",
                  "then END YOUR TURN.", 1)
elif args.mutate == "bell-ignores-blocked":
    # THE HOLE THE REVIEW CAUGHT: read while a shipping turn is pending and
    # the request is consumed, then dropped — and main was told not to
    # rewrite it, so it waits forever for a round that never ran.
    C = C.replace('        if (blocked or state.get("task") is not None\n'
                  '                or state.get("result") is not None):',
                  '        if (state.get("task") is not None\n'
                  '                or state.get("result") is not None):', 1)
elif args.mutate == "bell-double-starts":
    C = C.replace('        if (blocked or state.get("task") is not None\n'
                  '                or state.get("result") is not None):',
                  '        if (blocked\n'
                  '                or state.get("result") is not None):', 1)
elif args.mutate == "bell-matches-text":
    # Match what main SAYS, not what it wrote. The marker's name is in the
    # addendum, so this rings before the request exists.
    C = C.replace("    for block in (getattr(msg, \"content\", None) or []):\n"
                  "        for raw_path in _ring_paths_in_block(block):",
                  "    for block in (getattr(msg, \"content\", None) or []):\n"
                  "        if DELEGATE_RING_FILE in str(getattr(block, \"text\", \"\") or \"\"):\n"
                  "            return True\n"
                  "        for raw_path in _ring_paths_in_block(block):", 1)
elif args.mutate == "bell-fires-on-request":
    C = C.replace("            if leaf == DELEGATE_RING_FILE:",
                  "            if leaf in (DELEGATE_RING_FILE, DELEGATE_REQUEST_FILE):", 1)
elif args.mutate == "bell-never-starts":
    C = C.replace('            state["task"] = asyncio.create_task(',
                  '            state["task"] = None or (', 1)
elif args.mutate == "bell-drops-malformed":
    C = C.replace('            state["error"] = err', "            pass", 1)
elif args.mutate == "bell-errors-on-early-ring":
    # A ring before the request becomes a reported error instead of a no-op.
    # Main is then told its request was rejected when it was simply not
    # written yet, and the round it does write never runs.
    C = C.replace('            log_fn(f"[orchestrator] BELL rang with no '
                  '{DELEGATE_REQUEST_FILE} "\n'
                  '                   "on disk yet — deferring to the turn boundary")',
                  '            state["error"] = f"no {DELEGATE_REQUEST_FILE} on disk"', 1)
elif args.mutate == "bell-swallows-failure":
    C = C.replace('        state["result"] = DELEGATE_ROUND_FAILED_TEXT', "        pass", 1)
elif args.mutate == "bell-cancels-round":
    # Cancel instead of await: throws away children already paid for.
    C = C.replace('        state["result"] = await task',
                  '        task.cancel()\n        state["result"] = None', 1)
elif args.mutate == "delegate-preempts-final-draft":
    # Restore the ordering that let a delegate request written at budget
    # exhaustion push the last-chance draft to a boundary that never came.
    C = C.replace(
        'if not (final_draft_pending["value"] or soft_eject_pending["value"]):',
        "if True:", 1)
elif args.mutate == "unbounded-tasks":
    C = C.replace("for i, t in enumerate(tasks[:DELEGATE_MAX_TASKS]):",
                  "for i, t in enumerate(tasks):", 1)

# Execute just the delegation helpers, so a mutation to the shipped file is
# what runs and the module's import chain (docker, redis…) never loads.
WANT = {"read_delegate_request", "run_delegate_round", "_delegate_max_tasks",
        "_delegate_ring_seen", "_ring_paths_in_block",
        "start_delegate_round_if_rung", "collect_delegate_round",
        "cancel_delegate_round", "_agents_phrase", "_empty_wait_seen",
        "_widen_if_dead_end"}
WANT_A = {"DELEGATE_REQUEST_FILE", "DELEGATE_ROLES", "DELEGATE_MAX_TASKS",
          "DELEGATE_MAX_QUESTION", "DELEGATE_RING_FILE",
          "DELEGATE_ROUND_FAILED_TEXT", "_DELEGATE_WRITE_TOOLS",
          "EMPTY_WAIT_CORRECTION", "REFRAME_NOTE",
          "_DEAD_END_VERDICT"}
pieces = []
for node in ast.parse(C).body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in WANT:
        pieces.append(ast.get_source_segment(C, node))
    elif isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in WANT_A:
                pieces.append(ast.get_source_segment(C, node))
NS = types.ModuleType("_deleg_ns")
# The namespace is DERIVED from _common.py's own module-level imports, never
# hand-authored. Job 2aa7b80fd9b2 died on `NameError: name 'time' is not
# defined` after 29 checks passed here, because this dict used to carry a
# literal {"time": time, "os": _os} — the harness supplied a binding the
# shipped module did not have, and the same hand-injection had already
# papered over a missing `os` once before. Anything the file does not import,
# this namespace does not get.
_IMPORTED: dict = {}
for _n in ast.parse(C).body:
    if isinstance(_n, ast.Import):
        for _a in _n.names:
            _top = _a.name.split(".")[0]
            try:
                _IMPORTED[_a.asname or _top] = importlib.import_module(
                    _a.name if _a.asname else _top)
            except ImportError:
                pass
    elif isinstance(_n, ast.ImportFrom):
        # Repo-internal imports pull docker/redis; the point of exec'ing just
        # these functions is to never load that chain.
        if _n.level or not _n.module or _n.module.split(".")[0] == "modules":
            continue
        try:
            _m = importlib.import_module(_n.module)
        except ImportError:
            continue
        for _a in _n.names:
            if hasattr(_m, _a.name):
                _IMPORTED[_a.asname or _a.name] = getattr(_m, _a.name)
NS.__dict__.update(_IMPORTED)
exec(compile("\n\n".join(pieces), str(COMMON), "exec"), NS.__dict__)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


def _write(td: str, payload) -> str:
    d = Path(td) / ".scratch"
    d.mkdir(parents=True, exist_ok=True)
    (d / "delegate.json").write_text(
        payload if isinstance(payload, str) else json.dumps(payload))
    return td


def _request_checks() -> None:
    R = NS.__dict__["read_delegate_request"]
    with tempfile.TemporaryDirectory() as td:
        check("R1 no file is not an error", R(td), ([], None))
        _write(td, {"tasks": [{"role": "recon", "question": "Q1"},
                              {"role": "debugger", "question": "Q2"}]})
        tasks, err = R(td)
        check("R2 a valid request parses in order",
              ([t["role"] for t in tasks], err), (["recon", "debugger"], None))
        # CONSUMED: a request left on disk would be re-run at every turn
        # boundary, which is a job that never progresses.
        check("R3 the request is consumed, so it cannot re-fire", R(td), ([], None))
        check("R3 ...and is kept for forensics, not deleted",
              (Path(td) / ".scratch" / "delegate.json.consumed").is_file(), True)

    # Bad input must come back as a REASON for main, never as silence.
    for label, payload, needle in (
        ("malformed JSON", "{not json", "not valid JSON"),
        ("unknown role", {"tasks": [{"role": "wizard", "question": "Q"}]}, "must be one of"),
        ("empty question", {"tasks": [{"role": "recon", "question": "  "}]}, "is empty"),
        ("no tasks list", {"nope": 1}, "no non-empty `tasks`"),
    ):
        with tempfile.TemporaryDirectory() as td:
            _write(td, payload)
            tasks, err = R(td)
            check(f"R4 {label} is rejected with a reason",
                  (tasks, needle in (err or "")), ([], True))

    # A runaway request must be capped, not obeyed.
    with tempfile.TemporaryDirectory() as td:
        _write(td, {"tasks": [{"role": "recon", "question": f"Q{i}"} for i in range(9)]})
        tasks, err = R(td)
        check("R5 too many tasks are capped and the drop is reported",
              (len(tasks), "dropped" in (err or "")),
              (NS.__dict__["DELEGATE_MAX_TASKS"], True))


def _round_checks() -> None:
    run_round = NS.__dict__["run_delegate_round"]
    order: list[str] = []

    async def fake_pre_recon(*, job_id, work_dir, model, prompt, log_fn, tag, role):
        order.append(f"start:{role}")
        await asyncio.sleep(0.30 if role == "recon" else 0.05)
        order.append(f"end:{role}")
        if role == "judge":
            raise RuntimeError("boom")
        return f"reply-from-{role}"

    NS.__dict__["run_pre_recon"] = fake_pre_recon
    logs: list[str] = []
    tasks = [{"role": "recon", "question": "slow one"},
             {"role": "debugger", "question": "fast one"},
             {"role": "judge", "question": "this one crashes"}]
    t0 = time.monotonic()
    # asyncio.run, not get_event_loop: the bell drive above already ran and
    # closed its loop, and get_event_loop then raises rather than making one.
    # The round is expected to SURVIVE a crashing child, so a raise here is a
    # result to report, not a harness error to die on.
    try:
        text = asyncio.run(
            run_round(job_id="j", work_dir="/tmp", model="m",
                      log_fn=logs.append, tasks=tasks))
    except BaseException as exc:  # noqa: BLE001
        text = f"(the round itself raised {type(exc).__name__}: {exc})"
    took = time.monotonic() - t0

    # THE POINT: a round costs its slowest child, not the sum. Serially this
    # is 0.30+0.05+0.05 = 0.40s; concurrently it is ~0.30s.
    check("P1 the round runs CONCURRENTLY (slowest child, not the sum)",
          took < 0.40, True)
    check("P1 ...every child is started before any has finished",
          order[:3], ["start:recon", "start:debugger", "start:judge"])
    check("P2 every reply reaches main",
          all(f"reply-from-{r}" in text for r in ("recon", "debugger")), True)
    # One child failing is a labelled result, not a dead round.
    check("P3 a crashing child does not take the round down",
          "crashed: RuntimeError" in text or "this agent crashed" in text, True)
    check("P3 ...and the other replies still arrive",
          "reply-from-debugger" in text, True)
    check("P4 the log names the concurrency, so it can be audited",
          any("IN PARALLEL" in m for m in logs), True)
    check("P5 main is told how to ask again",
          "delegate.json" in text, True)


# --- the phantom-global gate ------------------------------------------------
# A name a function LOADS has to be BOUND somewhere the shipped module really
# binds it. This gate exists because 29 checks passed while `run_delegate_round`
# called `time.monotonic()` in a module that imported no `time`: the harness
# below used to hand-write {"time": time, "os": _os} into the exec namespace,
# so the tests ran against a module that only existed inside the tests. Job
# 2aa7b80fd9b2 found it instead, at t+2min, by failing.

if args.mutate and (C, X) == (_C0, _X0):
    # The anchor moved and str.replace said nothing. Without this the suite
    # runs the SHIPPED source, passes, and reports a mutation as caught-by-
    # nothing — a green run that proves the opposite of what it claims.
    raise SystemExit(
        f"MUTATION {args.mutate!r} DID NOT APPLY — its anchor no longer exists "
        "in the source. Fix the anchor; do not delete the mutation."
    )


def _target_names(t) -> set:
    if isinstance(t, ast.Name):
        return {t.id}
    if isinstance(t, (ast.Tuple, ast.List)):
        return set().union(*[_target_names(e) for e in t.elts]) if t.elts else set()
    return set()


def _module_level_names(tree) -> set:
    """Everything the module binds at import time, conditionals included."""
    out: set = set()

    def walk(body) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    out.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    out.add(a.asname or a.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                out.add(node.name)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    out.update(_target_names(t))
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                out.update(_target_names(node.target))
            elif isinstance(node, ast.If):
                walk(node.body); walk(node.orelse)
            elif isinstance(node, ast.Try):
                walk(node.body); walk(node.orelse); walk(node.finalbody)
                for h in node.handlers:
                    walk(h.body)
            elif isinstance(node, (ast.With, ast.AsyncWith, ast.For,
                                   ast.AsyncFor, ast.While)):
                walk(node.body)

    walk(tree.body)
    return out


def _bound_in(fn) -> set:
    """Every name the function binds. Deliberately OVER-broad: a false 'bound'
    costs one missed phantom, a false 'free' costs a wrong failure — and a gate
    that cries wolf is a gate somebody switches off."""
    def args_of(a) -> set:
        s = {x.arg for x in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)}
        if a.vararg:
            s.add(a.vararg.arg)
        if a.kwarg:
            s.add(a.kwarg.arg)
        return s

    bound = args_of(fn.args)
    for n in ast.walk(fn):
        if n is fn:
            continue
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(n.name); bound |= args_of(n.args)
        elif isinstance(n, ast.ClassDef):
            bound.add(n.name)
        elif isinstance(n, ast.Lambda):
            bound |= args_of(n.args)
        elif isinstance(n, ast.Import):
            # `import time as _time` inside a function binds _time locally —
            # three such sites exist in _common.py and must not trip the gate.
            for a in n.names:
                bound.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                bound.add(a.asname or a.name)
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                bound |= _target_names(t)
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            bound |= _target_names(n.target)
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            bound |= _target_names(n.target)
        elif isinstance(n, ast.withitem) and n.optional_vars is not None:
            bound |= _target_names(n.optional_vars)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound |= set(n.names)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            bound.add(n.name)
    return bound


def _phantom_globals(src: str, want: set) -> tuple:
    tree = ast.parse(src)
    allowed = _module_level_names(tree) | set(dir(builtins))
    bad, seen = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in want:
            seen.add(node.name)
            bound = _bound_in(node)
            free = sorted({
                n.id for n in ast.walk(node)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                and n.id not in bound and n.id not in allowed
            })
            if free:
                bad[node.name] = free
    return bad, sorted(want - seen)


def _phantom_checks() -> None:
    """The blast radius of this change set: functions no job had ever run
    end-to-end, so only a static gate stands between them and a dead job."""
    common_want = {"run_delegate_round", "read_delegate_request",
                   "_delegate_max_tasks", "publish_sdk", "run_pre_recon",
                   "_delegate_ring_seen", "_ring_paths_in_block",
                   "start_delegate_round_if_rung", "collect_delegate_round",
                   "cancel_delegate_round", "_agents_phrase",
                   "_empty_wait_seen", "_widen_if_dead_end"}
    bad, missing = _phantom_globals(C, common_want)
    check("N1 no delegate function loads a name _common.py never binds",
          bad, {})
    check("N1 ...and every function under the gate still exists", missing, [])

    events_want = {"summarize_agent_activity", "_parse_agent_roster"}
    bad_e, missing_e = _phantom_globals(G, events_want)
    check("N2 the activity summariser loads nothing gpt_run_events.py lacks",
          bad_e, {})
    check("N2 ...and both functions are still there", missing_e, [])

    # The gate has to be able to FAIL, or it is decoration. Feed it the exact
    # source that killed job 2aa7b80fd9b2.
    broke = C.replace("import threading\nimport time\nimport traceback",
                      "import threading\nimport traceback", 1)
    check("N3 the gate reproduces the job-2aa7b80fd9b2 failure",
          _phantom_globals(broke, {"run_delegate_round"})[0],
          {"run_delegate_round": ["time"]})
    # ...and it must not fire on a local `import x as _y`, which _common.py
    # uses three times; a noisy gate is a disabled gate.
    check("N3 ...without flagging function-local aliased imports",
          _phantom_globals(
              "def f():\n    import time as _t\n    return _t.monotonic()\n",
              {"f"})[0], {})


def _reframe_checks() -> None:
    """A "no" answers the question asked, not the goal behind it.

    The hard part is telling two "no"s apart, and this suite pins that. A fact
    about the target can close a strategy. A limit of one method does not.
    Synthetic domain-neutral sentences exercise the multilingual matcher
    without embedding a prior challenge's solution into the framework tests.
    """
    widen = NS.__dict__["_widen_if_dead_end"]
    NOTE = NS.__dict__["REFRAME_NOTE"]

    def fresh():
        return {"fired": False}

    # --- METHOD verdicts: these must widen ---
    METHOD = [
        ("a Korean method verdict",
         "- **판정: 계산 불가.** 방식 A만으로 목표 B를 달성할 수 없다."),
        ("an interface-shape limit",
         "- **판정: 불가능**\n  - 이 인터페이스는 한 단계만 처리한다."),
        ("a validation limit",
         "- **판정: 불가능**\n  - 검증 규칙 때문에 이 변환은 허용되지 않는다."),
        ("an English verdict", "VERDICT: impossible — method A cannot reach B."),
        ("a refuted hypothesis", "가설 H1은 반복 측정으로 REFUTED입니다."),
    ]
    for label, text in METHOD:
        out = widen(text, fresh(), lambda _m: None)
        check(f"F1 widens on {label}", out.endswith(NOTE), True)
        check(f"F1 ...keeping the original reply above it",
              out.startswith(text[:30]), True)

    # --- TARGET facts: these must NOT widen. Abandoning really is right. ---
    TARGET = [
        ("a missing target entry point",
         "대상 빌드에는 요청한 writable entry point가 없다."),
        ("a config that is on",
         "대상 설정에서 strict validation이 활성화되어 있다."),
        ("an ordinary finding",
         "입력 레코드는 처리 전에 정규화된다."),
        ("a plain empty reply", ""),
    ]
    for label, text in TARGET:
        check(f"F2 stays silent on {label}",
              widen(text, fresh(), lambda _m: None), text)

    # --- ONCE PER JOB. Repeating the same reframe would only add noise.
    st = fresh()
    t = METHOD[0][1]
    first = widen(t, st, lambda _m: None)
    second = widen(t, st, lambda _m: None)
    check("F3 the reframe fires once", first.endswith(NOTE), True)
    check("F3 ...and not again", second, t)

    # --- the note has to do the actual teaching ---
    check("F4 it names the distinction main must make",
          "TARGET" in NOTE and "ONE METHOD" in NOTE, True)
    check("F4 ...and the re-ask it wants",
          "how can I obtain" in NOTE, True)
    check("F5 the addendum teaches the same at question time",
          "ASK FOR THE GOAL, NOT FOR ONE METHOD" in X, True)
    check("F5 ...without leaking a prior challenge-specific example",
          "Can method X produce Y" in X and "kernel-image" not in X, True)

    # A nudge must never be able to end a turn.
    check("F6 a broken input does not raise",
          widen(object(), fresh(), lambda _m: None).__class__.__name__, "object")


def _empty_wait_checks() -> None:
    """An empty roster must be answered, not just recorded.

    The addendum forbids the empty `wait` in prose, and prose did not hold:
    job d18ff191928a called `wait` NINE times against a roster that cannot
    exist — 497s idle — and never wrote the delegate file once. The adapter
    already detected every one of them, but only into `gpt-events.jsonl`,
    which the model never reads. So the correction is delivered the way every
    other one is: noticed mid-turn, said on the turn boundary.
    """
    seen = NS.__dict__["_empty_wait_seen"]
    text = NS.__dict__["EMPTY_WAIT_CORRECTION"]

    def msg(*blocks):
        return types.SimpleNamespace(content=list(blocks))

    def result(content):
        return types.SimpleNamespace(content=content)

    EMPTY = '{"receiver_thread_ids": [], "agents_states": {}}'
    check("Q1 an empty roster is recognised, as JSON text",
          seen(msg(result(EMPTY))), True)
    check("Q1 ...and as an already-parsed object",
          seen(msg(result({"receiver_thread_ids": [], "agents_states": {}}))), True)

    # PRECISION MATTERS MORE THAN RECALL HERE: a false positive spends a turn
    # telling main it did nothing when it actually delegated.
    check("Q2 a roster WITH children is not empty",
          seen(msg(result('{"receiver_thread_ids": ["t1"], "agents_states": {}}'))),
          False)
    check("Q2 ...nor is one with live agent state",
          seen(msg(result({"receiver_thread_ids": [],
                           "agents_states": {"a": "running"}}))), False)
    check("Q3 an unrelated tool result does not match",
          seen(msg(result('{"path": "x", "kind": "add"}'))), False)
    check("Q3 ...nor does prose that merely names the field",
          seen(msg(types.SimpleNamespace(
              text="the roster field is receiver_thread_ids"))), False)
    check("Q3 ...nor an empty message", seen(types.SimpleNamespace(content=None)),
          False)

    # The reply has to say the three things that change behaviour.
    # INVERTED 2026-09-07. This asserted the correction tells main the roster
    # "can never fill" because spawn_agent is unregistered. Measured false: a
    # child that ran, wrote a file its parent could not write, and had its
    # reply returned produced exactly the empty payload.
    # docs/spawn-agent-works-2026-09-07.md.
    check("Q4 the correction explains the empty roster instead of misreading it",
          "NOT registered in this deployment" not in text
          and "TIMEOUT" in text, True)
    check("Q4 ...and names the file channel with the ring",
          ".scratch/delegate.json" in text and ".scratch/delegate.ring" in text,
          True)
    check("Q4 ...and tells main to stop LOOPING on wait, not to fear the tool",
          "Do NOT call `wait` in a loop." in text, True)
    check("Q4 ...and points at the tool that works before the fallback",
          0 <= text.find("spawn_agent(task_name")
          < text.find(".scratch/delegate.json"), True)


def _bell_checks() -> None:
    """The bell fires on a WRITE, and on nothing else.

    The marker's own name is in main's prompt — the addendum documents it —
    so it will also appear in whatever main says about it. A detector that
    matched text would ring before `delegate.json` was written, spend the
    turn's one eager start on a file that is not there, and leave the round
    to the boundary anyway: all of the risk, none of the speed.
    """
    ring = NS.__dict__["_delegate_ring_seen"]

    def msg(*blocks):
        return types.SimpleNamespace(content=list(blocks))

    def use(name, **inp):
        return types.SimpleNamespace(name=name, input=inp)

    def result(content):
        return types.SimpleNamespace(content=content)

    # Codex reports a write as `Edit` with a `changes` list.
    check("B1 a codex file write of the marker rings",
          ring(msg(use("Edit", changes=[
              {"path": "/data/jobs/j/work/.scratch/delegate.ring",
               "kind": "add"}]))), True)
    # The Claude provider spells the same act differently.
    check("B1 ...and so does a Write with file_path",
          ring(msg(use("Write", file_path=".scratch/delegate.ring"))), True)
    check("B1 ...and the tool RESULT form, as objects",
          ring(msg(result([{"path": ".scratch/delegate.ring", "kind": "add"}]))),
          True)
    check("B1 ...and the tool RESULT form, as its JSON text",
          ring(msg(result('[{"path": ".scratch/delegate.ring", "kind": "add"}]'))),
          True)

    # THE FALSE POSITIVE THAT WOULD MATTER. Main narrating the plan, or the
    # addendum quoted back, must not ring: `delegate.json` does not exist yet.
    check("B2 assistant TEXT naming the marker does not ring",
          ring(msg(types.SimpleNamespace(
              text="Next I will write `.scratch/delegate.ring` to ring the bell"))),
          False)
    check("B2 ...not even when the text is the addendum's own instruction",
          ring(msg(types.SimpleNamespace(text=X[:4000]))), False)
    # A read is not a write. `ls .scratch` must not start a round.
    check("B2 a Bash command mentioning the marker does not ring",
          ring(msg(use("Bash", command="ls -la .scratch/delegate.ring"))), False)
    check("B2 ...nor does a Read of it",
          ring(msg(use("Read", file_path=".scratch/delegate.ring"))), False)

    # The request itself is not the bell: main writes it, THEN rings. Firing
    # on the request would race a multi-step write against its own reader.
    check("B3 writing the request alone does not ring",
          ring(msg(use("Edit", changes=[
              {"path": ".scratch/delegate.json", "kind": "add"}]))), False)
    check("B3 a lookalike name does not ring",
          ring(msg(use("Write", file_path=".scratch/delegate.ring.bak"))), False)
    check("B3 ...and neither does an empty message",
          ring(types.SimpleNamespace(content=None)), False)
    # A write batch that touches the request and the marker together still
    # rings — one tool call is the cheapest way for main to do both.
    check("B3 one write of both files rings",
          ring(msg(use("Edit", changes=[
              {"path": ".scratch/delegate.json", "kind": "add"},
              {"path": ".scratch/delegate.ring", "kind": "add"}]))), True)


def _bell_drive_checks() -> None:
    """DRIVE THE REAL FUNCTIONS. Not their source text — the functions.

    Everything that killed job 2aa7b80fd9b2 was true of a path that no test
    had ever executed. String checks proved the code said the right words;
    only running it proves the words are wired to anything. So the shipped
    `start_delegate_round_if_rung` and `collect_delegate_round` are called
    here, with real files on real disk and a real event loop.
    """
    start = NS.__dict__["start_delegate_round_if_rung"]
    collect = NS.__dict__["collect_delegate_round"]
    FAILED_TEXT = NS.__dict__["DELEGATE_ROUND_FAILED_TEXT"]

    order: list[str] = []

    async def fake_pre_recon(*, job_id, work_dir, model, prompt, log_fn,
                             tag="pre-recon", role="recon"):
        order.append(f"start:{tag}")
        await asyncio.sleep(0.20)
        order.append(f"done:{tag}")
        return f"reply-from-{role}"

    NS.__dict__["run_pre_recon"] = fake_pre_recon

    def ring_msg():
        return types.SimpleNamespace(content=[types.SimpleNamespace(
            name="Edit",
            input={"changes": [{"path": ".scratch/delegate.ring",
                                "kind": "add"}]})])

    def quiet_msg():
        return types.SimpleNamespace(content=[
            types.SimpleNamespace(text="thinking about the next step")])

    def fresh_state():
        return {"task": None, "result": None, "error": None}

    def req(td, n=2, role="recon"):
        return _write(td, {"tasks": [{"role": role, "question": f"Q{i}"}
                                     for i in range(n)]})

    def on_disk(td):
        return (Path(td) / ".scratch" / "delegate.json").is_file()

    async def drive() -> None:
        logs: list[str] = []

        # E1 — a turn with no bell changes nothing, and leaves the request
        # for the boundary. This is the fallback that makes forgetting safe.
        with tempfile.TemporaryDirectory() as td:
            req(td)
            st = fresh_state()
            start(msg=quiet_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E1 no bell starts nothing", st["task"], None)
            check("E1 ...and the request survives for the boundary",
                  on_disk(td), True)

        # E2 — the bell starts the round, and START RETURNS WHILE THEY RUN.
        # That overlap IS the feature; without it the bell is decoration.
        with tempfile.TemporaryDirectory() as td:
            req(td, 3)
            st, order[:] = fresh_state(), []
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E2 the bell starts a round", st["task"] is not None, True)
            check("E2 ...and returns before it finishes, so main keeps working",
                  getattr(st["task"], "done", lambda: "not a task")(), False)
            check("E2 ...consuming the request so it cannot re-fire",
                  on_disk(td), False)
            # main "keeps working" here; the children are already going.
            await asyncio.sleep(0.05)
            check("E2 ...children are running during main's own work",
                  sorted(order), ["start:delegate#1:recon",
                                  "start:delegate#2:recon",
                                  "start:delegate#3:recon"])
            t0 = time.monotonic()
            await collect(state=st, log_fn=logs.append)
            took = time.monotonic() - t0
            # 3 x 0.20s serially is 0.60s; concurrently ~0.20s, and 0.05s of
            # it was already spent above.
            check("E2 ...and collecting costs the slowest child, not the sum",
                  took < 0.35, True)
            check("E2 every reply reaches main",
                  (st["result"] or "").count("reply-from-recon"), 3)
            check("E2 ...and the round is no longer in flight", st["task"], None)
            check("E2 the log names the bell, so it can be audited",
                  any("BELL" in m and "mid-turn" in m for m in logs), True)

        # E3 — THE HOLE THE REVIEW CAUGHT. While a shipping turn is pending
        # the bell must not even READ, or the request is consumed and then
        # dropped, and main was told not to rewrite it.
        with tempfile.TemporaryDirectory() as td:
            req(td)
            st = fresh_state()
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=True)
            check("E3 a blocked bell starts nothing", st["task"], None)
            check("E3 ...and does NOT consume the request", on_disk(td), True)
            check("E3 ...so the same request runs once unblocked",
                  (start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                         log_fn=logs.append, state=st, blocked=False),
                   st["task"] is not None)[1], True)
            await collect(state=st, log_fn=logs.append)
            check("E3 ...and its replies arrive intact",
                  "reply-from-recon" in (st["result"] or ""), True)

        # E4 — rung before the request was written. Must cost nothing.
        with tempfile.TemporaryDirectory() as td:
            st = fresh_state()
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E4 an early bell starts nothing", st["task"], None)
            check("E4 ...and records no error to report", st["error"], None)
            req(td)
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E4 ...and does not burn the turn's one start",
                  st["task"] is not None, True)
            await collect(state=st, log_fn=logs.append)

        # E5 — a malformed request the bell consumed has to reach main.
        with tempfile.TemporaryDirectory() as td:
            _write(td, "{not json")
            st = fresh_state()
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E5 a malformed request starts no round", st["task"], None)
            check("E5 ...and is held to be reported, not dropped",
                  bool(st["error"]) and "not valid JSON" in st["error"], True)

        # E6 — one ring per turn. A second must not double-spend.
        with tempfile.TemporaryDirectory() as td:
            req(td)
            st = fresh_state()
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            first = st["task"]
            req(td)  # main writes another request in the same turn
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E6 a second ring does not start a second round",
                  st["task"] is first, True)
            check("E6 ...and leaves the new request for the boundary",
                  on_disk(td), True)
            await collect(state=st, log_fn=logs.append)

        # E7 — a round that dies must not raise into the agent loop, and main
        # must be told, in the one shared text.
        async def boom(**_kw):
            raise RuntimeError("round exploded")

        with tempfile.TemporaryDirectory() as td:
            req(td)
            st = fresh_state()
            st["task"] = asyncio.get_running_loop().create_task(boom())
            await collect(state=st, log_fn=logs.append)
            check("E7 a dead round is caught, not raised", st["result"],
                  FAILED_TEXT)
            check("E7 ...and the traceback is logged, not just a repr",
                  any("Traceback" in m for m in logs), True)
            check("E7 ...and main is told not to rewrite the spent request",
                  "Do NOT rewrite it" in st["result"], True)

        # E8 — the bell itself must never be able to end a turn.
        st = fresh_state()
        start(msg=object(), job_id="j", work_dir="/nonexistent/nope",
              model="m", log_fn=logs.append, state=st, blocked=False)
        check("E8 a nonsense message does not raise out of the bell",
              st["task"], None)

        # E10 — a session that can never reach another boundary must not
        # walk away from N live `codex exec` children. They would outlive the
        # job on a slot the next job reuses.
        with tempfile.TemporaryDirectory() as td:
            req(td, 2)
            st = fresh_state()
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            doomed = st["task"]
            cancel = NS.__dict__["cancel_delegate_round"]
            cancel(state=st, log_fn=logs.append)
            check("E10 ...and clears the slot so nothing awaits it later",
                  st["task"], None)
            check("E10 ...and says so, because a silent cancel is a lost round",
                  any("cancelled the in-flight delegate round" in m
                      for m in logs), True)
            # cancel() only REQUESTS it; the task has to be given a chance to
            # process the request before `cancelled()` can be true.
            raised = None
            try:
                await doomed
            except asyncio.CancelledError as exc:
                raised = exc
            check("E10 a departing session cancels its in-flight round",
                  raised is not None, True)
            check("E10 ...and the children go down with it",
                  doomed.cancelled(), True)
        # cancelling when there is nothing to cancel must be a no-op
        st = fresh_state()
        cancel(state=st, log_fn=logs.append)
        check("E10 cancelling an idle state does nothing", st["task"], None)

        # E9 — a collected result waiting to be delivered blocks a new start,
        # so two rounds can never be in flight against one delivery slot.
        with tempfile.TemporaryDirectory() as td:
            req(td)
            st = fresh_state()
            st["result"] = "held over from the last boundary"
            start(msg=ring_msg(), job_id="j", work_dir=td, model="m",
                  log_fn=logs.append, state=st, blocked=False)
            check("E9 a held result blocks a new round", st["task"], None)
            check("E9 ...and the request is left unconsumed", on_disk(td), True)

    asyncio.run(drive())


def _cap_checks() -> None:
    """The cap must fit the memory the slot can actually reach.

    The default was 8, justified IN THE DOCSTRING by a 0.47 GB job peak — a
    number measured on a build where the delegate round could not run at all,
    so it described a worker with no concurrent peers in it. A wrong number
    with a citation attached is harder to catch than a wrong number alone,
    which is why the reasoning is pinned here and not only the value.

    Measured on job cc38cfa29161 (448 cgroup samples): 0.66 GB idle, 2.48 GB
    at three concurrent children => ~0.61 GB each, against a 4.29 GB base cap.
    Eight is 5.5 GB and does NOT fit that base. What makes eight safe is the
    high-water expander, so the default is tied to it: ON gets 8, OFF gets 4.
    A cap of 8 with the expander off is the OOM the whole chain exists to
    avoid, and nothing else in the code would notice.
    """
    import modules.worker_mem as _wm

    IDLE_GB, PER_CHILD_GB, BASE_GB = 0.66, 0.61, 4.29
    fn = NS.__dict__["_delegate_max_tasks"]
    saved = _wm.dynamic_enabled
    os.environ.pop("DELEGATE_MAX_TASKS", None)
    try:
        _wm.dynamic_enabled = lambda: True
        on = fn()
        _wm.dynamic_enabled = lambda: False
        off = fn()

        check("C1 with the expander ON the round may be eight", on, 8)
        check("C2 ...and with it OFF it drops back", off, 4)

        # ON: a full round has to fit the FIRST rung. Needing two rungs would
        # mean winning two 5 s sampler races instead of one.
        first_rung = BASE_GB * _wm.HIGH_WATER_FACTOR
        proj_on = IDLE_GB + PER_CHILD_GB * on
        check("C3 a full round fits ONE expansion step",
              proj_on < first_rung, True)
        check("C3 ...with headroom, since the projection is linear and from "
              "one job of one shape", proj_on < first_rung * 0.90, True)
        # ...and the ladder as a whole must still be reachable.
        top = BASE_GB * (_wm.HIGH_WATER_FACTOR ** _wm.MAX_HIGH_WATER_STEPS)
        check("C4 ...well inside the ladder's reach", proj_on < top, True)

        # OFF: no ladder exists, so the base cap is the whole budget.
        proj_off = IDLE_GB + PER_CHILD_GB * off
        check("C5 with no expander a full round fits the BASE cap",
              proj_off < BASE_GB, True)
        check("C5 ...with real headroom", proj_off < BASE_GB * 0.80, True)
        # The reason the two differ has to be real, not decorative.
        check("C6 the OFF default would NOT have fit at the ON size",
              IDLE_GB + PER_CHILD_GB * on < BASE_GB, False)

        check("C7 the cap is still a runaway guard, not a budget", off >= 4, True)

        # The operator override wins in both states, and is bounded.
        for raw, want_on in (("2", 2), ("32", 32), ("0", 8), ("33", 8),
                             ("banana", 8), ("", 8)):
            os.environ["DELEGATE_MAX_TASKS"] = raw
            _wm.dynamic_enabled = lambda: True
            check(f"C8 env {raw!r} -> {want_on}", fn(), want_on)
        os.environ.pop("DELEGATE_MAX_TASKS", None)

        # A settings file that cannot be read must degrade to the SAFE side.
        def _boom():
            raise RuntimeError("settings unreadable")
        _wm.dynamic_enabled = _boom
        check("C9 an unreadable policy falls back to the small cap", fn(), 4)
    finally:
        _wm.dynamic_enabled = saved
        os.environ.pop("DELEGATE_MAX_TASKS", None)

    doc = ast.get_docstring(
        next(n for n in ast.parse(C).body
             if isinstance(n, ast.FunctionDef) and n.name == "_delegate_max_tasks")) or ""
    check("C10 the docstring cites the job the numbers came from",
          "cc38cfa29161" in doc, True)
    check("C11 ...and states the per-child cost the cap rests on",
          "0.61" in doc and "2.48" in doc, True)
    check("C12 ...and names what makes eight safe",
          "HighWaterExpander" in doc and "dynamic_worker_mem" in doc, True)
    check("C13 ...and does not hide that the expansion is a race",
          "race" in doc.lower() and "5 s" in doc, True)


def _phrase_checks() -> None:
    """A round of ONE is a good round, so the log has to say so correctly.

    Job cc38cfa29161 printed `delegate round: 1 agents IN PARALLEL (judge)`
    twice — wrong on the plural, and wrong to claim concurrency about a round
    with nothing to run in parallel WITH. The addendum deliberately tells main
    that one question is a fine round; a log that reads as broken every time
    it takes that advice teaches the operator to distrust it.
    """
    phrase = NS.__dict__["_agents_phrase"]
    check("L1 one child is singular", phrase(1), "1 agent")
    check("L1 ...and more than one is plural",
          [phrase(n) for n in (2, 3, 8)], ["2 agents", "3 agents", "8 agents"])

    run_round = NS.__dict__["run_delegate_round"]

    async def fake_pre_recon(*, job_id, work_dir, model, prompt, log_fn,
                             tag="pre-recon", role="recon"):
        return f"reply-from-{role}"

    NS.__dict__["run_pre_recon"] = fake_pre_recon

    def announce(roles):
        logs: list[str] = []
        text = asyncio.run(run_round(
            job_id="j", work_dir="/tmp", model=None, log_fn=logs.append,
            tasks=[{"role": r, "question": "q"} for r in roles]))
        line = next(m for m in logs if "delegate round: " in m)
        return line, text

    one, one_text = announce(["judge"])
    many, many_text = announce(["recon", "debugger"])

    check("L2 a single-child round is announced in the singular",
          "1 agent (" in one, True)
    check("L2 ...and claims no parallelism it does not have",
          "IN PARALLEL" in one, False)
    check("L2 ...while still naming the role",
          one.endswith("(judge)"), True)
    check("L3 a real fan-out still says so",
          "2 agents IN PARALLEL" in many, True)

    # The same claim reaches MAIN, not just the log, so it is pinned too.
    check("L4 the reply to main does not call one agent concurrent",
          "concurrently" in one_text, False)
    check("L4 ...and reads as English",
          one_text.startswith("DELEGATE ROUND RESULTS — the orchestrator "
                              "ran 1 agent on your behalf"), True)
    check("L5 a real fan-out still tells main it was concurrent",
          "ran these 2 agents concurrently" in many_text, True)

    # The BELL announces the same round one line earlier, so it carries the
    # same claim and needs the same care.
    start = NS.__dict__["start_delegate_round_if_rung"]

    def ring_msg():
        return types.SimpleNamespace(content=[types.SimpleNamespace(
            name="Edit", input={"changes": [
                {"path": ".scratch/delegate.ring", "kind": "add"}]})])

    async def bell_line(roles):
        logs: list[str] = []
        with tempfile.TemporaryDirectory() as td:
            _write(td, {"tasks": [{"role": r, "question": "q"} for r in roles]})
            st = {"task": None, "result": None, "error": None}
            start(msg=ring_msg(), job_id="j", work_dir=td, model=None,
                  log_fn=logs.append, state=st, blocked=False)
            if st["task"] is not None:
                await st["task"]
        return next(m for m in logs if "BELL — starting" in m)

    b1 = asyncio.run(bell_line(["judge"]))
    b2 = asyncio.run(bell_line(["recon", "debugger"]))
    check("L6 the bell is singular for one child",
          "starting 1 agent NOW" in b1, True)
    check("L6 ...and its verb agrees",
          ("it runs while main keeps working" in b1,
           "they run while main keeps working" in b1), (True, False))
    check("L6 a real fan-out keeps the plural and the plural verb",
          ("starting 2 agents NOW" in b2,
           "they run while main keeps working" in b2), (True, True))


def _wiring_checks() -> None:
    # The round must be driven from the turn boundary, or nothing runs it.
    check("W1 the turn-boundary block calls the reader",
          "read_delegate_request(work_dir)" in C, True)
    check("W1 ...and runs the round with the job's own model",
          'model=summary.get("model")' in C, True)
    check("W2 a rejected request is reported TO MAIN, not just logged",
          "DELEGATE REQUEST REJECTED" in C, True)
    # A rewritten request with no new ring is a request that waits for the
    # turn to end — the rejection has to say so, or the fix is half a fix.
    check("W2 ...and the rejection tells main to ring the rewrite",
          "to ring it" in C and "DELEGATE_RING_FILE" in C, True)
    # `continue` matters: the injected text must become main's next turn.
    blk = C[C.find("ORCHESTRATOR-RUN DELEGATE ROUND"):]
    blk = blk[:blk.find("FINAL_DRAFT last-chance")]
    check("W3 the round's replies are injected as a user turn",
          "_widen_if_dead_end(_dtext, reframe_state, log_fn)" in blk
          and blk.count("continue") >= 2, True)

    # ---- neither call site may be able to fail the job ----
    tree = ast.parse(C)
    parent = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}

    def _calls(name):
        return [n for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == name]

    def _ancestors(node):
        cur, prev = parent.get(node), node
        while cur is not None:
            yield cur, prev
            prev, cur = cur, parent.get(cur)

    def _guarding_try(node):
        """The nearest enclosing Try whose BODY (not handler) holds the node."""
        for cur, prev in _ancestors(node):
            if isinstance(cur, ast.Try) and any(
                    prev is st or prev in set(ast.walk(st)) for st in cur.body):
                return cur
        return None

    def _catches_exception(t):
        return t is not None and any(
            isinstance(h.type, ast.Name) and h.type.id == "Exception"
            for h in t.handlers)

    def _enclosing_fn(node):
        for cur, _prev in _ancestors(node):
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cur.name
        return None

    def _in_message_stream(node):
        for cur, _prev in _ancestors(node):
            if isinstance(cur, ast.AsyncFor) and "receive_response" in (
                    ast.get_source_segment(C, cur.iter) or ""):
                return True
        return False

    # Two sites run a round now: the bell starts one mid-turn, the boundary
    # runs one that was asked for without a bell. Job 2aa7b80fd9b2 proved what
    # ONE unguarded site costs, so the check is over ALL of them.
    rounds = _calls("run_delegate_round")
    check("W4 the round has exactly two call sites (bell + boundary)",
          len(rounds), 2)
    check("W4 ...and every one of them is wrapped, catching Exception",
          [_catches_exception(_guarding_try(c)) for c in rounds],
          [True] * len(rounds))
    # create_task defers the failure to the await, so the await has to hold too.
    awaits = [n for n in ast.walk(tree) if isinstance(n, ast.Await)
              and _enclosing_fn(n) == "collect_delegate_round"]
    check("W4 the bell's round is awaited exactly once", len(awaits), 1)
    check("W4 ...inside a guard, since create_task defers the failure there",
          _catches_exception(_guarding_try(awaits[0])) if awaits else False, True)

    guards, seen_ids = [], set()
    for site in rounds + awaits:
        t = _guarding_try(site)
        if t is not None and id(t) not in seen_ids:
            seen_ids.add(id(t))
            guards.append(t)
    check("W4 every failure path has its own guard", len(guards), 3)
    bodies = [" ".join(ast.get_source_segment(C, h) or "" for h in t.handlers)
              for t in guards]
    check("W4 ...each logging the full traceback, not just a repr",
          [("traceback.format_exc()" in b) for b in bodies], [True] * len(guards))
    # Only the paths that hand main a reply say it; the bell's own guard has
    # nobody to talk to yet, because injection cannot happen mid-turn.
    check("W4 ...and every reply to main comes from ONE text",
          sum("DELEGATE_ROUND_FAILED_TEXT" in b for b in bodies), 2)
    check("W4 ...which tells main the file is spent, so it does not respin",
          "Do NOT rewrite it" in C, True)

    # ---- shipping outranks investigating, at BOTH reads ----
    reads = _calls("read_delegate_request")
    check("W5 the reader has exactly two call sites (bell + boundary)",
          len(reads), 2)
    boundary_reads = [r for r in reads
                      if _enclosing_fn(r) != "start_delegate_round_if_rung"]
    check("W5 exactly one of them is the boundary's", len(boundary_reads), 1)

    def _priority_gate(node):
        for cur, _prev in _ancestors(node):
            if isinstance(cur, ast.If):
                t = ast.get_source_segment(C, cur.test) or ""
                if "final_draft_pending" in t and "soft_eject_pending" in t:
                    return t
        return ""

    # Without this, a request written at budget exhaustion preempts the
    # last-chance draft — the exact way job d8decbd77ed9 ended with nothing.
    check("W5 FINAL_DRAFT and soft-eject outrank the boundary read",
          bool(_priority_gate(boundary_reads[0])) if boundary_reads else False,
          True)
    check("W5 ...and a deferred read leaves the request unconsumed",
          _guarding_try(boundary_reads[0]) is not None if boundary_reads else False,
          True)
    # The bell's read is gated by the caller, through `blocked=`.
    bell_calls = _calls("start_delegate_round_if_rung")
    check("W5 the bell is invoked exactly once", len(bell_calls), 1)
    blocked_arg = ""
    for kw in (bell_calls[0].keywords if bell_calls else []):
        if kw.arg == "blocked":
            blocked_arg = ast.get_source_segment(C, kw.value) or ""
    check("W5 ...and told to stand down while a shipping turn is pending",
          ("final_draft_pending" in blocked_arg
           and "soft_eject_pending" in blocked_arg), True)

    # ---- the bell rings mid-turn, or it is not a bell ----
    # Moved to the boundary it is the old code with extra steps; this is the
    # one structural fact behaviour cannot reach, so it is pinned here.
    check("W6 the bell is asked from inside the per-message stream",
          _in_message_stream(bell_calls[0]) if bell_calls else False, True)
    collects = _calls("collect_delegate_round")
    check("W6 the collector runs exactly once, at the boundary", len(collects), 1)
    check("W6 ...and NOT inside the stream, where it would block the turn",
          _in_message_stream(collects[0]) if collects else True, False)
    check("W6 ...and it is awaited",
          isinstance(parent.get(collects[0]), ast.Await) if collects else False,
          True)
    cancels = _calls("cancel_delegate_round")
    check("W7 the departing session cancels exactly once", len(cancels), 1)
    # It must sit on the path that RETURNS, not the killed/timeout path that
    # falls through to sandbox dispatch and still reaches a boundary.
    nxt = None
    for cur, prev in _ancestors(cancels[0]):
        if isinstance(cur, (ast.If, ast.ExceptHandler, ast.While)):
            body = cur.orelse if isinstance(cur, ast.If) else cur.body
            stmts = [x for x in body]
            for i, x in enumerate(stmts):
                if prev is x or prev in set(ast.walk(x)):
                    nxt = stmts[i + 1] if i + 1 < len(stmts) else None
                    break
            if nxt is not None:
                break
    check("W7 ...immediately before the session returns",
          isinstance(nxt, ast.Return), True)
    check("W6 a result held back by a shipping turn is delivered later",
          'delegate_state["result"]' in C
          and "_widen_if_dead_end(_bt, reframe_state, log_fn)" in C, True)
    # ---- the empty-wait correction is wired, once, and last ----
    ew = _calls("_empty_wait_seen")
    check("W8 the loop asks about the empty roster exactly once", len(ew), 1)
    check("W8 ...from inside the per-message stream",
          _in_message_stream(ew[0]) if ew else False, True)
    check("W8 ...guarded, so a diagnostic cannot end the turn it diagnoses",
          _catches_exception(_guarding_try(ew[0])) if ew else False, True)
    # Delivered on a boundary, and only once per job.
    check("W9 the correction is injected as a user turn",
          "await client.query(EMPTY_WAIT_CORRECTION)" in C, True)
    check("W9 ...exactly once, then it stops nagging",
          'empty_wait_state["corrected"] = True' in C
          and 'not empty_wait_state["corrected"]' in C, True)
    # The literal is wrapped across source lines, so match its parts.
    check("W9 ...and a repeat AFTER the correction is reported, not silent",
          "EMPTY WAIT again (#" in C and "correction was delivered" in C
          and "main is not " in C, True)
    # LAST: it corrects a habit, so it must not pre-empt anything that ships.
    _iq = C.find("await client.query(EMPTY_WAIT_CORRECTION)")
    for higher in ("FINAL_DRAFT_USER_TURN", "SOFT_EJECT_USER_TURN"):
        check(f"W9 ...after {higher}, which ships instead of correcting",
              0 < C.find(f"await client.query({higher})") < _iq, True)

    check("W6 a malformed file the bell consumed still reaches main",
          'delegate_state["error"]' in C and "REJECTED" in C, True)

    # And main has to be told to use the file, not the tool that is not there.
    check("A1 the addendum sends main to the file channel",
          ".scratch/delegate.json" in X and "END YOUR TURN" in X, True)
    # INVERTED 2026-09-07: it works. Measured in a live worker with the
    # production argv, 3/3, plus a two-child concurrency run whose replies both
    # came back. What the addendum must state plainly now is the trap that made
    # it look broken.
    check("A2 ...and states plainly that the empty roster is not failure",
          "THE EMPTY ROSTER IS NOT WHAT IT SOUNDS LIKE" in X
          and "`spawn_agent` DOES NOT WORK HERE" not in X, True)
    # ---- the bell only helps if main is told to ring it ----
    # PIN THE INSTRUCTION, NOT A MENTION. The addendum names the ring in
    # several places now, so "the string appears" stopped being evidence that
    # main is ever TOLD to write it — a mutation removing the imperative
    # slipped through on the other mentions.
    check("A4 the addendum tells main to write the ring marker",
          "RING THE BELL by writing `.scratch/delegate.ring`" in X, True)
    check("A4 ...and that is an imperative, not just a mention",
          ".scratch/delegate.ring" in X, True)
    check("A4 ...and fixes the order, request first",
          "write the request\nFIRST and the ring SECOND" in X
          or "FIRST and the ring SECOND" in X, True)
    check("A4 ...and says an early ring is harmless, not an error",
          "it is not an error" in X, True)
    # Compliance follows the payoff, so the reason has to be in the text.
    check("A4 ...and states the payoff, which is what earns compliance",
          "already working while you finish the turn" in X, True)
    check("A4 ...and forgetting it is documented as safe, not broken",
          "Without the ring the round still runs" in X, True)
    # THE DIAGNOSTIC MUST NOT TEACH THE OPPOSITE OF THE PROMPT. The EMPTY WAIT
    # warning fires exactly when main is confused about delegation, and it used
    # to end "Call spawn_agent before wait" — advising the one tool that is not
    # registered here, 40 lines below an addendum saying so. Job d18ff191928a
    # made nine empty waits (497s idle) and never wrote the file; that warning
    # is operator-facing, so it did not cause it, but a reader following it
    # would have drawn exactly the wrong conclusion.
    # INVERTED 2026-09-07. These two demanded that NO line advise calling
    # spawn_agent. Advising it is now the point; what must not come back is the
    # falsified claim and the wait loop it produced.
    check("A5 the falsified claim cannot return",
          "not registered in this deployment" in X.replace(
              "was not registered here", ""), False)
    check("A5 ...and the empty-wait warning names both channels, native first",
          0 <= X.find("spawn_agent(task_name") < X.find(".scratch/delegate.json"),
          True)
    # X is the whole module, so this also sweeps CODEX_NATIVE_ULTRA_ADDENDUM.
    # Its "call `wait` only for ids that actually exist" is a RESTRICTION, not a
    # loop instruction, and is excluded by name rather than by loosening the
    # pattern — a future line that really does invite looping must still fail.
    check("A3 ...and no line tells main to loop on wait",
          [l for l in X.splitlines()
           if re.search(r"call `wait`", l)
           and not re.search(r"do NOT|Do NOT|not need|only for ids", l)], [])


def _shape_checks() -> None:
    """The worked example teaches the shape, so it has to be the right one.

    A round's whole value is that it costs its SLOWEST child rather than the
    sum, which pays off when ONE investigation is split into several
    self-contained sub-questions. The first draft's example showed one `recon`
    and one `debugger` — two different roles, one task each — which reads as
    "one task per role" and quietly teaches the shape that gives up the
    saving. Roles are PROFILES (model + tools), not people; a role may repeat,
    and usually should.
    """
    check("S1 the example asks several tasks in ONE round",
          X.count('{"role": "recon"') >= 3, True)
    check("S2 ...and says outright that a role may repeat",
          "THE SAME ROLE MAY REPEAT" in X, True)
    check("S3 ...and explains why (a role is a profile, not a person)",
          "not a\nperson" in X or "not a person" in X, True)
    check("S4 mixing roles is scoped to when the WORK differs",
          "Mixing roles is for when the WORK differs" in X, True)

    # S6 — THE EXAMPLE MUST NOT TEACH THE LAST CHALLENGE.
    #
    # A worked example carrying real subject matter is copied, not adapted:
    # an example written from one job's material would have the next run, in
    # a different category, reaching for that job's specifics. The
    # placeholders are deliberate — they teach the FORM (one self-contained
    # question per task) and nothing about content.
    ex_start = X.find('.scratch/delegate.json\n    {"tasks": [')
    example = X[ex_start:X.find("]}", ex_start)] if ex_start >= 0 else ""
    check("S6 the worked example is findable", bool(example), True)
    leaked = [w for w in ("SLUB", "seccomp", "rootfs",
                          "freelist", "usercopy", "kmalloc", "libc", "flag")
              if w.lower() in example.lower()]
    check("S6 ...and carries no challenge-specific subject matter", leaked, [])
    check("S6 ...and says outright not to copy its shape",
          "do not copy a shape from them" in X, True)

    # S7 — AND MUST NOT ANCHOR A COUNT.
    check("S7 the round size follows the work, not a number",
          "as many as the work genuinely has" in X, True)
    check("S7 ...one is a fine round, and so is six",
          "One question is a fine round" in X, True)
    check("S7 ...no fixed per-round quota is stated",
          bool(re.search(r"At most \d+ tasks per round|always send exactly", X)),
          False)
    check("S7 ...and the cap is framed as a runaway guard",
          "runaway guard" in X, True)
    # The reader must still accept it, or the instruction is a lie.
    R = NS.__dict__["read_delegate_request"]
    with tempfile.TemporaryDirectory() as td:
        _write(td, {"tasks": [{"role": "recon", "question": f"Q{i}"}
                              for i in range(3)]})
        tasks, err = R(td)
        check("S5 three same-role tasks are accepted, not deduplicated",
              ([t["role"] for t in tasks], err),
              (["recon", "recon", "recon"], None))


def main() -> int:
    _phantom_checks()
    _reframe_checks()
    _empty_wait_checks()
    _cap_checks()
    _phrase_checks()
    _bell_checks()
    _bell_drive_checks()
    _request_checks()
    _shape_checks()
    _round_checks()
    _wiring_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
