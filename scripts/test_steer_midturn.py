#!/usr/bin/env python3
"""The operator's sentence, delivered while the turn is still running.

WHY THIS EXISTS

The steer rail lands at a TURN BOUNDARY, and that boundary is rare. Job
f666c4dcc372 held one main turn for 72 minutes with the operator's message
sitting undelivered; ba2725c84be2 waited 12. Tool calls are not rare: across
17,084 gaps between consecutive main tool calls, p50 is 0s, p95 is 32s, and
0.3% exceed five minutes. A PreToolUse hook is the only thing in this
codebase that runs mid-turn, so that is where the message now goes.

WHAT THIS SUITE PROTECTS

  * PEEK, NEVER TAKE. `take()` clears the queue as it reads. A hook that
    consumed the steer and then had `additionalContext` dropped by the CLI
    would lose the message entirely AND hide it from `pending()` — worse than
    the 72-minute wait, which at least kept it. The boundary rung stays the
    consumer; one visible duplicate beats one invisible loss.
  * ONCE PER MESSAGE, NOT PER TOOL CALL. Between injection and the next
    boundary the queue still holds the steer; without a ledger it would be
    re-injected on every Bash in between.
  * MAIN ONLY. A recon subagent that took a steer meant for the job and then
    exited would consume it where the operator cannot see.
  * A FAULT MUST NOT END A TURN. Same contract the boundary rung keeps.

Run from the repository root::

    python3 scripts/test_steer_midturn.py
    python3 scripts/test_steer_midturn.py --mutate hook-consumes-the-queue
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("hook-consumes-the-queue", "deliver-to-subagents-too",
             "re-inject-every-tool-call", "raise-on-fault")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="midturn-"))
os.environ["DATA_DIR"] = str(tmp)

from modules import steer  # noqa: E402
from modules import _common as C  # noqa: E402

work = tmp / "work"
work.mkdir(parents=True, exist_ok=True)


def run(hook, tool="Bash"):
    return asyncio.get_event_loop().run_until_complete(
        hook({"tool_name": tool, "tool_input": {}}, "tid", {}))


print("\n1. a queued steer reaches the model mid-turn")
steer.queue(work, "the instance moved — repoint at the new port")
C._STEER_SEEN.clear()
hook = C._midturn_steer("j1", work)
if args.mutate == "raise-on-fault":
    _orig = steer.pending
    steer.pending = lambda wd: (_ for _ in ()).throw(RuntimeError("disk gone"))
out = run(hook)
ctx = (out.get("hookSpecificOutput") or {}).get("additionalContext", "")
if args.mutate == "raise-on-fault":
    steer.pending = _orig
    check("a fault returns empty instead of raising", out, {})
else:
    check("the hook injects context", bool(ctx), True)
    check("...naming the operator, not an anonymous note",
          "OPERATOR STEER" in ctx, True)
    check("...carrying the message", "repoint at the new port" in ctx, True)

print("\n2. it peeks — the boundary rung is still the consumer")
if args.mutate == "hook-consumes-the-queue":
    steer.take(work)          # what a take()-based hook would have done
check("the steer is still queued after injection",
      len(steer.pending(work)), 1)

print("\n3. once per message, not once per tool call")
if args.mutate == "re-inject-every-tool-call":
    C._STEER_SEEN.clear()
again = run(hook)
check("a second tool call does not re-inject",
      (again.get("hookSpecificOutput") or {}).get("additionalContext"), None)

print("\n4. an empty queue is a no-op")
steer.take(work)
C._STEER_SEEN.clear()
check("nothing queued -> nothing injected", run(C._midturn_steer("j2", work)), {})

print("\n5. main only")
src = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
main_block = src[src.find("def main_session_hooks"):src.find("def main_session_hooks") + 2000]
sub_block = src[src.find("def kill_guard_hooks"):src.find("def kill_guard_hooks") + 1200]
if args.mutate == "deliver-to-subagents-too":
    sub_block += "\n        HookMatcher(matcher=None, hooks=[_midturn_steer(job_id, work_dir)]),"
check("main registers it", "_midturn_steer(" in main_block, True)
check("subagents do NOT", "_midturn_steer(" in sub_block, False)
check("...on every tool, not just Bash", "matcher=None" in main_block, True)

print("\n6. the factory never reaches for take()")
fac = src[src.find("def _midturn_steer"):src.find("def _midturn_steer") + 1800]
check("it peeks with pending()", "_steer.pending(" in fac, True)
check("it never calls take()", "_steer.take(" in fac, False)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
