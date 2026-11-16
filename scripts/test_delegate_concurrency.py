#!/usr/bin/env python3
"""Delegate children must actually overlap. For months they did not.

WHAT WAS WRONG, AND HOW IT HID

`run_delegate_round` gathers its children with `asyncio.gather`, logs
`N agents IN PARALLEL`, and reports `cost = slowest child, not the sum`. All
three were false. Every child launches Codex with the JOB'S work_dir as cwd,
and `acquire_turn_guard` takes a BLOCKING exclusive flock on
`<work_dir>/.codex-turn.lock` that it holds for the entire life of the Codex
process. So a child waited for main's own turn to finish, then for each
sibling in turn.

It hid because the orchestrator prints a `backend=...` banner at SPAWN time.
Measuring a child from that banner makes every child look like it started at
t=0. Measured from each child's FIRST REAL OUTPUT instead, three shipped jobs
give a sum of working spans SHORTER than the round that contained them:

    cc38cfa29161  children 1525s  round 1666s   (-141s)
    df05d2ce2710  children  674s  round  774s   (-100s)
    0b2a37b5d6c0  children  423s  round  472s    (-49s)

Negative overlap is not "less parallel than hoped", it is none, plus the lock
wait. Job 0b2a37b5d6c0 also shows the bell was inert for the same reason:
BELL at 03:11:59, main's turn ended 03:12:05, and the first child's real
output came at 03:12:10 — after main released the lock.

WHY THE LOCK CANNOT SIMPLY GO

It fences launches after an operator stop, and it is how the API's
stop-and-resume path knows the real Codex writer is gone. openai/codex#11435
also reports parallel `codex exec` instances restoring each other's sessions
from a shared CODEX_HOME, so concurrency there is not free.

WHAT WAS MEASURED, NOT ASSUMED (codex-cli 0.152.1, shared CODEX_HOME with a
1.4 GB session store, one shared cwd): three `codex exec` started within
0.1 ms of each other and finished together, each returning its own marker —
with AND without `--ephemeral`. The CLI does not serialise them and did not
cross-contaminate. So children get `--ephemeral` (they persist nothing a
sibling could restore, and they are never resumed) and skip the lock, while
main keeps both.

Run:
    python3 scripts/test_delegate_concurrency.py
    python3 scripts/test_delegate_concurrency.py --mutate child-takes-lock
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CODEX = ROOT / "modules" / "codex_cli.py"
GUARD = ROOT / "modules" / "codex_turn_guard.py"
OPTS = ROOT / "modules" / "gpt_responses.py"
COMMON = ROOT / "modules" / "_common.py"

X = CODEX.read_text()
G = GUARD.read_text()
O = OPTS.read_text()
C = COMMON.read_text()

MUTATIONS = ("child-takes-lock", "child-not-ephemeral", "child-ignores-stop",
             "children-not-concurrent", "ephemeral-without-lock-skip",
             "pass-fds-unguarded")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_X0, _G0, _O0, _C0 = X, G, O, C

if args.mutate == "child-takes-lock":
    X = X.replace("            if self.options.concurrent_child:\n"
                  "                # No lock, but the operator's stop still fences the launch.",
                  "            if False:\n"
                  "                # No lock, but the operator's stop still fences the launch.", 1)
elif args.mutate == "child-not-ephemeral":
    X = X.replace('*(["--ephemeral"] if self.options.concurrent_child else []),', "", 1)
elif args.mutate == "child-ignores-stop":
    X = X.replace("                check_turn_stop(Path(cwd))\n", "", 1)
elif args.mutate == "children-not-concurrent":
    C = C.replace("            concurrent_child=True,\n", "", 1)
elif args.mutate == "ephemeral-without-lock-skip":
    # The unsafe half on its own: persisted sessions AND concurrency.
    X = X.replace('*(["--ephemeral"] if self.options.concurrent_child else []),',
                  '*([] if self.options.concurrent_child else []),', 1)
elif args.mutate == "pass-fds-unguarded":
    X = X.replace("pass_fds=((turn_guard.fileno(),) if turn_guard else ()),",
                  "pass_fds=(turn_guard.fileno(),),", 1)

if args.mutate and (X, G, O, C) == (_X0, _G0, _O0, _C0):
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


def _fn(src: str, name: str):
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _option_checks() -> None:
    """One knob, because the halves are only safe together."""
    check("O1 the option exists on the session options",
          "concurrent_child: bool = False" in O, True)
    check("O1 ...defaulting False, so main is never accidentally one",
          "concurrent_child: bool = False" in O, True)
    check("O2 delegate children set it", "concurrent_child=True," in C, True)
    # Exactly one caller: main must never become a concurrent child.
    check("O2 ...and nothing else does", C.count("concurrent_child=True"), 1)


def _lock_checks() -> None:
    """The lock is the serialiser. A child must not take it; main must."""
    launch = _fn(X, "_spawn") or _fn(X, "start") or None
    src = X
    check("L1 the guard is still acquired for a non-child",
          "await asyncio.to_thread(acquire_turn_guard, cwd)" in src, True)
    check("L2 ...and skipped when this session is a concurrent child",
          "if self.options.concurrent_child:" in src
          and "turn_guard = None" in src, True)
    # A None handle must not be dereferenced when spawning.
    check("L3 a child inherits no lock descriptor",
          "pass_fds=((turn_guard.fileno(),) if turn_guard else ())" in src, True)
    # Dropping the lock must NOT drop the operator's stop fence.
    check("L4 a child still honours the operator stop fence",
          "check_turn_stop(Path(cwd))" in src, True)
    check("L4 ...and that check exists and raises the documented error",
          "def check_turn_stop(" in G and "CodexTurnStopRequested" in G, True)


def _ephemeral_checks() -> None:
    """A child persists nothing a sibling could restore."""
    check("E1 a child runs --ephemeral",
          '*(["--ephemeral"] if self.options.concurrent_child else []),' in X, True)
    # Main must NOT: it resumes across turns.
    cmd = _fn(X, "_command")
    seg = ast.get_source_segment(X, cmd) if cmd else ""
    check("E2 ...and it is conditional, never unconditional",
          seg.count("--ephemeral"), 1)
    check("E2 ...on the child flag specifically",
          "concurrent_child" in seg, True)


def _behaviour_checks() -> None:
    """The property, executed: work that skips the lock overlaps; work that
    takes it does not. The real `acquire_turn_guard` is driven here — this is
    the exact primitive that serialised every delegate round."""
    from modules.codex_turn_guard import acquire_turn_guard, release_turn_guard

    async def worker(work_dir, take_lock, hold_s, order, idx):
        def _acq():
            return acquire_turn_guard(Path(work_dir)) if take_lock else None
        h = await asyncio.to_thread(_acq)
        order.append(("start", idx, time.monotonic()))
        try:
            await asyncio.sleep(hold_s)
        finally:
            order.append(("end", idx, time.monotonic()))
            if h is not None:
                await asyncio.to_thread(release_turn_guard, h)

    async def drive(take_lock):
        with tempfile.TemporaryDirectory() as td:
            order = []
            t0 = time.monotonic()
            await asyncio.gather(*[
                worker(td, take_lock, 0.30, order, i) for i in range(3)
            ])
            return time.monotonic() - t0, order

    took_locked, ord_locked = asyncio.run(drive(True))
    took_free, ord_free = asyncio.run(drive(False))

    # THE REGRESSION ITSELF. Three 0.30 s units: serialised ~0.90 s,
    # overlapped ~0.30 s.
    check("B1 taking the guard SERIALISES three children",
          took_locked > 0.80, True)
    check("B1 ...one at a time, never two inside it at once",
          max(sum(1 for k, _, t in ord_locked
                  if k == "start" and t <= ts)
              - sum(1 for k, _, t in ord_locked if k == "end" and t <= ts)
              for _, _, ts in ord_locked), 1)
    check("B2 skipping it lets them overlap", took_free < 0.45, True)
    check("B2 ...with all three inside at once",
          max(sum(1 for k, _, t in ord_free if k == "start" and t <= ts)
              - sum(1 for k, _, t in ord_free if k == "end" and t <= ts)
              for _, _, ts in ord_free), 3)
    check("B3 and the difference is the whole feature",
          took_locked > took_free * 2, True)


def _honesty_checks() -> None:
    """The round's own log claimed the property it did not have."""
    check("H1 the round still claims the slowest-child cost",
          "cost = slowest child, not the sum" in C, True)
    # That line is only true once children skip the lock, so the two must
    # ship together — this pins them to the same source.
    check("H1 ...and the code that makes it true is present",
          "concurrent_child=True," in C, True)


def main() -> int:
    _option_checks()
    _lock_checks()
    _ephemeral_checks()
    _behaviour_checks()
    _honesty_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
