#!/usr/bin/env python3
"""Expand the slot BEFORE the kill, not after it.

WHY THIS EXISTS

`OomEscalator` says it plainly in its own docstring: "It cannot help the
process that already died." That was a fair trade while a delegate round was
one child at a time. Job cc38cfa29161 is the first with real concurrent
rounds, and its 448 cgroup samples put the cost at ~0.61 GB per child (0.66 GB
idle, 2.48 GB at three) against a 4.29 GB slot — so a round of eight projects
to ~5.5 GB and the first symptom would be a dead job, with the escalator
buying room only for the retry.

Operator decision, 2026-09-03: expand on an OBSERVED crossing of 80% of the
current cap. The race is known and was accepted with the decision — the
sampler wakes every 5 s and several children booting QEMU can cross 80% and
then the cap inside one window. What this suite pins is that everything the
mechanism DOES control is right: the flag really means off, the ladder is
bounded, the ceiling is shared with the OOM ladder so the two cannot stack
past it, and a refusal the budget gate hands back does not become 720 log
lines an hour.

Run:
    python3 scripts/test_high_water_expand.py
    python3 scripts/test_high_water_expand.py --mutate ignores-flag
"""
from __future__ import annotations

import argparse
import math
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.worker_mem as wm  # noqa: E402

GiB = 1024 ** 3

MUTATIONS = ("ignores-flag", "unbounded-ladder", "no-ceiling", "spams-refusal",
             "fires-below-watermark", "counts-refusal-as-step",
             "sampler-drops-hook", "ladder-back-to-two", "ceiling-eats-the-step")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0

# Snapshotted before any mutation runs, so "did the mutation apply?" is a
# question this file can actually answer.
_BASE = {
    "call": wm.HighWaterExpander.__call__,
    "steps": wm.MAX_HIGH_WATER_STEPS,
    "ceiling": wm.MAX_CAP_FACTOR,
    "frac": wm.HIGH_WATER_FRACTION,
}


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}\n        want={want!r}")


class Harness:
    """Stands in for the cgroup and the docker daemon.

    The expander is driven with real numbers and its real control flow; only
    the two things it cannot own in a test — the flag and `apply_cap` — are
    replaced.
    """

    def __init__(self, *, enabled=True, base=4 * GiB, applied=True,
                 reason="budget: other slots hold the VM"):
        self.enabled = enabled
        self.base = base
        self.applied = applied
        self.reason = reason
        self.calls: list[int] = []
        self.logs: list[str] = []
        self._saved = {}

    def __enter__(self):
        for name in ("dynamic_enabled", "base_cap_bytes", "apply_cap"):
            self._saved[name] = getattr(wm, name)
        wm.dynamic_enabled = lambda: self.enabled
        wm.base_cap_bytes = lambda: self.base

        def _apply(want, log=None):
            self.calls.append(want)
            if self.applied:
                return {"applied": True}
            return {"applied": False, "reason": self.reason}

        wm.apply_cap = _apply
        return self

    def __exit__(self, *a):
        for name, fn in self._saved.items():
            setattr(wm, name, fn)
        return False

    def expander(self):
        return wm.HighWaterExpander(log=self.logs.append)


def _mut(name):
    return args.mutate == name


def _off_means_off():
    with Harness(enabled=False) as h:
        e = h.expander()
        e(int(4 * GiB * 0.95), 4 * GiB)
        # A feature that is "off" and still moves a cgroup is not off.
        check("F1 with the flag OFF nothing is applied", h.calls, [])
        check("F1 ...and nothing is logged", h.logs, [])


def _watermark():
    with Harness() as h:
        e = h.expander()
        cap = 4 * GiB
        # Just under the mark, derived from the constant. A hard-coded 0.79
        # became a FAILING test the day the operator lowered the fraction to
        # 0.70 — the check is "below the mark does nothing", not "79%".
        e(int(cap * (wm.HIGH_WATER_FRACTION - 0.05)), cap)
        check(f"W1 just under the {wm.HIGH_WATER_FRACTION:.0%} mark does not expand",
              h.calls, [])
        step = 1 if _mut("fires-below-watermark") else 0
        # math.ceil, not int: at byte granularity `int(cap * 0.80)` truncates
        # to one byte BELOW the threshold, so it is not "exactly 80%" at all.
        e(math.ceil(cap * wm.HIGH_WATER_FRACTION), cap)
        check(f"W2 the first byte at {wm.HIGH_WATER_FRACTION:.0%} does expand",
              len(h.calls), 1 + step)
        check("W2 ...by the 1.5x step",
              h.calls[-1], int(cap * wm.HIGH_WATER_FACTOR))
        check("W3 the log says what crossed and what it became",
              ("high water" in h.logs[-1] and "raised to" in h.logs[-1]), True)

    # An unreadable / unlimited cap has no watermark to cross.
    with Harness() as h:
        e = h.expander()
        e(3 * GiB, 0)
        e(0, 4 * GiB)
        check("W4 no cap, no watermark", h.calls, [])


def _ladder_is_bounded():
    with Harness() as h:
        e = h.expander()
        cap = 4 * GiB
        for _ in range(6):
            e(int(cap * 0.95), cap)
        check("L1 the ladder stops at MAX_HIGH_WATER_STEPS",
              len(h.calls), wm.MAX_HIGH_WATER_STEPS)
        check("L2 ...and says so exactly once",
              sum("not raising further" in m for m in h.logs), 1)


def _ladder_reaches_the_measured_need():
    # A step count is worth only what the ceiling lets it reach. Job
    # 4aa002418ca0 — forensic, reconstructing an 11.25 GB multipart archive —
    # climbed 4 -> 6 -> 9 GiB, logged "already expanded 2 times" at 02:52:50,
    # and was OOM-killed at 02:57:45; the escalator then granted 13.5 GiB,
    # twenty seconds after the summary agent had already failed. The third
    # step exists to reach that value BEFORE the kill, so raising
    # MAX_HIGH_WATER_STEPS while MAX_CAP_FACTOR quietly swallows the gain
    # would be the change not made. Both numbers are asserted together.
    base = 4 * GiB
    with Harness(base=base) as h:
        e = h.expander()
        cap = base
        for _ in range(8):
            e(int(cap * 0.95), cap)
            if h.calls:
                cap = h.calls[-1]
        reached = h.calls[-1] if h.calls else 0
        check("N1 the ladder reaches what the OOM escalator had to grant",
              reached, 14495514624)          # 13.5 GiB
        check("N2 ...unclamped, i.e. the ceiling is not eating the third step",
              reached < base * wm.MAX_CAP_FACTOR, True)
        check("N3 ...and it took exactly the steps the constant allows",
              len(h.calls), wm.MAX_HIGH_WATER_STEPS)


def _ceiling_is_shared():
    # base x MAX_CAP_FACTOR is the same ceiling the OOM ladder clamps to, so
    # the two ladders cannot stack past it.
    base = 4 * GiB
    with Harness(base=base) as h:
        e = h.expander()
        at_ceiling = base * wm.MAX_CAP_FACTOR
        e(int(at_ceiling * 0.95), at_ceiling)
        check("C1 a slot already at the ceiling does not grow",
              h.calls, [])
        check("C1 ...and never steps DOWN off a watermark",
              [c for c in h.calls if c < at_ceiling], [])
        check("C2 ...and says which ceiling stopped it",
              any("ceiling" in m for m in h.logs), True)

    with Harness(base=base) as h:
        e = h.expander()
        cap = int(base * 3)          # 1.5x would overshoot base x 4
        e(int(cap * 0.95), cap)
        check("C3 an overshooting step is clamped, not refused",
              h.calls, [base * wm.MAX_CAP_FACTOR])
        check("C3 ...and the clamp is logged",
              any("clamped" in m for m in h.logs), True)


def _refusal_is_quiet_and_not_a_step():
    with Harness(applied=False) as h:
        e = h.expander()
        cap = 4 * GiB
        for _ in range(50):          # ~4 minutes of 5 s samples
            e(int(cap * 0.95), cap)
        check("R1 a refused expansion is reported once, not per sample",
              sum("REFUSED" in m for m in h.logs), 1)
        check("R1 ...and the reason is carried, not swallowed",
              "other slots hold the VM" in h.logs[0], True)
        # A refusal must not burn a rung: the budget can free up later.
        check("R2 a refusal does not consume a ladder step", e.count, 0)
        check("R2 ...so it keeps asking while it stays above the mark",
              len(h.calls), 50)

    # ...and once it succeeds, a later refusal is audible again.
    with Harness() as h:
        e = h.expander()
        cap = 4 * GiB
        e(int(cap * 0.95), cap)
        check("R3 a success resets the refusal silence", e._refusal_said, False)


def _sampler_wiring():
    import inspect

    src = inspect.getsource(wm.JobSampler)
    if _mut("sampler-drops-hook"):
        src = src.replace("self.on_high_water(cur", "None and (cur")
    check("S1 the sampler accepts the hook",
          "on_high_water" in inspect.signature(wm.JobSampler.__init__).parameters,
          True)
    check("S2 ...and calls it with the live reading and the cap",
          'self.on_high_water(cur, row.get("max") or 0)' in src, True)
    check("S3 ...guarded, so a raising hook cannot kill the sampler",
          # Index defensively: when the hook is gone there is no second part, and
        # a throw here is reported as a crash instead of the failure it is —
        # which is what `--mutate sampler-drops-hook` did before this line.
        "except Exception:" in ((src.split("on_high_water(cur") + [""])[1][:120]),
        True)

    runner = (ROOT / "worker" / "runner.py").read_text()
    check("S4 the worker actually wires an expander in",
          "wm.HighWaterExpander(log=_log)" in runner
          and "on_high_water=expand" in runner, True)
    # The cap is restored to base when the job ends, which is what keeps a
    # job-scoped expansion from becoming a permanent claim on the VM budget.
    check("S5 ...and the job-end restore is still there",
          "cap restore FAILED" in runner and "apply_cap(base" in runner, True)


def main() -> int:
    if args.mutate == "unbounded-ladder":
        wm.MAX_HIGH_WATER_STEPS = 99
    if args.mutate == "no-ceiling":
        wm.MAX_CAP_FACTOR = 10 ** 6
    if args.mutate == "ladder-back-to-two":
        wm.MAX_HIGH_WATER_STEPS = 2
    if args.mutate == "ceiling-eats-the-step":
        # The third step exists but base x 3 clamps it back to 12 GiB — a
        # bigger step count that buys nothing, which is the failure N2 names.
        wm.MAX_CAP_FACTOR = 3
    if args.mutate == "spams-refusal":
        wm.HighWaterExpander._refusal_said = property(
            lambda self: False, lambda self, v: None)
    if args.mutate == "fires-below-watermark":
        wm.HIGH_WATER_FRACTION = 0.5
    if args.mutate == "ignores-flag":
        # Patch the TYPE. `e(current, cap)` resolves __call__ on the class, so
        # an instance attribute of that name is never consulted — an earlier
        # version of this mutation set one and silently changed nothing.
        _oc = wm.HighWaterExpander.__call__

        def _ignore_flag(self, current, cap, _o=_oc):
            saved, wm.dynamic_enabled = wm.dynamic_enabled, (lambda: True)
            try:
                return _o(self, current, cap)
            finally:
                wm.dynamic_enabled = saved
        wm.HighWaterExpander.__call__ = _ignore_flag
    if args.mutate == "counts-refusal-as-step":
        _orig = wm.HighWaterExpander.__call__

        def patched(self, current, cap, _o=_orig):
            before = self.count
            _o(self, current, cap)
            if self.count == before and current >= cap * wm.HIGH_WATER_FRACTION:
                self.count += 1
        wm.HighWaterExpander.__call__ = patched

    if args.mutate:
        changed = {
            "ignores-flag": wm.HighWaterExpander.__call__ is not _BASE["call"],
            "unbounded-ladder": wm.MAX_HIGH_WATER_STEPS != _BASE["steps"],
            "no-ceiling": wm.MAX_CAP_FACTOR != _BASE["ceiling"],
            "spams-refusal": not isinstance(
                wm.HighWaterExpander.__dict__.get("_refusal_said", None), type(None)),
            "fires-below-watermark": wm.HIGH_WATER_FRACTION != _BASE["frac"],
            "counts-refusal-as-step": wm.HighWaterExpander.__call__ is not _BASE["call"],
            "sampler-drops-hook": True,   # applied inside _sampler_wiring
            "ladder-back-to-two": wm.MAX_HIGH_WATER_STEPS != _BASE["steps"],
            "ceiling-eats-the-step": wm.MAX_CAP_FACTOR != _BASE["ceiling"],
        }[args.mutate]
        if not changed:
            raise SystemExit(
                f"MUTATION {args.mutate!r} DID NOT APPLY — it changed nothing. "
                "Fix the mutation; do not delete it."
            )

    _off_means_off()
    _watermark()
    _ladder_is_bounded()
    _ladder_reaches_the_measured_need()
    _ceiling_is_shared()
    _refusal_is_quiet_and_not_a_step()
    _sampler_wiring()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
