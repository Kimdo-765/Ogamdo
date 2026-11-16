#!/usr/bin/env python3
"""The budget counts reservations, so the fraction has to fit the host.

WHAT HAPPENED

`apply_cap` refuses an expansion when `sum(other slots' CAPS) + want` exceeds
TOTAL_BUDGET_FRACTION of the VM. It sums caps, not usage, and a cap is held by
an idle slot exactly as firmly as by a busy one. This host runs 12 slots at
4.29 GB with worker_concurrency=3, so 11 idle slots hold 47.2 GB of
reservations they cannot use.

Job 23250acbdeeb climbed 4.29 -> 6.44 -> 9.66 GB, then asked for 14.5 GB after
an OOM:

    refused: 14495514624 B for worker-2 + 47244640256 B held by other slots

47.2 + 14.5 = 61.7 GB, over the 59.0 GB that 70% of an 84.3 GB host allows.
The host had 79.3 GB free. The slot OOM-killed twice.

0.70 was right for the 15.6 GB WSL host it was chosen on, where 30% was 4.7 GB.
At 84.3 GB it left 25 GB idle while refusing real work. Operator decision
2026-09-04: 0.85, which still stands 12.6 GB aside for the kernel, dockerd,
api, redis and the challenge containers an agent starts.

Run:
    python3 scripts/test_slot_budget_fraction.py
    python3 scripts/test_slot_budget_fraction.py --mutate diverged
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WM = ROOT / "modules" / "worker_mem.py"
API = ROOT / "api" / "routes" / "settings.py"
W = WM.read_text()
A = API.read_text()

MUTATIONS = ("diverged", "back-to-070", "reckless-095", "undocumented")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_W0, _A0 = W, A

if args.mutate == "diverged":
    A = A.replace("_TOTAL_BUDGET_FRACTION = 0.85",
                  "_TOTAL_BUDGET_FRACTION = 0.70", 1)
elif args.mutate == "back-to-070":
    W = W.replace("TOTAL_BUDGET_FRACTION = 0.85", "TOTAL_BUDGET_FRACTION = 0.70", 1)
    A = A.replace("_TOTAL_BUDGET_FRACTION = 0.85", "_TOTAL_BUDGET_FRACTION = 0.70", 1)
elif args.mutate == "reckless-095":
    W = W.replace("TOTAL_BUDGET_FRACTION = 0.85", "TOTAL_BUDGET_FRACTION = 0.95", 1)
    A = A.replace("_TOTAL_BUDGET_FRACTION = 0.85", "_TOTAL_BUDGET_FRACTION = 0.95", 1)
elif args.mutate == "undocumented":
    W = W.replace("# 0.70 -> 0.85 (operator, 2026-09-04).", "#", 1)

if args.mutate and (W, A) == (_W0, _A0):
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


def _frac(src: str, name: str) -> float:
    m = re.search(rf"^{name} = ([\d.]+)", src, re.M)
    return float(m.group(1)) if m else -1.0


GiB = 1024 ** 3
HOST = 84.3e9          # this deployment, measured
SLOTS, BASE = 12, 4 * GiB
CEILING_WANT = 14495514624   # what job 23250acbdeeb asked for and was refused


def _one_number_checks() -> None:
    """Two copies, one number. The comment in each says so, and a silent
    divergence would make the API advertise a budget the governor will not
    honour."""
    w, a = _frac(W, "TOTAL_BUDGET_FRACTION"), _frac(A, "_TOTAL_BUDGET_FRACTION")
    check("B1 both copies exist", (w > 0, a > 0), (True, True))
    check("B1 ...and they are the same number", w, a)
    check("B2 each names the other as its twin",
          ("api/routes/settings.py" in W and "modules/worker_mem.py" in A), True)


def _fits_this_host() -> None:
    """The point of the change: the ladder must reach its top on THIS host."""
    frac = _frac(W, "TOTAL_BUDGET_FRACTION")
    budget = HOST * frac
    others = (SLOTS - 1) * BASE          # every other slot holds its cap, idle or not
    room = budget - others
    # The ladder: 1.5x, 1.5x again, then the OOM escalator's 1.5x on top.
    for want, label in ((4.29e9 * 1.5, "rung 1 (6.44 GB)"),
                        (4.29e9 * 1.5 * 1.5, "rung 2 (9.66 GB)"),
                        (CEILING_WANT, "the OOM escalation that was refused")):
        check(f"B3 a slot can still be granted {label}", want <= room, True)
    # And the OS keeps a real share.
    check("B4 the host keeps a meaningful remainder",
          (HOST - budget) / 1e9 > 10.0, True)
    check("B4 ...and the fraction is not reckless", frac <= 0.90, True)


def _reasoning_is_recorded() -> None:
    """A tuning constant with no provenance gets retuned by the next reader."""
    check("B5 the change names the job that forced it",
          "23250acbdeeb" in W, True)
    check("B5 ...and the old value's provenance",
          "15.6 GB" in W and "0.70 -> 0.85" in W, True)
    check("B5 ...and what the sum actually counts",
          "counts every slot's CAP" in W, True)


def main() -> int:
    _one_number_checks()
    _fits_this_host()
    _reasoning_is_recorded()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
