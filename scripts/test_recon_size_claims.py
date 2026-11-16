#!/usr/bin/env python3
"""What the platform TELLS main it will receive has to be what arrives.

WHY THIS EXISTS

`PRE_RECON_MAX_CHARS` was deliberately raised 8,000 -> 32,000 on 2026-07-26,
because recon on a heap challenge genuinely emits 18-19.5 KB and no truncation
strategy survived it. The constant moved; nothing else did. For two months
afterwards:

  * eleven prompt sites still told the agent it would get a "2 KB summary"
  * `run_pre_recon`'s own docstring still said "capped at 8 KB"

Measured across 19 stored replies: median 3,697 B, max 13,154 B. So the
platform was describing itself at between a sixth and a sixteenth of reality,
in the prompt the model reads before deciding how much weight to give that
summary.

WHAT THIS SUITE DOES NOT DO

It does not touch the instructions asking RECON to be brief ("REPLY in
≤2 KB"). Those are requests, not descriptions, and raising them would make
replies longer — a behaviour change wearing a documentation fix's clothes.
Only statements to MAIN about what it is handed are pinned here.

Run from the repository root::

    python3 scripts/test_recon_size_claims.py
    python3 scripts/test_recon_size_claims.py --mutate restore-the-2kb-claim
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("restore-the-2kb-claim", "docstring-drifts-again",
             "cap-changes-silently")
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


INJECTORS = ["modules/web/analyzer.py", "modules/crypto/analyzer.py",
             "modules/rev/analyzer.py", "modules/web3/analyzer.py"]

print("\n1. the injection block does not put a size on what main receives")
for f in INJECTORS:
    src = (ROOT / f).read_text(encoding="utf-8")
    blk = src[src.find("PRE-RECON COMPLETED"):][:500]
    if args.mutate == "restore-the-2kb-claim" and f == INJECTORS[0]:
        blk = blk.replace("Its summary is", "Its 2 KB summary is")
    check(f"{Path(f).parent.name}: no stale size in the handoff",
          bool(re.search(r"\d+\s*KB summary", blk)), False)
    check(f"{Path(f).parent.name}: the block is still there",
          "PRE-RECON COMPLETED" in blk, True)

print("\n2. the docstring names the constant instead of a frozen number")
common = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
# To the END of the docstring, not a fixed window: this one runs well past
# 900 chars and a short slice silently tests the wrong text.
_d0 = common.find("def run_pre_recon")
_d1 = common.find('"""', common.find('"""', _d0) + 3)
doc = common[_d0:_d1]
if args.mutate == "docstring-drifts-again":
    doc = doc.replace("PRE_RECON_MAX_CHARS (32 KB", "8 KB (")
check("it points at PRE_RECON_MAX_CHARS", "PRE_RECON_MAX_CHARS" in doc, True)
check("...and does not assert a bare 8 KB cap",
      bool(re.search(r"capped\s*\n?\s*at 8 KB", doc)), False)

print("\n3. the constant and the stated size agree")
m = re.search(r"^PRE_RECON_MAX_CHARS\s*=\s*(\d+)", common, re.M)
check("the constant is defined", bool(m), True)
cap = int(m.group(1)) if m else 0
if args.mutate == "cap-changes-silently":
    cap = 8000
stated = re.search(r"PRE_RECON_MAX_CHARS \((\d+) KB", doc)
check("the docstring's KB figure matches the constant",
      bool(stated) and abs(int(stated.group(1)) * 1024 - cap) < 2048, True)

print("\n4. asks to recon are left alone — this is documentation, not policy")
asks = sum((ROOT / f).read_text(encoding="utf-8").count("REPLY in ≤2 KB")
           for f in INJECTORS)
check("recon is still asked to answer briefly", asks >= 3, True)

print("\n5. reality check against the stored replies")
sizes = [p.stat().st_size for p in
         (ROOT / "data" / "jobs").glob("*/work/pre_recon_reply.txt")]
if sizes:
    sizes.sort()
    med, mx = sizes[len(sizes) // 2], sizes[-1]
    print(f"  info n={len(sizes)} median={med:,}B max={mx:,}B cap={cap:,}B")
    check("every stored reply is inside the real cap", mx <= cap, True)
    check("...and the old 2 KB claim would have been wrong for most of them",
          sum(1 for s in sizes if s > 2048) > len(sizes) // 2, True)
else:
    print("  skip no stored replies on this box")

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
