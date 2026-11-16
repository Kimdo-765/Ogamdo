#!/usr/bin/env python3
"""The GPT timeline is re-fetched every 2s, so it must not ship what it hides.

WHY THIS EXISTS

The job panel froze completely on 96d867af0f04. The server was innocent — the
timeline route answered in 35 ms — but it answered with 1.17 MB, every two
seconds, and the browser parsed and rendered all of it.

Measured breakdown of that payload (800 events, 1,108 KB of `events`):

    detail    658 KB     rendered inside a COLLAPSED <details>
    input     108 KB     same
    summary   118 KB     actually displayed
    ts/model/title/…

So 78% of the bytes were behind "원본 입력/출력 보기", a disclosure nobody had
opened, shipped twice a second.

WHAT THE MEASUREMENT CORRECTED

The first fix aimed at `summary`, because that field looked like the obvious
one to cap. It would have saved NOTHING: web-ui/app.js already cuts summary at
700 chars for display, and not one of the 800 events exceeded 700. The weight
was never where it looked, which is why this file pins the numbers rather than
the intuition.

The second attempt clipped detail/input to a fixed length. Also weak — 800
small payloads add up, so a 1500-char cap reached only 687 KB and a 300-char
cap 494 KB. Keeping detail for the NEWEST events instead lands at ~350 KB,
within a few KB of dropping them altogether (322 KB), because the floor is the
summaries. Expanding a card is something an operator does to what just
happened; an older card's full text is in run.log, which is what a post-mortem
reads anyway.

Run:
    python3 scripts/test_timeline_payload_size.py
    python3 scripts/test_timeline_payload_size.py --mutate keep-all-details
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SRC = (ROOT / "modules" / "gpt_run_events.py").read_text()
APP = (ROOT / "web-ui" / "app.js").read_text()

MUTATIONS = (
    "keep-all-details",   # every event keeps its hidden payload again
    "keep-none",          # even the newest events lose it, so expanding shows nothing
    "clip-summary",       # the field the UI already truncates gets capped too
    "no-trim-call",       # the trimmer is defined but never applied
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_S0 = SRC

if args.mutate == "keep-all-details":
    SRC = SRC.replace("_TIMELINE_DETAIL_KEEP = 40", "_TIMELINE_DETAIL_KEEP = 10**9", 1)
elif args.mutate == "keep-none":
    SRC = SRC.replace("_TIMELINE_DETAIL_KEEP = 40", "_TIMELINE_DETAIL_KEEP = 0", 1)
elif args.mutate == "clip-summary":
    SRC = SRC.replace('    for key in ("detail", "input"):',
                      '    for key in ("detail", "input", "summary"):', 1)
elif args.mutate == "no-trim-call":
    SRC = SRC.replace("    return _trim_timeline(events), source",
                      "    return events, source", 1)

if args.mutate and SRC == _S0:
    raise SystemExit(f"MUTATION {args.mutate!r} CHANGED NOTHING — anchor is stale.")

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# Exec the (possibly mutated) trimmer alone — importing the module would load
# the real one and ignore every mutation above.
_ns: dict = {"Any": object, "json": json}
# Start at the FIRST constant the trimmer needs, not just the one this suite
# names — slicing from _TIMELINE_DETAIL_KEEP left _TIMELINE_FIELD_MAX out of
# the exec namespace and every case died on NameError instead of failing.
_start = min(SRC.index("_TIMELINE_FIELD_MAX ="), SRC.index("_TIMELINE_DETAIL_KEEP ="))
_end = SRC.index("\ndef ", SRC.index("def _clip_timeline_event"))
exec(SRC[_start:_end], _ns)
trim = _ns["_trim_timeline"]

# A synthetic run shaped like the one that froze: many events, each carrying a
# fat hidden payload and a short visible summary.
EVENTS = [
    {"ts": f"2026-09-06T0{i%10}:00:00Z", "kind": "tool", "tool": "Bash",
     "summary": "짧은 한 줄 요약", "detail": "X" * 3000, "input": {"command": "Y" * 1500}}
    for i in range(800)
]
RAW = len(json.dumps(EVENTS, ensure_ascii=False))


def _size(evs):
    return len(json.dumps(evs, ensure_ascii=False))


def main() -> int:
    print("\nT — the payload the browser has to parse every 2s")
    out = trim(EVENTS)
    check("T0 every event survives — this trims fields, not history",
          len(out), len(EVENTS))
    size = _size(out)
    print(f"        원본 {RAW//1024} KB → {size//1024} KB")
    # The freeze was the size. Anything above half is not a fix.
    check("T1 the payload is at least halved", size * 2 < RAW)

    withpayload = sum(1 for e in out if e.get("detail") or e.get("input"))
    check("T2 the newest events stay expandable", withpayload > 0)
    check("T3 ...but not all of them — that was the bug",
          withpayload < len(out))
    # The ones that keep it must be the NEWEST: an operator expands what just
    # happened, and keeping the oldest instead would be worse than useless.
    tail_has = all(out[i].get("detail") for i in range(len(out) - 5, len(out)))
    head_has = any(out[i].get("detail") for i in range(5))
    check("T4 it is the newest that keep it", tail_has)
    check("T5 ...and the oldest that lose it", head_has, False)

    print("\nS — summary is NOT the field to cap")
    # It looked like the obvious target and would have saved nothing; the UI
    # already truncates it. Pinned so the next reader does not retry that.
    check("S1 the UI truncates summary for display at 700",
          "fullSummary.length > 700" in APP)
    check("S2 the server does not also clip summary",
          all(e.get("summary") == "짧은 한 줄 요약" for e in out))

    print("\nW — the trimmer is actually applied")
    check("W1 read_gpt_timeline returns trimmed events",
          "return _trim_timeline(events), source" in SRC)
    # Defensive: when W1's string is gone this must FAIL, not raise — a suite
    # that dies on the mutation it exists to catch reports a crash, not a bite.
    _a, _b = SRC.find("events = events[-tail:]"), SRC.find("return _trim_timeline(")
    check("W2 ...after the tail cut, so the cap counts kept events",
          _a > -1 and _b > -1 and _a < _b)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
