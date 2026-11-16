#!/usr/bin/env python3
"""The live-agent-activity feed must survive leaving the job view.

The panel (`.sdk-live-feed`, web-ui/app.js) is fed by the redis channel
`job:<id>:sdk`. That channel was pubsub-ONLY: `_publish` is fire-and-forget and
nothing wrote the events down, so the div started empty on every render.
Leaving the job view and coming back threw away everything the agent had said
— on a run forty minutes in, the operator got a blank box and no way back to
what they had just been reading. Reported exactly that way:

    "Live Agent Activity가 job ui를 나갔다 들어오면 사라지는데
     이전 기록도 볼 수 있게 해줄 수 있어?"

The curated monitor feed already had the answer in the same codebase:
modules/_monitor.py appends `monitor.jsonl` AND publishes, and
api/routes/jobs.py replays its tail on connect. This suite pins the same two
halves for the sdk feed.

WHAT THIS PINS
  * every sdk publisher goes through publish_sdk, so nothing is pubsub-only
  * publish_sdk appends one JSON object per line to <job>/sdk.jsonl
  * a write failure never propagates — history is worth less than the turn
  * the SSE endpoint replays that tail, bounded, and marks it backfill
  * the replay cap is on the REPLAY, not on the file: the record stays whole

Run from the repository root::

    python3 scripts/test_sdk_activity_history.py
    python3 scripts/test_sdk_activity_history.py --mutate pubsub-only
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
COMMON = ROOT / "modules" / "_common.py"
ROUTES = ROOT / "api" / "routes" / "jobs.py"
COMMON_SRC = COMMON.read_text()
ROUTES_SRC = ROUTES.read_text()

MUTATIONS = ("pubsub-only", "no-backfill", "unbounded-replay", "write-raises")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

if args.mutate == "pubsub-only":
    COMMON_SRC = COMMON_SRC.replace("publish_sdk(job_id, {",
                                    '_publish(job_id, "sdk", {')
elif args.mutate == "no-backfill":
    ROUTES_SRC = ROUTES_SRC.replace('yield sse("sdk", entry)', "pass", 1)
elif args.mutate == "unbounded-replay":
    ROUTES_SRC = ROUTES_SRC.replace("text.splitlines()[-400:]", "text.splitlines()", 1)
elif args.mutate == "write-raises":
    # Drop the guard entirely (still valid Python) so an unwritable job dir
    # propagates and takes the turn down with it.
    COMMON_SRC = COMMON_SRC.replace(
        '    try:\n'
        '        path = job_dir(job_id) / "sdk.jsonl"\n'
        '        with path.open("a") as fp:\n'
        '            fp.write(json.dumps(payload, ensure_ascii=False) + "\\n")\n'
        "    except Exception:\n"
        "        pass\n",
        '    path = job_dir(job_id) / "sdk.jsonl"\n'
        '    with path.open("a") as fp:\n'
        '        fp.write(json.dumps(payload, ensure_ascii=False) + "\\n")\n', 1)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


# ---------------------------------------------------------- the writer half

def _publish_sdk_fn():
    """Execute the shipped publish_sdk with its two dependencies stubbed."""
    tree = ast.parse(COMMON_SRC)
    src = next((ast.get_source_segment(COMMON_SRC, n) for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "publish_sdk"), None)
    if src is None:
        return None, None
    published: list = []
    ns = {"json": json,
          "_publish": lambda j, c, p: published.append((j, c, p))}
    exec(compile(src, str(COMMON), "exec"), ns)
    return ns["publish_sdk"], published


def _writer_checks() -> None:
    fn, published = _publish_sdk_fn()
    check("W0 publish_sdk exists", fn is not None, True)
    if fn is None:
        return
    with tempfile.TemporaryDirectory() as td:
        jd = Path(td) / "job1"
        jd.mkdir()
        fn.__globals__["job_dir"] = lambda _j: jd
        fn("job1", {"kind": "text", "tag": "main", "text": "안녕"})
        fn("job1", {"kind": "tool_use", "tag": "recon", "name": "Bash",
                    "input": {"command": "ls"}})
        lines = (jd / "sdk.jsonl").read_text().splitlines()
        check("W1 one JSON object per line is appended", len(lines), 2)
        check("W1 ...round-trips, non-ASCII intact",
              json.loads(lines[0])["text"], "안녕")
        check("W1 ...and the second event is the tool call",
              json.loads(lines[1])["name"], "Bash")
        check("W2 it still publishes to the live channel",
              [c for _j, c, _p in published], ["sdk", "sdk"])

        # History must never cost a turn. An unwritable job dir is the case:
        # the publish still has to happen.
        published.clear()
        fn.__globals__["job_dir"] = lambda _j: Path(td) / "does" / "not" / "exist"
        try:
            fn("job1", {"kind": "text", "tag": "main", "text": "x"})
            raised = False
        except Exception:
            raised = True
        check("W3 a write failure does not raise", raised, False)
        check("W3 ...and the live publish still happens",
              len(published), 1)

    # Nothing may bypass it, or the feed has holes exactly where it matters.
    # Count CALL SITES (they pass a dict literal), not publish_sdk's own final
    # hand-off to _publish — an earlier draft counted both and read the
    # intended one as a bypass.
    check("W4 no sdk publisher bypasses publish_sdk",
          COMMON_SRC.count('_publish(job_id, "sdk", {'), 0)
    check("W4 ...and publish_sdk itself still reaches the live channel",
          COMMON_SRC.count('_publish(job_id, "sdk", payload)'), 1)
    check("W4 ...and all four publishers route through it",
          COMMON_SRC.count("publish_sdk(job_id, {"), 4)


# --------------------------------------------------------- the replay half

def _replay_checks() -> None:
    m = re.search(r'sdkp = jd / "sdk\.jsonl".*?yield sse\("backfill_done"',
                  ROUTES_SRC, re.S)
    check("R0 the stream replays sdk.jsonl", m is not None, True)
    if m is None:
        return
    blk = m.group(0)
    check("R1 replayed events are marked as backfill",
          'entry["backfill"] = True' in blk, True)
    check("R1 ...and are emitted on the sdk channel the panel listens to",
          'yield sse("sdk", entry)' in blk, True)
    check("R2 the replay is bounded by event count", "[-400:]" in blk, True)
    check("R2 ...and by bytes read off the end", "512 * 1024" in blk, True)
    check("R3 a partial first line is discarded, not fed to json.loads",
          'split("\\n", 1)[-1]' in blk or "split('\\n', 1)[-1]" in blk, True)
    check("R4 a broken history never breaks the stream",
          "except Exception" in blk, True)
    # The cap belongs on the replay. Capping the FILE would quietly destroy
    # the record this whole change exists to keep.
    check("R5 nothing truncates sdk.jsonl itself",
          bool(re.search(r'sdk\.jsonl[^\n]*\b(w|truncate|unlink)\b', ROUTES_SRC)),
          False)


def main() -> int:
    _writer_checks()
    _replay_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
