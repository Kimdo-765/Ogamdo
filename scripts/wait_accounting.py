#!/usr/bin/env python3
"""How much of a job was spent blocking on `wait`, and on what.

WHAT THE EMPTY COLUMN DOES **NOT** MEAN (read this before quoting a number).

This tool counts waits whose payload is `{"receiver_thread_ids": [],
"agents_states": {}}`. That was long read as "no child existed, so these
seconds are pure loss". **That reading is wrong**, measured 2026-09-07: in a
controlled run where a child demonstrably ran and wrote a file the parent was
forbidden to write, `wait` returned exactly that empty payload (3/3). OpenAI
documents v1 `wait_agent` as returning empty status ON TIMEOUT, and
openai/codex#24951 has it blocking 27,017 s before returning
`{"status":{},"timed_out":true}`. See docs/spawn-agent-works-2026-09-07.md.

So the `빈` column measures EMPTY RETURNS, not absent children. The seconds are
real wall-clock the parent spent blocked; whether a child was doing useful work
in parallel during them is NOT determined by anything here. Job c294fdec75da
is the caution: main announced a parallel delegation in its own narration,
used the file channel zero times, and then produced 13 of these empty returns.

Quote these numbers as "time the parent spent inside wait", never as "idle" or
"wasted".

This exists because `bd33eb9` needs a follow-up measurement. That commit made
the system prompt agree with the tool surface — main is no longer told to call
`spawn_agent` in a session that never registered it. Whether that recovers the
idle time is a question about jobs, not about code, and it is answered by
running this against jobs that finish AFTER the workers were restarted.

READ THE BASE RATE BEFORE CELEBRATING A ZERO. Across the 37 jobs that ran
before the fix, 11 (30%) made no `wait` call at all, and among those lasting
four minutes or more it was 8 of 34 (24%) — including a 120.5-minute job
(a2fcb3c313ab) and an 88.5-minute one (8cdbdad12d21). A single post-fix job
showing zero waits is therefore consistent with chance at roughly one in four,
and a job that ends inside four minutes is weaker still: 8 of the 14 most
recent pre-fix jobs had not yet made their first call at that point.

So this tool answers "did the idle time go away" only over SEVERAL post-fix
jobs, weighted toward long ones. Do not read one row as a result.

Usage:
    python3 scripts/wait_accounting.py                  # every job, newest first
    python3 scripts/wait_accounting.py c450344f8d04     # one job, with detail
    python3 scripts/wait_accounting.py --since 2026-09-07T03:30  # after the restart
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOBS = ROOT / "data" / "jobs"


def load(job_dir: Path):
    p = job_dir / "gpt-events.jsonl"
    if not p.exists():
        return None
    evs = []
    for line in p.open(errors="replace"):
        line = line.strip()
        if line:
            try:
                evs.append(json.loads(line))
            except Exception:
                pass
    if not evs:
        return None
    t0 = datetime.datetime.fromisoformat(evs[0]["ts"])
    tn = datetime.datetime.fromisoformat(evs[-1]["ts"])
    waits = [e for e in evs
             if e.get("tool") == "wait" and e.get("kind") == "tool_completed"]
    # The payload, not the duration, is what makes a wait wasted.
    empty = 0
    for e in evs:
        d = e.get("detail")
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except Exception:
                d = None
        if isinstance(d, dict) and "receiver_thread_ids" in d:
            if not d.get("receiver_thread_ids") and not d.get("agents_states"):
                empty += 1
    first = None
    for e in evs:
        if e.get("tool") == "wait":
            first = (datetime.datetime.fromisoformat(e["ts"]) - t0).total_seconds()
            break
    log = ""
    lp = job_dir / "run.log"
    if lp.exists():
        log = lp.read_text(errors="replace")
    try:
        status = json.loads((job_dir / "meta.json").read_text()).get("status", "?")
    except Exception:
        status = "?"
    dur = (tn - t0).total_seconds()
    wait_s = sum(e.get("duration_ms") or 0 for e in waits) / 1000
    return dict(
        job=job_dir.name, status=status, dur=dur, n_wait=len(waits),
        wait_s=wait_s, pct=(wait_s / dur * 100) if dur else 0.0,
        empty=empty, first=first,
        ring=log.count("delegate.ring"), spawn=log.count("spawn_agent"), t0=t0,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("job", nargs="?")
    ap.add_argument("--since", help="ISO timestamp; only jobs started after it")
    a = ap.parse_args()

    dirs = ([JOBS / a.job] if a.job else
            sorted((d for d in JOBS.iterdir() if d.is_dir()),
                   key=os.path.getmtime, reverse=True))
    since = datetime.datetime.fromisoformat(a.since) if a.since else None
    if since and since.tzinfo is None:
        since = since.replace(tzinfo=datetime.timezone.utc)

    rows = []
    for d in dirs:
        r = load(d)
        if not r:
            continue
        if since and r["t0"] < since:
            continue
        rows.append(r)
        if a.job:
            break
    if not rows:
        print("해당 job 없음")
        return 1

    print(f"{'job':14s} {'상태':11s} {'길이(분)':>8s} {'wait':>5s} {'빈':>4s} "
          f"{'wait(분)':>8s} {'비중':>7s} {'첫wait':>8s} {'ring':>5s}")
    tot_d = tot_w = 0.0
    for r in rows:
        tot_d += r["dur"]
        tot_w += r["wait_s"]
        first = f"{r['first']:.0f}s" if r["first"] is not None else "-"
        print(f"{r['job']:14s} {r['status']:11s} {r['dur']/60:8.1f} {r['n_wait']:5d} "
              f"{r['empty']:4d} {r['wait_s']/60:8.1f} {r['pct']:6.1f}% {first:>8s} "
              f"{r['ring']:5d}")
    if len(rows) > 1:
        print(f"\n합계 {len(rows)}개 job: {tot_d/3600:.1f}시간 중 wait "
              f"{tot_w/60:.1f}분 ({tot_w/tot_d*100:.1f}%)")
    # A job that ended before its own decision point proves nothing either way.
    short = [r for r in rows if r["dur"] < 600]
    if short:
        print(f"\n주의: {len(short)}개 job 이 10분 미만이라 단독으로는 판별력이 없다 "
              f"({', '.join(r['job'] for r in short)}). 관측된 첫 wait 은 45~857초에 "
              f"걸쳐 있고, 수정 전에도 4분 이상 job 의 24%(8/34)가 wait 0건이었다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
