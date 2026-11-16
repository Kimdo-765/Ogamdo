#!/usr/bin/env python3
"""Nine and a half hours were spent after the wall was already visible.

WHY THIS EXISTS

Measured across the twelve corpus jobs: 9.5 hours, 49 attempts and roughly $80
ran AFTER the same postjudge verdict had repeated three times in a row.
`340e62bdcd32` reached that state at attempt 3 and ran to attempt 17 before a
human woke up and pressed stop -- 3.9 hours and $35 past the point its own
instruments had stopped changing their answer. `5efafb6ee9ab` produced
twenty-six identical `network_error` verdicts in a row.

The job that actually captured a flag never repeated a verdict once. That is
the whole argument for the run length being worth reporting: it separates the
jobs that were grinding from the one that was working.

WHAT THIS SUITE PROTECTS

  * IT NEVER STOPS ANYTHING. The operator is the only brake in this system by
    design; a self-declared halt would be a ceiling and this is not one. The
    signal writes metadata, emits an event and logs a line. There is a
    mutation that makes it halt, and it is caught.
  * THE RUN IS CONSECUTIVE. Counting every occurrence of a verdict instead of
    the current streak makes a job that alternates look stuck, and a job that
    is genuinely stuck indistinguishable from one that tried four things.
  * IT ESCALATES, IT DOES NOT NAG. A twelve-long run reports three times, at 3,
    6 and 12. A line printed after every attempt is wallpaper.
  * THE GATE, AND THAT A REJECTED CLAIM IS STILL RECORDED. Taken from
    pentest-harness's goal tool: the model may declare itself blocked, but the
    claim is mechanically rejected until the condition has persisted. Keeping
    the rejected claim is the only way to learn whether the channel is used at
    all -- an unused channel and a channel nobody needed look identical.
  * THE PROMPT AND THE GATE AGREE. The preamble promises "at least three
    consecutive attempts"; `BLOCKED_AFTER` is what enforces it. A prompt
    describing a rule the code does not apply is worse than no prompt.
  * THE REAL CORPUS. Replayed over the verdicts as they actually arrived, not
    over a fixture.

Run from the repository root::

    python3 scripts/test_blocked_signal.py
    python3 scripts/test_blocked_signal.py --mutate signal-halts-the-job
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "signal-halts-the-job",
    "run-counts-every-occurrence",
    "fire-on-every-attempt",
    "accept-an-early-claim",
    "drop-the-rejected-claim",
    "threshold-of-one",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="blocked-test-"))
os.environ["DATA_DIR"] = str(tmp)
(tmp / "jobs").mkdir()

import modules._blocked as B  # noqa: E402
from modules.storage import JOBS_DIR  # noqa: E402

# --- mutations (in-process only: modules/ is bind-mounted into live workers
# and a file-rewriting mutation would reach a running job) --------------------
if args.mutate == "signal-halts-the-job":
    _real_signal = B.maybe_signal
    def _halting(job_id, work_dir=None, log_fn=None):
        got = _real_signal(job_id, work_dir, log_fn)
        if got.get("signalling"):
            from modules._common import write_meta
            write_meta(job_id, status="stopped")
        return got
    B.maybe_signal = _halting
elif args.mutate == "run-counts-every-occurrence":
    def _all_occurrences(job_id):
        from modules._events import read_events
        vs = [e.get("verdict") for e in read_events(job_id)
              if e.get("phase") == "postjudge" and e.get("kind") == "verdict"]
        if not vs:
            return None, 0, 0
        return vs[-1], vs.count(vs[-1]), len(vs)
    B.verdict_run = _all_occurrences
elif args.mutate == "fire-on-every-attempt":
    B._ESCALATE_AT = tuple(range(3, 200))
elif args.mutate == "accept-an-early-claim":
    _real_eval = B.evaluate
    def _ungated(job_id, work_dir=None):
        got = _real_eval(job_id, work_dir)
        if got.get("agent_reason"):
            got["agent_reason_state"] = "accepted"
        return got
    B.evaluate = _ungated
elif args.mutate == "drop-the-rejected-claim":
    _real_eval2 = B.evaluate
    def _forget(job_id, work_dir=None):
        got = _real_eval2(job_id, work_dir)
        if got.get("agent_reason_state") == "rejected_too_early":
            got["agent_reason"] = None
            got["agent_reason_state"] = None
        return got
    B.evaluate = _forget
elif args.mutate == "threshold-of-one":
    B.BLOCKED_AFTER = 1

T0 = datetime(2026, 9, 19, tzinfo=timezone.utc)


def make_job(name, verdicts, *, reason=None):
    d = JOBS_DIR / name
    (d / "work").mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(
        {"id": name, "status": "running", "started_at": T0.isoformat()}))
    lines = []
    for i, v in enumerate(verdicts):
        ts = (T0 + timedelta(seconds=60 * (i + 1))).isoformat()
        lines.append(json.dumps({"ts": ts, "phase": "postjudge", "kind": "verdict",
                                 "verdict": v, "next_action": "retry",
                                 "failure_code": None}))
    (d / "events.jsonl").write_text("".join(l + "\n" for l in lines))
    if reason is not None:
        (d / "work" / "blocked.json").write_text(
            json.dumps({"reason": reason}), encoding="utf-8")
    return d


print("\n1. the run is the current streak, not a tally")
make_job("streak", ["partial"] * 5)
check("five in a row is a run of five", B.verdict_run("streak")[:2], ("partial", 5))
make_job("broken", ["partial", "partial", "network_error", "partial"])
check("a different verdict ends the run",
      B.verdict_run("broken")[:2], ("partial", 1))
make_job("alternating", ["partial", "netw", "partial", "netw", "partial", "netw"])
check("a job that alternates is not stuck", B.verdict_run("alternating")[1], 1)
check("...so it does not signal", B.evaluate("alternating")["signalling"], False)
make_job("none", [])
check("no verdict yet is not a run of zero-length anything",
      B.verdict_run("none"), (None, 0, 0))

print("\n2. the threshold, and what it lets through")
for n, want in ((1, False), (2, False), (3, True), (9, True)):
    make_job(f"t{n}", ["partial"] * n)
    check(f"{n} identical verdict(s) -> signalling={want}",
          B.evaluate(f"t{n}")["signalling"], want)

print("\n3. it escalates; it does not nag")
# 340e62bdcd32's own shape: twelve partials. Three reports, not twelve.
d = make_job("esc", [])
fires = []
for i in range(1, 13):
    with (d / "events.jsonl").open("a") as fp:
        fp.write(json.dumps({
            "ts": (T0 + timedelta(seconds=60 * i)).isoformat(),
            "phase": "postjudge", "kind": "verdict", "verdict": "partial"}) + "\n")
    before = (B.read_signal("esc") or {}).get("emitted_at_run") or 0
    rec = B.maybe_signal("esc", d / "work")
    if (rec.get("emitted_at_run") or 0) > before:
        fires.append(i)
check("a twelve-long run reports at 3, 6 and 12", fires, [3, 6, 12])
events = [json.loads(l) for l in (d / "events.jsonl").read_text().splitlines()
          if '"blocked_signal"' in l]
check("...and emits exactly that many events", len(events), 3)
check("...under a declared phase", sorted({e["phase"] for e in events}), ["agent"])

print("\n4. it does not stop anything — the operator is the only brake")
d = make_job("nostop", ["partial"] * 4)
B.maybe_signal("nostop", d / "work")
meta = json.loads((d / "meta.json").read_text())
check("the job's status is untouched by a signal", meta["status"], "running")
check("...and no terminal timestamp was stamped", meta.get("finished_at"), None)
check("the signal is recorded where the dashboard reads it",
      (meta["blocked_signal"]["signalling"], meta["blocked_signal"]["run"]),
      (True, 4))
src = (ROOT / "modules" / "_blocked.py").read_text(encoding="utf-8")
check("nothing in the module writes a terminal status",
      any(w in src for w in ('status="stopped"', "status='stopped'",
                             'status="failed"', "'failed'")), False)

print("\n5. the gate on the agent's own claim, and the rejected claim it keeps")
d = make_job("early", ["partial"] * 2, reason="the target closes every connection")
got = B.evaluate("early", d / "work")
check("a claim before the threshold is rejected",
      got["agent_reason_state"], "rejected_too_early")
# Kept on purpose: whether the model reaches for this channel, and how early,
# is the only way to find out if it is used at all.
check("...and the claim itself is KEPT, not discarded",
      got["agent_reason"], "the target closes every connection")
check("...and a rejected claim does not make the job signal",
      got["signalling"], False)
d = make_job("late", ["partial"] * 3, reason="the target closes every connection")
got = B.evaluate("late", d / "work")
check("the same claim at the threshold is accepted",
      (got["agent_reason_state"], got["signalling"]), ("accepted", True))
d = make_job("noreason", ["partial"] * 4)
check("a job that never wrote one reports no claim, not an empty one",
      (B.evaluate("noreason", d / "work")["agent_reason"],
       B.evaluate("noreason", d / "work")["agent_reason_state"]), (None, None))
d = make_job("junk", ["partial"] * 4)
(d / "work" / "blocked.json").write_text("not json at all")
check("an unparseable claim is no claim, and does not raise",
      B.evaluate("junk", d / "work")["agent_reason"], None)

print("\n6. the prompt promises exactly what the gate enforces")
from modules._prompts import CTF_PREAMBLE  # noqa: E402
check("the channel reaches the agent's preamble",
      "IF YOU ARE BLOCKED" in CTF_PREAMBLE, True)
check("...with the path the agent's cwd actually has",
      "> ./blocked.json" in CTF_PREAMBLE and "$WORK_DIR" not in B.BLOCKED_CHANNEL_PROMPT,
      True)
check("...naming the same threshold the code applies",
      f"at least\nthree consecutive" in B.BLOCKED_CHANNEL_PROMPT
      and B.BLOCKED_AFTER == 3, True)
check("...and saying plainly that it does not stop the job",
      "does NOT stop the job" in B.BLOCKED_CHANNEL_PROMPT, True)
# Difficulty is not blocked. Without this the channel becomes a complaint box.
check("...and narrowing what blocked means",
      all(w in B.BLOCKED_CHANNEL_PROMPT
          for w in ("Difficulty is not blocked", "Uncertainty is not blocked")), True)


print("\n7. the real corpus, replayed as the verdicts actually arrived")
_real = ROOT / "data" / "jobs"
if _real.is_dir():
    os.environ["DATA_DIR"] = str(ROOT / "data")
    from modules._events import read_events as _read_real  # noqa: E402

    def replay(job):
        vs = [e.get("verdict") for e in _read_real(job)
              if e.get("phase") == "postjudge" and e.get("kind") == "verdict"]
        run = emitted = 0
        last = None
        fires = []
        for i, v in enumerate(vs, 1):
            if v == last:
                run += 1
            else:
                run, last, emitted = 1, v, 0
            due = max((t for t in B._ESCALATE_AT if run >= t), default=0)
            if run >= B.BLOCKED_AFTER and due > emitted:
                emitted = due
                fires.append(i)
        return vs, fires

    _, f340 = replay("340e62bdcd32")
    check("340e62bdcd32 is flagged at attempt 3, not left to 17",
          f340[:3], [3, 6, 12])
    _, f5ef = replay("5efafb6ee9ab")
    check("5efafb6ee9ab's 26 identical network_errors are flagged at 4",
          f5ef[0], 4)
    vs_ok, f_ok = replay("ccf6d5838457")
    # The discriminator. A signal that also fires on the job that worked is
    # not a signal, it is a decoration.
    check("the job that CAPTURED A FLAG is never flagged", f_ok, [])
    check("...because it never repeated a verdict at all",
          max((vs_ok.count(v) for v in set(vs_ok)), default=0) <= 1, True)
    # Honest about what it cannot see: two attempts is under the threshold, so
    # the 2.5 hours 44591f39ef9f spent on a dead instance are invisible here.
    _, f445 = replay("44591f39ef9f")
    check("a job with only two attempts is NOT flagged, and that is a limit",
          f445, [])
    # COUNTED, NOT ASSERTED. This pinned the number 3 and went red the day a
    # fourth job legitimately ground (7dc1be932b26, verdict='partial' three in
    # a row). A guard that fails because the platform did its job teaches you
    # to skip the line. The PROPERTY is what matters: every flagged job
    # actually repeated a verdict to the threshold, and no unflagged one did.
    _flagged, _wrong = [], []
    for j in sorted(os.listdir(_real)):
        if not (_real / j / "events.jsonl").is_file():
            continue
        vs, fl = replay(j)
        run = max((vs.count(v) for v in set(vs)), default=0)
        if fl:
            _flagged.append(j)
            if run < B.BLOCKED_AFTER:
                _wrong.append((j, "flagged below threshold", run))
        elif run >= B.BLOCKED_AFTER:
            _wrong.append((j, "ground but not flagged", run))
    check(f"every flag is earned and none is missed "
          f"({len(_flagged)} flagged of the corpus)", _wrong, [])
    os.environ["DATA_DIR"] = str(tmp)
else:
    print("  --   no data/jobs on this box; corpus replay skipped")

print("\n8. the dashboard shows it, and shows it as a signal")
app_js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
css = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
check("the tile has a place for it", 'class="row-blocked"' in app_js, True)
check("...updated outside the row signature, like cost and the manager bar",
      app_js.index("_ROW_SIG.set(li, _rowHtml)")
      < app_js.index('li.querySelector(".row-blocked")'), True)
check("...hidden unless the job is actually signalling",
      "blkEl.hidden = !b || !b.signalling;" in app_js, True)
# Amber, not red: the job is still running and may still land it.
check("...and coloured as a warning rather than a failure",
      "--yellow" in css.split(".row-blocked")[1][:400], True)
# There used to be a projection step here that rebuilt the public meta for
# chained jobs, and this asked whether it short-circuited for everything else.
# The chaining module is gone and so is the projection, so the guarantee is
# now structural: nothing stands between the read and the response.
_jobs_src = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
check("the api passes the field through untouched — no projection step "
      "between read_job_meta and the response",
      "_public_job_meta" not in _jobs_src and "out.append(meta)" in _jobs_src, True)

print("\n8b. the agent's CLAIM is surfaced even where the platform sees no wall")
# Two different facts wore one name. `signalling` asks whether the PLATFORM
# sees a wall — N identical judge verdicts — and misc/forensic have no judge
# ladder at all, so `verdict_run` returns (None, 0, 0) and the claim could
# never be accepted there. Measured: all three blocked.json files in this
# box's corpus are misc jobs, each naming the exact obstacle, and every one
# was discarded. The claim is read from disk on the detail route so it needs
# no per-module hook and works on jobs that already finished.
_jobs_api = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
common = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
check("the detail route reads the claim from the job dir",
      'blocked.json' in _jobs_api and '"blocked_reason": blocked_reason' in _jobs_api, True)
check("...from BOTH places a module may write it",
      '_jd / "blocked.json"' in _jobs_api and '_jd / "work" / "blocked.json"' in _jobs_api, True)
check("...and the UI renders it", "job.blocked_reason" in app_js, True)
check("the escalation signal is left alone — it answers a different question",
      "maybe_signal" in common and "verdict_run" in
      (ROOT / "modules" / "_blocked.py").read_text(encoding="utf-8"), True)

print("\n9. it is wired into the attempt loop, once, and cannot end a turn")
common = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
check("the hook runs where an attempt concludes", common.count(
    "_blocked.maybe_signal(job_id, work_dir, log_fn)"), 1)
check("...after the flag gate, so the verdict is already part of the run",
      common.index('"flag_gate"') < common.index("_blocked.maybe_signal"), True)
check("...and a fault in it cannot end the turn it observes",
      "signal skipped" in common and "advisory only" in common, True)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
