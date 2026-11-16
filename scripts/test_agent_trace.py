#!/usr/bin/env python3
"""A picture of a run has to be checkable, or it is decoration.

WHY THIS EXISTS

The operator asked whether Ogamdo could draw an agent workflow like an n8n
canvas. It cannot: there is no authored graph here. The shape emerges from a
loop, so the only honest drawing is the trajectory that was actually walked.
That makes the chart an ASSERTION ABOUT WHAT HAPPENED, and assertions need
tests -- a pretty diagram that quietly loses two hours is worse than no
diagram, because it will be believed.

WHAT THIS SUITE PROTECTS

  * THE ARITHMETIC. The lanes tile the job's wall clock exactly. It held on
    all twelve corpus jobs to within 0.7s, and the UI prints the residual
    rather than hiding it. The first draft of this view anchored lane 1 on
    itself, which reported 5dcebc463810's first segment as 0 seconds when it
    was 9,955 of that job's 10,016 -- the whole job, drawn as nothing.
  * THE JOIN KEY. Usage rows are matched to lanes BY TIMESTAMP. The ledger's
    `attempt` field is per `(role, stage)` -- see usage_ledger.next_attempt --
    so on 340e62bdcd32 prejudge counts to 51 while postjudge counts to 26, and
    joining on it silently interleaves unrelated calls. It looks like a key.
    It is not one.
  * ABSENT IS NOT ZERO. A segment that never happened is None and is not
    drawn; a segment that happened and was short keeps a pixel floor. Run time
    is under 2.3% of every job in the corpus, so a purely proportional width
    renders the finding itself invisible.
  * COST IS NOT ZERO EITHER. Every `main` row ever written carries
    `cost_basis: "none"`. An agent segment's cost is unattributable, and a
    chart that prints $0.00 there says drafting is free about jobs that spent
    80% of their clock drafting.
  * WHAT IS NOT DRAWN. Subagent spawns and injected turns have no structured
    record. They stay undrawn until someone adds the emit_event call, rather
    than being inferred from log prose -- the same mistake as the recon
    attribution retracted in 43f6cd2.

Run from the repository root::

    python3 scripts/test_agent_trace.py
    python3 scripts/test_agent_trace.py --mutate join-on-attempt
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
    "join-on-attempt",
    "lane1-anchors-on-itself",
    "absent-segment-is-zero",
    "no-tail-lane",
    "unreported-cost-counts-as-zero",
    "drop-pixel-floor",
    "summary-asserts-outcome",
    "naive-isoformat-only",
    "trace-tab-toggles",
    "sibling-tab-does-not-leave-trace",
    "block-edge-drawn-live",
    "idle-node-looks-run",
    "retries-from-verdicts",
    "subagent-absent-is-zero",
    "main-counted-as-subagent",
    "injection-joins-on-attempt",
    "injection-rung-dropped",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    ok = got == want
    if ok:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="trace-test-"))
os.environ["DATA_DIR"] = str(tmp)
(tmp / "jobs").mkdir()

T0 = datetime(2026, 9, 17, 0, 0, 0, tzinfo=timezone.utc)


def at(sec):
    return (T0 + timedelta(seconds=sec)).isoformat()


def make_job(name, *, events, usage=(), manager=(), started=0, ended=None):
    d = tmp / "jobs" / name
    d.mkdir(parents=True, exist_ok=True)
    meta = {"id": name, "status": "stopped" if ended is not None else "running",
            "started_at": at(started)}
    if ended is not None:
        meta["stopped_at"] = at(ended)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (d / "events.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    if usage:
        (d / "usage.jsonl").write_text(
            "".join(json.dumps(u) + "\n" for u in usage), encoding="utf-8")
    if manager:
        (d / "manager.jsonl").write_text(
            "".join(json.dumps(m) + "\n" for m in manager), encoding="utf-8")
    return d


def attempt(t, *, verdict="partial", exit_code=2, gate=True, exit_=True):
    """One full attempt starting `t` seconds in: 1s prejudge, 4s run, 10s judge."""
    out = [
        {"ts": at(t), "phase": "prejudge", "kind": "result", "ok": False,
         "severity": "high", "target_liveness": "live", "issues": 3},
        {"ts": at(t + 1), "phase": "run", "kind": "start", "script": "exploit.py",
         "target": "http://x", "timeout_s": 300},
    ]
    if exit_:
        out.append({"ts": at(t + 5), "phase": "run", "kind": "exit",
                    "exit_code": exit_code, "stdout_bytes": 10, "stderr_bytes": 0,
                    "timeout": False, "killed_by_supervise": False})
        out.append({"ts": at(t + 15), "phase": "postjudge", "kind": "verdict",
                    "verdict": verdict, "next_action": "stop", "failure_code": None})
    if gate:
        out.append({"ts": at(t + 16), "phase": "run", "kind": "flag_gate",
                    "flags_count": 0, "tier": "", "suppressed": False,
                    "verdict": verdict, "exit_code": exit_code,
                    "terminal_capture": False, "reason": "no_capture_evidence"})
    return out


import modules._trace as X  # noqa: E402

# --- mutations --------------------------------------------------------------
# Each captures the REAL function before rebinding. A lambda that calls the
# name it is being bound to recurses; that cost this repo a hung suite once.
if args.mutate == "join-on-attempt":
    def _by_attempt(lanes, usage):
        totals = {}
        for row in usage:
            key = f"{row.get('role')}/{row.get('stage')}"
            totals[key] = totals.get(key, 0) + 1
            i = (row.get("attempt") or 1) - 1
            if 0 <= i < len(lanes):
                lanes[i]["calls"][key] = lanes[i]["calls"].get(key, 0) + 1
                lanes[i]["tokens"] += X._token_total(row.get("tokens"))
        return totals
    X._attribute_usage = _by_attempt
elif args.mutate == "lane1-anchors-on-itself":
    _real_build = X._build_lanes
    X._build_lanes = lambda events, started: _real_build(events, None)
elif args.mutate == "absent-segment-is-zero":
    _real_span = X._span
    def _zero_span(a, b):
        got = _real_span(a, b)
        return got if got else {"t0": None, "t1": None, "s": 0.0}
    X._span = _zero_span
elif args.mutate == "no-tail-lane":
    X._append_tail_lane = lambda lanes, started, ended: None
elif args.mutate == "injection-joins-on-attempt":
    def _by_attempt(lanes, events):
        totals = {}
        for ev in events:
            if ev.get("phase") != "agent" or ev.get("kind") != "injected_turn":
                continue
            rung = ev.get("rung") or "?"
            totals[rung] = totals.get(rung, 0) + 1
            i = (ev.get("attempt") or 1) - 1
            if 0 <= i < len(lanes):
                lanes[i]["injections"][rung] = lanes[i]["injections"].get(rung, 0) + 1
        return totals
    X._attribute_injections = _by_attempt
elif args.mutate == "injection-rung-dropped":
    _real_inj = X._attribute_injections
    def _no_rung(lanes, events):
        got = _real_inj(lanes, events)
        return {"injected": sum(got.values())} if got else {}
    X._attribute_injections = _no_rung
elif args.mutate == "subagent-absent-is-zero":
    _real_sub = X._subagents
    def _zeroed(job_id):
        got = _real_sub(job_id)
        got["source"] = got["source"] or "gpt-events.jsonl"
        return got
    X._subagents = _zeroed
elif args.mutate == "main-counted-as-subagent":
    import re as _re
    _src = X._subagents.__doc__
    def _with_main(job_id, _r=X._subagents):
        got = _r(job_id)
        if got["main_tools"]:
            got["roles"]["main"] = {"spawns": 1, "tools": got["main_tools"],
                                    "models": [], "first_ts": None, "last_ts": None}
        return got
    X._subagents = _with_main
elif args.mutate == "naive-isoformat-only":
    from datetime import datetime as _dt, timezone as _tz
    def _naive(value):
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            d = _dt.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=_tz.utc)
    X._parse_ts = _naive
elif args.mutate == "unreported-cost-counts-as-zero":
    _real_attr = X._attribute_usage
    def _cost_is_zero(lanes, usage):
        got = _real_attr(lanes, usage)
        for lane in lanes:
            lane["cost_complete"] = True
            if lane["cost_usd"] is None:
                lane["cost_usd"] = 0.0
        return got
    X._attribute_usage = _cost_is_zero

print("\n1. the lanes tile the job's wall clock")
# Three attempts at 100/200/300s, a 100s head and a 284s tail. Every second of
# the job belongs to exactly one segment of exactly one lane.
make_job("three", started=0, ended=600,
         events=attempt(100) + attempt(200) + attempt(300, verdict="network_error"),
         usage=[
             {"ts": at(5), "role": "main", "stage": "main", "cost_basis": "none",
              "cost_usd": None, "attempt": 1,
              "tokens": {"input_tokens": 10, "output_tokens": 90}},
             {"ts": at(101), "role": "judge", "stage": "prejudge",
              "cost_basis": "reported", "cost_usd": 0.5, "attempt": 1,
              "tokens": {"input_tokens": 1, "output_tokens": 1}},
             {"ts": at(114), "role": "judge", "stage": "postjudge",
              "cost_basis": "reported", "cost_usd": 0.25, "attempt": 1,
              "tokens": {"input_tokens": 1, "output_tokens": 1}},
             {"ts": at(201), "role": "judge", "stage": "prejudge",
              "cost_basis": "reported", "cost_usd": 0.5, "attempt": 2,
              "tokens": {"input_tokens": 1, "output_tokens": 1}},
             # attempt=1 again: a DIFFERENT counter (reviewer's), in lane 3.
             {"ts": at(310), "role": "reviewer", "stage": "reviewer",
              "cost_basis": "reported", "cost_usd": 0.1, "attempt": 1,
              "tokens": {"input_tokens": 1, "output_tokens": 1}},
         ])
t = X.build_trace("three")
tt = t["totals"]
total = tt["agent_s"] + tt["run_s"] + tt["adjudicate_s"]
check("the segments sum to the job's wall clock, exactly",
      round(total, 6), round(t["wall_s"], 6))
check("...and the wall clock is what meta says it is", t["wall_s"], 600.0)
check("lane 1's agent segment anchors on the JOB's start, not its own",
      t["lanes"][0]["agent"]["s"], 101.0)
check("the time after the last execution is a lane, not a rounding error",
      t["lanes"][-1]["agent"]["s"], 284.0)
check("...and that lane is marked as never having reached execution",
      (t["lanes"][-1].get("unreached"), t["lanes"][-1]["run"]), (True, None))
check("every execution is counted", tt["runs"], 3)

print("\n2. usage joins on time, because `attempt` is not a key")
# The ledger's counter is per (role, stage) -- usage_ledger.next_attempt. Two
# rows both saying attempt=1 here belong to lane 1 and lane 3.
check("a call is attributed to the lane whose window holds it",
      [sorted(l["calls"]) for l in t["lanes"]],
      [["judge/postjudge", "judge/prejudge", "main/main"],
       ["judge/prejudge"], ["reviewer/reviewer"], []])
check("...so the reviewer's attempt=1 lands in lane 3, not lane 1",
      t["lanes"][2]["calls"].get("reviewer/reviewer"), 1)
check("job-level call counts survive the join",
      tt["calls"]["judge/prejudge"], 2)

print("\n3. absent is not zero, and unreported is not free")
check("a lane that never ran has no run segment at all",
      t["lanes"][-1]["run"], None)
check("...and no adjudicate segment either", t["lanes"][-1]["adjudicate"], None)
check("a lane holding an unreported call is flagged incomplete",
      t["lanes"][0]["cost_complete"], False)
check("...and the job total says so too", tt["cost_complete"], False)
check("a lane with only reported calls is complete",
      t["lanes"][1]["cost_complete"], True)
check("a lane with NO calls reports unknown cost, not $0",
      (t["lanes"][-1]["cost_usd"], t["lanes"][-1]["calls"]), (None, {}))

print("\n4. a job that is still running, and one that never ran")
make_job("inflight", started=0, ended=None,
         events=attempt(100) + [
             {"ts": at(200), "phase": "prejudge", "kind": "result", "ok": True,
              "severity": "low", "target_liveness": "live", "issues": 0},
             {"ts": at(201), "phase": "run", "kind": "start",
              "script": "exploit.py", "target": "http://x", "timeout_s": 300},
         ])
t2 = X.build_trace("inflight")
check("an attempt with no exit event does not crash the trace",
      t2.get("error"), None)
check("...it is an open lane", t2["lanes"][-1]["open"], True)
check("...whose run segment has no duration yet",
      t2["lanes"][-1]["run"]["s"], None)
check("...and the job is reported as running", t2["running"], True)

make_job("noevents", started=0, ended=900, events=[])
t3 = X.build_trace("noevents")
check("a job with no events is one unreached lane, not an empty chart",
      (len(t3["lanes"]), t3["lanes"][0]["agent"]["s"]), (1, 900.0))
check("...and says so in a note",
      any("events.jsonl" in n for n in t3["notes"]), True)

make_job("spawnfail", started=0, ended=100, events=[
    {"ts": at(10), "phase": "prejudge", "kind": "result", "ok": True,
     "severity": "low", "target_liveness": "live", "issues": 0},
    {"ts": at(11), "phase": "run", "kind": "spawn_failed", "error": "boom"},
])
t4 = X.build_trace("spawnfail")
check("a spawn failure produces a lane rather than an exception",
      (t4.get("error"), len(t4["lanes"])), (None, 1))
check("...and is marked as such", t4["lanes"][0]["run"]["spawn_failed"], True)

print("\n5. the manager series")
make_job("mgr", started=0, ended=600, events=attempt(100),
         # `_manager` writes %z (`+0000`), not isoformat (`+00:00`), and
         # Python 3.10's fromisoformat rejects the first. Every manager row in
         # every job was silently dropped until this was fixed, so the format
         # is pinned here in the shape the real writer emits.
         manager=[{"ts": at(150).replace("+00:00", "+0000"), "stage": "recon",
                   "steps_done": 1, "steps_total": 7, "flag_probability": 10,
                   "confidence": "low"},
                  {"ts": at(400), "stage": "vuln-identified", "steps_done": 3,
                   "steps_total": 7, "flag_probability": 40,
                   "confidence": "medium"}])
t5 = X.build_trace("mgr")
check("manager assessments come back oldest first",
      [m["flag_probability"] for m in t5["manager"]], [10, 40])
check("...including the %z-offset row the real writer emits",
      X._parse_ts("2026-09-18T16:42:15+0000") is not None, True)
check("...without widening something that is not an offset",
      X._parse_ts("not a date"), None)
_real_mgr = (ROOT / "data" / "jobs" / "340e62bdcd32" / "manager.jsonl")
if _real_mgr.is_file():
    os.environ["DATA_DIR"] = str(ROOT / "data")
    check("a real manager.jsonl on this box is READ, not dropped",
          len(X._manager_series("340e62bdcd32")), 1)
    os.environ["DATA_DIR"] = str(tmp)

print("\n6. the corpus itself — the property that makes the chart trustworthy")
# Not synthetic. If the real jobs on this box ever stop reconciling, the number
# printed in the UI's footer moves off zero and this fails first.
_real_jobs = ROOT / "data" / "jobs"
if _real_jobs.is_dir():
    os.environ["DATA_DIR"] = str(ROOT / "data")
    worst, seen, worst_job, live = 0.0, 0, None, 0
    for d in sorted(_real_jobs.iterdir()):
        if not (d / "meta.json").is_file():
            continue
        rt = X.build_trace(d.name)
        if rt.get("error") or rt["wall_s"] is None:
            continue
        # A LIVE job cannot reconcile and must not be asked to. Its in-flight
        # run has started and not exited, so `run.s` is None by design — the
        # honest answer while it is still executing — and the gap grows with
        # the run. Measured on e925acfecb84 mid-sandbox: 429 s, then 445 s a
        # minute later. Including these made the guard red whenever a job
        # happened to be running, which is how a guard stops being read.
        if rt.get("running"):
            live += 1
            continue
        s = (rt["totals"]["agent_s"] + rt["totals"]["run_s"]
             + rt["totals"]["adjudicate_s"])
        drift = abs(rt["wall_s"] - s)
        seen += 1
        if drift > worst:
            worst, worst_job = drift, d.name
    # `live` is printed rather than dropped: a run of skips is the thing that
    # would otherwise hide a corpus shrinking to nothing.
    check(f"every FINISHED job on this box reconciles ({seen} jobs, worst "
          f"{worst:.4f}s on {worst_job}; {live} live job(s) skipped)",
          worst < 0.01, True)
    os.environ["DATA_DIR"] = str(tmp)
else:
    print("  --   no data/jobs on this box; corpus check skipped")

print("\n7. the view, and what it refuses to draw")
css = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
if args.mutate == "drop-pixel-floor":
    css = css.replace(".tr-seg { display: block; min-width: 6px;",
                      ".tr-seg { display: block;", 1)
# Execution is 0.0-2.3% of wall clock on every corpus job. Without a floor the
# segment that carries the finding is drawn at under one pixel.
check("a present-but-tiny segment keeps a pixel floor",
      ".tr-seg" in css and "min-width: 6px" in css.split(".tr-seg")[1][:80], True)
check("the trace view hides the log, monitor and timeline",
      css.count('.run-log-window[data-view="trace"]') >= 4, True)

app_js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
if args.mutate == "summary-asserts-outcome":
    app_js = app_js.replace('${_traceSeg("run", "", tt.run_s, sum,',
                            '${_traceSeg("run", " ok", tt.run_s, sum,', 1)
# The summary reports WHERE the clock went, not how it turned out. Colouring
# its run segment green put "run: ok" above seventeen rows that all exited
# non-zero -- the chart contradicting its own data.
_sum = app_js.split("function _traceSummary(")[1].split("function renderTrace")[0]
check("the summary bar asserts no outcome",
      '" ok"' not in _sum and '" warn"' not in _sum, True)
check("...while a lane still colours by its own verdict",
      "_traceVerdictCls(lane.verdict)" in app_js, True)
check("an absent segment is omitted, not drawn at zero",
      "if (seconds === null || seconds === undefined) return \"\";" in app_js, True)
check("the trace is painted in place, not into the hashed markup",
      'put("div.tr-feed", parts.trace);' in app_js, True)
check("...and its buttons are delegated, since that container is replaced",
      'e.target.closest(".tr-scale' in app_js, True)
check("the view is fetched only when it is the one being looked at",
      'if (activityView === "trace") {' in app_js, True)

# The trace is not a mode on top of the other views, it is one OF them.
# `activityView` short-circuits on traceView, so a sibling tab that does not
# clear the flag changes its own preference and leaves the screen exactly where
# it was -- and `if (monitorView) _setMonitorView(false)` is a no-op when
# monitorView is already false, which made Run log completely inert. The
# operator's report was "it does not appear on completed jobs"; every job
# renders, but the tabs did not behave like tabs.
if args.mutate == "trace-tab-toggles":
    app_js = app_js.replace('viewTraceBtn.addEventListener("click", () => _setTraceView(true));',
                            'viewTraceBtn.addEventListener("click", () => _setTraceView(!traceView));', 1)
if args.mutate == "sibling-tab-does-not-leave-trace":
    _i = app_js.find('viewLogBtn.addEventListener("click"')
    assert _i >= 0, "sibling handler not found — the mutation would be a no-op"
    _seg = app_js[_i:_i + 260]
    assert "_leaveTraceView();" in _seg, "mutation target already absent"
    app_js = app_js[:_i] + _seg.replace("_leaveTraceView();", "", 1) + app_js[_i + 260:]
check("the trace tab SELECTS rather than toggles",
      "_setTraceView(!traceView)" not in app_js
      and '_setTraceView(true)' in app_js, True)
_sibs = ["viewLogBtn", "viewMonBtn", "gptTimelineBtn", "gptLogBtn",
         "viewClaudeTlBtn"]
def _handler_body(name: str) -> str:
    i = app_js.find(f'{name}.addEventListener("click"')
    return app_js[i:i + 260] if i >= 0 else ""
check("every sibling view tab leaves the trace, so none of them is inert",
      [n for n in _sibs if "_leaveTraceView()" not in _handler_body(n)], [])
check("...and leaving does not render, so the sibling setter renders once",
      "function _leaveTraceView()" in app_js
      and "renderJob" not in app_js.split("function _leaveTraceView()")[1].split("}")[0],
      True)

print("\n7b. subagents — the record that was there the whole time")
# `agent_started` in the provider stream is a real spawn: role, model, session
# id, timestamp. This view first shipped saying those edges were undrawable
# prose, which was wrong -- every job in the corpus is GPT/Codex and the stream
# is structured. They are in no other file: codex bills a session once, so
# there is no usage row, and events.jsonl tracks the exploit loop, not the
# agent's team.
make_job("subs", started=0, ended=600, events=attempt(100))
(tmp / "jobs" / "subs" / "gpt-events.jsonl").write_text("".join(
    json.dumps(e) + "\n" for e in [
        {"ts": at(5), "kind": "agent_started", "role": "main", "model": "m"},
        {"ts": at(10), "kind": "tool_started", "role": "main"},
        {"ts": at(11), "kind": "tool_started", "role": "main"},
        {"ts": at(20), "kind": "agent_started", "role": "recon", "model": "m"},
        {"ts": at(22), "kind": "tool_started", "role": "recon"},
        {"ts": at(25), "kind": "message", "role": "recon", "summary": "debugger 이야기"},
    ]), encoding="utf-8")
t6 = X.build_trace("subs")
sa = t6["subagents"]
check("a spawned role is counted from the provider stream",
      (sorted(sa["roles"]), sa["roles"]["recon"]["spawns"], sa["roles"]["recon"]["tools"]),
      (["recon"], 1, 1))
check("main is not one of its own subagents",
      ("main" not in sa["roles"], sa["main_tools"]), (True, 2))
# ccf6d5838457's stream says "plan: Docker debugger probe" in an agent message.
# A substring match would have reported a debugger spawn that never happened.
check("a role NAMED in prose is not a spawn", "debugger" in sa["roles"], False)
check("roles that were available and never called are named",
      "debugger" in sa["never_invoked"] and "recon" not in sa["never_invoked"], True)

make_job("nostream", started=0, ended=300, events=attempt(50))
sa2 = X.build_trace("nostream")["subagents"]
check("no provider stream reports NOT RECORDED, not zero spawns",
      (sa2["source"], sa2["roles"]), (None, {}))

if _real_jobs.is_dir():
    os.environ["DATA_DIR"] = str(ROOT / "data")
    _spawned = 0
    _seen = 0
    for d in sorted(_real_jobs.iterdir()):
        if not (d / "meta.json").is_file():
            continue
        _seen += 1
        if "recon" in X.build_trace(d.name)["subagents"]["roles"]:
            _spawned += 1
    check(f"the real corpus shows recon actually running ({_spawned}/{_seen} jobs)",
          _spawned > 0, True)
    os.environ["DATA_DIR"] = str(tmp)

print("\n7c. injected turns — now emitted, so now drawable")
from modules._events import PHASES as _PHASES  # noqa: E402
# `emit_event` tags an unknown phase "?phase" so a miswiring is visible. That
# is the right default and the wrong outcome here, so the phase is declared.
check("the agent turn boundary is a declared phase", "agent" in _PHASES, True)

common_src = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
# Every rung on the ladder, not just the two that already reached
# summary["injected_turns"] -- which is not persisted to result.json anyway, so
# nothing survived the run in a readable form before this.
_RUNGS = ["final_draft", "operator_steer", "soft_eject", "empty_wait",
          "contrarian_reframe", "postjudge_feedback"]
check("every rung of the injection ladder emits an event",
      [r for r in _RUNGS if f'"{r}"' not in common_src], [])
check("...emitted BEFORE the query, like the log line and the existing record",
      common_src.index('_emit_injected_turn(job_id, "final_draft"')
      < common_src.index("await client.query(FINAL_DRAFT_USER_TURN)"), True)

# A steer fires between one attempt's flag gate and the next attempt's
# prejudge. It belongs to the lane it delayed -- the NEXT attempt's agent
# segment -- not to whichever attempt counter it happened to carry.
make_job("inj", started=0, ended=900,
         events=sorted(attempt(100) + attempt(500) + [
             {"ts": at(40), "phase": "agent", "kind": "injected_turn",
              "rung": "postjudge_feedback", "attempt": 1, "chars": 100},
             {"ts": at(300), "phase": "agent", "kind": "injected_turn",
              "rung": "operator_steer", "attempt": 1, "chars": 50, "messages": 2},
             {"ts": at(800), "phase": "agent", "kind": "injected_turn",
              "rung": "final_draft", "attempt": 2, "chars": 900},
         ], key=lambda e: e["ts"]))
t7 = X.build_trace("inj")
check("injections are tallied by rung, not merged into one number",
      t7["totals"]["injections"],
      {"postjudge_feedback": 1, "operator_steer": 1, "final_draft": 1})
check("an injection between two attempts lands in the lane it delayed",
      [l["injections"] for l in t7["lanes"]],
      [{"postjudge_feedback": 1}, {"operator_steer": 1}, {"final_draft": 1}])
check("...and the run loop is untouched by the new event kind",
      (t7["totals"]["runs"], round(t7["wall_s"] - (
          t7["totals"]["agent_s"] + t7["totals"]["run_s"]
          + t7["totals"]["adjudicate_s"]), 6)), (2, 0.0))

t8 = X.build_trace("three")
check("a job from BEFORE the instrumentation says its absence is ambiguous",
      any("구분되지 않습니다" in n for n in t8["notes"]), True)
# The first version of this compared a KST date string against a UTC
# `started_at`, so job 35a98fd7b823 -- which ran 58 minutes AFTER the
# instrumentation and genuinely injected nothing -- was told its zero was
# unknowable. The boundary is an instant now, not a date.
make_job("after", started=0, ended=600, events=attempt(100))
_after = tmp / "jobs" / "after" / "meta.json"
_am = json.loads(_after.read_text())
_am["started_at"] = "2026-09-19T01:00:00+00:00"   # past the instant
_am["stopped_at"] = "2026-09-19T02:00:00+00:00"
_after.write_text(json.dumps(_am))
check("...and a job from AFTER it does not — its zero is a real zero",
      any("구분되지 않습니다" in n for n in X.build_trace("after")["notes"]), False)
check("the boundary is an instant, not a bare date",
      "_INJECTION_INSTRUMENTED_AT = datetime(" in
      (ROOT / "modules" / "_trace.py").read_text(encoding="utf-8"), True)

print("\n8. the graph view — a different question, not a nicer picture")
# Lanes answer "where did the clock go"; the graph answers "what is wired to
# what". The operator asked for the second and got the first, so both ship.
# The graph earns its place by showing something lanes structurally cannot: an
# edge that exists in the design and does nothing. prejudge raised would_block
# 5 times on 340e62bdcd32 and all 17 runs proceeded; on 5efafb6ee9ab it was 25
# against 27. Drawing that edge as live would be a lie about the pipeline.
if args.mutate == "block-edge-drawn-live":
    app_js = app_js.replace('const blockStub = d.blocked ? `<g class="g-dead">',
                            'const blockStub = d.blocked ? `<g class="g-live">', 1)
if args.mutate == "idle-node-looks-run":
    app_js = app_js.replace('"g-run" + (d.ran ? "" : " g-idle"),', '"g-run",', 1)
if args.mutate == "retries-from-verdicts":
    app_js = app_js.replace("retries: Math.max(0, lanes.length - 1),",
                            "retries: Object.keys(verdicts).length,", 1)
check("the would_block edge is drawn dead-ended, not as a live branch",
      'class="g-dead"' in app_js and 'class="g-x"' in app_js, True)
check("...and says the runs went ahead anyway",
      "실행을 멈추지 않음" in app_js, True)
_idle = ["d.prejudged ?", "d.ran ?", "d.adjudicated ?", "d.gated ?"]
check("a node nothing reached is dimmed, not drawn like one that ran",
      [n for n in _idle if f'{n} "" : " g-idle"' not in app_js], [])
check("the retry count derives from the lanes, so it cannot disagree with them",
      "retries: Math.max(0, lanes.length - 1)" in app_js, True)
check("both shapes are reachable, and the toggle is delegated like the others",
      'e.target.closest(".tr-shape' in app_js
      and 'data-action="trace-shape-graph"' in app_js
      and 'data-action="trace-shape-lanes"' in app_js, True)
check("spawned subagents are drawn, with the edge that spawned them",
      '"g-subagent"' in app_js and '"g-spawn"' in app_js, True)
check("...under a class of their own, not the one the subtitle text uses",
      '"g-subagent"' in app_js and 'class="g-sub"' in app_js, True)
check("injected turns are drawn, pushed INTO main rather than spawned by it",
      '"g-inject"' in app_js and '"g-injwire"' in app_js, True)
check("...named by rung, because which rung fired is the whole point",
      "OPERATOR STEER" in app_js and "FINAL DRAFT" in app_js
      and "EMPTY WAIT" in app_js, True)
check("the legend no longer says injected turns are undrawn",
      "주입 턴(soft-eject / empty-wait / OPERATOR STEER)은 아직" not in app_js
      and "agent/injected_turn" in app_js, True)
check("a job with no provider stream says so instead of drawing zeros",
      "0회가 아니라 미기록" in app_js, True)
check("only the shape being looked at is built",
      'traceShape === "graph"\n      ? _traceGraph(t)' in app_js, True)
css_g = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
check("the dead edge is dashed, and the idle node has its own fill",
      "stroke-dasharray" in css_g.split(".g-dead path")[1][:120]
      and ".g-node.g-idle rect" in css_g, True)

# Both feedback edges are now recorded. What must stay true is that each is
# drawn from an EVENT and never inferred from log prose -- the mistake that
# produced the recon attribution retracted in 43f6cd2, and the mistake this
# feature repeated when it declared these edges unrecorded without checking.
mods = (ROOT / "modules").glob("*.py")
emits = {p.name for p in mods
         if 'emit_event(job_id, "agent", "injected_turn"' in p.read_text(errors="replace")}
check("injected turns are emitted as structured events", emits, {"_common.py"})
_tr_src = (ROOT / "modules" / "_trace.py").read_text(encoding="utf-8")
check("events the lanes do not place still travel, generically",
      "_other_events" in _tr_src and '"other_events"' in _tr_src, True)
check("...and the UI lists them", "t.other_events" in app_js, True)
check("a run the job outlived is LABELLED, not just drawn long — the field "
      "the builder sets has to reach the reader or it is decoration",
      "lane.run.unterminated" in app_js, True)
check("...and nothing scrapes the log for them instead",
      "[orchestrator] injecting" not in (ROOT / "modules" / "_trace.py").read_text(encoding="utf-8"),
      True)
check("...and the legend no longer claims either edge is undrawable",
      "subagent 생성과 주입 턴" not in app_js
      and "기록된 것만" in app_js, True)

trace_src = (ROOT / "modules" / "_trace.py").read_text(encoding="utf-8")
check("the join key's hazard is documented where someone would change it",
      "next_attempt" in trace_src and "per" in trace_src, True)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
