#!/usr/bin/env python3
"""Stopping ONE RUN, and telling postjudge that is what happened.

WHY THIS EXISTS

A sandbox grinding for ten minutes on an exploit the operator has stopped
believing in is this platform's most expensive way to learn nothing. The only
lever was `/stop`, which ends the session and takes the work tree's context
with it — the agent then has to be rebuilt by a retry instead of simply
moving on to its next turn.

WHAT THIS SUITE PROTECTS

  * THE FACT MUST REACH THE JUDGE. An operator stop is neither a failure nor
    a success: nothing was learned about whether the exploit works. A judge
    that reads the missing result as a negative one will steer the agent away
    from an approach that was never refuted.
  * A STOP MUST NOT OUTLIVE ITS RUN. The request is a file; left on disk it
    would kill the NEXT run before its first poll, which reads as "the runner
    is broken" rather than "someone stopped it".
  * IT MUST BE HEARD BEFORE THE MODEL IS ASKED ANYTHING. The operator pressed
    it because the run is wasting time.

Run from the repository root::

    python3 scripts/test_runner_operator_stop.py
    python3 scripts/test_runner_operator_stop.py --mutate stop-survives-its-run
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("stop-survives-its-run", "judged-as-failure", "checked-after-supervise",
             "fact-not-propagated", "route-ignores-status",
             "request-forgotten-on-repaint")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


RUNNER = (ROOT / "modules" / "_runner.py").read_text(encoding="utf-8")
COMMON = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
JOBSAPI = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
APPJS = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")

if args.mutate == "stop-survives-its-run":
    RUNNER = RUNNER.replace(
        "    if _take_runner_stop(job_dir_path) is not None:\n"
        '        _log("[runner] discarding a stop request filed before this run began")\n',
        "", 1)
elif args.mutate == "judged-as-failure":
    RUNNER = RUNNER.replace("do NOT treat the absence of a result as a negative result", "", 1)
elif args.mutate == "checked-after-supervise":
    RUNNER = RUNNER.replace("_op_stop = _take_runner_stop(job_dir_path)",
                            "_op_stop = None  # moved", 1)
elif args.mutate == "fact-not-propagated":
    RUNNER = RUNNER.replace('        payload["stopped_by_operator"] = True\n', "", 1)
elif args.mutate == "request-forgotten-on-repaint":
    APPJS = APPJS.replace("_runnerStopAt[id] = Date.now()", "void 0", 1)
elif args.mutate == "route-ignores-status":
    JOBSAPI = JOBSAPI.replace('if meta.get("status") != "running":',
                              "if False:", 1)

print("1. the rail: a file, consumed on read")
# Imported rather than grepped: the round-trip is the contract, and a stop
# that is read twice is a stop that kills the next run too.
try:
    from modules._runner import request_runner_stop, _take_runner_stop
    _live = True
except Exception as exc:  # docker missing on the host is not this suite's problem
    print(f"  --   modules._runner not importable here ({exc.__class__.__name__});"
          " falling back to source checks")
    _live = False

if _live and args.mutate is None:
    d = Path(tempfile.mkdtemp(prefix="runner-stop-"))
    check("filing a stop writes the request", request_runner_stop(d, "too slow"))
    check("...and it is on disk", (d / "runner.stop").is_file())
    got = _take_runner_stop(d)
    check("...read back with the operator's reason",
          isinstance(got, dict) and got.get("reason") == "too slow")
    check("...and CONSUMED, so it cannot kill the next run",
          not (d / "runner.stop").is_file())
    check("a second read finds nothing", _take_runner_stop(d), None)

print("\n2. a stop does not outlive the run it was meant for")
check("the runner discards a stale request before waiting",
      "_take_runner_stop(job_dir_path) is not None" in RUNNER
      and RUNNER.index("_take_runner_stop(job_dir_path) is not None")
      < RUNNER.index("result = _wait_with_supervise("))

print("\n3. heard before anything expensive")
_wait = RUNNER.split("def _wait_with_supervise", 1)[1]
_loop = _wait.split("while True:", 1)[1]
check("the stop is checked inside the wait loop",
      "_take_runner_stop(job_dir_path)" in _loop)
check("...before the container exit probe",
      _loop.index("_take_runner_stop") < _loop.index("container.reload()"))
check("...and before the supervise judge is asked",
      _loop.index("_take_runner_stop") < _loop.index("supervise_result = "))

print("\n4. the fact travels to everything that reads a run's outcome")
check("the wait returns a marker rather than a bare exit code",
      '"stopped_by_operator": True' in _wait)
check("run_in_sandbox puts it in the payload",
      'payload["stopped_by_operator"] = True' in RUNNER)
check("the run/exit EVENT carries it, so the trace and replay see it",
      "stopped_by_operator=bool(res.get(\"stopped_by_operator\"))" in RUNNER)
check("the operator's reason rides along", '"operator_stop"' in RUNNER)

print("\n5. it is not a failure, and the judge is told so")
# Flattened before matching: these sentences are written across several
# source lines, and a literal anchor would pin the LINE BREAKS rather than
# the meaning — the failure mode that left three mutations dead elsewhere in
# this tree until they were swept today.
def _flat(s: str) -> str:
    return re.sub(r'["\s]+', " ", s)

_note = _flat(RUNNER.split('elif res.get("stopped_by_operator"):', 1)[1][:900])
check("the judge-facing note says it neither failed nor finished",
      "did not fail and it did not finish" in _note)
check("...and forbids reading the absence of a result as a negative one",
      "do NOT treat the absence of a result as a negative result" in _note)
_flatc = _flat(COMMON)
check("main's own turn feedback says the same",
      "THE OPERATOR STOPPED THIS RUN" in _flatc
      and "the approach itself was not refuted" in _flatc)
check("WHY_STOPPED.md records it too",
      "the OPERATOR stopped this run" in _flatc)

print("\n6. the route, and what it refuses")
check("there is a run-scoped stop endpoint",
      '@router.post("/{job_id}/runner/stop")' in JOBSAPI)
check("...that files the request through the runner's own rail",
      "request_runner_stop(jd, reason)" in JOBSAPI)
check("...and refuses when no run can be in flight",
      'if meta.get("status") != "running":' in JOBSAPI
      and "no run is in flight" in JOBSAPI)
check("it is NOT the job stop — that one still exists, separately",
      '@router.post("/{job_id}/stop")' in JOBSAPI)

print("\n7. the operator can reach it")
check("a button offers it while the job runs",
      'data-action="runner-stop"' in APPJS
      and 'job.status === "running"' in APPJS.split("runnerStopHtml", 1)[1][:200])
check("...and posts to the run-scoped route, not /stop",
      "/runner/stop`" in APPJS)
check("...carrying the operator's reason",
      "JSON.stringify({ reason: why })" in APPJS)
# The controls row is rebuilt by the 2s poll and stopping the RUN leaves the
# JOB running, so the button stays on screen. Without state outside the DOM
# its "requested" label reverted within two seconds and the operator, seeing
# no effect, clicks again.
check("a filed request survives the repaint that follows it",
      "_runnerStopAt[id] = Date.now()" in APPJS
      and "_runnerStopAt[id] || 0" in APPJS)
check("...and the button is disabled while it is pending",
      "_stopPending ? \"disabled\" : \"\"" in APPJS)

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
