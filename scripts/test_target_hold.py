#!/usr/bin/env python3
"""A dead remote holds the run; nothing else does.

WHY THIS EXISTS

Nothing checked whether the challenge's remote was still answering. Job
7599aaf936b0 ran 75 turns against an expired instance and ended only because
a human pressed stop — `agent_error_kind` was None, because from the inside
nothing had gone wrong. 81% of this platform's spend goes to jobs that do not
solve, and a job working against an address that stopped existing is the
purest form of that.

So the run HOLDS: status `hold`, the reason recorded, the work tree and
session kept, and the job waits for a new target instead of spending on a
dead one.

WHAT THIS SUITE PROTECTS

  * IT MUST NOT FIRE ON ONE REFUSED CONNECT. Job 1aedc9880862 logged
    `Connection refused` thirteen times against localhost:3000 while its
    challenge was healthy — the agent had torn down its own container. A
    spurious hold is worse than no hold: the job stops and waits for a human
    who has no reason to look. Hence N consecutive misses, spaced, and only
    against the DECLARED REMOTE.
  * A HOLD MUST SURVIVE THE FINAL-STATUS WRITE. Every module ends with
    `status=final_status`; without a guard in the one shared helper they all
    call, the hold would be overwritten as `no_flag` — filing the job as a
    miss when it never got to try.
  * CRASHES STILL CRASH. `finished` and `failed` bypass that helper and are
    deliberately untouched. An immortal job is a worse bottleneck than the
    one this fixes.

Run from the repository root::

    python3 scripts/test_target_hold.py
    python3 scripts/test_target_hold.py --mutate hold-on-first-miss
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("hold-on-first-miss", "watch-local-targets-too",
             "no-flag-clobbers-hold", "loop-ignores-hold",
             "monitor-parks-on-hold", "steer-rejects-hold",
             "hold-priced-as-terminal", "ui-hides-hold-resume",
             "hold-reason-not-rendered",
              "resume-button-always-visible",
              "resume-button-sends-stale-target")
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


from modules import _target_watch as W  # noqa: E402

DEAD = "example.com:9"          # resolves, port closed
W._CONNECT_S = 3.0
W._MIN_GAP_S = 0.0              # spacing is asserted separately, below
if args.mutate == "hold-on-first-miss":
    W._FAILS_TO_HOLD = 1
if args.mutate == "watch-local-targets-too":
    W.is_remote = lambda t: bool(t)

print("\n1. only the declared remote is watched")
for t, want in (("http://host3.dreamhack.games:12345/", True),
                ("host3.dreamhack.games:12345", True),
                ("http://127.0.0.1:3000/", False),
                ("http://localhost:3000/", False),
                ("http://172.18.0.1:8080/", False),
                ("http://10.1.2.3/", False),
                ("", False), (None, False)):
    check(f"is_remote({str(t)[:34]!r})", W.is_remote(t), want)

print("\n2. one refused connect is not a dead target")
W.forget("j1")
meta = {"target_url": DEAD}
first = W.check("j1", meta)
second = W.check("j1", meta)
check("miss 1 does not hold", first, None)
check("miss 2 does not hold", second, None)
third = W.check("j1", meta)
check("miss 3 holds", bool(third), True)
check("...and says why", "stopped answering" in (third or ""), True)
check("a 4th probe does not re-fire", W.check("j1", meta), None)

print("\n3. a local-only or targetless job is never held")
W.forget("j2")
held_local = [W.check("j2", {"target_url": "http://127.0.0.1:9/"}) for _ in range(5)]
check("local target -> never held", [r for r in held_local if r], [])
W.forget("j3")
held_none = [W.check("j3", {}) for _ in range(5)]
check("no target -> never held", [r for r in held_none if r], [])

print("\n4. probes are spaced, so a tight tool loop cannot burn the budget")
W.forget("j4")
W._MIN_GAP_S = 3600.0
W.check("j4", {"target_url": DEAD})
before = W._STATE["j4"]["fails"]
W.check("j4", {"target_url": DEAD})
check("a second probe inside the gap is skipped",
      W._STATE["j4"]["fails"], before)
W._MIN_GAP_S = 0.0

print("\n5. the hold survives the final-status write")
src = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
nfs = src[src.find("def no_flag_status"):src.find("def no_flag_status") + 1400]
if args.mutate == "no-flag-clobbers-hold":
    nfs = nfs.replace('if meta.get("status") == "hold":', "if False:")
check("no_flag_status returns hold for a held job",
      'if meta.get("status") == "hold":' in nfs and 'return "hold"' in nfs, True)
check("every module funnels through it",
      all("no_flag_status(" in (ROOT / "modules" / m / f).read_text(encoding="utf-8")
          for m, f in (("rev", "analyzer.py"), ("crypto", "analyzer.py"),
                       ("forensic", "orchestrator.py"))), True)

print("\n6. crashes still crash — those branches bypass the helper")
rev = (ROOT / "modules" / "rev" / "analyzer.py").read_text(encoding="utf-8")
check("failed is set directly, not via no_flag_status",
      'final_status = "failed"' in rev, True)
check("finished is set directly too", 'final_status = "finished"' in rev, True)

print("\n7. the loop leaves, and every agent can detect")
# Slice exactly the inserted block — the wider loop legitimately mentions
# both words, and a window that runs past the block tests the wrong text.
_start = src.find("while True:\n            # The hold is recorded")
_end = src.find("log_fn(f\"Main session turn", _start)
loop = src[_start:_end]
if args.mutate == "loop-ignores-hold":
    loop = loop.replace('== "hold"', '== "never"')
check("the orchestrator loop exits on hold", '== "hold"' in loop, True)
# Comments stripped first: the block's own comment says "not `stopped` and
# not `failed`", and asserting on prose rather than code is how a check
# passes while meaning nothing.
_code = "\n".join(l for l in loop.splitlines()
                  if not l.strip().startswith("#"))
check("...without setting stopped or failed",
      "stopped" not in _code and "failed" not in _code, True)
check("main registers the watchdog",
      "_target_hold_guard(job_id, work_dir)" in src, True)
check("subagents register it too — recon probes the remote as well",
      "_target_hold_guard(job_id)" in src, True)

print("\n8. every lifecycle status set has a DELIBERATE answer about hold")
# A new status is only half-added when one module knows it. `hold` was born
# in _manager and six other sets kept their own idea of "over" — which is how
# a held job ended up with a monitor watching a log that would never grow
# again. The point of this census is not that hold is everywhere: it is that
# each set's answer is written down, with the reason, so the next status does
# not have to be re-derived the same way.
import re

def _pyset(text, name):
    m = re.search(r"^" + re.escape(name) + r"[^=\n]*=\s*\{(.*?)\}", text,
                  re.S | re.M)
    return set(re.findall(r'"(\w+)"', m.group(1))) if m else None

_SRC = {
    "modules/_manager.py": (ROOT / "modules" / "_manager.py").read_text(encoding="utf-8"),
    "modules/_monitor.py": (ROOT / "modules" / "_monitor.py").read_text(encoding="utf-8"),
    "modules/_harvester.py": (ROOT / "modules" / "_harvester.py").read_text(encoding="utf-8"),
    "modules/_common.py": src,
    "api/routes/jobs.py": (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8"),
}
if args.mutate == "monitor-parks-on-hold":
    _SRC["modules/_monitor.py"] = _SRC["modules/_monitor.py"].replace(
        '"flag_ready",\n             "hold"}', '"flag_ready"}', 1)
if args.mutate == "steer-rejects-hold":
    _SRC["api/routes/jobs.py"] = _SRC["api/routes/jobs.py"].replace(
        '_STEER_TERMINAL = {"finished"', '_STEER_TERMINAL = {"hold", "finished"', 1)
if args.mutate == "hold-priced-as-terminal":
    _SRC["api/routes/jobs.py"] = _SRC["api/routes/jobs.py"].replace(
        '_USAGE_TERMINAL_STATUSES = {"finished"',
        '_USAGE_TERMINAL_STATUSES = {"hold", "finished"', 1)

# (file, constant, hold is a member, what that decision buys)
CENSUS = (
    ("modules/_manager.py", "_TERMINAL", True,
     "the manager stops assessing a run that is not moving"),
    ("modules/_monitor.py", "_TERMINAL", True,
     "a held run appends nothing, so the watcher must release its slot; "
     "the read offset is in the statefile, so resume is exact"),
    ("modules/_harvester.py", "_TERMINAL", True,
     "drain the candidates already seen instead of holding them hostage "
     "until the operator finds a new target"),
    ("modules/_common.py", "_TERMINAL_STATUSES", False,
     "a parked run has no finished_at — it has not finished"),
    ("api/routes/jobs.py", "_USAGE_TERMINAL_STATUSES", False,
     "that slot is the TERMINAL unpriced estimate; a held run's number is "
     "still provisional and will move when it resumes"),
    ("api/routes/jobs.py", "_STEER_TERMINAL", False,
     "the whole point of the hold is that the operator can still reach it"),
    ("api/routes/jobs.py", "_TERMINAL_META_STATUSES", False,
     "the SSE stream stays open so the resume shows up live"),
)
for _file, _name, _want, _why in CENSUS:
    _members = _pyset(_SRC[_file], _name)
    check(f"{_file}:{_name} {'includes' if _want else 'excludes'} hold "
          f"— {_why}",
          None if _members is None else ("hold" in _members), _want)

print("\n9. the operator can actually get a held job moving again")
appjs = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
css = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
if args.mutate == "ui-hides-hold-resume":
    appjs = appjs.replace('"stopped", "flag_ready", "hold",',
                          '"stopped", "flag_ready",', 1)
_retry = re.search(r"const showRetry = canRetry && \[(.*?)\]", appjs, re.S)
check("the resume buttons are offered on a held job — Continue carries the "
      "New target field, which IS the way out of a hold",
      bool(_retry) and "hold" in re.findall(r'"(\w+)"', _retry.group(1)), True)
_poll = re.search(r"const JOB_TERMINAL = \[(.*?)\]", appjs, re.S)
check("...but polling does NOT stop on hold, or the resume never renders",
      bool(_poll) and "hold" not in re.findall(r'"(\w+)"', _poll.group(1)), True)
check("the pill has its own colour instead of falling through to bare text",
      ".status.hold {" in css, True)
# The reason is the operator's INPUT, not decoration: it names the address
# that died, and picking the replacement is the whole loop. It was written to
# meta and passed through the API from the first commit, and rendered nowhere.
if args.mutate == "hold-reason-not-rendered":
    # NOT a suffix: `job.hold_reason_missing` still CONTAINS the anchor, so
    # the substring check below would pass against its own mutant.
    appjs = appjs.replace("job.hold_reason", "job.heldReason")
check("the reason is rendered, not just recorded",
      "job.hold_reason" in appjs, True)
_after_hold = appjs.split("job.hold_reason", 1)
check("...and it points at the control that actually resumes the run",
      "Continue" in (_after_hold[1][:700] if len(_after_hold) > 1 else ""), True)

# A dedicated way out. Change target writes meta and resumes nothing -- which
# is documented, correct, and still sent an operator to it, because on a held
# job it is the control that mentions the thing that broke. The resume is now
# its own button rather than the fifth field of the Continue dialog.
if args.mutate == "resume-button-always-visible":
    appjs = appjs.replace('(job.status === "hold" && canContinue)', "(canContinue)", 1)
if args.mutate == "resume-button-sends-stale-target":
    appjs = appjs.replace("body: JSON.stringify({ comment: note }),",
                          "body: JSON.stringify({ comment: note, target: where }),", 1)
check("a held job gets its own resume button",
      'data-action="resume-hold"' in appjs, True)
_rb = re.search(r"const resumeHoldHtml = \(([^)]*)\)", appjs)
check("...offered ONLY on hold, not on every continuable job",
      bool(_rb) and 'job.status === "hold"' in _rb.group(1), True)
check("...and only where continue-in-place is supported at all",
      bool(_rb) and "canContinue" in _rb.group(1), True)
check("...wired to a handler", "resumeHeldJob(id, resumeHoldBtn)" in appjs, True)
_fn = appjs.split("async function resumeHeldJob", 1)
_body = _fn[1][:1800] if len(_fn) > 1 else ""
check("...which posts the SAME tested continue route",
      "/continue`" in _body, True)
# Omitting `target` is the point: meta.target_url is authoritative and a panel
# open since before Change target would otherwise write the dead address back.
check("...and does NOT send a target, so a stale tab cannot overwrite a newer one",
      "target:" not in _body, True)
check("...carrying a note that tells the agent not to re-investigate",
      "do NOT re-investigate" in _body, True)
check("the banner names the button that resumes",
      "resume-hold" in appjs
      and "재개" in (appjs.split("job.hold_reason", 1)[1][:900] if "job.hold_reason" in appjs else ""), True)

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
