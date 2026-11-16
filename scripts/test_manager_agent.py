#!/usr/bin/env python3
"""The number on a job tile has to be worth acting on.

WHY THIS EXISTS

With several jobs running, the dashboard could say what each one WAS doing and
never what it was WORTH. This session produced both failure shapes: job
340e62bdcd32 spent its last two hours measuring replica latency, and job
44591f39ef9f spent 2.5 hours analysing an instance that died in its first
ninety seconds. Neither was distinguishable from progress by looking at the row.

WHAT THIS SUITE PROTECTS

  * The DENOMINATOR. `steps_done/steps_total` is derived from a fixed ladder,
    never taken from the model. A bar whose denominator moves between
    assessments shows progress that did not happen -- 3/11 then 4/9 reads as
    advancement and is not.
  * The DIRECTION OF FAILURE. An unparseable or out-of-range probability
    resolves LOW. The first draft clamped, which turned a model that returned
    999 into "100%, high confidence" -- the one direction this number must
    never fail in, because it is the direction an operator acts on.
  * COUNTS over the whole log, not the tail the model reads. The first draft
    counted `auto-run turn` inside the 40-line window and reported 1 for a job
    that had run seventeen.
  * The NOISE filter staying positional. `TOOL_RESULT` bodies quote judge
    verdicts and agent prose back, and a content-matching filter pulls the echo
    in with the signal. That has bitten this repo before.

Run from the repository root::

    python3 scripts/test_manager_agent.py
    python3 scripts/test_manager_agent.py --mutate clamp-instead-of-reject
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", str(ROOT / "data"))

MUTATIONS = (
    "clamp-instead-of-reject",
    "model-supplies-denominator",
    "count-from-window",
    "noise-filter-by-content",
    "captured-flag-not-pinned",
    "reassess-every-tick",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


from modules import _manager as M  # noqa: E402

_real_normalize = M._normalize
if args.mutate == "clamp-instead-of-reject":
    def _clamping(raw, signals):
        rec = _real_normalize(raw, signals)
        try:
            rec["flag_probability"] = max(0, min(100, int(raw.get("flag_probability", 0))))
        except Exception:
            rec["flag_probability"] = 0
        return rec
    M._normalize = _clamping
if args.mutate == "model-supplies-denominator":
    def _model_steps(raw, signals):
        rec = _real_normalize(raw, signals)
        rec["steps_total"] = int(raw.get("steps_total", 7) or 7)
        rec["steps_done"] = int(raw.get("steps_done", 1) or 1)
        return rec
    M._normalize = _model_steps
if args.mutate == "captured-flag-not-pinned":
    def _unpinned(raw, signals):
        return _real_normalize(raw, {**signals, "flags": 0})
    M._normalize = _unpinned

# ---------------------------------------------------------------------------
# 1. The ladder.
# ---------------------------------------------------------------------------
check("the ladder has a fixed length", len(M.STAGES), 7)
check("...it starts at recon", M.STAGES[0], "recon")
check("...and ends at the flag", M.STAGES[-1], "flag-captured")
check("...verification comes after an exploit exists",
      M.STAGES.index("exploit-drafted") < M.STAGES.index("remote-verified"), True)
check("...and local before remote",
      M.STAGES.index("local-verified") < M.STAGES.index("remote-verified"), True)

# ---------------------------------------------------------------------------
# 2. Normalisation: where the numbers come from, and which way they fail.
# ---------------------------------------------------------------------------
base = {"flags": 0}
r = M._normalize({"stage": "exploit-drafted", "flag_probability": 37}, base)
check("a stage maps to its position on the ladder", (r["steps_done"], r["steps_total"]), (4, 7))
check("...and a valid probability survives", r["flag_probability"], 37)

# The denominator must not move, whatever the model says.
r2 = M._normalize(
    {"stage": "recon", "flag_probability": 50, "steps_total": 11, "steps_done": 9}, base)
check("the model cannot supply the denominator", r2["steps_total"], 7)
check("...nor the numerator", r2["steps_done"], 1)

for bad, label in ((999, "999"), (-5, "-5"), ("abc", "a string"), (None, "null")):
    rb = M._normalize({"stage": "recon", "flag_probability": bad}, base)
    check(f"an out-of-range probability ({label}) resolves LOW, not high",
          rb["flag_probability"], 0)

check("an unknown stage falls to the first rung, not the last",
      M._normalize({"stage": "nonsense", "flag_probability": 10}, base)["stage"], "recon")

# A captured flag is a fact, not an estimate.
rf = M._normalize({"stage": "recon", "flag_probability": 5}, {"flags": 1})
check("a captured flag pins the stage", rf["stage"], "flag-captured")
check("...and the probability", rf["flag_probability"], 100)

check("confidence is constrained to the three it may return",
      M._normalize({"stage": "recon", "confidence": "certain"}, base)["confidence"], "low")

# ---------------------------------------------------------------------------
# 3. Signals: counted over the whole log, filtered positionally.
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="mgr-test-"))
jobs = tmp / "jobs" / "aa00bb11cc22"
(jobs / "work").mkdir(parents=True)
(jobs / "meta.json").write_text(json.dumps({"module": "web", "status": "running"}))

# Twelve turns, then enough padding to push the early ones out of the window
# the model reads. The count must still be twelve.
lines = []
for i in range(12):
    lines.append(f"[00:0{i%10}:00] [orchestrator] auto-run turn {i}: executing exploit.py")
    lines.append(f"[00:0{i%10}:01] [judge] postjudge verdict=partial next_action=stop")
for i in range(80):
    lines.append(f"[01:00:{i%60:02d}] [main] AGENT: thinking {i}")
# The echo trap: a TOOL_RESULT body quoting a verdict back.
lines.append('[01:30:00] [main] TOOL_RESULT: [orchestrator] auto-run turn 99: executing x')
lines.append('[01:30:01] [main] TOOL_RESULT: [judge] postjudge verdict=success next_action=stop')
(jobs / "run.log").write_text("\n".join(lines), encoding="utf-8")

os.environ["DATA_DIR"] = str(tmp)
if args.mutate == "count-from-window":
    # Truncate the REAL reader rather than aliasing it to _signal_lines, which
    # calls _all_signal_lines itself -- the first draft did that and recursed
    # until the interpreter gave up, which reads as "caught" on an exit code
    # and is not a check failing.
    _real_all = M._all_signal_lines
    M._all_signal_lines = lambda jid: _real_all(jid)[-M._SIGNAL_LINES:]
if args.mutate == "noise-filter-by-content":
    M._NOISE_RE = __import__("re").compile(r"nothing-matches-this")

sig = M.collect_signals("aa00bb11cc22")
check("turns are counted over the WHOLE log, not the window",
      sig["auto_run_turns"], 12)
check("...and the model is shown only the tail",
      len(sig["signal_lines"]) <= M._SIGNAL_LINES, True)
check("a TOOL_RESULT echoing a turn line does not inflate the count",
      sig["auto_run_turns"], 12)
check("...nor does one echoing a verdict change the last verdict",
      sig["last_verdict"], "partial")
check("structured state is read, not inferred", sig["module"], "web")

# ---------------------------------------------------------------------------
# 4. Cost discipline and wiring.
# ---------------------------------------------------------------------------
mgr_src = Path(M.__file__).read_text(encoding="utf-8")
if args.mutate == "reassess-every-tick":
    mgr_src = mgr_src.replace("if n != last_len:", "if True:", 1)
check("a job is re-assessed only when its log GREW",
      "if n != last_len:" in mgr_src, True)
check("...and assessed once more after it ends, so no row freezes mid-run",
      mgr_src.count("await assess(job_id)") >= 2, True)
check("the interval has a floor", "max(30," in mgr_src, True)

from modules.agent_provider import ROLE_OVERRIDABLE  # noqa: E402
from modules.model_presets import CONFIGURABLE_ROLES  # noqa: E402
from modules.settings_io import SCHEMA  # noqa: E402

check("manager is a routable role", "manager" in ROLE_OVERRIDABLE, True)
check("...and a preset-configurable one", "manager" in CONFIGURABLE_ROLES, True)
_keys = {k for k, *_ in SCHEMA}
check("...with its own on/off switch", "manager_agent" in _keys, True)
check("...and its own interval", "manager_interval_s" in _keys, True)
check("it defaults OFF — it spends tokens on every running job",
      [d for k, _, _, d in SCHEMA if k == "manager_agent"], [False])

app_js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
# The row re-renders every few seconds; anything volatile inside the signature
# rewrites the whole row and every node in it.
check("the tile's volatile numbers are updated OUTSIDE the row signature",
      "const mgrEl = li.querySelector" in app_js
      and app_js.index("_ROW_SIG.set(li, _rowHtml)") < app_js.index("const mgrEl = li.querySelector"),
      True)
check("the bar shows pipeline position, not the probability again",
      "m.steps_done" in app_js and "(done / Math.max(1, total))" in app_js, True)
css = (ROOT / "web-ui" / "style.css").read_text(encoding="utf-8")
check("the job list is a grid", "grid-template-columns" in css.split("#jobs-list")[1][:400], True)

import shutil  # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
