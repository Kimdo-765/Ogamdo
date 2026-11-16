#!/usr/bin/env python3
"""Prejudge's depth is capped. Postjudge's is not, and recon's is capped
only for prejudge.

WHY THIS EXISTS — ONE MEASUREMENT, TWO LEVERS (2026-09-15)

Job 6beae26b0ec2 (pwn) spent 9m39s in `auto-run turn 0`. Three seconds of that
was the remote exploit. The rest was the judge:

    prejudge   8m51s      <- Claude, serial, BEFORE the sandbox starts
    runner        3s      <- the thing everyone assumed was slow
    postjudge    45s

The same shape held across four jobs (95.1% / 99.5% / 98.2% judge share), and
`runner` container create->destroy measured 1-2s, so the 9.84GB image was
never the story either.

Two facts made prejudge the one stage worth capping:

  1. `prejudge_ship_gate` is OFF while `judge_mode` is `enforce`. Prejudge
     runs, logs every issue it finds, and CANNOT stop the run — `_runner.py`
     Stage 2 reads `target` and the meta timeout and nothing else. The full
     latency of a gate that does not gate.
  2. Raising the effort bought issue COUNT, not a different decision. On
     claude-opus-5[1m], max -> high cut prejudge 15m29s -> 8m51s (pwn) and
     4m56s -> 1m37s (rev), and all four verdicts were the same
     `ok=True severity=low`.

The second change here is a correctness fix, not a measured win. `_recon_def`
passed no `effort` at all, and `build_judge_agents` resolved recon's model
against Settings' `agent_provider` rather than the judge session's — so a
Claude judge on a gpt job would have been handed a recon pinned to a gpt
model. Both are fixed and both are DORMANT: the judge has not been observed
invoking recon in any job inspected, whose transcripts carry `Bash` calls and
no `Agent`/`Task` call.

An earlier version of this file read a BARE `claude-opus-5` usage row as that
recon subagent and built a story on it — that prejudge delegates where
postjudge does not, and that this was the twelve-fold cost gap. It is not a
second agent: `record_usage_by_model` emits the SDK's `model_usage` map
verbatim. Prejudge costs more because it BUILDS the session and investigates
the script; postjudge resumes it and judges the output. The timing table
above is unaffected — it was measured, not inferred.

The floor is medium, not lower, and that is a measurement too. Before any
effort was passed, prejudge returned `ok=False` or `severity=high` on 17 of 53
verdicts. That is free noise while the ship gate is off and a third of all
runs aborted before executing the moment an operator turns it on.

Run from the repository root::

    python3 scripts/test_prejudge_effort_ceiling.py
    python3 scripts/test_prejudge_effort_ceiling.py --mutate cap-becomes-floor
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "cap-becomes-floor",
    "cap-every-stage",
    "recon-never-capped",
    "recon-on-every-stage",
    "unknown-effort-passes-through",
    "ceiling-is-max",
    "recon-ignores-provider",
    "recon-drops-effort",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

SRC_PATH = ROOT / "modules" / "_judge.py"


def _replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"mutation anchor count={count}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _region(source: str) -> str:
    """The shipped helper block, lifted out of the real module.

    Sliced rather than copied so the suite can never drift from the code it
    claims to test: if the block moves or is renamed, this raises instead of
    silently testing a stale duplicate.
    """
    start = source.index("_PREJUDGE_EFFORT_CEILING = ")
    end = source.index("def _attempt(")
    return source[start:end]


# Mutations that target `modules/_common.py` instead of this region. They are
# applied after import, by rebinding `build_judge_agents` -- so the region
# passes through untouched. Without this branch `_mutated` raised on them and
# the suite died BEFORE running a single check, which an exit code alone
# reports as "the mutation was caught". It was not; nothing had run.
_COMMON_MUTATIONS = frozenset({"recon-ignores-provider", "recon-drops-effort"})


def _mutated(region: str) -> str:
    m = args.mutate
    if m is None or m in _COMMON_MUTATIONS:
        return region
    if m == "cap-becomes-floor":
        # The comparison inverts: a preset BELOW the ceiling gets raised to it.
        return _replace_once(region, "<= _EFFORT_LADDER.index", ">= _EFFORT_LADDER.index")
    if m == "cap-every-stage":
        # The stage guard goes away, so postjudge is capped too.
        return _replace_once(region, '    if stage != "prejudge":\n        return base\n', "")
    if m == "recon-never-capped":
        return _replace_once(
            region,
            '    if stage != "prejudge":\n        return None\n    eff = _effort_for_stage(stage)',
            '    if stage != "prejudge":\n        return None\n    eff = None',
        )
    if m == "recon-on-every-stage":
        return _replace_once(
            region,
            '    if stage != "prejudge":\n        return None\n    eff = _effort_for_stage(stage)',
            "    eff = _effort_for_stage(stage)",
        )
    if m == "unknown-effort-passes-through":
        # An effort outside the ladder is handed through instead of capped.
        return _replace_once(region, "    except ValueError:\n        pass\n",
                             "    except ValueError:\n        return base\n")
    if m == "ceiling-is-max":
        return _replace_once(region, '_PREJUDGE_EFFORT_CEILING = "medium"',
                             '_PREJUDGE_EFFORT_CEILING = "max"')
    raise AssertionError(m)


SOURCE = SRC_PATH.read_text(encoding="utf-8")
REGION = _mutated(_region(SOURCE))

import modules.agent_provider as AP  # noqa: E402

_PRESET = {"value": "high"}
AP.role_effort_for = lambda provider=None: _PRESET["value"]

NS: dict = {}
exec(compile(REGION, str(SRC_PATH), "exec"), NS)
effort_for_stage = NS["_effort_for_stage"]
recon_effort_for_stage = NS["_recon_effort_for_stage"]

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


def at(preset, fn, *a):
    _PRESET["value"] = preset
    return fn(*a)


# ---------------------------------------------------------------------------
# 1. Prejudge is capped, and capped is not the same as pinned.
# ---------------------------------------------------------------------------
for deep in ("high", "xhigh", "max", "ultra"):
    check(f"prejudge caps a {deep} preset to medium",
          at(deep, effort_for_stage, "prejudge"), "medium")

for shallow in ("none", "minimal", "low"):
    check(f"prejudge leaves a {shallow} preset ALONE — a ceiling, not a floor",
          at(shallow, effort_for_stage, "prejudge"), shallow)

check("a preset already AT the ceiling is untouched",
      at("medium", effort_for_stage, "prejudge"), "medium")

# ---------------------------------------------------------------------------
# 2. Every other stage keeps the preset. Postjudge decides success vs retry
#    and costs 10-45s; capping it would buy nothing and cost the decision.
# ---------------------------------------------------------------------------
for stage in ("postjudge", "supervise", None):
    check(f"{stage or 'an unnamed stage'} keeps the preset unchanged",
          at("max", effort_for_stage, stage), "max")
check("postjudge is not raised either — the preset is the preset",
      at("low", effort_for_stage, "postjudge"), "low")

# ---------------------------------------------------------------------------
# 3. An effort nobody recognises is capped, not passed through. The preset
#    vocabulary feeds a CLI too, so it is WIDER than what a judge turn can
#    take; the safe direction for an unknown is down.
# ---------------------------------------------------------------------------
check("an unrecognised preset is capped, not trusted",
      at("turbo", effort_for_stage, "prejudge"), "medium")
check("...and an empty preset falls to the ceiling",
      at("", effort_for_stage, "prejudge"), "medium")
check("...and None does too", at(None, effort_for_stage, "prejudge"), "medium")

# ---------------------------------------------------------------------------
# 4. Recon. ONLY prejudge's is capped — that subagent is the whole reason
#    prejudge cost 12x postjudge on the same script.
# ---------------------------------------------------------------------------
check("prejudge's recon gets the capped effort",
      at("max", recon_effort_for_stage, "prejudge"), "medium")
for stage in ("postjudge", "supervise", None):
    check(f"{stage or 'an unnamed stage'}'s recon stays unset",
          at("max", recon_effort_for_stage, stage), None)
check("a shallow preset reaches recon unchanged",
      at("low", recon_effort_for_stage, "prejudge"), "low")

# `AgentDefinition.effort` takes a narrower vocabulary than the preset does.
# Handing it one it rejects would fail the whole turn, so it is dropped.
check("an effort AgentDefinition would reject is dropped, not forwarded",
      at("minimal", recon_effort_for_stage, "prejudge"), None)
check("...and 'none' likewise", at("none", recon_effort_for_stage, "prejudge"), None)

# ---------------------------------------------------------------------------
# 5. The facts the comments assert are the facts the code encodes.
# ---------------------------------------------------------------------------
check("the ceiling is medium", NS["_PREJUDGE_EFFORT_CEILING"], "medium")
check("the ladder runs shallow -> deep",
      NS["_EFFORT_LADDER"].index("low") < NS["_EFFORT_LADDER"].index("max"), True)
check("every AgentDefinition effort is on the ladder",
      set(NS["_AGENT_DEF_EFFORTS"]) <= set(NS["_EFFORT_LADDER"]), True)

# The wiring, read from the shipped source: the helper has to be what the
# options block actually calls, or this whole suite tests a function nothing
# uses. Both were inline expressions once.
_flat = " ".join(SOURCE.split())
check("the Claude options block uses the stage effort",
      "effort=_eff," in _flat and "_eff = _effort_for_stage(stage)" in _flat, True)
check("...and build_judge_agents is handed the recon effort",
      "effort=_recon_effort_for_stage(stage)" in _flat, True)
check("...and the stage actually reaches the turn",
      _flat.count("stage=stage") >= 3, True)

# ---------------------------------------------------------------------------
# 6. Recon follows the JUDGE SESSION's provider, not the job's.
#
#    `build_judge_agents` used to call `resolve_role_model` with no provider,
#    so it resolved against Settings' `agent_provider`. On a gpt job that
#    handed the CLAUDE judge a recon pinned to a gpt model — one that session
#    cannot run.
#
#    Guarded here rather than demonstrated in a job, because the judge has not
#    been observed invoking recon at all. That keeps the definition correct
#    for the day it does, and keeps this suite honest about which of its
#    claims are measured and which are defensive.
#
#    Asserted by FAMILY, not by exact string: the preset store differs between
#    this host and a worker, and a test that pinned the string would pass in
#    one and fail in the other while testing nothing either time.
# ---------------------------------------------------------------------------
import types  # noqa: E402

if "claude_agent_sdk" not in sys.modules:
    _sdk = types.ModuleType("claude_agent_sdk")

    class _AgentDefinition:
        def __init__(self, **kw):
            for _k, _v in kw.items():
                setattr(self, _k, _v)

    _sdk.AgentDefinition = _AgentDefinition
    sys.modules["claude_agent_sdk"] = _sdk

import modules._common as C  # noqa: E402

if args.mutate == "recon-ignores-provider":
    _real = C.build_judge_agents
    C.build_judge_agents = (
        lambda *a, **k: _real(*a, **{x: y for x, y in k.items() if x != "provider"}))
if args.mutate == "recon-drops-effort":
    _real_e = C.build_judge_agents
    C.build_judge_agents = (
        lambda *a, **k: _real_e(*a, **{x: y for x, y in k.items() if x != "effort"}))

JUDGE_MODEL = "claude-opus-5[1m]"


def _family(m: str | None) -> str:
    m = (m or "").lower()
    for fam in ("claude", "gpt", "grok"):
        if m.startswith(fam):
            return fam
    return f"?({m})"


def recon(provider, effort="medium"):
    return C.build_judge_agents(
        JUDGE_MODEL, job_id="t", effort=effort, provider=provider)["recon"]


for prov in ("claude", "gpt", "grok"):
    check(f"a {prov} judge gets a {prov} recon", _family(recon(prov).model), prov)

check("the judge's OWN model reaches recon, so the cache prefixes line up",
      recon("claude").model, JUDGE_MODEL)
check("the capped effort rides along with it", recon("claude").effort, "medium")
check("...and an unset effort stays unset", recon("claude", None).effort, None)
check("recon stays read-only — it never gets a hand on the exploit",
      sorted(recon("claude").tools), ["Bash", "Glob", "Grep", "Read"])

check("the judge hands build_judge_agents ITS provider, not the job's",
      "provider=provider" in _flat, True)
check("...and build_judge_agents forwards it to the resolver",
      'resolve_role_model( "recon", model or LATEST_JUDGE_MODEL, provider)'
      in " ".join(C.__loader__.get_source("modules._common").split()), True)

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
