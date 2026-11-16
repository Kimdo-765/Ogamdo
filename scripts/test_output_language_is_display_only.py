#!/usr/bin/env python3
"""The output-language setting steers the MONITOR FEED and nothing else.

WHAT CHANGED, AND WHY

Until 2026-09-20 this setting reached every solving prompt: main, recon,
subagents, judge, reviewer, report, the Codex resumed turn, the GPT children,
and an `AGENT_OUTPUT_LANGUAGE` variable in the agent's own process env. The
suite this file replaces existed to prove that reach.

The operator's call, and it is the right one: the agents solve best in
English. Pointing their working language somewhere else spends accuracy on
output nobody reads as prose — `report.md`, `findings.json`, the exploit and
the flag are technical artefacts either way. What the operator DOES read
while a job runs is the monitor's commentary, so that is the one place the
setting now applies.

WHAT THIS SUITE PROTECTS

  * NO SOLVING PROMPT CARRIES IT. Each removed wire is asserted absent by
    name. Re-adding one silently is the regression this exists to catch.
  * THE SETTING IS NOT DEAD. A setting that steers nothing is worse than no
    setting — it is a promise the UI keeps making. It must reach the monitor.
  * THE UI MUST SAY WHAT IT NOW DOES. The Settings copy described the old
    reach in detail; prose promising what the code does not do is the defect
    this repo keeps finding.

Run from the repository root::

    python3 scripts/test_output_language_is_display_only.py
    python3 scripts/test_output_language_is_display_only.py --mutate main-carries-language
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("main-carries-language", "judge-carries-language",
             "env-var-returns", "monitor-loses-it", "ui-still-claims-reach")
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


SRC = {n: (ROOT / p).read_text(encoding="utf-8") for n, p in {
    "common": "modules/_common.py",
    "judge": "modules/_judge.py",
    "reviewer": "modules/reviewer.py",
    "codex": "modules/codex_cli.py",
    "responses": "modules/gpt_responses.py",
    "live_fire": "modules/live_fire_agent.py",
    "misc": "modules/misc/orchestrator.py",
    "forensic": "modules/forensic/orchestrator.py",
    "monitor": "modules/_monitor.py",
    "index": "web-ui/index.html",
}.items()}

if args.mutate == "main-carries-language":
    SRC["common"] = SRC["common"].replace(
        "    system_prompt = sanitize_for_argv(",
        "    system_prompt = with_output_language(system_prompt, job_id)\n"
        "    system_prompt = sanitize_for_argv(", 1)
elif args.mutate == "judge-carries-language":
    SRC["judge"] = SRC["judge"].replace(
        "    job_id = Path(cwd).name",
        "    job_id = Path(cwd).name\n"
        "    user_prompt = instruction_for_job(job_id) + user_prompt", 1)
elif args.mutate == "env-var-returns":
    SRC["common"] = SRC["common"].replace(
        '    env: dict[str, str] = {"JOB_ID": str(job_id)}',
        '    env: dict[str, str] = {"JOB_ID": str(job_id)}\n'
        '    env["AGENT_OUTPUT_LANGUAGE"] = "ko"', 1)
elif args.mutate == "monitor-loses-it":
    # ALL occurrences: the name appears on the import line and at the call,
    # and replacing one left the other for the check to find.
    SRC["monitor"] = SRC["monitor"].replace("resolve_output_language", "_gone")
elif args.mutate == "ui-still-claims-reach":
    SRC["index"] = SRC["index"].replace("Monitor feed language",
                                        "Default output language", 1)

print("1. no solving prompt carries a language policy")
# By name, one per wire that used to exist. A general grep would go green the
# day someone adds a differently-spelled one.
WIRES = [
    ("common", "with_output_language(", "main / recon / subagents / report"),
    ("judge", "instruction_for_job(job_id)", "judge"),
    ("reviewer", "instruction_for_job(job_id)", "reviewer (both modes)"),
    ("codex", "output_language_instruction(", "Codex resumed turn + child configs"),
    ("responses", "output_language_instruction(", "GPT Responses children"),
    ("live_fire", "with_output_language(", "live-fire agent"),
    ("misc", "with_output_language(", "misc orchestrator"),
    ("forensic", "with_output_language(", "forensic orchestrator"),
]
# Comments are stripped first: misc/forensic keep a paragraph of measured
# history that NAMES the old call, and a substring search would read that
# record as the wire still being there.
def _code(s: str) -> str:
    return "\n".join(l for l in s.splitlines() if not l.strip().startswith("#"))

for key, needle, who in WIRES:
    check(f"{who} carries none", needle in _code(SRC[key]), False)
check("nothing injects AGENT_OUTPUT_LANGUAGE into the agent env",
      'env["AGENT_OUTPUT_LANGUAGE"]' in SRC["common"], False)

print("\n2. the setting is not dead — it steers the feed the operator reads")
M = SRC["monitor"]
check("the monitor resolves it", "resolve_output_language" in M)
check("...per call, so the toggle takes effect without a restart",
      "def _monitor_langs(" in M and M.count("langs = MONITOR_LANGS") == 0)
check("...for the narration", "langs = _monitor_langs()" in M)
check("...for the raw-fallback entry too",
      "text = {l: snippet for l in _monitor_langs()}" in M)
check("...and for the findings it extracts", "The vuln object" in M)
check("a path or endpoint is never translated", "stays verbatim" in M)

print("\n3. the UI says what it now does")
IDX = SRC["index"]
check("the control is named for the feed", "Monitor feed language" in IDX)
check("...and no longer claims it reaches the solving roles",
      "applied consistently to Main" in IDX, False)
# Flattened: the sentence wraps, and matching the raw literal would pin the
# line break rather than the meaning.
check("...and says why, so the next reader does not re-add it",
      "solve best in English" in re.sub(r"\s+", " ", IDX))

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
