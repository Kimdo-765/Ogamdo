#!/usr/bin/env python3
"""The prompt main is given and the tools it is given must agree.

WHY THIS EXISTS

`modules/codex_cli.py` carries two addenda that contradict each other on
purpose, because two different deployments are possible:

    CODEX_TOOL_ADDENDUM          "`spawn_agent` is not registered in this
                                  deployment ... do NOT call `wait` at all ...
                                  delegate by writing `.scratch/delegate.json`"

    CODEX_NATIVE_ULTRA_ADDENDUM  "use `spawn_agent` with the registered role ...
                                  Do not use the fallback file-delegation
                                  protocol in this mode"

Exactly one of them is true of any given session, and which one is decided by
whether `--config features.multi_agent_v2=true` reaches the CLI. That is a
single fact. It was read in two places, with two different predicates:

    addendum choice, _instructions   enable_subagents and effort == "ultra"
    the flag itself, _command        enable_subagents and mav2_enabled()

The shipped configuration is `gpt_effort: ultra` with
`codex_multi_agent_v2: False` — and `data/settings.json` is untracked, so
nothing in the repository showed that those two predicates disagreed on it.
Main was handed a prompt telling it to call `spawn_agent`, and NOT to use the
file channel, in a session where `spawn_agent` was never registered.

WHAT IT COST

Job a4eec9fe5cd8 (2026-09-07), a 142.5-minute run that did solve its
challenge:

    wait calls                                59
    time in wait                     1,706 s = 28.4 min = 19.9% of the run
    non-empty rosters                          0   (118 payloads inspected)
    spawn_agent calls                          0
    stopped at exactly 30 s / 60 s      24 / 10   = 58% on timeout boundaries

Round numbers are the tool giving up, not a child answering. The recon and
judge turns that DID run in that job appear under their own `role` in
gpt-events.jsonl — which is what a real child looks like here, and confirms
the empty rosters were not concealing one.

WHY THIS SHAPE OF TEST

The defect was not in either site. Each was self-consistent and would pass any
test written against it alone. The defect was that they were checked
separately, so this suite asserts the built system prompt and the built
argv TOGETHER, for every combination that reaches them.

Run:
    python3 scripts/test_codex_addendum_agrees_with_flags.py
    python3 scripts/test_codex_addendum_agrees_with_flags.py --mutate prompt-ignores-setting
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SRC_PATH = ROOT / "modules" / "codex_cli.py"
SRC = SRC_PATH.read_text()

MUTATIONS = (
    # The original defect: the prompt decides on effort alone.
    "prompt-ignores-setting",
    # The mirror image: the flag goes out whatever the operator set.
    "command-ignores-setting",
    # The predicate stops reading the setting at all.
    "helper-always-true",
    # The predicate forgets bounded roles, so a recon child is told to spawn.
    "helper-ignores-enable-subagents",
    # An unreadable settings file must not silently disarm the advertisement
    # in one place while the other keeps it.
    "fallback-flips",
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

_S0 = SRC
if args.mutate == "prompt-ignores-setting":
    SRC = SRC.replace(
        "                    self._native_subagents_enabled()\n"
        '                    and _normalize_effort(self.options.effort) == "ultra"',
        "                    self.options.enable_subagents\n"
        '                    and _normalize_effort(self.options.effort) == "ultra"',
        1,
    )
elif args.mutate == "command-ignores-setting":
    SRC = SRC.replace(
        "        if self._native_subagents_enabled():\n"
        "            # GPT-5.6 Sol selects Codex multi-agent v2.",
        "        if self.options.enable_subagents:\n"
        "            # GPT-5.6 Sol selects Codex multi-agent v2.",
        1,
    )
elif args.mutate == "helper-always-true":
    SRC = SRC.replace(
        "            return codex_multi_agent_v2_enabled()", "            return True", 1)
elif args.mutate == "helper-ignores-enable-subagents":
    SRC = SRC.replace(
        "        if not self.options.enable_subagents:\n            return False\n", "", 1)
elif args.mutate == "fallback-flips":
    SRC = SRC.replace(
        "            return True          # unreadable policy keeps today's behaviour",
        "            return False", 1)
if args.mutate and SRC == _S0:
    raise SystemExit(f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor is stale.")

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# --- load the (possibly mutated) adapter as its own module -----------------
# Importing modules.codex_cli would load the real file and every mutation
# would report a false PASS.
import modules.codex_cli as _real                      # noqa: E402  (resolves deps)
import modules.settings_io as _settings_io             # noqa: E402

MOD = types.ModuleType("_codex_cli_under_test")
MOD.__dict__.update({"__name__": "_codex_cli_under_test", "__file__": str(SRC_PATH)})
exec(compile(SRC, str(SRC_PATH), "exec"), MOD.__dict__)

from modules.gpt_responses import GptSessionOptions   # noqa: E402


class _Policy:
    """Swap `codex_multi_agent_v2_enabled` for the duration of one case.

    The adapter imports it INSIDE the helper, so patching the settings module
    is what the real code path actually reads — patching a name on the adapter
    would test a binding that does not exist.
    """

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self._orig = _settings_io.codex_multi_agent_v2_enabled
        if self.value == "raises":
            def _f():
                raise RuntimeError("settings.json unreadable")
        else:
            def _f():
                return self.value
        _settings_io.codex_multi_agent_v2_enabled = _f
        return self

    def __exit__(self, *exc):
        _settings_io.codex_multi_agent_v2_enabled = self._orig


def build(*, mav2, effort, enable_subagents=True, enable_tools=True):
    """Return (system_prompt, argv) as one session would really receive them."""
    tmp = tempfile.mkdtemp()
    opts = GptSessionOptions(
        system_prompt="MISSION. Delegate with mcp__team__spawn_subagent(subagent_type ∈ …).",
        model="gpt-daybreak-blue-latest",
        cwd=tmp,
        effort=effort,
        enable_subagents=enable_subagents,
        enable_tools=enable_tools,
    )
    client = MOD.CodexCLIClient(opts)
    client._codex_bin = "/usr/local/bin/codex"      # _command asserts on this
    with _Policy(mav2):
        system = client._instructions("solve it", resuming=False)
        argv = client._command(resuming=False)
    return system, argv


def reads(system, argv):
    """The two halves of the single fact, named the same way."""
    return {
        "prompt_advertises_v2_roles": "NATIVE ULTRA MODE" in system,
        "prompt_teaches_spawn": "spawn_agent(task_name" in system,
        "prompt_warns_empty_roster": "EMPTY ROSTER" in system,
        "prompt_keeps_file_fallback": ".scratch/delegate.json" in system,
        "cli_registers_v2": "features.multi_agent_v2=true" in argv,
    }


def main() -> int:
    print("\nA — the prompt and the argv agree, in every combination")
    # This is the whole point of the suite: not that either value is right,
    # but that they are never allowed to differ.
    combos = [
        (True, "ultra", True), (False, "ultra", True),
        (True, "high", True), (False, "high", True),
        (True, "ultra", False), (False, "ultra", False),
        (True, "medium", True), (False, "low", True),
    ]
    for mav2, effort, subs in combos:
        s, a = build(mav2=mav2, effort=effort, enable_subagents=subs)
        r = reads(s, " ".join(a))
        label = f"A mav2={mav2} effort={effort} subagents={subs}"
        # A prompt may decline to advertise a registered tool (non-ultra does
        # exactly that). What it must NEVER do is advertise an absent one.
        check(f"{label}: never advertises v2 roles the CLI did not register",
              r["prompt_advertises_v2_roles"] and not r["cli_registers_v2"], False)
        # Every configuration must leave main a delegation route it can
        # actually take. Being told to use neither is what the pre-bd33eb9
        # contradiction amounted to.
        check(f"{label}: some working delegation route is taught",
              r["prompt_teaches_spawn"] or r["prompt_advertises_v2_roles"]
              or r["prompt_keeps_file_fallback"])

    print("\nS — the shipped configuration, which is where this broke")
    # gpt_effort: ultra + codex_multi_agent_v2: False.
    #
    # What is taught here changed on 2026-09-07 and the reason matters. This
    # path used to say "`spawn_agent` DOES NOT WORK HERE" and route everything
    # through the file channel. Measured in a live worker with the production
    # argv, spawn_agent works: a child wrote a file the parent was forbidden to
    # write, 3/3, and a two-child run came back with both replies while the
    # parent kept working. docs/spawn-agent-works-2026-09-07.md.
    s, a = build(mav2=False, effort="ultra")
    check("S1 native spawn is taught, with its real signature",
          "spawn_agent(task_name" in s)
    check("S2 ...with the empty-roster inoculation, which is the actual trap",
          "EMPTY ROSTER" in s and "Do NOT call `wait` in a loop" in s)
    check("S3 ...and the file channel survives as a fallback",
          ".scratch/delegate.json" in s and "delegate.ring" in s)
    # find(), not index(): a mutation that removes either string should report
    # a clean FAIL here, not raise and hide every check after it.
    _sp, _fb = s.find("spawn_agent(task_name"), s.find(".scratch/delegate.json")
    check("S4 ...ordered native-first, since the fallback costs a turn boundary",
          _sp >= 0 and _fb >= 0 and _sp < _fb)
    check("S5 the v2 role addendum is NOT sent", "NATIVE ULTRA MODE" in s, False)
    check("S6 ...and the CLI correspondingly does not register v2",
          "features.multi_agent_v2=true" in " ".join(a), False)
    # The claim that started it all must not come back.
    check("S7 the falsified claim is gone", "not registered in this deployment" in s, False)

    print("\nN — the native configuration is still reachable")
    # Turning the operator setting back on must restore native mode intact,
    # or this fix would be a one-way door.
    s, a = build(mav2=True, effort="ultra")
    check("N1 native mode is advertised", "NATIVE ULTRA MODE" in s)
    check("N2 ...the CLI registers it", "features.multi_agent_v2=true" in " ".join(a))
    check("N3 ...and v2 mode still forbids the file protocol, which would "
          "end the turn for nothing",
          "Do not use the fallback file-delegation protocol" in s)

    print("\nB — bounded roles are unchanged")
    # recon/debugger/triage/judge run with enable_subagents=False. They got
    # CODEX_TOOL_ADDENDUM before this fix and must still get it, plus the line
    # that tells them not to delegate onward.
    s, a = build(mav2=True, effort="ultra", enable_subagents=False)
    check("B1 a bounded role never gets native mode", "NATIVE ULTRA MODE" in s, False)
    check("B2 ...and is still told not to delegate onward",
          "Do not delegate this bounded role to subagents." in s)
    check("B3 ...and gets no multi-agent flags",
          "features.multi_agent_v2=true" in " ".join(a), False)

    print("\nU — an unreadable policy file fails the same way in both halves")
    # The failure mode that made this hard to see was one fact read twice.
    # If the setting cannot be read, both halves must still land together.
    s, a = build(mav2="raises", effort="ultra")
    r = reads(s, " ".join(a))
    check("U1 prompt and argv still agree when the setting raises",
          r["prompt_advertises_v2_roles"], r["cli_registers_v2"])
    check("U2 ...and the historical default is to advertise",
          r["cli_registers_v2"])

    print("\nO — one predicate, not two")
    # A future edit that re-derives the answer at either site reopens the bug,
    # so pin that both sites call the same helper.
    body = SRC
    check("O1 the addendum choice calls the shared predicate",
          "self._native_subagents_enabled()\n"
          '                    and _normalize_effort(self.options.effort) == "ultra"' in body)
    check("O2 the flag block calls the shared predicate",
          "if self._native_subagents_enabled():" in body)
    check("O3 ...and the setting is read in exactly one place",
          body.count("codex_multi_agent_v2_enabled()"), 1)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
