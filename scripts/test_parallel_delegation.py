#!/usr/bin/env python3
"""A round of subagents may run at once — but only where that is possible.

WHAT WAS MEASURED

Job 24225668a27d spent 491 of 950 seconds — 52% of its wall-clock — with main
blocked in `wait` on ONE child at a time. Job 7b8bd665f130 repeated it. The
operator watched the count and said so:

    "sub agent 생성했을때 main은 대기하고 sub agent도 하나씩밖에 생성을 안하네"

Nothing in the runtime forced that. There is no lock, no semaphore and no
queue in the spawn path (the only threading.Lock in modules/_common.py guards
Grok auth), `features.multi_agent_v2` is enabled with per-role config files,
and one job showed two children genuinely in flight (a 1.5s `wait` — a child
already finished — immediately followed by an 81.6s one). What forced it was
the PROMPT: section 8 counted the budget in SPAWNS and narrated them strictly
in sequence ("spawn #3 returns: your NEXT action MUST be…"), with a ceiling of
3 and no sentence anywhere permitting concurrency. Three parallel questions
exhausted the budget instantly.

The budget itself is prose, not machinery: the orchestrator's real gate is
SOFT_EJECT on tool_calls (default 150). So this is a prose→prose change.

WHY THE TWO HALVES LIVE IN DIFFERENT FILES

  * The ROUND reframe is provider-neutral and belongs in the shared prompt.
  * The CONCURRENCY instruction is Codex-only and must NOT reach the shared
    prompt. Claude's MCP `mcp__team__spawn_subagent` runs the subagent to
    completion INSIDE the tool call — synchronous by construction — so
    telling a Claude-routed main to "launch several at once" asks for
    something it cannot do.

THE CONSTRAINT THAT COMES WITH IT

Each spawn is handed ./.scratch/subagent_log.md AT LAUNCH, so children started
together cannot see each other's findings. Parallel fan-out on the SAME
question re-derives it twice — the waste that log exists to prevent (job
89d442ef3291: recon#3 and recon#4 both re-derived the libc symbol VMA→file
mapping). The instruction must scope itself to independent questions and say
why, or it trades 52% idle for duplicated work.

Run from the repository root::

    python3 scripts/test_parallel_delegation.py
    python3 scripts/test_parallel_delegation.py --mutate budget-counts-spawns
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "modules" / "_prompts.py"
CODEX = ROOT / "modules" / "codex_cli.py"

MUTATIONS = ("budget-counts-spawns",              "concurrency-leaks-into-shared", "drops-independence-rule",
             "drops-vm-probe-rule", "status-as-result",
             "empty-wait-unreported", "feature-flag-as-table")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

P = PROMPTS.read_text()
C = CODEX.read_text()

if args.mutate == "budget-counts-spawns":
    P = P.replace("8. SUBAGENT BUDGET — counted in ROUNDS, not in spawns:",
                  "8. SUBAGENT BUDGET (commit threshold):", 1)
    P = P.replace("     · rounds #1-3: free to delegate.",
                  "     · spawns #1-3: free to delegate.", 1)
elif args.mutate == "concurrency-leaks-into-shared":
    P = P.replace("   WIDEN EACH ROUND BEFORE ADDING ONE.",
                  "   Write .scratch/delegate.json for all of them FIRST.\n"
                  "   WIDEN EACH ROUND BEFORE ADDING ONE.", 1)
elif args.mutate == "drops-independence-rule":
    P = re.sub(r"   ONLY GENUINELY INDEPENDENT QUESTIONS GO IN THE SAME ROUND.*?"
               r"rounds, and no instruction here changes that\.", "", P, count=1, flags=re.S)
    C = C.replace("INDEPENDENT is the whole condition.", "Anything goes.", 1)
elif args.mutate == "feature-flag-as-table":
    # Put the switch back where it was: sub-keys only, so the boolean is
    # never set and the feature is never enabled.
    C = C.replace('"features.multi_agent_v2=true",',
                  '"features.multi_agent_v2.enabled_maybe=true",', 1)
elif args.mutate == "empty-wait-unreported":
    C = C.replace("EMPTY WAIT — no child agents existed", "", 1)
elif args.mutate == "status-as-result":
    # Restore the fallback that recorded a tool's payload as the word
    # "completed", which is how `wait`'s timed_out flag was thrown away.
    C = C.replace("    if body is None:", "    body = body or status\n    if False:", 1)
elif args.mutate == "drops-vm-probe-rule":
    C = C.replace("keep one equivalent VM probe alive at a time", "run VM probes freely", 1)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


def main() -> int:
    # --- the shared prompt: rounds, not spawns -------------------------------
    check("S1 the budget is counted in ROUNDS",
          "counted in ROUNDS" in P, True)
    check("S1 ...and the free allowance is rounds, not spawns",
          "rounds #1-3: free to delegate" in P, True)
    check("S1 ...with the old spawn-numbered wording gone",
          "spawns #1-3: free to delegate" in P, False)
    check("S2 a round is defined as a fan-out, so N at once is still one",
          "is ONE round, not three" in P, True)
    check("S3 the commit threshold survives — this is not a licence to stall",
          "MUST be `Write exploit.py`" in P and "analysis\n       paralysis" in P,
          True)

    # --- the constraint that makes fan-out safe ------------------------------
    for label, text, where in (
        ("shared prompt", P, "_prompts.py"),
        ("codex addendum", C, "codex_cli.py"),
    ):
        check(f"I1 {label} scopes fan-out to INDEPENDENT questions",
              "INDEPENDENT" in text, True)
        check(f"I1 {label} ...and says WHY (the scratch log is read at launch)",
              ("AT LAUNCH" in text), True)

    # --- the Codex-only half -------------------------------------------------
    # The addendum used to tell main to call `spawn_agent` for a whole round
    # before waiting. That instruction was retired once the tool was PROVEN
    # absent (codex exec, two models, told to answer NO_SPAWN_TOOL and it
    # never did) — see scripts/test_orchestrator_delegation.py. The round is
    # now declared in a file and run by the orchestrator, so what this must
    # pin is the file channel, not the tool.
    check("C1 the addendum sends a round to the file channel",
          ".scratch/delegate.json" in C and "END YOUR TURN" in C, True)
    # INVERTED 2026-09-07. Both of these pinned the claim that spawn_agent is
    # unregistered and that believing otherwise costs 80-100 s per call. The
    # claim rested on "no spawn event in the stream"; a run where a child
    # provably ran — it wrote a file its parent was forbidden to write, and its
    # reply came back — emits no spawn event either. Measured in a live worker
    # with the production argv, 3/3. docs/spawn-agent-works-2026-09-07.md.
    check("C1 ...and teaches the native tool that actually works",
          "spawn_agent(task_name" in C
          and "`spawn_agent` DOES NOT WORK HERE" not in C, True)
    check("C1 ...and names the REAL cost, which is looping on an empty roster",
          "23% and 27%" in C, True)
    check("C2 transport reliability remains category-neutral",
          "Bound long-running commands" in C, True)
    check("C2 ...and defers deliverables to the task prompt",
          "Follow the task system prompt for canonical deliverables" in C,
          True)
    check("C2 ...without leaking pwn-only artifact names",
          not any(term in C for term in
                  ("QEMU", "exploit.py", "solver.py", "report.md")), True)

    # --- and must NOT leak into the shared prompt ----------------------------
    # Claude's MCP spawn tool runs the subagent to completion inside the tool
    # call. Telling a Claude-routed main to launch several at once asks for
    # something the transport cannot do.
    leaked = [phrase for phrase in
              (".scratch/delegate.json",
               "DELEGATE BY WRITING A FILE",
               "spawn_agent for all of them FIRST")
              if phrase in P]
    check("X1 the concurrency instruction stays out of the shared prompt",
          leaked, [])

    # --- the documented roster, and the payload that proves a timeout -------
    # openai/codex exposes list_agents (codex-rs/core/src/tools/handlers/
    # multi_agents_v2/list_agents.rs) returning {"agents":[{agent_name,
    # agent_status}]}, and spawn_agent is ToolName::plain("spawn_agent") — no
    # namespace, not encrypted. Across three jobs the timeline still recorded
    # `wait` calls and zero spawns, so the roster is the only thing that can
    # put the child list where the operator sees it.
    # list_agents belonged to the spawn path and went with it. What must
    # survive is the warning about the empty roster: a `wait` whose result
    # carries no receiver_thread_ids bought nothing, and main has to know
    # that on sight rather than waiting again.
    # The warning survives; what it says changed. An empty roster does NOT
    # mean nothing was delegated — that is the misreading that cost four
    # months — so the addendum must explain the timeout, not the absence.
    check("L1 the addendum explains what an empty wait really means",
          "receiver_thread_ids" in C
          and "TIMEOUT" in C
          and "empty one means nothing was delegated" not in C, True)
    check("L2 ...and says not to LOOP on it, nor to re-spawn because of it",
          "Do NOT call `wait` in a loop." in C
          and "Do not re-spawn because of it." in C, True)

    # v2 `wait` returns {"message","timed_out"}; the adapter used to store the
    # status word instead, so every wait read "completed" and the one bit that
    # distinguishes a real child from an empty spin was discarded.
    check("L3 an unknown tool payload is kept, not replaced by the status",
          "if body is None:" in C and "rest or status" in C, True)
    check("L3 ...and the envelope fields are the only thing dropped",
          '"type", "id", "status", "call_id", "name"' in C, True)

    # --- the stall must be named, because the prose did not hold ----------
    #
    # Job 6bce0d49c5e2 recorded a `wait` that blocked 99.2s on
    #   {"receiver_thread_ids": [], "agents_states": {}}
    # — main waiting on nothing, having never called spawn_agent, in a run
    # whose addendum already forbade exactly that ("call `wait` only for a
    # child id that actually exists"). Every idle figure this platform has
    # measured is suspect for the same reason, and none of it was visible
    # while the wait body was stored as the word "completed".
    #
    # worker/docker_memguard.sh states the rule this follows: prompt
    # adherence is not a guarantee, and the guarantee is the point. So the
    # timeline says it, not just the instructions.
    check("W1 an empty wait is reported on the timeline",
          "EMPTY WAIT" in C, True)
    check("W1 ...keyed on the fields v2's wait actually returns",
          "receiver_thread_ids" in C and "agents_states" in C, True)
    check("W2 ...and only when BOTH are empty, so a real child is never flagged",
          'not (_wb.get("receiver_thread_ids")' in C, True)
    check("W3 ...as a failed-status warning, not a quiet note",
          'title="EMPTY WAIT' in C and 'status="failed"' in C, True)

    # W4 — IT MUST LIVE WHERE `body` EXISTS.
    #
    # The first version of this guard passed while the detection sat in the
    # `item.started` branch, where `body` has not been computed yet: it read
    # the PREVIOUS tool's body and never fired once. Job 2e02f9e3bcb6 blocked
    # 80.7s on an empty roster and the timeline said nothing. Asking only
    # "does the string appear" is what let that through, so check the
    # STRUCTURE: the detection has to be inside the branch that assigns body.
    import re as _re
    completed = _re.search(
        r'if event_type == "item\.completed":\n(.*?)\n\s*if body:',
        C, _re.S)
    check("W4 the completed branch is findable", completed is not None, True)
    body_branch = completed.group(1) if completed else ""
    check("W4 the empty-wait check runs where body is assigned",
          "EMPTY WAIT" in body_branch, True)
    started = _re.search(r"if item_id not in started_tools:\n(.*?)\n\s*if event_type ==",
                         C, _re.S)
    check("W4 ...and NOT in the started branch, where body is stale",
          "EMPTY WAIT" in (started.group(1) if started else ""), False)

    # --- the switch, and where the options live ---------------------------
    #
    # `codex --help`: "--enable <FEATURE>  Enable a feature (repeatable).
    # Equivalent to `-c features.<name>=true`". So features.multi_agent_v2 is
    # a BOOLEAN. This adapter used to set only sub-keys of that name
    # (features.multi_agent_v2.tool_namespace / .hide_spawn_agent_metadata),
    # which makes it a TABLE and never flips the switch — and codex accepts
    # unknown config keys silently (`-c totally.bogus.key=1` exits 0), so
    # nothing reported it. Across five jobs on two CLI versions spawn_agent
    # was never called once while `wait` returned an empty roster.
    check("F1 the feature flag is set as a BOOLEAN",
          '"features.multi_agent_v2=true"' in C, True)
    check("F2 ...and no sub-key turns that name back into a table",
          bool(re.search(r'"features\.multi_agent_v2\.[a-z_]+=', C)), False)
    check("F3 the options live in their own top-level table",
          '"multi_agent_v2.hide_spawn_agent_metadata=false"' in C
          and "'multi_agent_v2.tool_namespace=\"agents\"'" in C, True)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
