#!/usr/bin/env python3
"""Who is doing the work must be visible, or nobody can make it parallel.

WHAT WAS INVISIBLE, measured on job 24225668a27d:

    gpt-events.jsonl   20 `wait` rows, ZERO delegation rows
    main's own words   "후속 recon이 ... 분석 중입니다"
                       "Judge 검토는 통과했지만"
                       four alternative hypotheses refuted that main never
                       probed with a Bash call of its own

So children ran and reported, and the instrument recorded none of it.  The
job spent 491s of 950s (52%) inside `wait`, and no one could say whether that
was one child or four, serial or parallel, because the only rows were the
waits themselves.

TWO CAUSES, both in modules/codex_cli.py:

  1. `_command` turns on `features.multi_agent_v2.tool_namespace="agents"`,
     so the spawn tool can arrive as `agents.spawn_agent`.  The classifier
     tested `lower_name == "spawn_agent"` — an equality check that a
     namespaced spelling can never satisfy.
  2. The stream gate `if kind not in _TOOL_ITEM_TYPES: continue` dropped any
     item type the adapter had not been taught, silently.  A spawn carrying
     an unfamiliar type vanished before the classifier ever saw it.

WHAT THIS SUITE PINS
  * a tool name is classified by MEANING, after its namespace is stripped
  * an unrecognised item type is reported once per kind instead of dropped
  * a delegation-shaped item reaches the timeline even when its type is new
  * message/reasoning streams are NOT mistaken for delegations
  * the activity summary counts what the data supports and no more
  * app.js and its cache buster move together — commit 9f916d7 records the
    release where they did not

Run from the repository root::

    python3 scripts/test_delegation_observability.py
    python3 scripts/test_delegation_observability.py --mutate equality-name-match
"""
from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CODEX = ROOT / "modules" / "codex_cli.py"
EVENTS = ROOT / "modules" / "gpt_run_events.py"
CODEX_SRC = CODEX.read_text()
EVENTS_SRC = EVENTS.read_text()

MUTATIONS = ("equality-name-match", "silent-unknown-items",
             "drop-unknown-delegation-items", "delegation-eats-messages",
             "silent-unknown-tool-names")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    n = source.count(old)
    if n != 1:
        raise RuntimeError(f"mutation anchor count={n}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _mutated(src: str) -> str:
    if args.mutate == "equality-name-match":
        # The state that recorded 20 waits and no delegations.
        src = _replace_once(
            src,
            "    if bare in _DELEGATION_TOOL_NAMES "
            "or _looks_like_delegation_item(item_kind):",
            '    if name == "spawn_agent":',
        )
    elif args.mutate == "silent-unknown-items":
        src = _replace_once(
            src,
            "                        if not _looks_like_delegation_item(kind):\n"
            "                            continue",
            "                        continue",
        )
    elif args.mutate == "drop-unknown-delegation-items":
        src = _replace_once(
            src,
            "    return any(h in k for h in _DELEGATION_ITEM_HINTS)",
            "    return False",
        )
    elif args.mutate == "silent-unknown-tool-names":
        # Leave the item-type gate intact but stop naming unclassified tools.
        # A spawn spelled `create_task` on a KNOWN item type then goes back to
        # being an ordinary tool call with nothing said — invisible a second
        # time, by a second route.
        src = _replace_once(src, "seen_tool_names.add(lower_name)", "pass")
    elif args.mutate == "delegation-eats-messages":
        # Drop the stream exclusion: `agent_message` / `agent_reasoning` then
        # read as delegations and the count inflates without bound.
        src = _replace_once(
            src,
            '    if k.endswith(("_message", "_reasoning", "_delta", "_text")):\n'
            "        return False\n",
            "",
        )
    return src


CODEX_TEXT = _mutated(CODEX_SRC)

# Execute only the helpers, so the mutation is what is exercised and the
# adapter's import chain is not.
WANT_F = {"_bare_tool_name", "_looks_like_delegation_item", "_timeline_kind_for"}
WANT_A = {"_DELEGATION_TOOL_NAMES", "_DELEGATION_ITEM_HINTS", "_TOOL_ITEM_TYPES"}
pieces: list[str] = []
for node in ast.parse(CODEX_TEXT).body:
    if isinstance(node, ast.FunctionDef) and node.name in WANT_F:
        pieces.append(ast.get_source_segment(CODEX_TEXT, node))
    elif isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in WANT_A:
                pieces.append(ast.get_source_segment(CODEX_TEXT, node))
NS = types.ModuleType("_codex_obs_ns")
exec(compile("\n\n".join(pieces), str(CODEX), "exec"), NS.__dict__)

from modules.gpt_run_events import summarize_agent_activity  # noqa: E402

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


# ------------------------------------------------------- name normalisation

def _name_checks() -> None:
    bare = NS._bare_tool_name
    # `tool_namespace="agents"` is set in _command, so all three spellings
    # are the same tool and must classify the same way.
    for spelling in ("spawn_agent", "agents.spawn_agent", "agents__spawn_agent",
                     "agents/spawn_agent", "agents::spawn_agent"):
        check(f"N1 {spelling} normalises to spawn_agent",
              bare(spelling), "spawn_agent")
    check("N2 an un-namespaced tool is untouched apart from case",
          bare("Bash"), "bash")
    check("N2 ...and wait stays wait", bare("wait"), "wait")


# --------------------------------------------------------- classification

def _classify_checks() -> None:
    kind = NS._timeline_kind_for
    # THE regression: every namespaced spelling must reach the delegation lane.
    for spelling in ("spawn_agent", "agents.spawn_agent", "agents__spawn_agent"):
        check(f"C1 {spelling} is a delegation",
              kind(spelling, "collab_tool_call"), "delegation")
    # ...and an unfamiliar ITEM type is the other half of the same bug.
    check("C1 an unknown agent-shaped item type is a delegation too",
          kind("whatever", "agent_spawn"), "delegation")
    check("C1 ...including a subagent-shaped one",
          kind("x", "subagent_call"), "delegation")

    # The ordinary lanes must not move.
    check("C2 Bash is still a plain tool",
          kind("Bash", "command_execution"), "tool_started")
    check("C2 Edit is still an artifact", kind("Edit", "file_change"), "artifact")
    check("C2 WebSearch is still a plain tool",
          kind("WebSearch", "web_search"), "tool_started")
    check("C2 wait is still wait", kind("wait", "collab_tool_call"), "wait")
    check("C2 ...even namespaced", kind("agents.wait", "collab_tool_call"), "wait")

    # A delegation lane that swallows the agent's own talk would report a
    # child for every sentence main utters.
    for stream in ("agent_message", "agent_reasoning", "agent_text",
                   "agent_message_delta"):
        check(f"C3 {stream} is NOT a delegation",
              kind("x", stream), "tool_started")


# ------------------------------------------------- the gate stops being silent

def _gate_checks() -> None:
    # Source-level, because this lives inside the streaming loop: what matters
    # is that the unknown-kind branch REPORTS before it decides.
    gate = re.search(
        r"if kind not in _TOOL_ITEM_TYPES:(.*?)\n                    if item_id",
        CODEX_TEXT, re.S)
    body = gate.group(1) if gate else ""
    check("G1 the unknown-item gate exists", bool(gate), True)
    check("G1 ...and emits a record instead of dropping in silence",
          "emit_gpt_event(" in body, True)
    check("G1 ...once per kind, so an unfamiliar vocabulary cannot flood",
          "seen_item_kinds" in body, True)
    # Structural, not substring. The first version of this check searched the
    # gate body for the string "_looks_like_delegation_item(kind)" and passed
    # against a mutant whose guard had been deleted — because that same call
    # also appears inside the diagnostic message it emits. It was measuring
    # that the name occurs, not that the `continue` is guarded by it.
    gate_node = None
    for node in ast.walk(ast.parse(CODEX_TEXT)):
        if not isinstance(node, ast.If):
            continue
        t = node.test
        if (isinstance(t, ast.Compare) and len(t.ops) == 1
                and isinstance(t.ops[0], ast.NotIn)
                and isinstance(t.comparators[0], ast.Name)
                and t.comparators[0].id == "_TOOL_ITEM_TYPES"):
            gate_node = node
            break
    check("G1 ...and the gate is findable as a structure", gate_node is not None,
          True)
    bare_continue = [n for n in (gate_node.body if gate_node else [])
                     if isinstance(n, ast.Continue)]
    check("G1 ...and it does NOT continue unconditionally",
          bare_continue, [])
    guarded = [
        n for n in (gate_node.body if gate_node else [])
        if isinstance(n, ast.If)
        and any(isinstance(b, ast.Continue) for b in n.body)
        and "_looks_like_delegation_item" in ast.dump(n.test)
    ]
    check("G1 ...its skip is guarded by the delegation-shape test",
          len(guarded), 1)
    # The set must be initialised, or the once-per-kind guard is a NameError
    # on the first unknown item — in the middle of a live job.
    check("G2 the once-per-kind set is initialised beside started_tools",
          "seen_item_kinds: set[str] = set()" in CODEX_TEXT, True)

    # G3 — the hole one level down. The item-type gate cannot see a tool whose
    # ITEM type is already known: `wait` demonstrably arrives that way, so a
    # spawn spelled `create_task` or `run_agent` on the same item type would
    # land in the plain-tool lane and say nothing. Being wrong about the
    # spelling is expected; being silent about it is what cost job
    # 24225668a27d its delegation record.
    tree = ast.parse(CODEX_TEXT)
    named = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.If)
        and "seen_tool_names" in ast.dump(n.test)
        and any("emit_gpt_event" in ast.dump(b) for b in n.body)
    ]
    check("G3 an unclassified tool name is reported, not passed over",
          len(named), 1)
    check("G3 ...only for the item types that can carry a spawn",
          all(t in ast.dump(named[0].test) if named else False
              for t in ("collab_tool_call", "mcp_tool_call")), True)
    check("G3 ...and only when it did NOT already classify as a delegation",
          "tool_started" in ast.dump(named[0].test) if named else False, True)
    check("G3 ...once per name, so a chatty tool cannot flood the log",
          any("seen_tool_names" in ast.dump(b) and "add" in ast.dump(b)
              for b in named[0].body) if named else False, True)
    check("G3 ...and the set is initialised",
          "seen_tool_names: set[str] = set()" in CODEX_TEXT, True)


# ------------------------------------------------------------ the readout

def _activity_checks() -> None:
    # Collapsed-timeline shape: a record still marked running is one whose
    # completion was never merged in.
    events = [
        {"kind": "delegation", "status": "completed", "role": "main"},
        {"kind": "delegation", "status": "completed", "role": "main"},
        {"kind": "wait", "status": "running", "role": "main"},
        {"kind": "tool", "status": "completed", "role": "main"},
    ]
    cards = [{"role": "main", "status": "waiting"},
             {"role": "recon", "status": "running"},
             {"role": "judge", "status": "completed"}]
    act = summarize_agent_activity(events, cards)
    check("A1 running counts only role cards that are working",
          (act["running"], sorted(act["running_roles"])), (2, ["main", "recon"]))
    check("A1 delegations counts the children actually spawned",
          act["delegations"], 2)
    check("A1 an open wait is reported as main blocked",
          (act["main_waiting"], act["waits_open"]), (True, 1))

    # A job recorded before the adapter fix has no delegation rows at all.
    # The readout must say 0 rather than invent a number.
    old = [{"kind": "wait", "status": "completed", "role": "main"}] * 10
    act2 = summarize_agent_activity(old, [{"role": "main", "status": "running"}])
    check("A2 a pre-fix job reports 0 delegations, not a guess",
          (act2["delegations"], act2["running"], act2["main_waiting"]),
          (0, 1, False))
    check("A3 no events and no cards is not an error",
          summarize_agent_activity([], [])["running"], 0)

    # A4 — "0 delegations" must not be reported as fact when the runtime
    # cannot report spawns at all.
    #
    # Job 7b8bd665f130 was the first run carrying the adapter fix. ZERO
    # diagnostic rows fired (no unknown item type, no unclassified tool name)
    # and the tool tally was Bash/Edit/`wait` only — so the Codex CLI emits no
    # spawn item whatsoever; the child is made inside the CLI and never
    # reaches the stream. Main's messages that same run said it was delegating
    # to recon, to debugger, and that "judge 검토까지 완료했습니다", and every
    # `wait` came back with findings. Printing "위임 0건" there is the same
    # class of untruth as the `/` health probe that could never return 200.
    codex_like = [{"kind": "wait", "status": "completed", "role": "main"}] * 6
    a = summarize_agent_activity(codex_like, [{"role": "main", "status": "running"}])
    check("A4 waits with no delegation rows => spawns are NOT observable",
          (a["delegations"], a["spawns_observable"]), (0, False))
    # A run that genuinely delegated through an observable path keeps saying so.
    claude_like = [{"kind": "delegation", "status": "completed", "role": "main"},
                   {"kind": "wait", "status": "completed", "role": "main"}]
    b = summarize_agent_activity(claude_like, [])
    check("A4 ...but a real delegation row makes them observable again",
          (b["delegations"], b["spawns_observable"]), (1, True))
    # A job that never delegated and never waited is honestly zero, not
    # "unavailable" — otherwise the flag would be permanently on.
    c = summarize_agent_activity([{"kind": "tool", "status": "completed"}], [])
    check("A4 ...and a job with neither is a truthful zero",
          (c["delegations"], c["spawns_observable"]), (0, True))


# ------------------------------------------------------- the shipping guard

def _cachebuster_checks() -> None:
    """app.js and its ?v= tag must move together.

    Commit 9f916d7 — "the GPT-preset commits shipped app.js without moving the
    cache buster" — is the release this guards. A browser holding the previous
    app.js renders the previous UI against the new API and the change looks
    like it silently did nothing.
    """
    def _head(path: str) -> str:
        out = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=str(ROOT),
                             capture_output=True, text=True)
        return out.stdout if out.returncode == 0 else ""

    app_now = (ROOT / "web-ui" / "app.js").read_text()
    app_head = _head("web-ui/app.js")
    html_now = (ROOT / "web-ui" / "index.html").read_text()
    html_head = _head("web-ui/index.html")
    if not app_head or not html_head:
        print("SKIP  B1 cache-buster guard (no git HEAD to compare)")
        return
    tag = lambda t: (re.search(r"app\.js\?v=([0-9a-zA-Z]+)", t) or [None, ""])[1]
    if app_now == app_head:
        check("B1 app.js unchanged, so the buster need not move", True, True)
        return
    check("B1 app.js changed, so its cache buster moved too",
          tag(html_now) != tag(html_head), True)
    check("B1 ...and the page still references exactly one app.js",
          len(re.findall(r"app\.js\?v=", html_now)), 1)


def main() -> int:
    _name_checks()
    _classify_checks()
    _gate_checks()
    _activity_checks()
    _cachebuster_checks()
    # --- A5: the roster, when the run reports one -------------------------
    #
    # Codex emits no spawn item, so nothing else on the timeline can name the
    # children. `list_agents` is the documented way to ask — openai/codex
    # codex-rs/core/src/tools/handlers/multi_agents_v2/list_agents.rs returns
    # {"agents":[{agent_name, agent_status}]} — and it only survives the
    # adapter because _tool_result stopped replacing an unknown body with the
    # word "completed".
    from modules.gpt_run_events import _parse_agent_roster
    check("A5 a roster payload parses to name/status pairs",
          _parse_agent_roster({"agents": [
              {"agent_name": "recon-1", "agent_status": {"state": "running"}},
              {"agent_name": "recon-2", "agent_status": "completed"}]}),
          [{"name": "recon-1", "status": "running"},
           {"name": "recon-2", "status": "completed"}])
    check("A5 ...and survives being handed over as a JSON string",
          _parse_agent_roster('{"agents":[{"agent_name":"j","agent_status":"running"}]}'),
          [{"name": "j", "status": "running"}])
    # None, not [] — an unparseable snapshot must leave the previous roster
    # standing rather than silently emptying it.
    check("A5 ...and a non-roster body returns None, not an empty roster",
          (_parse_agent_roster("completed"), _parse_agent_roster("{bad")),
          (None, None))

    roster_events = [
        {"kind": "tool", "tool": "list_agents", "status": "completed",
         "detail": {"agents": [{"agent_name": "a", "agent_status": "running"},
                               {"agent_name": "b", "agent_status": "completed"}]}},
        {"kind": "wait", "status": "running", "role": "main"},
    ]
    act = summarize_agent_activity(roster_events, [{"role": "main", "status": "waiting"}])
    check("A5 the summary reports the roster and how many are still active",
          (len(act["children"]), act["children_active"], act["roster_seen"]),
          (2, 1, True))
    # LAST ONE WINS: a roster is a snapshot, and a stale one is a worse answer
    # than the newest — never a supplement to it.
    two = roster_events + [
        {"kind": "tool", "tool": "list_agents", "status": "completed",
         "detail": {"agents": [{"agent_name": "a", "agent_status": "completed"}]}}]
    act2 = summarize_agent_activity(two, [])
    check("A5 ...and the newest snapshot replaces the older one",
          (len(act2["children"]), act2["children_active"]), (1, 0))
    check("A6 a job that never asked reports no roster, not a fake empty one",
          summarize_agent_activity([{"kind": "wait", "status": "completed"}],
                                   [])["roster_seen"], False)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
