"""Codex CLI adapter backed by ChatGPT OAuth.

HexTech's shared orchestration loop expects the small message/client surface
implemented by :mod:`modules.gpt_responses`.  This adapter keeps that surface,
but runs ``codex exec --json`` so a login created by ``codex login`` can use a
ChatGPT subscription instead of a Platform API key.

The CLI owns OAuth token refresh and session persistence.  This module never
copies a token into a prompt or environment variable; it only launches Codex
with the mounted ``CODEX_HOME`` and parses the documented JSONL event stream.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import time
from pathlib import Path
from typing import Any, AsyncIterator

from modules.gpt_responses import (
    AssistantMessage,
    GptSessionOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)
from modules.gpt_run_events import context_from_options, emit_gpt_event
from modules.codex_turn_guard import (
    acquire_turn_guard,
    check_turn_stop,
    release_turn_guard,
)


DEFAULT_TURN_TIMEOUT_S = 3600.0
MAX_EVENT_TEXT_CHARS = 48_000
MAX_STDERR_CHARS = 64_000
# Keep the asyncio transport comfortably above the historical 64 KiB default,
# but do not confuse that implementation limit with our application boundary.
# A JSONL event may legitimately exceed this transport limit, so
# `_read_bounded_jsonl_line()` drains it in chunks up to the separate hard cap.
SUBPROCESS_STREAM_LIMIT_BYTES = 1024 * 1024
MAX_JSONL_EVENT_BYTES = 8 * 1024 * 1024
_STREAM_DRAIN_CHUNK_BYTES = 64 * 1024

# Native Codex roles exposed only for GPT/Codex CLI main sessions.  Their
# config files are generated per job so the provider-scoped GPT preset can
# select a different model for each role without touching Claude/Grok agents.
CODEX_AGENT_ROLES: dict[str, str] = {
    "recon": "Read-only static analysis and concise evidence synthesis.",
    "debugger": "Dynamic analysis with gdb, tracing, and bounded VM probes.",
    "triage": "Independent read-only verification of candidate findings.",
    "judge": "Read-only pre-ship review of solver correctness and reliability.",
}


class CodexCLIError(RuntimeError):
    pass


CODEX_TOOL_ADDENDUM = """## CODEX CLI TOOL SURFACE

This session runs through OpenAI Codex CLI with ChatGPT OAuth. Use Codex's
native shell, file-editing, web, planning and subagent tools rather than Claude
MCP tool names.

DELEGATE WITH `spawn_agent`. IT WORKS HERE — MEASURED, NOT ASSUMED.

    spawn_agent(task_name=..., message=...)

Measured 2026-09-07 in this image, with this command line, against this
deployment's own credentials: two children spawned with one `sleep 20` each
finished in 53s wall-clock TOTAL, both wrote their files, the parent ran its
own shell command while they worked, and BOTH REPLIES CAME BACK. Children run
concurrently and you are not blocked while they do.

An earlier version of this text said `spawn_agent` was not registered here. It
was wrong, and the way it was wrong is worth knowing: the evidence was "no
spawn event in the stream", and a run where a child provably ran — it wrote a
file the parent was forbidden to write — produces no spawn event either.

THE EMPTY ROSTER IS NOT WHAT IT SOUNDS LIKE. Every `wait` in those measured
runs returned

    {"receiver_thread_ids": [], "agents_states": {}}

WHILE THE CHILDREN WERE RUNNING AND THEIR REPLIES ARRIVED ANYWAY. OpenAI
documents this shape as what `wait_agent` returns on TIMEOUT, and
openai/codex#24951 has it blocking far past its own timeout_ms. So:

  - An empty roster is NOT failure. Do not re-spawn because of it.
  - A child's reply reaches you as INPUT when it finishes. You do not need
    `wait` to receive it.
  - Do NOT call `wait` in a loop. If one returns empty, go do the part only
    you can do. Two jobs burned 23% and 27% of their wall-clock re-waiting on
    empty rosters that meant nothing.

FALLBACK, IF `spawn_agent` EVER ERRORS. Everything below about round shape,
independence and question quality applies to BOTH channels — only the
transport differs. To use the fallback, write


    .scratch/delegate.json
    {"tasks": [
      {"role": "recon", "question": "<ONE self-contained question: name the
                                      file / address / artifact and say what
                                      you want DECIDED>"},
      {"role": "recon", "question": "<a second question whose answer does NOT
                                      depend on the first>"},
      {"role": "recon", "question": "<...and so on, for as many independent
                                      questions as the work actually has>"}
    ]}

then RING THE BELL by writing `.scratch/delegate.ring` (any content — it is a
signal, not data), and END YOUR TURN. Roles: recon, debugger, triage, judge.

THE RING IS WHAT STARTS THEM EARLY. The orchestrator sees the ring the instant
you write it — not when your turn ends — and launches every task CONCURRENTLY
right then, so your agents are already working while you finish the turn.
Without the ring the round still runs, but only after your turn ends: you pay
the whole wait instead of overlapping it. Order matters — write the request
FIRST and the ring SECOND, because a ring with no request on disk does nothing
(it is not an error; it just waits for the turn to end, as before).

Either way the orchestrator runs every task CONCURRENTLY and hands you all the
replies as your next input. This path costs you a TURN BOUNDARY that
`spawn_agent` does not, so prefer the native tool and keep this for when it
actually fails.

THE PLACEHOLDERS ARE THE POINT — do not copy a shape from them. Write the
questions THIS challenge needs, in whatever terms this challenge is in. The
example is deliberately empty of subject matter so that it teaches the FORM (a
self-contained question per task) and nothing about the content.

HOW MANY: as many as the work genuinely has. One question is a fine round; so
is six. Do not pad a round to reach a number, and do not split one question
into fragments that each need the others to make sense — a task must be
answerable on its own. There is an upper cap only as a runaway guard; if you
exceed it the extra tasks are dropped and you are told so.

THE SAME ROLE MAY REPEAT, AND USUALLY SHOULD. The example above is three
`recon` tasks, not one — a role is a PROFILE (which model, which tools), not a
person, so N recons are N independent investigators with the same setup.
Splitting one investigation into several self-contained sub-questions is the
normal shape of a round and the whole reason it costs one child's time instead
of N. Mixing roles is for when the WORK differs — a `debugger` to observe
runtime state while a `recon` reads source.

PUT THE WHOLE ROUND IN ONE FILE. The round costs its SLOWEST child, so two
questions asked together cost what the longer one costs alone; asked in two
rounds they cost the sum. Only questions that are INDEPENDENT belong in the
same file — each agent is launched without the others' findings, so two agents
on the same question just derive it twice. If B needs A's answer, they are two
rounds.

Each question must stand alone: name the files, the addresses and the exact
thing you want decided. The agent does not see your reasoning, only this text.

ASK FOR THE GOAL, NOT FOR ONE METHOD OF REACHING IT. "Can method X produce Y"
invites an accurate "no" that closes a path "how can I obtain Y at all" would
have kept open — and a correct answer to the wrong question is the hardest
kind to catch, because nothing about it looks wrong. Name the artifacts
precisely, and state the DECISION at the level of what you actually need.
RING, THEN KEEP WORKING. This is the point of ringing early: between the ring
and the end of your turn, your agents are running and you are not blocked.
Reading the files you already know you need, drafting the threat model, or
sketching the canonical deliverable are all better uses of that time than
stopping — and the
replies are waiting for you as soon as the turn ends.

INDEPENDENT is the whole condition. Each child is handed the shared scratch log
AT LAUNCH, so children started together cannot see each other's findings — two
concurrent agents on the same question just re-derive it twice. Split a round
by SUBJECT (a different file, a different hypothesis, a different layer). If B
needs A's answer, they belong in different rounds.

IF YOU EVER SEE AN EMPTY `wait`, RE-READ THE TOP OF THIS TEXT. Its result
carries {"receiver_thread_ids": [], "agents_states": {}}. That is NOT proof
the roster is empty — measured, a child that ran and answered produces exactly
that. Do not wait again on it, do not re-spawn because of it, and do not
conclude delegation is unavailable. Do your own work; the reply arrives.

GPT/Codex reliability rules:
- A piped compiler/build command reports the last program's status by default.
  Use `set -o pipefail` (or capture the build log separately), then verify the
  expected artifact with `test -x`, `file`, or an equivalent direct check.
- Bound long-running commands with a timeout or tracked process and verify the
  expected result directly rather than inferring success from narration.
- Follow the task system prompt for canonical deliverables, validation gates,
  and its success signal; this transport addendum does not redefine them.
""".strip()


# `ultra` is Codex's native multi-agent mode.  Keeping it on the legacy
# file-delegation shim fragments one hard investigation into many independent
# exec turns and defeats the reason the operator selected ultra in the first
# place.  The CLI command below now enables multi_agent_v2 correctly, so ultra
# sessions get one small, internally consistent native-tool contract.  Other
# efforts retain CODEX_TOOL_ADDENDUM until their existing orchestration path is
# migrated and evaluated separately.
CODEX_NATIVE_ULTRA_ADDENDUM = """
## CODEX CLI — NATIVE ULTRA MODE

This session runs through OpenAI Codex CLI with native multi-agent v2 enabled.
For genuinely independent work, use `spawn_agent` with the registered
`recon`, `debugger`, `triage`, or `judge` role and keep useful main-thread work
moving while the children run.  A delegation is real only after `spawn_agent`
returns a child id; call `wait` only for ids that actually exist.  Ask each
child a self-contained, goal-level question.  A negative result for one method
does not close the underlying goal, so use an independent framing before
declaring a required primitive impossible.

Do not use the fallback file-delegation protocol in this mode; it would end
the main turn unnecessarily.

Reliability rules:
- Verify build exit status and the expected output artifact directly.
- Bound long-running commands with a timeout or tracked process, and clean up
  only processes that this session started.
- Follow the task system prompt for canonical deliverables, validation gates,
  and its success signal; this transport addendum does not redefine them.
""".strip()


def adapt_system_prompt_for_codex(system_prompt: str) -> str:
    """Remove Claude/Grok-specific tool spellings from a shared prompt."""
    text = str(system_prompt or "")
    replacements = {
        "mcp__team__spawn_subagent": "spawn_agent",
        "spawn_subagent": "spawn_agent",
        "subagent_type=": "agent_type=",
        "subagent_type ∈": "agent_type ∈",
        "Claude Code": "Codex CLI",
        "Claude SDK": "Codex CLI",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def resolve_codex_bin() -> str:
    """Return the Codex executable path or raise an operator-facing error."""
    configured = str(os.environ.get("CODEX_BIN") or "").strip()
    candidates = [configured] if configured else []
    found = shutil.which("codex")
    if found:
        candidates.append(found)
    candidates.extend(("/usr/local/bin/codex", "/usr/bin/codex"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(
        "Codex CLI is not installed in this container. Rebuild the api and "
        "worker images after the Codex OAuth update."
    )


def _normalize_effort(value: str | None) -> str | None:
    effort = str(value or "").strip().lower()
    return (
        effort
        if effort in {
            "none",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh",
            "max",
            "ultra",
        }
        else None
    )


def _toml_string(value: Any) -> str:
    """Encode a scalar as a TOML-compatible quoted string."""
    return json.dumps(str(value), ensure_ascii=False)


# Context-window controls for every Codex process this adapter starts.
#
# `_command` passes --ignore-user-config, so the operator's own
# ~/.codex/config.toml never reaches the CLI: a value that is not passed here
# does not exist for the run.  The pair is written TWICE on purpose — once
# into main's argv and once into every role overlay below — because a child
# does not inherit the parent's config.  That is the same lesson the
# developer_instructions line in this file already records ("Child agents do
# not automatically receive the main agent's developer prompt"), and setting
# it only on main would leave every recon/triage/judge/debugger subagent on
# the default window while the operator believed otherwise.
CODEX_MODEL_CONTEXT_WINDOW = 1050000
CODEX_AUTO_COMPACT_TOKEN_LIMIT = 240000


def _write_codex_agent_configs(
    cwd: str | Path,
    parent_model: str,
    effort: str | None,
    language_instruction: str = "",
) -> dict[str, Path]:
    """Write GPT-only role overlays and return absolute paths by role.

    Codex custom roles accept a ``config_file`` whose values override the
    spawned child.  Keeping these files below the job's own tmp directory
    avoids mutating the operator's CODEX_HOME and makes retries independent.
    """
    from modules.model_presets import resolve_role_model

    role_dir = Path(cwd).resolve() / "tmp" / "codex-agents"
    role_dir.mkdir(parents=True, exist_ok=True)
    normalized_effort = _normalize_effort(effort)
    paths: dict[str, Path] = {}
    for role in CODEX_AGENT_ROLES:
        model = resolve_role_model(role, parent_model, "gpt")
        # Effort support is model-specific.  The parent's value is known to be
        # valid only for the parent model; blindly copying e.g. ``ultra`` onto
        # an independently pinned role model can make every native spawn fail.
        # Same-model children inherit it exactly.  A different role model uses
        # its own CLI default until presets support per-role effort explicitly.
        role_effort = (
            normalized_effort
            if str(model).strip().lower() == str(parent_model).strip().lower()
            else None
        )
        lines = [
            f"model = {_toml_string(model)}",
            f"model_context_window = {CODEX_MODEL_CONTEXT_WINDOW}",
            "model_auto_compact_token_limit = "
            f"{CODEX_AUTO_COMPACT_TOKEN_LIMIT}",
        ]
        if role_effort:
            lines.append(
                "model_reasoning_effort = " + _toml_string(role_effort)
            )
        if language_instruction:
            # Child agents do not automatically receive the main agent's
            # developer prompt. Put the same immutable job-language policy in
            # every role overlay so native Codex delegation cannot drift.
            lines.append(
                "developer_instructions = "
                + _toml_string(language_instruction)
            )
        content = "\n".join(lines) + "\n"
        path = role_dir / f"{role}.toml"
        try:
            current = path.read_text() if path.is_file() else None
        except OSError:
            current = None
        if current != content:
            tmp = path.with_suffix(".toml.tmp")
            tmp.write_text(content)
            tmp.replace(path)
        paths[role] = path
    return paths


def _positive_timeout(value: Any) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TURN_TIMEOUT_S
    return timeout if timeout > 0 else DEFAULT_TURN_TIMEOUT_S


def _cap_text(value: Any, limit: int = MAX_EVENT_TEXT_CHARS) -> str:
    text = str(value if value is not None else "")
    if len(text) <= limit:
        return text
    half = (limit - 120) // 2
    return (
        text[:half]
        + f"\n... ({len(text) - (2 * half)} characters elided) ...\n"
        + text[-half:]
    )


def _json_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


async def _read_bounded_jsonl_line(
    reader: asyncio.StreamReader,
    hard_cap: int = MAX_JSONL_EVENT_BYTES,
) -> tuple[bytes, bool]:
    """Read one newline-delimited event without losing stream alignment.

    ``StreamReader.readline()`` raises ``ValueError`` when a line exceeds the
    reader's transport limit.  ``readuntil()`` exposes how much can be consumed,
    which lets us preserve legitimate multi-limit events and deliberately drain
    an event that exceeds the application hard cap.  The returned boolean says
    that the event was dropped; the next call starts at the next JSONL record.
    """
    cap = max(1, int(hard_cap))
    buf = bytearray()
    dropped = False

    while True:
        try:
            chunk = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError as exc:
            # Consume exactly the bytes asyncio says precede the separator (or
            # the separator-prefix it retained), but never materialize that
            # potentially large span as one new bytes object.
            remaining = max(1, int(exc.consumed))
            while remaining:
                part = await reader.read(min(remaining, _STREAM_DRAIN_CHUNK_BYTES))
                if not part:
                    return (b"", True) if dropped else (bytes(buf), False)
                remaining -= len(part)
                if dropped:
                    continue
                if len(buf) + len(part) > cap:
                    buf.clear()
                    dropped = True
                else:
                    buf.extend(part)
            continue
        except asyncio.IncompleteReadError as exc:
            chunk = exc.partial
            if dropped or len(buf) + len(chunk) > cap:
                return b"", True
            buf.extend(chunk)
            return bytes(buf), False

        if dropped or len(buf) + len(chunk) > cap:
            return b"", True
        buf.extend(chunk)
        return bytes(buf), False


def _usage_from_event(raw: Any) -> dict[str, int]:
    usage = raw if isinstance(raw, dict) else {}
    total_input = int(usage.get("input_tokens") or usage.get("inputTokens") or 0)
    cached = int(
        usage.get("cached_input_tokens") or usage.get("cachedInputTokens") or 0
    )
    cache_write = int(
        usage.get("cache_write_input_tokens") or usage.get("cacheWriteInputTokens") or 0
    )
    output = int(usage.get("output_tokens") or usage.get("outputTokens") or 0)
    return {
        "inputTokens": max(0, total_input - cached - cache_write),
        "outputTokens": output,
        "cacheCreationInputTokens": cache_write,
        "cacheReadInputTokens": cached,
    }


def _merge_usage(target: dict[str, int], incoming: dict[str, int]) -> None:
    for key in (
        "inputTokens",
        "outputTokens",
        "cacheCreationInputTokens",
        "cacheReadInputTokens",
    ):
        target[key] = int(target.get(key) or 0) + int(incoming.get(key) or 0)


def _heartbeat_usage(usage: dict[str, int]) -> dict[str, int]:
    return {
        "input_tokens": int(usage.get("inputTokens") or 0),
        "output_tokens": int(usage.get("outputTokens") or 0),
        "cache_creation_input_tokens": int(usage.get("cacheCreationInputTokens") or 0),
        "cache_read_input_tokens": int(usage.get("cacheReadInputTokens") or 0),
    }


def _tool_name_and_input(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(item.get("type") or "")
    if kind == "command_execution":
        return "Bash", {"command": item.get("command") or ""}
    if kind == "file_change":
        return "Edit", {"changes": item.get("changes") or []}
    if kind == "web_search":
        return "WebSearch", {"query": item.get("query") or ""}
    if kind in {"mcp_tool_call", "collab_tool_call"}:
        name = item.get("tool") or item.get("name") or item.get("server") or kind
        raw_input = item.get("arguments") or item.get("input") or {}
        if not isinstance(raw_input, dict):
            raw_input = {"value": raw_input}
        return str(name), raw_input
    return kind or "codex_tool", {"item": item}


def _tool_result(item: dict[str, Any]) -> tuple[str, bool]:
    kind = str(item.get("type") or "")
    status = str(item.get("status") or "").lower()
    is_error = status in {"failed", "error", "cancelled", "declined"}
    if kind == "command_execution":
        body = (
            item.get("aggregated_output")
            or item.get("output")
            or item.get("stdout")
            or ""
        )
        exit_code = item.get("exit_code")
        if exit_code is not None:
            body = f"{body}\n[exit_code={exit_code}]".strip()
            try:
                is_error = is_error or int(exit_code) != 0
            except (TypeError, ValueError):
                is_error = True
        return _cap_text(body), is_error
    body = (
        item.get("result")
        or item.get("output")
        or item.get("error")
        or item.get("changes")
        or item.get("query")
    )
    if body is None:
        # DON'T FALL BACK TO THE STATUS STRING AND CALL IT THE RESULT.
        #
        # It used to end `or status`, so an item whose payload lives under a
        # field this list has not been taught was recorded as the single word
        # "completed". The multi-agent `wait` tool is exactly that shape: per
        # openai/codex (codex-rs/core/src/tools/handlers/multi_agents_v2/
        # wait.rs) it returns {"message", "timed_out"}, and `timed_out` is the
        # one bit that says whether main waited on a real child or spun on
        # nothing. Every wait in jobs 20a2b843e843 and c53d3e1147f1 was stored
        # as detail="completed" — 60.0s durations that look exactly like a
        # timeout, with the field that would prove it thrown away.
        #
        # So keep whatever the item actually carries. Drop only the envelope
        # fields we already record in their own columns; anything else is
        # payload, and payload we do not understand is the payload most worth
        # keeping.
        rest = {k: v for k, v in item.items()
                if k not in {"type", "id", "status", "call_id", "name",
                             "tool", "server", "arguments", "input"}}
        body = rest or status
    return _cap_text(_json_text(body)), is_error


_TOOL_ITEM_TYPES = {
    "command_execution",
    "file_change",
    "mcp_tool_call",
    "web_search",
    "collab_tool_call",
}

# WHY THE NEXT THREE DEFINITIONS EXIST
#
# `_command` turns multi-agent v2 on and namespaces its tools:
#
#     features.multi_agent_v2.tool_namespace="agents"
#
# so the spawn tool can arrive as `agents.spawn_agent` / `agents__spawn_agent`
# as easily as bare `spawn_agent`, and the spawn ITEM can carry a type this
# adapter has never heard of.  Both were fatal to the timeline: an equality
# test on the bare name reclassified every delegation as an ordinary tool, and
# the `kind not in _TOOL_ITEM_TYPES` gate below dropped unknown items on the
# floor without a word.
#
# Recorded sessions showed native children completing while the event stream
# contained only `wait` rows.  Delegation was working and the instrument was
# blind, so the adapter must recognize namespaced tool spellings.
#
# The rule here is deliberately DISCOVER-DON'T-GUESS: rather than hard-code a
# guess at Codex's spelling, an unrecognised item type is reported ONCE per
# kind so the next job names the vocabulary in its own log.
_DELEGATION_TOOL_NAMES = {
    "spawn_agent", "spawn_subagent", "spawn", "create_agent", "start_agent",
}
_DELEGATION_ITEM_HINTS = ("agent", "spawn", "subagent", "delegat")


def _bare_tool_name(name: str) -> str:
    """Strip any namespace Codex prefixed onto a tool name.

    `agents.spawn_agent`, `agents__spawn_agent` and `spawn_agent` must all
    answer `spawn_agent`, or the timeline classifies by spelling instead of
    by meaning.
    """
    out = str(name).strip().lower()
    for sep in ("__", "::", ".", "/", ":"):
        if sep in out:
            out = out.rsplit(sep, 1)[-1]
    return out


def _timeline_kind_for(name: str, item_kind: str) -> str:
    """Which timeline lane a tool call belongs in.

    Split out of the event loop so the classification can be tested on the
    spellings Codex actually emits, rather than only by driving a live
    subprocess. The delegation arm reads BOTH the (namespace-stripped) tool
    name and the item type: multi-agent v2 can namespace the name, give the
    item an unfamiliar type, or both, and missing it costs the timeline every
    record of who is doing the work.
    """
    bare = _bare_tool_name(name)
    if bare == "wait":
        return "wait"
    if name in {"Edit", "Write"}:
        return "artifact"
    if bare in _DELEGATION_TOOL_NAMES or _looks_like_delegation_item(item_kind):
        return "delegation"
    return "tool_started"


def _looks_like_delegation_item(kind: str) -> bool:
    """An unknown item type that is plainly about a child agent.

    Message/reasoning/delta streams are excluded: they are the agent talking,
    not the agent being spawned, and `agent_message` is already handled by its
    own branch above the gate.
    """
    k = str(kind).lower()
    if k.endswith(("_message", "_reasoning", "_delta", "_text")):
        return False
    return any(h in k for h in _DELEGATION_ITEM_HINTS)


class CodexCLIClient:
    """Multi-turn ``codex exec`` client using persisted ChatGPT OAuth."""

    def __init__(self, options: GptSessionOptions):
        self.options = options
        self.session_id: str | None = options.resume
        self._pending_prompt: str | None = None
        self._codex_bin: str | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._closed = False
        self._turn_count = 0
        self._usage_totals = {
            "inputTokens": 0,
            "outputTokens": 0,
            "cacheCreationInputTokens": 0,
            "cacheReadInputTokens": 0,
        }

    async def __aenter__(self) -> "CodexCLIClient":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def start(self) -> None:
        if self._codex_bin is not None:
            return
        binary = resolve_codex_bin()
        try:
            from modules.settings_io import has_codex_oauth

            authenticated = has_codex_oauth()
        except Exception:
            authenticated = False
        if not authenticated:
            raise CodexCLIError(
                "Codex ChatGPT OAuth is not available. Run `codex login` on "
                "the host and mount HOST_CODEX_HOME into the containers."
            )
        self._codex_bin = binary

    async def close(self) -> None:
        self._closed = True
        await self._stop_process()

    async def query(self, prompt: str) -> None:
        if self._codex_bin is None:
            await self.start()
        if self._pending_prompt is not None:
            raise CodexCLIError("a Codex turn is already pending")
        self._pending_prompt = str(prompt or " ")

    def _native_subagents_enabled(self) -> bool:
        """Is Codex's native multi-agent surface actually registered?

        THE PROMPT AND THE COMMAND MUST READ THE SAME ANSWER. They did not.
        `_instructions` chose its addendum on `effort == "ultra"` alone, while
        the `features.multi_agent_v2=true` flag in `_command` was gated on the
        operator setting as well. With the shipped configuration —
        `gpt_effort: ultra` and `codex_multi_agent_v2: False`, which lives in
        the untracked `data/settings.json` and so is invisible to a reading of
        this file — the two disagreed. Main was handed a prompt telling it to
        call `spawn_agent`, and NOT to use the file-delegation fallback, in a
        session where `spawn_agent` was never registered.

        Measured on a4eec9fe5cd8 (2026-09-07): 59 `wait` calls costing 28.4 of
        the run's 142.5 minutes, every payload `{"receiver_thread_ids": [],
        "agents_states": {}}`, 24 stopping at exactly 30 s and 10 at exactly
        60 s. Round numbers are the tool timing out, not a child answering.
        The recon and judge turns that DID run in that job appear under their
        own `role` in the event stream, which is what a real child looks like.

        The comment in `_command` says the operator can withdraw the whole
        multi-agent advertisement. Only half of it was ever withdrawn.
        """
        if not self.options.enable_subagents:
            return False
        try:
            from modules.settings_io import codex_multi_agent_v2_enabled

            return codex_multi_agent_v2_enabled()
        except Exception:
            return True          # unreadable policy keeps today's behaviour

    def _instructions(self, prompt: str, *, resuming: bool) -> str:
        if resuming:
            # A resumed `codex exec` turn does not replay system_prompt. The
            # session normally remembers it, but explicitly carrying this
            # small immutable policy makes /continue and /retry deterministic.
            return (
                prompt
            )
        system = adapt_system_prompt_for_codex(self.options.system_prompt)
        if self.options.append_tool_addendum and self.options.enable_tools:
            addendum = (
                CODEX_NATIVE_ULTRA_ADDENDUM
                if (
                    self._native_subagents_enabled()
                    and _normalize_effort(self.options.effort) == "ultra"
                )
                else CODEX_TOOL_ADDENDUM
            )
            system = system.rstrip() + "\n\n" + addendum
        if not self.options.enable_tools:
            system = (
                system.rstrip()
                + "\n\nThis is a text-only helper turn. Do not call shell, file, "
                "web, MCP, or subagent tools; answer only from the supplied context."
            )
        elif not self.options.enable_subagents:
            system = (
                system.rstrip() + "\n\nDo not delegate this bounded role to subagents."
            )
        if self.options.add_dirs:
            dirs = ", ".join(str(d) for d in self.options.add_dirs)
            system += f"\n\nAdditional reference directories: {dirs}"
        return (
            "<hextech_system_instructions>\n"
            + system
            + "\n</hextech_system_instructions>\n\n<user_task>\n"
            + prompt
            + "\n</user_task>"
        )

    def _command(self, *, resuming: bool) -> list[str]:
        assert self._codex_bin is not None
        effort = _normalize_effort(self.options.effort)
        sandbox = "danger-full-access" if self.options.enable_tools else "read-only"
        common = [
            "--json",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            # A delegate child writes no session rollout file. Measured on
            # codex-cli 0.152.1: three `codex exec` sharing one CODEX_HOME and
            # one cwd start within 0.1 ms of each other and finish together,
            # each returning its own marker — the CLI does not serialise them
            # and did not cross-contaminate. But openai/codex#11435 reports
            # parallel instances restoring each other's sessions, so a child
            # that persists nothing cannot be the source of that for a sibling.
            # It costs prompt-cache reuse, which a one-question session that is
            # never resumed barely has.
            *(["--ephemeral"] if self.options.concurrent_child else []),
            "--model",
            str(self.options.model),
            "--config",
            f'sandbox_mode="{sandbox}"',
        ]
        common.extend(
            (
                "--config",
                f"model_context_window={CODEX_MODEL_CONTEXT_WINDOW}",
                "--config",
                "model_auto_compact_token_limit="
                f"{CODEX_AUTO_COMPACT_TOKEN_LIMIT}",
            )
        )
        if effort:
            common.extend(("--config", f'model_reasoning_effort="{effort}"'))
        # The operator can withdraw the whole multi-agent advertisement —
        # these flags AND the prompt that advertises them, which is what
        # `_native_subagents_enabled` exists to keep in step.
        # `spawn_agent` is not registered here and `wait` only ever returns an
        # empty roster, so what this block buys main is a tool that costs time
        # and returns nothing. The file channel needs none of it, and a child's
        # model arrives on its own `--model`, not through these overlays.
        if self._native_subagents_enabled():
            # GPT-5.6 Sol selects Codex multi-agent v2. Explicitly expose its
            # routing fields and register the GPT preset's per-role overlays;
            # --ignore-user-config otherwise leaves every child inheriting
            # main's model. These flags are confined to this Codex adapter.
            # THE BOOLEAN IS THE SWITCH; THE OPTIONS LIVE ELSEWHERE.
            #
            # `codex --help` documents `--enable <FEATURE>` as "Equivalent to
            # -c features.<name>=true", so `features.multi_agent_v2` is a
            # BOOLEAN feature flag. This adapter only ever set SUB-KEYS of it
            # (`features.multi_agent_v2.tool_namespace`, and
            # `...hide_spawn_agent_metadata`), which makes that name a TABLE
            # and never turns the flag on — and codex accepts unknown config
            # keys silently (verified: `-c totally.bogus.key=1` exits 0), so
            # nothing ever said so.
            #
            # Measured consequence across five jobs on two CLI versions
            # (0.147.0 and 0.152.1): `spawn_agent` was never called once,
            # while `wait` returned {"receiver_thread_ids": [],
            # "agents_states": {}} after 80-99s — main blocking on a roster
            # that could not exist. Every idle figure this platform has
            # reported (52% / 44% / 39% / 35% of wall-clock) is that.
            #
            # Options belong in their own top-level `multi_agent_v2` table,
            # not under `features.` — the two cannot share a name, since one
            # is a bool and the other a table.
            common.extend(
                (
                    "--config",
                    "features.multi_agent_v2=true",
                    "--config",
                    "multi_agent_v2.hide_spawn_agent_metadata=false",
                    "--config",
                    'multi_agent_v2.tool_namespace="agents"',
                )
            )
            from modules.output_language import output_language_instruction

            role_configs = _write_codex_agent_configs(
                self.options.cwd,
                str(self.options.model),
                effort,
                "",
            )
            for role, path in role_configs.items():
                common.extend(
                    (
                        "--config",
                        f"agents.{role}.description="
                        + _toml_string(CODEX_AGENT_ROLES[role]),
                        "--config",
                        f"agents.{role}.config_file=" + _toml_string(path),
                    )
                )
        if resuming:
            return [
                self._codex_bin,
                "exec",
                "resume",
                *common,
                str(self.session_id),
                "-",
            ]
        command = [self._codex_bin, "exec", *common, "--sandbox", sandbox]
        for path in self.options.add_dirs:
            command.extend(("--add-dir", str(path)))
        command.append("-")
        return command

    def _environment(self) -> dict[str, str]:
        env = {k: str(v) for k, v in os.environ.items()}
        env.update({k: str(v) for k, v in (self.options.env or {}).items()})
        # This runtime is explicitly the ChatGPT OAuth path. Never let an API
        # key inherited from .env silently switch billing/auth semantics.
        env.pop("OPENAI_API_KEY", None)
        env.pop("CODEX_API_KEY", None)
        return env

    async def receive_response(
        self, *, turn_timeout_s: float | None = None
    ) -> AsyncIterator[Any]:
        if self._pending_prompt is None:
            raise CodexCLIError("query() must be called before receive_response()")
        if self._closed:
            raise CodexCLIError("Codex client is closed")
        if self._codex_bin is None:
            await self.start()

        prompt = self._pending_prompt
        self._pending_prompt = None
        resuming = bool(self.session_id)
        prompt = self._instructions(prompt, resuming=resuming)
        timeout_value = (
            turn_timeout_s
            if turn_timeout_s is not None
            else self.options.turn_timeout_s
            if self.options.turn_timeout_s is not None
            else os.environ.get("CODEX_TURN_TIMEOUT_S", DEFAULT_TURN_TIMEOUT_S)
        )
        timeout = _positive_timeout(timeout_value)
        self._turn_count += 1
        started = time.monotonic()
        event_job_id, event_role, event_model = context_from_options(self.options)
        emit_gpt_event(
            event_job_id,
            "turn_started",
            role=event_role,
            model=event_model,
            turn=self._turn_count,
            status="running",
            title="Turn 시작",
        )
        stderr_parts: list[str] = []
        started_tools: set[str] = set()
        # Reported-once-per-kind, so an unfamiliar Codex vocabulary shows up
        # in the log without flooding it.
        seen_item_kinds: set[str] = set()
        # Same discover-don't-guess rule one level down: an item type we DO
        # know can still carry a tool name we do not.
        seen_tool_names: set[str] = set()
        tool_started_at: dict[str, float] = {}
        error = False
        turn_completed = False
        stop_reason = "completed"
        turn_usage: dict[str, int] = {}

        command = self._command(resuming=resuming)
        cwd = Path(self.options.cwd)
        cwd.mkdir(parents=True, exist_ok=True)
        turn_guard = None
        try:
            # Acquire outside the subprocess and inherit the descriptor into
            # Codex.  The API can therefore distinguish "RQ stop was sent"
            # from "the actual CLI writer has terminated" before resuming the
            # same thread in a successor job.
            # THE LOCK IS WHY DELEGATION WAS NEVER PARALLEL. `acquire_turn_guard`
            # takes a BLOCKING exclusive flock on <work_dir>/.codex-turn.lock and
            # holds it for the whole life of the Codex process. Every delegate
            # child runs with the job's work_dir as cwd, so children queued
            # behind main and then behind each other: measured on jobs
            # cc38cfa29161 / df05d2ce2710 / 0b2a37b5d6c0, the sum of the
            # children's real working spans was SHORTER than the round that
            # contained them (-141s / -100s / -49s) — no overlap at all, plus
            # the lock wait. The `IN PARALLEL` log line was not true.
            #
            # A child skips the guard because it has nothing the guard protects:
            # it persists no session (--ephemeral above) and it is never the
            # writer the API's stop-and-resume path waits for. Main still takes
            # it, unchanged.
            if self.options.concurrent_child:
                # No lock, but the operator's stop still fences the launch.
                # Dropping the lock must not also drop "stop means stop".
                check_turn_stop(Path(cwd))
                turn_guard = None
            else:
                turn_guard = await asyncio.to_thread(acquire_turn_guard, cwd)
            self._proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(cwd),
                env=self._environment(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                limit=SUBPROCESS_STREAM_LIMIT_BYTES,
                # A child holds no guard, so it inherits no descriptor.
                pass_fds=((turn_guard.fileno(),) if turn_guard else ()),
            )
        except Exception as exc:
            release_turn_guard(turn_guard)
            turn_guard = None
            emit_gpt_event(
                event_job_id,
                "turn_failed",
                role=event_role,
                model=event_model,
                turn=self._turn_count,
                status="failed",
                summary=f"{type(exc).__name__}: {exc}"[:1000],
            )
            yield AssistantMessage(
                [TextBlock(f"[Codex CLI launch error] {type(exc).__name__}: {exc}")]
            )
            yield self._result(started, True, "process_error")
            return

        assert self._proc.stdin and self._proc.stdout and self._proc.stderr
        self._proc.stdin.write(prompt.encode("utf-8", errors="replace"))
        await self._proc.stdin.drain()
        self._proc.stdin.close()
        stderr_task = asyncio.create_task(
            self._collect_stderr(self._proc.stderr, stderr_parts)
        )

        try:
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise asyncio.TimeoutError
                line, dropped = await asyncio.wait_for(
                    _read_bounded_jsonl_line(
                        self._proc.stdout,
                        hard_cap=MAX_JSONL_EVENT_BYTES,
                    ),
                    remaining,
                )
                if dropped:
                    summary = (
                        "Codex CLI JSONL event exceeded the "
                        f"{MAX_JSONL_EVENT_BYTES}-byte hard cap; drained through "
                        "the delimiter and resumed at the next event"
                    )
                    emit_gpt_event(
                        event_job_id,
                        "stream_event_dropped",
                        role=event_role,
                        model=event_model,
                        turn=self._turn_count,
                        status="warning",
                        title="Oversized event dropped",
                        summary=summary,
                    )
                    yield AssistantMessage([TextBlock(f"[Codex CLI warning] {summary}")])
                    continue
                if not line:
                    break
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                event_type = str(event.get("type") or "")

                if event_type == "thread.started":
                    sid = str(event.get("thread_id") or "").strip()
                    if sid:
                        self.session_id = sid
                        emit_gpt_event(
                            event_job_id,
                            "agent_started",
                            role=event_role,
                            model=event_model,
                            session_id=sid,
                            turn=self._turn_count,
                            status="running",
                            title="Agent 시작",
                        )
                        yield SystemMessage(
                            {
                                "type": "init",
                                "subtype": "init",
                                "session_id": sid,
                                "auth": "chatgpt_oauth",
                            }
                        )
                    continue

                if event_type in {"item.started", "item.completed"}:
                    item = event.get("item") or {}
                    if not isinstance(item, dict):
                        continue
                    kind = str(item.get("type") or "")
                    item_id = str(item.get("id") or f"{kind}-{len(started_tools)}")
                    if kind == "agent_message" and event_type == "item.completed":
                        text = str(item.get("text") or "")
                        if text:
                            emit_gpt_event(
                                event_job_id,
                                "message",
                                role=event_role,
                                model=event_model,
                                turn=self._turn_count,
                                status="info",
                                title="분석 업데이트",
                                summary=text[:4000],
                            )
                            yield AssistantMessage([TextBlock(text)])
                        continue
                    if kind not in _TOOL_ITEM_TYPES:
                        # Say it once, then decide. A silent `continue` here
                        # is what made delegation invisible.
                        if kind and kind not in seen_item_kinds:
                            seen_item_kinds.add(kind)
                            emit_gpt_event(
                                event_job_id,
                                "warning",
                                role=event_role,
                                model=event_model,
                                turn=self._turn_count,
                                status="info",
                                title=f"Codex item type not on the timeline: {kind}",
                                summary=(
                                    f"item.type={kind!r} is not in "
                                    f"_TOOL_ITEM_TYPES, so it is "
                                    + ("PROMOTED to the timeline as a "
                                       "delegation-shaped item."
                                       if _looks_like_delegation_item(kind)
                                       else "not shown as a tool call.")
                                    + " Recorded once per kind so the adapter"
                                      " can be taught this vocabulary."
                                ),
                                detail=_cap_text(_json_text(item))[:2000],
                            )
                        # A child-agent item must reach the timeline even
                        # though its type is unfamiliar; `_tool_name_and_input`
                        # already has a fallback that names it.
                        if not _looks_like_delegation_item(kind):
                            continue
                    if item_id not in started_tools:
                        name, raw_input = _tool_name_and_input(item)
                        started_tools.add(item_id)
                        tool_started_at[item_id] = time.monotonic()
                        lower_name = _bare_tool_name(name)
                        timeline_kind = _timeline_kind_for(name, kind)
                        # The item-type gate above cannot see this case: a
                        # multi-agent call that arrives as a KNOWN item type
                        # (`wait` demonstrably does) but under a name outside
                        # _DELEGATION_TOOL_NAMES lands in the plain-tool lane
                        # with nothing said. If Codex spells its spawn
                        # `create_task` or `run_agent`, that is how it would
                        # stay invisible a second time. Name it once.
                        if (kind in {"collab_tool_call", "mcp_tool_call"}
                                and timeline_kind == "tool_started"
                                and lower_name not in seen_tool_names):
                            seen_tool_names.add(lower_name)
                            emit_gpt_event(
                                event_job_id,
                                "warning",
                                role=event_role,
                                model=event_model,
                                turn=self._turn_count,
                                status="info",
                                title=f"Codex tool not classified: {name}",
                                summary=(
                                    f"item.type={kind!r} tool={name!r} "
                                    f"(normalised {lower_name!r}) is on the "
                                    "timeline as a plain tool. If this is "
                                    "actually a spawn/delegation, add it to "
                                    "_DELEGATION_TOOL_NAMES. Reported once "
                                    "per name."
                                ),
                                detail=_cap_text(_json_text(raw_input))[:1000],
                            )
                        event_fields: dict[str, Any] = {
                            "role": event_role,
                            "model": event_model,
                            "turn": self._turn_count,
                            "call_id": item_id,
                            "tool": name,
                            "status": "running",
                            "title": (
                                "Subagent 작업 대기"
                                if timeline_kind == "wait"
                                else f"{name} 실행"
                            ),
                            "input": raw_input,
                        }
                        if timeline_kind == "delegation":
                            event_fields["target_role"] = str(
                                raw_input.get("agent_type") or raw_input.get("role") or "subagent"
                            )
                            event_fields["agent_name"] = str(
                                raw_input.get("task_name") or raw_input.get("name") or ""
                            )
                            event_fields["title"] = (
                                f"{event_fields['target_role']} subagent 시작"
                            )
                        if lower_name == "wait":
                            event_fields["summary"] = "native subagent 응답을 기다리는 중"
                        emit_gpt_event(event_job_id, timeline_kind, **event_fields)
                        yield AssistantMessage(
                            [ToolUseBlock(name=name, input=raw_input, id=item_id)]
                        )
                    if event_type == "item.completed":
                        body, item_error = _tool_result(item)
                        name, raw_input = _tool_name_and_input(item)
                        elapsed = tool_started_at.pop(item_id, None)
                        # AN EMPTY WAIT IS A STALL, AND IT MUST NOT LOOK LIKE
                        # WORK.
                        #
                        # v2's wait returns {sender_thread_id,
                        # receiver_thread_ids, prompt, agents_states}. Job
                        # 2e02f9e3bcb6 — the first run on Codex 0.152.1 —
                        # blocked 80.7s on `receiver_thread_ids: []` /
                        # `agents_states: {}`, exactly as 6bce0d49c5e2 did on
                        # 0.147.0: main waiting on nothing, having never
                        # called spawn_agent. The CLI upgrade did not change
                        # it, so every idle figure this platform has measured
                        # (52% / 44% / 39% / 35%) is suspect for the same
                        # reason.
                        #
                        # THIS BELONGS IN THE COMPLETED BRANCH. A first draft
                        # sat in `item.started`, where `body` has not been
                        # computed yet — it silently read the PREVIOUS tool's
                        # body and never fired, which the same run exposed.
                        # The addendum already forbids the empty wait in
                        # prose and the prose did not hold; this is the
                        # timeline saying it, per the rule
                        # worker/docker_memguard.sh states outright — prompt
                        # adherence is not a guarantee, and the guarantee is
                        # the point.
                        if _bare_tool_name(name) == "wait" and not item_error:
                            try:
                                _wb = (json.loads(body)
                                       if body.strip().startswith("{") else {})
                            except Exception:
                                _wb = {}
                            if isinstance(_wb, dict) and (
                                "receiver_thread_ids" in _wb
                                or "agents_states" in _wb
                            ) and not (_wb.get("receiver_thread_ids")
                                       or _wb.get("agents_states")):
                                _idle = (int(time.monotonic() - elapsed)
                                         if elapsed is not None else None)
                                emit_gpt_event(
                                    event_job_id,
                                    "warning",
                                    role=event_role,
                                    model=event_model,
                                    turn=self._turn_count,
                                    status="failed",
                                    title="EMPTY WAIT — no child agents existed",
                                    summary=(
                                        "`wait` returned no receiver_thread_ids and "
                                        "no agents_states, so nothing was delegated"
                                        + (f": this turn idled {_idle}s on an empty "
                                           "roster." if _idle is not None else ".")
                                        # NOT "call spawn_agent": it is not
                                        # registered in this deployment, which
                                        # is the whole reason the roster came
                                        # back empty. This line is read by an
                                        # operator, and it used to tell them
                                        # the opposite of what the addendum
                                        # tells main 40 lines above.
                                        + " `spawn_agent` is not registered "
                                        "here — main should write "
                                        "`.scratch/delegate.json` and ring "
                                        "`.scratch/delegate.ring`, or do the "
                                        "work directly."
                                    ),
                                    detail=body[:2000],
                                )
                        emit_gpt_event(
                            event_job_id,
                            "tool_completed",
                            role=event_role,
                            model=event_model,
                            turn=self._turn_count,
                            call_id=item_id,
                            tool=name,
                            status="failed" if item_error else "completed",
                            duration_ms=(
                                int((time.monotonic() - elapsed) * 1000)
                                if elapsed is not None else None
                            ),
                            summary=(
                                "native subagent 응답 수신"
                                if _bare_tool_name(name) == "wait"
                                else " ".join(body.split())[:240]
                            ),
                            output_lines=len(body.splitlines()),
                            output_bytes=len(body.encode("utf-8", errors="replace")),
                            detail=body[:12000],
                            input=raw_input,
                        )
                        if body:
                            yield UserMessage(
                                [
                                    ToolResultBlock(
                                        content=body,
                                        is_error=item_error,
                                        tool_use_id=item_id,
                                    )
                                ]
                            )
                    continue

                if event_type == "turn.completed":
                    turn_completed = True
                    turn_usage = _usage_from_event(event.get("usage"))
                    _merge_usage(self._usage_totals, turn_usage)
                    continue
                if event_type in {"turn.failed", "error"}:
                    error = True
                    stop_reason = (
                        "turn_failed" if event_type == "turn.failed" else "error"
                    )
                    detail = event.get("error") or event.get("message") or event
                    yield AssistantMessage(
                        [
                            TextBlock(
                                f"[Codex CLI {stop_reason}] {_cap_text(_json_text(detail))}"
                            )
                        ]
                    )

            return_code = await self._proc.wait()
            try:
                await stderr_task
            except Exception:
                pass
            if return_code != 0:
                error = True
                stop_reason = "process_error"
                detail = "".join(stderr_parts).strip()
                if detail:
                    yield AssistantMessage(
                        [
                            TextBlock(
                                f"[Codex CLI exited {return_code}] {_cap_text(detail)}"
                            )
                        ]
                    )
            elif not turn_completed and not error:
                error = True
                stop_reason = "unexpected_eof"
                yield AssistantMessage(
                    [TextBlock("[Codex CLI ended before turn.completed]")]
                )
        except asyncio.TimeoutError:
            error = True
            stop_reason = "timeout"
            await self._stop_process()
            yield AssistantMessage(
                [TextBlock(f"[Codex CLI turn timed out after {timeout:.0f}s]")]
            )
        finally:
            # Normal completion is already reaped, so this is a cheap no-op in
            # the common case.  On cancellation or any other BaseException it is
            # the only owner-aware cleanup path: terminate the process group
            # before discarding the handle that close() would otherwise need.
            await self._stop_process()
            if not stderr_task.done():
                stderr_task.cancel()
            try:
                await stderr_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self._proc = None
            release_turn_guard(turn_guard)

        duration_ms = int((time.monotonic() - started) * 1000)
        emit_gpt_event(
            event_job_id,
            "turn_failed" if error else "turn_completed",
            role=event_role,
            model=event_model,
            turn=self._turn_count,
            status="failed" if error else "completed",
            stop_reason=stop_reason,
            duration_ms=duration_ms,
            title="Turn 실패" if error else "Turn 완료",
        )
        if turn_usage:
            yield AssistantMessage([], usage=_heartbeat_usage(turn_usage))
        yield self._result(started, error, stop_reason)

    def _result(
        self,
        started: float,
        error: bool,
        stop_reason: str,
    ) -> ResultMessage:
        model_usage = {}
        if any(self._usage_totals.values()):
            model_usage[str(self.options.model)] = dict(self._usage_totals)
        return ResultMessage(
            duration_ms=int((time.monotonic() - started) * 1000),
            num_turns=self._turn_count,
            total_cost_usd=None,
            is_error=error,
            stop_reason=stop_reason,
            usage=dict(self._usage_totals),
            session_id=self.session_id,
            model_usage=model_usage,
        )

    async def _collect_stderr(
        self, stream: asyncio.StreamReader, parts: list[str]
    ) -> None:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            if sum(len(part) for part in parts) < MAX_STDERR_CHARS:
                parts.append(chunk.decode("utf-8", errors="replace"))

    async def _stop_process(self) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        # The fallback has to be guarded for the same reason it exists. A
        # ProcessLookupError from killpg most often means the whole group is
        # already gone — so `proc.terminate()` raises it straight back, out of
        # a teardown path whose entire job is to not care whether the child
        # outlived us. Measured flaky, not theoretical: 2 red in 4 runs of
        # test_codex_cli.py, traceback at the unguarded proc.kill.
        #
        # ProcessLookupError ONLY. The first version caught OSError too, which
        # made EPERM and EIO — genuine "could not clean up" failures — return
        # as if teardown had succeeded. That does not remove a flake, it
        # removes the observation of one. Narrowing still closes the race this
        # guard exists for: repeats stay green with EPERM left to propagate.
        #
        # The returncode check at the top of this method cannot close the
        # window either — the process can exit between that check and here.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                proc.terminate()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
            return
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                return
        try:
            await proc.wait()
        except Exception:
            pass


async def query_codex_once(
    *,
    prompt: str,
    cwd: str,
    system_prompt: str,
    model: str,
    effort: str | None = None,
    timeout_s: float | None = None,
    enable_tools: bool = False,
    enable_subagents: bool = False,
) -> dict[str, Any]:
    """Run one Codex OAuth turn and return the provider-neutral helper view."""
    options = GptSessionOptions(
        system_prompt=system_prompt,
        model=model,
        cwd=cwd,
        effort=effort,
        turn_timeout_s=timeout_s,
        append_tool_addendum=enable_tools,
        enable_tools=enable_tools,
        enable_subagents=enable_subagents,
    )
    text_parts: list[str] = []
    result: ResultMessage | None = None
    tool_used = False
    try:
        async with CodexCLIClient(options) as client:
            await client.query(prompt)
            async for message in client.receive_response(turn_timeout_s=timeout_s):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text_parts.append(block.text)
                        elif isinstance(block, ToolUseBlock):
                            tool_used = True
                elif isinstance(message, ResultMessage):
                    result = message
    except Exception as exc:
        return {
            "text": "".join(text_parts),
            "error": f"{type(exc).__name__}: {exc}",
        }
    error_text = None
    if tool_used and not enable_tools:
        error_text = "tool_use_in_text_only_role: Codex attempted a tool call"
    elif result is not None and result.is_error:
        error_text = f"Codex CLI turn ended with {result.stop_reason or 'error'}"
    return {
        "text": "".join(text_parts),
        "error": error_text,
        "session_id": getattr(result, "session_id", None),
        "usage": getattr(result, "usage", {}) if result else {},
        "model_usage": getattr(result, "model_usage", {}) if result else {},
    }
