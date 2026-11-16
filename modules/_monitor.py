"""Per-job live MONITOR — a curated, LLM-narrated signal feed over run.log.

Why this exists
---------------
`run.log` is a raw human tail: a long pwn job emits ~1000 lines, ~96% of them
`[main] TOOL`/`TOOL_RESULT` echo. Reading it live to understand "what is the
agent actually doing" means eyeballing that noise. The MONITOR is the answer:
a background task filters run.log to meaningful SIGNAL events (stage/status
changes, `[main] AGENT:` prose, `[orchestrator]` subagent lifecycle, judge /
prejudge / retry, errors, `FLAG_CANDIDATE`), batches them, and asks a cheap
model to narrate WHAT JUST HAPPENED in one short line — in every configured
language (default ko + en). The result is appended to `<job>/monitor.jsonl`
and published to the Redis channel `job:<id>:monitor` so the SSE stream can
push it live to the UI, next to the raw run log, with a language selector.

Design
------
* HYBRID: structured meta changes (stage/status/flag) get a deterministic,
  localized entry (no LLM); prose signal batches get an LLM narration.
* LIVE / always-on: an async supervisor (started from api.main) sweeps
  running jobs every few seconds and ensures a monitor task per job — so
  commentary is generated even if nobody is watching (opt-out via
  MONITOR_ENABLED=0). A cheap model is pinned (MONITOR_MODEL, default
  sonnet) — NEVER the job's own opus, which would be waste.
* Runs in the API container (has claude-agent-sdk + ~/.claude/.env auth +
  the /data mount + redis), which is free of the worker's exploit-run glibc
  pollution that can break CLI spawns.
* Best-effort: every failure is swallowed — observability must never break
  the pipeline it observes, and must never touch run.log/meta.json.

This module is import-light: it talks to redis directly and imports the SDK
lazily inside the narration call, so importing it from api/ is cheap and
side-effect-free.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from modules._sdk_buffer import AGENT_MAX_BUFFER_BYTES

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
JOBS_DIR = DATA_DIR / "jobs"

MONITOR_ENABLED = os.environ.get("MONITOR_ENABLED", "1") != "0"


def monitor_enabled() -> bool:
    """Both switches must say yes before a monitor task is created.

    Two gates, deliberately, because they answer different questions:

      MONITOR_ENABLED (env)   — "this deployment cannot run it at all".
                                Unchanged, still an absolute kill switch.
      monitor_agent (setting) — "the operator wants it", flippable from the
                                Settings UI without restarting the API.

    The setting defaults to OFF (settings_io.monitor_agent_enabled), which is
    what retires this agent without deleting a line of it: every function
    below still exists and still works, and turning the toggle back on
    restores the feature exactly as it was.

    Resolved per call, never captured at import — a module-level constant
    would freeze the operator's choice until the next API restart, and the
    whole point of a UI toggle is that it takes effect now.
    """
    if not MONITOR_ENABLED:
        return False
    try:
        from modules.settings_io import monitor_agent_enabled
    except Exception:
        return False
    try:
        return bool(monitor_agent_enabled())
    except Exception:
        return False
MONITOR_MODEL = os.environ.get("MONITOR_MODEL", "claude-sonnet-4-6")
MONITOR_LANGS = tuple(
    x.strip() for x in os.environ.get("MONITOR_LANGS", "ko,en").split(",") if x.strip()
) or ("ko", "en")

_LANG_NAMES = {
    "ko": "Korean", "en": "English", "ja": "Japanese", "zh": "Chinese",
    "es": "Spanish", "fr": "French", "de": "German", "ru": "Russian",
}


def _monitor_langs() -> tuple[str, ...]:
    """Which languages this feed is narrated in — resolved PER CALL.

    The output-language setting used to steer the solving prompts: main,
    recon, judge, reviewer, report, the Codex resume, the GPT children. It
    does not any more. The agents work best in English and telling them to
    think in another one bought nothing the operator could read anyway — the
    artefacts that matter (report.md, findings.json, the flag) are technical.
    What the operator DOES read live is this feed, so the setting now picks
    its language and nothing else.

    `auto` keeps both, which is what the UI's language selector expects. A
    pinned language narrates once instead of twice, which also halves what
    this role spends per batch.

    Per call, never captured at import: a module-level constant would freeze
    the operator's choice until the next API restart, and this file already
    learned that lesson once with `monitor_enabled`.
    """
    try:
        from modules.output_language import resolve_output_language
        lang = resolve_output_language()
    except Exception:
        return MONITOR_LANGS
    return (lang,) if lang in _LANG_NAMES else MONITOR_LANGS

# `hold` is not the end of a run — the operator is expected to supply a new
# remote target and resume it. It belongs here anyway because this set means
# "stop watching", not "the job is over": a held run appends nothing to
# run.log, so a watcher parked on it never flushes and never releases its
# slot. Re-attaching is safe because the read offset lives in the statefile,
# so the supervisor picks the job back up at the right byte on resume.
_TERMINAL = {"finished", "failed", "no_flag", "stopped", "flag_ready",
             "hold"}

POLL_S = 4.0          # run.log / meta.json poll cadence
BATCH_MAX = 6         # flush the pending signal batch once it reaches this many
BATCH_MAX_S = 9.0     # ...or once this long has elapsed with >=1 pending
BACKLOG_SKIP = 8192   # if a fresh monitor attaches to a log already bigger than
                      # this, skip narrating the backlog (start live)
_NARRATE_TIMEOUT_S = 60
# Local inference is slower per call than a hosted one and has no queue in
# front of it. Measured on this box: 16.7-29.0 s for a monitor batch on
# gemma4-heretic (11.9B Q4, fully resident in VRAM). 120 s leaves room for a
# cold load — the first call after a model is evicted pays ~14 s extra — and
# still fails rather than hanging the watcher.
_LOCAL_TIMEOUT_S = 120
# Per-signal-line ceiling, applied at INGEST so it bounds all four consumers at
# once: classify(), the narration prompt, the redis publish, and the `raw` field
# persisted in monitor.jsonl. The monitor narrates — it never needed a full tool
# result — and run.log keeps the untruncated line for search. See the rationale
# at the clip site in run_monitor().
_MONITOR_BODY_MAX = 2000

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

# ---------------------------------------------------------------------------
# redis publish (own tiny client — keep this module independent of _common)
# ---------------------------------------------------------------------------
_redis = None
_redis_failed = False


def _get_redis():
    global _redis, _redis_failed
    if _redis is not None:
        return _redis
    if _redis_failed:
        return None
    try:
        from redis import Redis
        _redis = Redis.from_url(_REDIS_URL, socket_timeout=1, socket_connect_timeout=1)
    except Exception:
        _redis_failed = True
        return None
    return _redis


def _publish(job_id: str, entry: dict) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.publish(f"job:{job_id}:monitor", json.dumps(entry, ensure_ascii=False))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# signal classification (deterministic filter over a run.log line body)
# ---------------------------------------------------------------------------
# `body` = the run.log line WITHOUT the "[HH:MM:SS] " timestamp prefix, e.g.
# "[main] AGENT: ...", "[orchestrator] isolated recon#1 done ...",
# "[judge] prejudge BLOCKED ...". Returns (kind, severity) or None to drop.

_SEV_RANK = {"info": 0, "good": 1, "warn": 2, "err": 3}

_RE_TOOLECHO = re.compile(r"\bTOOL (Bash|Read|Edit|Write|mcp)\b|TOOL_RESULT|\bTHINK\b")
_RE_ARTIFACT = re.compile(r"TOOL (Write|Edit)[^\n]*(exploit|solver)\.py")

# Lines the AGENT ITSELF authored: its tool INPUT (`TOOL Bash: {"command": ...}`,
# `TOOL mcp__team__spawn_subagent: {"prompt": ...}`) and its own prose
# (`AGENT: ...`). Nothing here is an error EVENT — it is the agent talking.
#
# This distinction is the single biggest correctness fix in this file. Measured
# on one pwn run: 5 of 7 kind=error entries were false, and every one was
# the error regex hitting text the agent had WRITTEN rather than output it
# RECEIVED —
#   "Exception:"  inside a Python heredoc the agent was composing
#   "SIGSEGV"     inside a tool `description` ("Trigger SIGSEGV with …")
#   "SIGSEGV"     inside a subagent prompt the agent was drafting
#   "SIGSEGV"     in prose stating there is NO SIGSEGV handler — the opposite
# An err badge that is wrong 5 times out of 7 is worse than no badge: the two
# REAL errors in that run (a Traceback and a BrokenPipeError) were unfindable.
_RE_AGENT_AUTHORED = re.compile(r"\] (?:TOOL (?:Bash|Read|Edit|Write|mcp)\S*:|AGENT:)")

# FILE CONTENT the agent asked for, echoed back through TOOL_RESULT. Read
# output is `<lineno>\t<source>`; grep output is `<path>:<lineno>:<source>`.
# Neither is an EVENT — it is data — but both arrive on a TOOL_RESULT line,
# which the agent-authored rule above counts as "received" and therefore
# eligible to be an error.
#
# Job e601cd358ad6 shows the cost: the agent Read its own exploit.py and the
# source lines
#     [main] TOOL_RESULT: 93\t            except OSError:
#     [main] TOOL_RESULT: 110\t        except OSError:
# matched the exception-class pattern, so an entry whose narration is plainly
# "agent initialising: anchoring cwd, reading prior artifacts" was badged err.
# Code that HANDLES an error is not an error. The same line shape also carries
# SIGSEGV mentions into the crash bucket for the same wrong reason.
_RE_FILE_CONTENT = re.compile(
    r"TOOL_RESULT:\s*(?:\d+\t|[^\s:]+:\d+:)"
)

# Genuine failure output. `Exception:` alone used to be here and was far too
# loose; requiring the Python exception-class SHAPE keeps BrokenPipeError /
# ValueError / bare Exception while ignoring the word in prose.
_RE_ERROR = re.compile(
    # TOOL_ERROR is the orchestrator's own marker for a failed tool call. It
    # happens to match the exception-class pattern below, but naming it makes
    # that intentional rather than a coincidence of spelling. Two real
    # pre-recon failures ("TOOL_ERROR: Exit code 1") were previously filed as
    # phase/info and lost.
    r"TOOL_ERROR\b|traceback \(most recent call last\)|"
    r"\b[A-Za-z_]\w*(?:Error|Exception)\s*:|"
    r"budget_abort|\bkilled\b|connection refused|could not connect|broken pipe",
    re.I,
)

# A crash is the GOAL in pwn/rev, not a fault: the agent deliberately segfaults
# the target to observe its state or to prove a primitive. Reporting that as
# an error inverts the meaning of the run's most important progress signal, so
# these get their own kind and a severity that depends on the module.
_RE_CRASH = re.compile(r"sigsegv|segfault|core dumped", re.I)
_CRASH_IS_EXPECTED = {"pwn", "rev"}

_RE_JUDGE = re.compile(r"prejudge|postjudge|\bjudge\b|verdict|blocked ship", re.I)
# `attempt 0/` is the FIRST attempt — a plain turn boundary, not a retry. The
# old `attempt \d+/` matched it, so every run emitted a warn-level "retry"
# entry narrated from the single line "Main session turn (attempt 0/∞)", which
# the narrator could only render as "no signal data".
_RE_RETRY = re.compile(r"attempt [1-9]\d*/|auto-retry|retry_hint|contrarian|redirect|halting", re.I)
# Pure bookkeeping — carries no information a narration could add to.
_RE_TURN_MARKER = re.compile(r"^main session turn \(attempt \d+/", re.I)
_RE_SUBAGENT = re.compile(r"\[orchestrator\]|spawning|isolated ", re.I)
_RE_AGENT = re.compile(r"\] AGENT:")
_RE_PHASE = re.compile(r"\[(runner|report|sandbox|autoboot|pre-recon)\]", re.I)


def classify(body: str, module: str = "") -> tuple[str, str] | None:
    """(kind, severity) for one run.log body, or None to drop it.

    `module` selects crash semantics — see _RE_CRASH.
    """
    # Bookkeeping with nothing to narrate.
    if _RE_TURN_MARKER.match(body.strip()):
        return None
    # FLAG and ERROR are checked BEFORE the tool-echo skip: a captured flag or a
    # crash/connection error often surfaces inside a TOOL_RESULT line (e.g.
    # "[main] TOOL_RESULT: Could not connect to host"), and dropping those as
    # "tool echo" would lose the two most important signals.
    if "FLAG_CANDIDATE:" in body and "{" in body:
        return ("flag", "good")
    # THREE kinds of text, three treatments — conflating any two of them is
    # what produced every false badge this classifier has had:
    #
    #   DATA    file content the agent READ back. Neither intent nor event;
    #           drops to the tool-echo path below like any other echo. Must be
    #           checked FIRST: it arrives on a TOOL_RESULT line, so the
    #           "received" rule would otherwise let its source code — `except
    #           OSError:`, a comment mentioning SIGSEGV — become an event.
    #   INTENT  what the agent WROTE: a command body, a subagent prompt, its
    #           own prose. Never a failure, but a crash mention here is worth
    #           surfacing ("about to segfault the target").
    #   EVENT   everything else — output the agent RECEIVED, orchestrator and
    #           runner lines. Only these can be a failure.
    if _RE_FILE_CONTENT.search(body):
        return ("artifact", "info") if _RE_ARTIFACT.search(body) else None

    agent_authored = bool(_RE_AGENT_AUTHORED.search(body))
    if not agent_authored and _RE_ERROR.search(body):
        return ("error", "err")
    # Crash detection runs on agent-authored lines TOO, because in pwn the
    # agent announcing "Trigger SIGSEGV with the PoC input" IS the
    # interesting moment. Restricting it to received output dropped that entry
    # from the feed entirely — trading a wrong badge for a missing event, which
    # is not an improvement. Reported as its own kind at info: informative,
    # not alarming.
    if _RE_CRASH.search(body):
        if module in _CRASH_IS_EXPECTED:
            return ("crash", "info")
        if not agent_authored:
            return ("error", "err")
    if _RE_TOOLECHO.search(body):
        # tool echo is noise — except an exploit/solver write, which is a real
        # milestone worth surfacing.
        if _RE_ARTIFACT.search(body):
            return ("artifact", "info")
        return None
    if _RE_JUDGE.search(body):
        return ("judge", "warn")
    if _RE_RETRY.search(body):
        return ("retry", "warn")
    if _RE_SUBAGENT.search(body):
        return ("subagent", "info")
    if _RE_AGENT.search(body):
        return ("agent", "info")
    if _RE_PHASE.search(body):
        return ("phase", "info")
    return None


# ---------------------------------------------------------------------------
# entry construction + emit
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entry(kind: str, sev: str, text: dict, *, raw: list | None = None, **extra) -> dict:
    e: dict[str, Any] = {
        "ts": _now_iso(),
        "kind": kind,
        "sev": sev,
        "text": text,
        "raw": raw or [],
    }
    if extra:
        e.update(extra)
    return e


# --- findings ---------------------------------------------------------------
# The narrator already reads every batch, so naming a concrete weakness costs
# no extra call and no extra spend. What this is NOT: a second flag channel or
# a replacement for report.md. It is the running answer to "what has this job
# found so far", which previously existed only as prose in run.log — answering
# it meant grepping `[main] AGENT` lines by timestamp.
#
# Deduped on the finding's own identity, not on narration similarity: a
# repeated narration is noise and `_flush_batch` drops it, but the agent
# restating a real finding must not create a second row.
_VULN_SEEN: dict[str, set] = {}


def _vuln_key(v: dict) -> str:
    norm = lambda s: re.sub(r"\s+", " ", str(s or "")).strip().lower()
    return f"{norm(v.get('title'))}|{norm(v.get('where'))}"


def _seen_vulns(job_id: str) -> set:
    """Keys already in monitor.jsonl — seeded once so an API restart (which
    kills and re-creates the watcher) does not re-announce old findings."""
    key = str(job_id)
    if key in _VULN_SEEN:
        return _VULN_SEEN[key]
    seen: set = set()
    try:
        p = JOBS_DIR / Path(job_id).name / "monitor.jsonl"
        if p.is_file():
            for line in p.read_text(errors="replace").splitlines()[-400:]:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("kind") == "vuln" and isinstance(e.get("vuln"), dict):
                    seen.add(_vuln_key(e["vuln"]))
    except Exception:
        pass
    _VULN_SEEN[key] = seen
    return seen


def _known_vuln_titles(job_id: str, limit: int = 12) -> tuple[str, ...]:
    """Findings already on the panel, newest last.

    Fed back into the narration prompt so the model can recognise its own
    restatement. Measured need: on job 7dc1be932b26 the panel filled with
    EIGHT rows that were one finding, worded eight ways. The exact-key dedup below
    never fires on those, and the character-bigram floor this file already
    uses for narrations catches NONE of them at its 0.80 threshold (measured
    against those very eight). Lowering that threshold would collapse
    genuinely different findings instead, so the judgement has to be
    semantic — and the model is already reading this batch.
    """
    out: list[str] = []
    try:
        p = JOBS_DIR / Path(job_id).name / "monitor.jsonl"
        if p.is_file():
            for line in p.read_text(errors="replace").splitlines()[-400:]:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("kind") == "vuln" and isinstance(e.get("vuln"), dict):
                    ttl = str(e["vuln"].get("title") or "").strip()
                    if ttl:
                        out.append(ttl)
    except Exception:
        return ()
    return tuple(out[-limit:])


def _emit_vuln(job_id: str, v: dict, bodies: list[str]) -> None:
    try:
        seen = _seen_vulns(job_id)
        k = _vuln_key(v)
        if not k.strip("|") or k in seen:
            return
        seen.add(k)
        grade = str(v.get("severity") or "medium").lower()
        # Map onto the feed's OWN severity vocabulary rather than adding
        # values the row renderer has no icon for.
        sev = "err" if grade in ("high", "critical") else "warn"
        where = v.get("where") or ""
        tail = f" ({where})" if where else ""
        _emit(job_id, _entry(
            "vuln", sev,
            {"ko": f"취약점 [{grade}] {v.get('title')}{tail}",
             "en": f"vuln [{grade}] {v.get('title')}{tail}"},
            raw=bodies[-2:], vuln=v))
    except Exception:
        # A findings fault must never break narration, which is the feed's
        # actual job.
        pass


def _emit(job_id: str, entry: dict) -> None:
    """Append to <job>/monitor.jsonl and publish to redis. Best-effort."""
    try:
        p = JOBS_DIR / Path(job_id).name / "monitor.jsonl"
        if not p.parent.is_dir():
            return
        with p.open("a") as fp:
            fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
    _publish(job_id, entry)


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# LLM narration of a signal batch (cheap model, strict-JSON multi-language)
# ---------------------------------------------------------------------------
def _narrate_sys_prompt(known: tuple[str, ...] = ()) -> str:
    langs = _monitor_langs()
    want = ", ".join(
        f'"{l}" ({_LANG_NAMES.get(l, l)})' for l in langs
    )
    return (
        "You are a live MONITOR for an autonomous CTF-solving agent run. "
        "You receive a small batch of already-filtered raw log SIGNAL lines from "
        "one moment of the run (agent prose, subagent lifecycle, judge/retry, "
        "errors, artifacts). Summarize WHAT JUST HAPPENED in ONE short, concrete, "
        "technical line per language (max ~160 chars each). Plain text, no markdown, "
        "no line breaks within a value. "
        "Korean (ko) lines MUST be written in Hangul (한국어), not English. "
        "English (en) lines in English. "
        f"The vuln object's \"title\" and \"why\" use {_LANG_NAMES.get(langs[0], langs[0])} "
        "as well; its \"where\" is a path or endpoint and stays verbatim. "
        f"Respond with STRICT JSON ONLY — an object whose keys are exactly {want}"
        ", plus an OPTIONAL \"vuln\" key described next. "
        "No prose, no code fences, nothing but the JSON object.\n\n"
        "VULN — include this key ONLY when these lines ASSERT a concrete "
        "security weakness in the TARGET that the agent has identified. Shape: "
        '{"title": "<=80 chars", "severity": "low|medium|high|critical", '
        '"where": "file.py:123 | endpoint | component", "why": "<=160 chars, '
        'the mechanism"}. '
        "Omit the key entirely — do not send null, do not invent one — when the "
        "batch is progress, tooling, setup, a plan, a question, or a hypothesis "
        "the agent has not yet confirmed. A plan to look for a bug is not a "
        "finding. Report the weakness in the challenge, never a problem with "
        "the agent's own scripts or environment. One vuln per batch at most: "
        "pick the most specific."
        + (
            "\n\nALREADY REPORTED — do not send a vuln that is any of these "
            "said differently. The agent restates its own findings as it "
            "works, and a panel of one finding worded eight ways is worse "
            "than no panel: every row is an action the operator might take. "
            "Same underlying weakness = same finding, even when this batch "
            "names a different file, a different symptom, or a narrower case "
            "of it. Send a vuln ONLY for a weakness that is not in this "
            "list:\n" + "\n".join(f"  - {k}" for k in known)
            if known else ""
        )
    )


def _parse_narration_json(acc: str) -> dict:
    """Parse model JSON into {lang: line}. Empty dict on any failure."""
    langs = _monitor_langs()
    acc = (acc or "").strip()
    if not acc:
        return {}
    if acc.startswith("```"):
        acc = acc.split("\n", 1)[1] if "\n" in acc else acc[3:]
        if acc.endswith("```"):
            acc = acc[:-3]
        acc = acc.strip()
    # Tolerate a leading/trailing prose wrapper by carving the outermost object.
    if "{" in acc and "}" in acc:
        acc = acc[acc.find("{"): acc.rfind("}") + 1]
    try:
        d = json.loads(acc)
        if not isinstance(d, dict):
            return {}
        out = {l: str(d.get(l, "")).strip() for l in langs}
        # Optional structured finding. Validated here rather than at the call
        # site so a malformed one is simply absent, never half-present.
        v = d.get("vuln")
        if isinstance(v, dict):
            title = str(v.get("title") or "").strip()
            if title:
                out["vuln"] = {
                    "title": title[:160],
                    "severity": (str(v.get("severity") or "").strip().lower()
                                 or "medium"),
                    "where": str(v.get("where") or "").strip()[:200],
                    "why": str(v.get("why") or "").strip()[:400],
                }
        # Require at least one non-empty LANGUAGE line. `out` may now also
        # carry "vuln", and counting that as content would let a narration
        # with no prose at all through the gate.
        if not any(out.get(l) for l in langs):
            return {}
        return out
    except Exception:
        return {}


def _prefer_grok_narration(model: str) -> bool:
    """True when the job/settings path wants Grok, or the model id is Grok."""
    m = (model or "").strip().lower()
    if m.startswith("grok"):
        return True
    try:
        from modules.agent_provider import active_provider, has_grok_auth
        if active_provider() == "grok" and has_grok_auth():
            return True
    except Exception:
        pass
    # Claude weekly-limit era: if Claude auth is dead but Grok works, prefer Grok.
    try:
        from modules.agent_provider import has_grok_auth
        from modules.settings_io import has_claude_auth
        if has_grok_auth() and not has_claude_auth():
            return True
    except Exception:
        pass
    return False


def _prefer_gpt_narration(model: str) -> bool:
    """True when the selected stack/model is OpenAI GPT."""
    m = (model or "").strip().lower()
    if m.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return True
    try:
        from modules.agent_provider import active_provider, has_openai_auth
        return active_provider() == "gpt" and has_openai_auth()
    except Exception:
        return False


async def _narrate_claude(signal_lines: list[str], model: str,
                          known: tuple[str, ...] = ()) -> dict:
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        import anyio
    except Exception:
        return {}

    prompt = "SIGNAL LINES:\n" + "\n".join(signal_lines[-12:])
    options = ClaudeAgentOptions(
        max_buffer_size=AGENT_MAX_BUFFER_BYTES,
        system_prompt=_narrate_sys_prompt(known),
        model=model,
        allowed_tools=[],
        disallowed_tools=["Agent", "Task", "WebSearch", "WebFetch", "Bash",
                          "Read", "Write", "Edit", "Glob", "Grep"],
        permission_mode="bypassPermissions",
    )
    acc = ""
    try:
        with anyio.fail_after(_NARRATE_TIMEOUT_S):
            async for msg in query(prompt=prompt, options=options):
                cls = type(msg).__name__
                if cls == "AssistantMessage":
                    for block in getattr(msg, "content", []) or []:
                        if type(block).__name__ == "TextBlock":
                            acc += getattr(block, "text", "") or ""
                elif cls == "ResultMessage":
                    if getattr(msg, "is_error", False):
                        return {}
    except Exception:
        return {}
    return _parse_narration_json(acc)


def ollama_base_url() -> str:
    """Where Ollama answers, or "" when the operator has not said.

    Empty is meaningful: it separates "there is no local runtime here" from
    "there is one and it is down". The UI shows those differently and so does
    the narrator — an unconfigured local target is skipped, a configured one
    that fails is a fault.
    """
    try:
        from modules.settings_io import get_setting
        raw = str(get_setting("ollama_url") or "").strip()
    except Exception:
        raw = ""
    if not raw:
        raw = os.environ.get("OLLAMA_URL", "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw.rstrip("/")


# A [Local] pin is strict on purpose: it never falls through to a paid model,
# because not spending was the reason to choose it. The price of that
# strictness is a feed of raw snippets with no stated cause, which reads as
# "the narrator is broken" rather than "nobody filled the URL in". Say which
# it is, once per job.
_LOCAL_CFG_WARNED: set[str] = set()


def _local_cfg_gap(provider: str | None, model: str | None) -> str:
    """What Settings still needs before a [Local] monitor can narrate.

    Mirrors the two early `return {}` guards in `_narrate_local` exactly, so
    the warning cannot claim a gap the narrator would have tolerated, nor
    stay quiet about one that silently costs every batch its narration.
    """
    if str(provider or "").strip().lower() != "local":
        return ""
    missing: list[str] = []
    if not ollama_base_url():
        missing.append("Ollama URL")
    if not ((model or "").strip() or os.environ.get("OLLAMA_MODEL", "").strip()):
        missing.append("Ollama model")
    return " / ".join(missing)


async def _narrate_local(signal_lines: list[str], model: str | None = None,
                         known: tuple[str, ...] = ()) -> dict:
    """Narrate through Ollama on this box, with the model's THINKING OFF.

    That flag is the whole difference between usable and unusable, and the
    earlier explanation here (raise `num_predict` until it answers) was wrong
    about which ceiling was being hit. gemma4-heretic reasons before it
    answers, and `num_predict` never bounded that — `num_ctx` did. Measured,
    one narration of six log lines:

        think on   →  75.0 s, done_reason=length, content 0 chars,
                      thinking 11,181 chars, prompt 467 + eval 3629 = 4096,
                      which is exactly n_ctx_slot. The model spent its ENTIRE
                      context reasoning and never emitted a visible token.
        think off  →   2.9 s, done_reason=stop, content 358 chars of valid
                      JSON, eval 110 tokens.

    Fifteen times faster, and the zero-length answers stop happening at all.
    Six log lines summarised in one sentence is not a problem that repays
    eleven thousand characters of deliberation.

    It is also what makes the local monitor survive a full board. Ollama runs
    ONE slot here (`num_parallel` unset → 1), so concurrent jobs serialise.
    Measured across 15 simultaneous narrations, thinking off:

        k= 1  p50  2.6 s      k= 8  p50 12.7 s
        k= 4  p50  8.0 s      k=15  p50 20.6 s   —  0 failures at every k

    Throughput holds at 0.39 req/s. A job flushes at most one batch per
    BATCH_MAX_S (9 s) and never has two in flight, so the board needs
    0.111 req/s per active job: ~3.5 jobs narrating CONTINUOUSLY, and more in
    practice because signal arrives in bursts. With thinking on the same run
    managed 0.02 req/s and returned EMPTY for 8 of 15.

    `num_predict` stays uncapped — with thinking off the answer is ~110
    tokens, so there is nothing left to cap.
    """
    base = ollama_base_url()
    if not base:
        return {}
    mdl = (model or "").strip() or os.environ.get("OLLAMA_MODEL", "")
    if not mdl:
        return {}
    payload = {
        "model": mdl,
        "stream": False,
        # Ignored by models that do not think; decisive for the ones that do.
        "think": False,
        "options": {"temperature": 0.2, "num_predict": -1},
        "messages": [
            {"role": "system", "content": _narrate_sys_prompt(known)},
            {"role": "user",
             "content": "SIGNAL LINES:\n" + "\n".join(signal_lines[-12:])},
        ],
    }
    try:
        import anyio

        def _post() -> str:
            import json as _json
            import urllib.request
            req = urllib.request.Request(
                f"{base}/api/chat",
                data=_json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=_LOCAL_TIMEOUT_S) as r:
                body = _json.loads(r.read().decode("utf-8", "replace"))
            return str(((body or {}).get("message") or {}).get("content") or "")

        with anyio.fail_after(_LOCAL_TIMEOUT_S + 5):
            acc = await anyio.to_thread.run_sync(_post)
    except Exception:
        return {}
    return _parse_narration_json(acc)


async def _narrate_grok(signal_lines: list[str], model: str | None = None,
                        known: tuple[str, ...] = ()) -> dict:
    """Narrate via Grok Build ACP (api container must have ~/.grok + binary)."""
    try:
        from modules.grok_acp import query_grok_once, resolve_grok_bin
        from modules.agent_provider import default_model_for
        resolve_grok_bin()  # fail fast if binary missing
    except Exception:
        return {}

    grok_model = (model or "").strip()
    if not grok_model or grok_model.lower().startswith("claude"):
        try:
            grok_model = default_model_for("grok")
        except Exception:
            grok_model = "grok-4.6"
    # Prefer a fast model for live commentary when possible.
    if grok_model in ("grok-build", ""):  # grok-build is retired; treat it as unset
        grok_model = os.environ.get("MONITOR_GROK_MODEL", "grok-4.5")

    prompt = "SIGNAL LINES:\n" + "\n".join(signal_lines[-12:])
    try:
        r = await query_grok_once(
            prompt=prompt,
            cwd="/tmp",
            system_prompt=_narrate_sys_prompt(known),
            model=grok_model,
            effort="low",
            timeout_s=float(_NARRATE_TIMEOUT_S),
        )
    except Exception:
        return {}
    if r.get("error"):
        return {}
    return _parse_narration_json(r.get("text") or "")


async def _narrate_gpt(signal_lines: list[str], model: str | None = None,
                       known: tuple[str, ...] = ()) -> dict:
    """Narrate via the selected Codex OAuth / GPT API runtime (text-only)."""
    try:
        from modules.gpt_agent import query_gpt_once
        from modules.agent_provider import default_model_for
    except Exception:
        return {}
    gpt_model = (model or "").strip()
    if not gpt_model or gpt_model.lower().startswith(("claude", "grok")):
        gpt_model = default_model_for("gpt")
    prompt = "SIGNAL LINES:\n" + "\n".join(signal_lines[-12:])
    try:
        r = await query_gpt_once(
            prompt=prompt,
            cwd="/tmp",
            system_prompt=_narrate_sys_prompt(known),
            model=gpt_model,
            effort="low",
            timeout_s=float(_NARRATE_TIMEOUT_S),
            enable_tools=False,
        )
    except Exception:
        return {}
    return {} if r.get("error") else _parse_narration_json(r.get("text") or "")


async def _narrate(signal_lines: list[str], model: str,
                   known: tuple[str, ...] = (),
                   provider: str | None = None) -> dict:
    """Return {lang: one-line summary} for the batch, or {} on any failure.

    When Settings ``agent_provider=grok`` (or the model id is Grok), use
    Grok ONLY — do not fall back to Claude (operator chose Grok for the
    whole stack). Claude-selected jobs still try Claude first, then Grok
    once as a weekly-limit escape hatch.
    """
    if not signal_lines:
        return {}

    # Local is decided by the ROUTED PROVIDER, never by the model id: a local
    # tag is whatever the operator pulled (`gemma4-heretic:latest`), so there
    # is no family prefix to match on the way `grok-`/`gpt-` are matched.
    prefer_local = str(provider or "").strip().lower() == "local"
    prefer_gpt = _prefer_gpt_narration(model)
    prefer_grok = _prefer_grok_narration(model)
    # Selected non-Claude providers are strict; Claude keeps its Grok escape
    # hatch for historical weekly-limit failures.
    if prefer_local:
        order = ("local",)
    elif prefer_gpt:
        order = ("gpt",)
    elif prefer_grok:
        order = ("grok",)
    else:
        order = ("claude", "grok")
    for backend in order:
        try:
            if backend == "local":
                out = await _narrate_local(signal_lines, model, known)
            elif backend == "gpt":
                out = await _narrate_gpt(signal_lines, model, known)
            elif backend == "grok":
                out = await _narrate_grok(signal_lines, model, known)
            else:
                out = await _narrate_claude(signal_lines, model, known)
        except Exception:
            out = {}
        if out:
            # Drop empty language keys so UI can fall through, but keep filled ones.
            cleaned = {k: v for k, v in out.items() if v}
            if cleaned:
                # Ensure every MONITOR_LANGS key exists (empty → UI falls back).
                projected = {l: cleaned.get(l, "") for l in _monitor_langs()}
                # ...and carry the finding THROUGH this projection. Rebuilding
                # the dict from MONITOR_LANGS alone silently dropped it here,
                # between a parser that produced it and a caller that emits
                # it — both of which had guards, while the seam between them
                # did not. The model was returning `vuln` the whole time.
                if isinstance(cleaned.get("vuln"), dict):
                    projected["vuln"] = cleaned["vuln"]
                return projected
    return {}


def _norm_for_dedup(t: str) -> str:
    """Comparison form for near-duplicate detection: letters and digits only."""
    return re.sub(r"[^0-9a-z\uac00-\ud7a3]+", "", (t or "").lower())


def _too_similar(a: str, b: str) -> bool:
    """True when two narrations say the same thing.

    Character-bigram Jaccard, not equality: the narrator rephrases. On one
    job two entries 108 s apart described the same fix in different words,
    and there was no suppression of any kind.
    """
    na, nb = _norm_for_dedup(a), _norm_for_dedup(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    if min(len(na), len(nb)) < 12:
        return False
    ga = {na[i:i + 2] for i in range(len(na) - 1)}
    gb = {nb[i:i + 2] for i in range(len(nb) - 1)}
    inter = len(ga & gb)
    union = len(ga | gb) or 1
    return inter / union >= 0.80


async def _flush_batch(job_id: str, batch: list[tuple[str, tuple[str, str]]],
                       model: str, *, turns: int | None = None,
                       recent: list[str] | None = None,
                       provider: str | None = None) -> None:
    """batch = [(body, (kind, sev)), ...]. Narrate + emit ONE entry."""
    if not batch:
        return
    bodies = [b for b, _ in batch]
    # representative kind = most severe; severity = max
    top = max(batch, key=lambda x: _SEV_RANK.get(x[1][1], 0))
    kind, sev = top[1]
    # The findings already on the panel ride along so the narrator can
    # recognise its own restatement — see `_known_vuln_titles`.
    _gap = _local_cfg_gap(provider, model)
    if _gap and job_id not in _LOCAL_CFG_WARNED:
        _LOCAL_CFG_WARNED.add(job_id)
        _ko = f"Monitor가 [Local]로 지정됐지만 Settings에 {_gap}이(가) 비어 있습니다 — 원문만 표시됩니다."
        _en = f"Monitor is pinned to [Local] but Settings has no {_gap} — raw lines only."
        _warn = {"ko": _ko, "en": _en}
        for _l in _monitor_langs():
            _warn.setdefault(_l, _en)
        _emit(job_id, _entry("monitor", "warn", _warn))
    text = await _narrate(bodies, model, _known_vuln_titles(job_id), provider)
    # Pulled out here, ahead of the near-duplicate gate below: that gate
    # `return`s, and a finding must survive a narration that merely restates
    # the previous one.
    if isinstance(text, dict) and text.get("vuln"):
        _emit_vuln(job_id, text.pop("vuln"), bodies)
    if not text:
        # LLM unavailable: fall back to a raw-only entry so the signal still
        # shows up in the monitor feed (just without narration). Both ko and
        # en get the same English log snippet — UI language toggle can't invent
        # Hangul here; the real fix is making _narrate succeed (Grok path).
        snippet = bodies[-1][:160]
        text = {l: snippet for l in _monitor_langs()}
        text["_fallback"] = "1"
        # Tiny ko-only prefix so operators can tell fallback from real narration.
        if "ko" in text:
            text["ko"] = f"(원문) {snippet}"
    else:
        # Drop a narration that merely restates the previous one. Only real
        # narrations are compared — a raw fallback stub is already distinct
        # enough, and suppressing those would hide the degraded-feed signal.
        probe = text.get("en") or text.get("ko") or ""
        if recent and any(_too_similar(probe, r) for r in recent):
            return
        if recent is not None:
            recent.append(probe)
            del recent[:-6]
    # `turns` lets the operator see the run's PACE, not just its events. It was
    # already read from meta for stage entries but never reached the narrated
    # ones, so every prose line in the feed showed a blank.
    _emit(job_id, _entry(kind, sev, text, raw=bodies, turns=turns))


# ---------------------------------------------------------------------------
# the per-job monitor loop
# ---------------------------------------------------------------------------
def _statefile(job_id: str) -> Path:
    return JOBS_DIR / Path(job_id).name / ".monitor.state"


async def run_monitor(job_id: str, model: str | None = None) -> None:
    # Every provider narrates. GPT used to return here on the grounds that its
    # deterministic Timeline replaced the narrator — but `_narrate_gpt` and the
    # model-family pinning below were written, complete, and unreachable, so
    # the operator could not have the Monitor on a GPT job no matter what they
    # selected. The Timeline answers "what happened"; this answers "what does
    # it mean", and they are not substitutes. The operator's own toggle
    # (`monitor_agent`) remains the only switch.

    # Settings-managed provider keys live in settings.json, not necessarily in
    # the API process environment. Mirror them before selecting/narrating with
    # a provider so GPT works immediately after saving the key in the UI.
    try:
        from modules.settings_io import apply_to_env
        apply_to_env()
    except Exception:
        pass

    # Active model-preset can override the cheap sonnet default for the
    # monitor role; empty preset entry → MONITOR_MODEL. An explicit
    # caller-supplied `model` still wins over both.
    #
    # provider_for_ROLE, not provider_for_job — the same correction the
    # harvester already carries. The operator may pin this role to a different
    # backend than the job's, and reading the job's provider silently
    # overruled that: on e925acfecb84 the monitor was routed to Grok, resolved
    # `claude-haiku-4-5` from the CLAUDE preset because the job was Claude,
    # and then narrated on Claude because the model id starts with "claude".
    # An unrouted role resolves to exactly provider_for_job, so a deployment
    # that pins nothing is unchanged.
    try:
        from modules.agent_provider import provider_for_role
        provider = provider_for_role(job_id, "monitor")
    except Exception:
        provider = None
    if model is None:
        try:
            from modules.model_presets import resolve_role_model
            model = resolve_role_model("monitor", MONITOR_MODEL, provider)
        except Exception:
            model = MONITOR_MODEL
    model = model or MONITOR_MODEL
    # Pin the selected provider's model family so narration never falls back
    # into another provider merely because MONITOR_MODEL defaults to Claude.
    try:
        from modules.agent_provider import (
            active_provider, default_model_for, has_grok_auth, has_openai_auth,
        )
        provider = provider or active_provider()
        if provider == "gpt" and has_openai_auth():
            if not str(model).lower().startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
                model = os.environ.get("MONITOR_GPT_MODEL", default_model_for("gpt"))
        elif provider == "grok" and has_grok_auth():
            if not str(model).lower().startswith("grok"):
                model = os.environ.get("MONITOR_GROK_MODEL", "grok-4.5")
    except Exception:
        pass
    jd = JOBS_DIR / Path(job_id).name
    logp = jd / "run.log"
    metap = jd / "meta.json"
    monp = jd / "monitor.jsonl"
    statep = _statefile(job_id)

    # --- resolve starting offset (resume-safe) -----------------------------
    try:
        size = logp.stat().st_size
    except OSError:
        size = 0
    off = 0
    resumed = False
    st = _read_json(statep)
    if isinstance(st.get("off"), int) and 0 <= st["off"] <= size:
        off = st["off"]           # exact resume across an API restart
        resumed = True
    elif not monp.exists() and size > BACKLOG_SKIP:
        off = size                # fresh attach to an already-long log: go live
        _emit(job_id, _entry("start", "info",
              {"ko": "모니터링 시작 (이미 진행 중인 job)", "en": "monitoring started (job already running)"}))
    elif not monp.exists():
        _emit(job_id, _entry("start", "info",
              {"ko": "모니터링 시작", "en": "monitoring started"}))
    else:
        off = size                # monitor file exists but no state: avoid re-narrating

    prev_stage = None
    prev_flags = None
    prev_status = None
    pending: list[tuple[str, tuple[str, str]]] = []
    last_flush = time.monotonic()
    # Module decides crash semantics (a segfault is the goal in pwn, a fault in
    # web). Read once per iteration below; seeded here so the very first ingest
    # before any meta read still classifies.
    job_module = ""
    # Last few narrations, for near-duplicate suppression.
    recent_texts: list[str] = []
    turns = None

    while True:
        # --- ingest new run.log bytes --------------------------------------
        try:
            with logp.open("rb") as fp:
                fp.seek(off)
                data = fp.read()
                off = fp.tell()
        except OSError:
            data = b""
        if data:
            for raw in data.decode("utf-8", "replace").splitlines():
                m = re.match(r"^\[(\d\d:\d\d:\d\d)\] (.*)$", raw)
                body = m.group(2) if m else raw
                # Bound the body BEFORE it is classified, narrated, published
                # and persisted. run.log stopped truncating TOOL_RESULT
                # (101beba), and the monitor consumed that change three times
                # over: `raw=bodies` is written verbatim into monitor.jsonl
                # (which the UI re-reads whole every 2 s), the same bodies are
                # published to redis, and up to 12 of them are concatenated
                # into the narration prompt with no bound at all. Measured on
                # the first post-change job (f52f0219803f): narration input
                # 303,686 B vs 191,093 B before = 1.59x, worst single body
                # 30,942 B (~7.7 K tokens), monitor.jsonl 374 KB vs a prior
                # 20-job max of 208 KB. Unbounded, 12 x the 200 KB run.log
                # valve would exceed the narrator's context window, and
                # _narrate then returns {} and the feed silently degrades to a
                # 160-char stub — a regression in the operator's PRIMARY view.
                #
                # Capping at ingest also fixes a false-positive: classify()
                # checks FLAG/ERROR before dropping tool echo, so on that same
                # job the full bodies added 4 new kind=flag entries, ALL FAKE —
                # judge subagents Read-ing exploit.py and echoing its literal
                # `print("FLAG_CANDIDATE: ...")` source at offsets 27 K-30 K.
                # 2 KB still shows far more than the old 300-char preview
                # without reaching into a Read of the exploit's own source.
                if len(body) > _MONITOR_BODY_MAX:
                    body = body[:_MONITOR_BODY_MAX] + " …(monitor-clipped)"
                kc = classify(body, job_module)
                if kc:
                    pending.append((body, kc))
            try:
                statep.write_text(json.dumps({"off": off}))
            except Exception:
                pass

        # --- meta-driven deterministic entries -----------------------------
        meta = _read_json(metap)
        status = meta.get("status")
        stage = meta.get("stage")
        turns = meta.get("agent_turns")
        flags = meta.get("flag_candidates")
        job_module = str(meta.get("module") or job_module or "")

        if stage and stage != prev_stage:
            _emit(job_id, _entry("stage", "info",
                  {"ko": f"단계 → {stage}", "en": f"stage → {stage}"},
                  stage=stage, turns=turns))
            prev_stage = stage
        if flags and flags != prev_flags:
            _emit(job_id, _entry("flag", "good",
                  {"ko": f"🚩 FLAG 후보: {flags}", "en": f"🚩 flag candidate: {flags}"},
                  flags=flags))
            prev_flags = flags

        # --- flush the prose batch through the LLM -------------------------
        now = time.monotonic()
        if pending and (len(pending) >= BATCH_MAX or now - last_flush >= BATCH_MAX_S):
            # Flush in CHUNKS of BATCH_MAX, not "everything pending".
            #
            # The ingest loop above appends every line a single poll produced
            # before this check runs, so a burst delivered 10 signal lines at
            # once and they became ONE entry. Job e601cd358ad6: libprotobuf
            # decomp FAILED + libz decompiling + libz FAILED + libzstd
            # decompiling + libzstd FAILED + AUTOBOOT.md written — six distinct
            # events compressed into a single ~160-char sentence. The narrator
            # was not writing badly; it was asked to summarise ten things in one
            # line. Chunking keeps the compression ratio at what BATCH_MAX
            # actually promises.
            last_flush = now
            while pending:
                batch, pending = pending[:BATCH_MAX], pending[BATCH_MAX:]
                await _flush_batch(job_id, batch, model,
                                   turns=turns, recent=recent_texts,
                                   provider=provider)

        # --- terminal? -----------------------------------------------------
        if status and status in _TERMINAL:
            if pending:
                await _flush_batch(job_id, pending, model,
                                   turns=turns, recent=recent_texts,
                                   provider=provider)
                pending = []
            if status == "hold":
                # Held, not ended: say so, or the feed reads as a finished run
                # and the operator has no reason to supply a new target.
                _emit(job_id, _entry("held", "warn",
                      {"ko": "■ 보류: 새 원격 타깃 대기",
                       "en": "■ held: waiting for a new remote target"},
                      status=status))
            else:
                _emit(job_id, _entry("terminal", "good" if status == "finished" else "warn",
                      {"ko": f"■ 종료: {status}", "en": f"■ terminal: {status}"},
                      status=status))
            return

        prev_status = status
        await asyncio.sleep(POLL_S)


# ---------------------------------------------------------------------------
# supervisor + ensure — one monitor task per running job (always-on)
# ---------------------------------------------------------------------------
_TASKS: dict[str, "asyncio.Task"] = {}


def _is_terminal(job_id: str) -> bool:
    """True if the job's meta.status is a terminal state (the run is over)."""
    meta = _read_json(JOBS_DIR / Path(job_id).name / "meta.json")
    return meta.get("status") in _TERMINAL


def ensure_monitor(job_id: str) -> None:
    """Start a monitor task for job_id if none is alive. Idempotent.
    Must be called from within the API's asyncio loop."""
    if not monitor_enabled() or not job_id:
        return
    t = _TASKS.get(job_id)
    if t is not None and not t.done():
        return
    # Don't spin up a LIVE monitor for a job that's already terminal. The run
    # is over and run.log won't grow, so a fresh task would only re-emit
    # stage/flag/terminal (prev_* start at None) and re-narrate the tail —
    # which is exactly the "monitor keeps working after the job ends" bug
    # (job cff9474c35cf): the route calls ensure_monitor on every GET
    # /monitor and every SSE /stream open, neither status-gated, so each UI
    # reconnect to a finished job spawned a fresh short-lived task that
    # re-appended duplicate terminal/stage/flag entries. The route serves
    # monitor.jsonl history directly, so a finished job's feed still renders
    # in full without any live task. (The supervisor already filters terminal
    # jobs; this closes the same gap for the two route call sites.)
    if _is_terminal(job_id):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _TASKS[job_id] = loop.create_task(_guarded(job_id))


async def _guarded(job_id: str) -> None:
    try:
        await run_monitor(job_id)
    except Exception:
        pass
    finally:
        _TASKS.pop(job_id, None)


def _scan_running() -> list[str]:
    out: list[str] = []
    try:
        for d in JOBS_DIR.iterdir():
            if not d.is_dir():
                continue
            meta = _read_json(d / "meta.json")
            status = meta.get("status")
            # a job is worth monitoring while it has a non-terminal status AND
            # a run.log has begun (skip queued jobs that haven't started).
            if (status and status not in _TERMINAL
                    and (d / "run.log").exists()):
                out.append(d.name)
    except Exception:
        return out
    return out


async def _supervisor() -> None:
    while True:
        try:
            for jid in _scan_running():
                ensure_monitor(jid)
        except Exception:
            pass
        await asyncio.sleep(8)


def start_supervisor() -> None:
    """Launch the always-on supervisor. Call once from api.main startup."""
    if not monitor_enabled():
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_supervisor())
