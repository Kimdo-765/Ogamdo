"""One readable flow per job, whatever ran it.

GPT jobs have had a structured timeline since gpt-events.jsonl existed. Claude
and grok jobs got a `<pre>` of run.log — the same work, rendered as a wall of
`[main] TOOL Bash: {"command": "...` lines the operator has to parse by eye.
The data was never the problem: sdk.jsonl already carries `text`, `tool_use`,
`tool_result` and `thinking`, tagged by which agent produced them.

So this normalises that stream into the SAME event vocabulary the GPT timeline
endpoint emits — `message`, `tool`, `artifact`, `wait`, `warning`, `error` —
and the existing renderer draws both. One renderer, two sources; a second
renderer would drift from the first the way two placement policies do.

That sameness has to cover the AGENT CARDS, not just the event list. The
renderer reads `agent.role` and `agent.model`; this path emitted `name` and no
model at all, so every claude and grok job drew `agent` / "model 미확인" beside
a GPT job showing the real one. `_agent_identity` closes that.

WHAT IT CANNOT SHOW, AND SAYS SO

A tool's duration needs two timestamps. `publish_sdk` stamps `ts` as of this
change, so jobs from here on have them; every job recorded before it has none,
and a fabricated duration is worse than a blank one. `source` reports which
case a payload is, and the view says "timing not recorded" rather than "0ms".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modules.storage import JOBS_DIR

# What the renderer's icon map knows. Anything outside it draws a bare dot, so
# a new kind here is a silent downgrade rather than an error -- keep to these.
_KINDS = ("message", "tool", "artifact", "wait", "warning", "error",
          "agent_started", "turn_started", "turn_completed", "delegation")
_MAX_SUMMARY = 700
_MAX_DETAIL = 4000


def _job_dir(job_id: str) -> Path:
    return JOBS_DIR / Path(job_id).name


def _read(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        if not path.is_file():
            return out
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        return out
    return out


def _tool_label(name: str, payload: Any) -> str:
    """The one line that stands in for a whole tool call.

    The agent's own `description` when it wrote one -- the prompts ask for it
    and it is what a human would have written. Otherwise the most identifying
    field the tool has, trimmed to one line: a command, a path, a pattern.
    """
    if isinstance(payload, dict):
        for key in ("description", "command", "file_path", "path", "pattern",
                    "query", "url", "prompt"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                one = " ".join(value.split())
                return one[:160]
    return name or "tool"


# Tools whose subject is a file the operator can open. The job file endpoint
# resolves a BASENAME against <job>/ and <job>/work/, so that is what travels.
_FILE_KEYS = ("file_path", "path", "notebook_path")


def _tool_file(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in _FILE_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            name = Path(value.strip()).name
            return name or None
    return None


def _ms_between(a: str | None, b: str | None) -> int | None:
    from modules._trace import _parse_ts

    t0, t1 = _parse_ts(a), _parse_ts(b)
    if t0 is None or t1 is None:
        return None
    return max(0, int((t1 - t0).total_seconds() * 1000))


def _read_meta(job_id: str) -> dict:
    """The job's meta.json, or {} -- never an exception."""
    try:
        data = json.loads(
            (_job_dir(job_id) / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _agent_identity(job_id: str, meta: dict):
    """Model + provider for an agent TAG, resolved the way the GPT path does.

    The renderer reads `agent.role` and `agent.model`; this path used to emit
    neither, so every claude and grok job drew the card as `agent` /
    "model 미확인" while GPT jobs showed the real thing. One renderer, two
    sources means the same keys, not merely the same event list.

    `meta.model` is only written when the job ENDS, so sourcing the model from
    it alone leaves every RUNNING job -- the one case an operator is actually
    watching -- still reading "미확인". `role_model_for` answers before the job
    finishes, so it leads and `meta.model` is only the request hint for main.

    Resolution can fail (settings unreadable, preset removed). It then returns
    nothing for that tag and the card says the model is unknown, which is what
    this module does everywhere else rather than show a plausible guess.
    """
    cache: dict[str, dict] = {}

    def resolve(tag: str) -> dict:
        if tag in cache:
            return cache[tag]
        out: dict[str, str] = {}
        try:
            from modules.agent_provider import provider_for_role, role_model_for

            # A tag that is not a routable role resolves to the job's own
            # backend, which is exactly what a subagent runs on.
            provider = provider_for_role(job_id, tag)
            if provider:
                out["provider"] = provider
            model = role_model_for(
                tag, provider, meta.get("model") if tag == "main" else None)
            if model:
                out["model"] = model
        except Exception:
            pass
        cache[tag] = out
        return out

    return resolve


def build_timeline(job_id: str, tail: int | None = None) -> dict:
    """Normalised events for a non-GPT job. Never raises."""
    try:
        return _build(job_id, tail)
    except Exception as exc:  # pragma: no cover - defensive
        return {"enabled": False, "events": [], "agents": [],
                "source": f"unavailable ({exc.__class__.__name__})"}


def _build(job_id: str, tail: int | None) -> dict:
    records = _read(_job_dir(job_id) / "sdk.jsonl")
    if not records:
        return {"enabled": False, "events": [], "agents": [],
                "source": "no sdk.jsonl"}

    meta = _read_meta(job_id)
    identify = _agent_identity(job_id, meta)
    job_running = str(meta.get("status") or "").strip().lower() == "running"

    events: list[dict] = []
    # A tool_result belongs to the most recent unresolved tool_use of the SAME
    # agent: main and a subagent interleave through one file.
    open_tool: dict[str, dict] = {}
    agents: dict[str, dict] = {}
    timed = 0

    for rec in records:
        kind = rec.get("kind")
        tag = str(rec.get("tag") or "main")
        ts = rec.get("ts") if isinstance(rec.get("ts"), str) else None
        if ts:
            timed += 1
        slot = agents.get(tag)
        if slot is None:
            slot = {"name": tag, "role": tag, "status": "running",
                    "tools": 0, "messages": 0, "last_at": ""}
            # Only model/provider, and only when they resolved -- an absent
            # key is the honest "unknown" the renderer already words.
            slot.update(identify(tag))
            agents[tag] = slot
        if ts:
            slot["last_at"] = ts

        if kind == "text":
            text = str(rec.get("text") or "").strip()
            if not text:
                continue
            slot["messages"] += 1
            events.append({
                "kind": "message", "role": tag, "status": "info", "ts": ts,
                "title": "분석 업데이트",
                "summary": text[:_MAX_SUMMARY],
            })
        elif kind == "thinking":
            text = str(rec.get("thinking") or "").strip()
            if not text:
                # An empty thinking block is the SDK reporting that extended
                # thinking ran, not that it thought nothing. A card saying
                # nothing is worse than no card.
                continue
            events.append({
                "kind": "message", "role": tag, "status": "info", "ts": ts,
                "title": "사고", "summary": text[:_MAX_SUMMARY],
            })
        elif kind == "tool_use":
            name = str(rec.get("name") or "tool")
            ev = {
                "kind": "tool", "role": tag, "status": "running", "ts": ts,
                "title": name, "tool": name,
                "summary": _tool_label(name, rec.get("input")),
                "input": rec.get("input"),
            }
            got_file = _tool_file(rec.get("input"))
            if got_file:
                ev["file"] = got_file
            slot["tools"] += 1
            events.append(ev)
            open_tool[tag] = ev
        elif kind == "tool_result":
            ev = open_tool.pop(tag, None)
            preview = str(rec.get("preview") or "")
            if ev is None:
                # A result with no call in front of it. Kept rather than
                # dropped: it is evidence the stream is incomplete.
                events.append({
                    "kind": "warning", "role": tag, "status": "warning",
                    "ts": ts, "title": "결과만 기록됨",
                    "summary": preview[:_MAX_SUMMARY],
                })
                continue
            ev["status"] = "failed" if rec.get("is_error") else "completed"
            ev["detail"] = preview[:_MAX_DETAIL]
            # Absent, not zero. A job recorded before publish_sdk stamped `ts`
            # has no duration to report, and the key is left off entirely --
            # `_fmtDuration(null)` renders "0ms" because Number(null) is 0,
            # which is the fabricated figure this whole module refuses to show.
            took = _ms_between(ev.get("ts"), ts)
            if took is not None:
                ev["duration_ms"] = took

    # Every tag used to be stamped "completed" unconditionally, which told the
    # operator a live agent had finished -- it did exactly that on a job while
    # it was still running. A tag is running only while the JOB is, and only
    # when it owns the newest record or still holds a tool call that never got
    # its result. A finished job leaves such a call behind too, which is why
    # `job_running` gates both tests rather than the open call alone.
    newest = max((s.get("last_at") or "") for s in agents.values()) if agents else ""
    for tag, slot in agents.items():
        live = bool(newest) and (slot.get("last_at") or "") == newest
        slot["status"] = ("running" if job_running and (live or tag in open_tool)
                          else "completed")
    clipped = 0
    if tail and len(events) > tail:
        clipped = len(events) - tail
        events = events[-tail:]

    # Said plainly rather than implied by empty time columns: a job recorded
    # before publish_sdk stamped `ts` can be ordered but not timed.
    source = ("structured events" if timed
              else "structured events (timing not recorded)")
    return {
        "enabled": True,
        "events": events,
        "agents": list(agents.values()),
        "source": source,
        "clipped": clipped,
    }
