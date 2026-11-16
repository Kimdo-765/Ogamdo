"""Per-job execution trace — the shape a job ACTUALLY took, as lanes.

Ogamdo has no authored workflow graph. The shape of a run is not declared
anywhere; it emerges one attempt at a time from a loop whose exit condition is
a judge verdict. So the only honest thing to draw is the trajectory that was
actually walked, and the axis that matters is TIME. Across the twelve jobs in
the corpus when this was written, the single segment where the agent drafts
between runs held 24%-99% of every job's wall clock; `340e62bdcd32` spent 80%
of 4.8 hours there and 252 seconds — 2% — actually executing an exploit. A
node-and-edge graph folds precisely that away: it would draw seventeen
identical passes through four nodes and call the job well-behaved.

Everything here is derived from files the pipeline already writes:

    events.jsonl   the loop spine   (prejudge result -> run start/exit ->
                                     postjudge verdict -> flag gate)
    usage.jsonl    model calls      (role, stage, provider, model, tokens, cost)
    manager.jsonl  stage assessment (optional, may be absent)
    meta.json      job start/end

    gpt-events.jsonl  subagent spawns (agent_started / tool_started per role)

Nothing new is emitted to produce this view. An earlier version of this file
claimed subagent spawns were undrawable prose needing new instrumentation.
That was wrong: for GPT/Codex jobs — every job in this corpus — the provider
stream has carried them structurally all along, with role, model and session
id. They appear in NO other file, because codex bills a session once and
events.jsonl tracks the exploit loop rather than the agent's own team. Across
the corpus the agent had four roles available and reached for `recon` in nine
of twelve jobs and for nothing else, ever.

ONE edge is still not drawable and is absent here rather than guessed: feedback
injections (soft-eject, empty-wait, OPERATOR STEER), which live only as run.log
prose and would need one `emit_event` call. Do not infer them from the log —
that is how a causal story gets told about a mechanism nobody verified.

EVERYTHING IS A LANE. There is no separate "head" or "tail" concept: the time
before the first execution is lane 1's agent segment, and time after the last
flag gate is a final lane that never reached execution. That is not a framing
choice, it is what makes the arithmetic checkable — the lanes sum to the job's
wall clock exactly, on all eleven corpus jobs that recorded events.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules._events import read_events

# Segments are keyed off these. `prejudge/result` opens a lane because it is
# the first event of an attempt; `run/start` also opens one, because a lane
# whose prejudge never emitted a result is still a lane that ran.
# When `agent/injected_turn` started being emitted, as an INSTANT rather than a
# date. The first version of this was the bare string "2026-09-19", which is a
# KST date; compared against a UTC `started_at` it declared a job that ran 58
# minutes AFTER the instrumentation to be one that predated it, and told the
# operator its zero injections were unknowable when they were simply zero.
_INJECTION_INSTRUMENTED_AT = datetime(2026, 9, 18, 18, 34, 4, tzinfo=timezone.utc)

_OFFSET_NO_COLON = re.compile(r"([+-])(\d{2})(\d{2})$")

_OPEN_KINDS = (("prejudge", "result"), ("run", "start"))
_CLOSE_KINDS = (("run", "flag_gate"),)


# Every (phase, kind) the lane builder consumes. Anything else in events.jsonl
# is written by something and read by nothing: `agent/held` carries the reason
# a run parked, `agent/blocked_signal` the escalation, `operator/decided` the
# module choice and why. They reach run.log as prose and stop there, so the
# structured record — the one with the fields — was the half nobody could see.
_LANE_CONSUMED = frozenset(
    _OPEN_KINDS + _CLOSE_KINDS
    + (("run", "exit"), ("postjudge", "verdict"), ("agent", "injected_turn"))
)


def _other_events(events: list[dict]) -> list[dict]:
    """Events the lane vocabulary does not place, newest last.

    Deliberately a passthrough rather than a per-kind renderer: the next kind
    someone emits should appear without a second edit here, which is exactly
    what did not happen for the five that were already being written.
    """
    out = []
    for ev in events:
        key = (ev.get("phase"), ev.get("kind"))
        if key in _LANE_CONSUMED or not key[0]:
            continue
        detail = {k: v for k, v in ev.items()
                  if k not in ("ts", "phase", "kind") and v not in (None, "", [], {})}
        out.append({
            "ts": ev.get("ts"),
            "phase": key[0],
            "kind": key[1],
            # Bounded: this rides in a payload the dashboard polls.
            "detail": {k: (str(v)[:400] if not isinstance(v, (int, float, bool)) else v)
                       for k, v in list(detail.items())[:8]},
        })
    return out[-40:]


def _jobs_dir() -> Path:
    from modules._events import _jobs_dir as _d

    return _d()


def _parse_ts(value: Any) -> datetime | None:
    """ISO-8601 to an aware datetime, or None.

    Two offset spellings appear in the corpus and they are NOT interchangeable
    on this box. `_events` and `usage_ledger` write `.isoformat()`, which gives
    `+00:00`; `_manager` writes `%z`, which gives `+0000`. Python 3.10's
    `fromisoformat` parses only the first and raises on the second -- it was
    3.11 that made the parser general. This box runs 3.10, so the compact form
    has to be widened here. Getting this wrong is silent: every manager row in
    every job was dropped, the series came back empty, and the sparkline simply
    never appeared, with nothing logged.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # `+0000` / `-0530` -> `+00:00` / `-05:30`. Anchored at the end so a
        # date like 2026-09-18 is never mistaken for an offset.
        widened = _OFFSET_NO_COLON.sub(r"\1\2:\3", text)
        try:
            dt = datetime.fromisoformat(widened)
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _span(a: datetime | None, b: datetime | None) -> dict | None:
    """A measured segment, or None when either endpoint is missing.

    None means "not measured", which the UI must render differently from a
    zero-length segment — same discipline as the dashboard rings. A negative
    span (clock skew, or a file written out of order) is clamped to 0 rather
    than dropped, so the lane still reconciles.
    """
    if a is None or b is None:
        return None
    return {
        "t0": a.isoformat(),
        "t1": b.isoformat(),
        "s": max(0.0, (b - a).total_seconds()),
    }


def _read_jsonl(path: Path) -> list[dict]:
    """Every well-formed object in a .jsonl, skipping the rest. Never raises."""
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


def _token_total(tokens: Any) -> int:
    """Input + output only.

    Cache reads are deliberately excluded: `340e62bdcd32` read 1.18M cached
    tokens on a single main-agent row, which would dwarf every other lane and
    say nothing about what that lane did.
    """
    if not isinstance(tokens, dict):
        return 0
    total = 0
    for key in ("input_tokens", "output_tokens"):
        value = tokens.get(key)
        if isinstance(value, (int, float)):
            total += int(value)
    return total


def _lane_shell(n: int, t0: datetime) -> dict:
    return {
        "n": n,
        "t0": t0.isoformat(),
        "t1": None,
        "open": True,
        "agent": None,
        "run": None,
        "adjudicate": None,
        "prejudge": None,
        "flag_gate": None,
        "verdict": None,
        "calls": {},
        "tokens": 0,
        "cost_usd": None,
        "cost_complete": True,
        "injections": {},
        # Present on EVERY lane so the shape is uniform: a reader who writes
        # `if lane["unreached"]` must not get a KeyError on lane 1.
        "unreached": False,
        "_t0": t0,
        "_t1": None,
        "_run_start": None,
        "_run_exit": None,
        "_verdict_at": None,
    }


def _build_lanes(events: list[dict], started: datetime | None) -> list[dict]:
    """Group the event stream into attempts.

    A lane opens on the first event of an attempt and closes on its flag gate.
    An attempt that never reached its gate — the job was stopped mid-run, or
    the agent kept drafting after the last execution — stays open, which is
    how the trailing drafting time becomes visible instead of vanishing.
    """
    lanes: list[dict] = []
    cur: dict | None = None
    for ev in events:
        key = (ev.get("phase"), ev.get("kind"))
        ts = _parse_ts(ev.get("ts"))
        if ts is None:
            continue
        if key in _OPEN_KINDS and cur is None:
            cur = _lane_shell(len(lanes) + 1, ts)
            lanes.append(cur)
        if cur is None:
            # A stray event before any opener (a `terminal/status`, or a
            # `run/exit` whose start was lost). It belongs to no attempt.
            continue
        if key == ("prejudge", "result"):
            cur["prejudge"] = {
                "ok": bool(ev.get("ok")),
                "severity": ev.get("severity") or "",
                "issues": ev.get("issues"),
                "target_liveness": ev.get("target_liveness") or "",
                "would_block": False,
            }
        elif key == ("prejudge", "would_block"):
            if cur["prejudge"] is None:
                cur["prejudge"] = {
                    "ok": False,
                    "severity": ev.get("severity") or "",
                    "issues": ev.get("issues"),
                    "target_liveness": "",
                    "would_block": True,
                }
            else:
                cur["prejudge"]["would_block"] = True
        elif key == ("run", "start"):
            cur["_run_start"] = ts
            cur["run"] = {
                "script": ev.get("script") or "",
                "timeout_s": ev.get("timeout_s"),
                "exit_code": None,
                "timeout": False,
                "killed_by_supervise": False,
                "stdout_bytes": None,
                "stderr_bytes": None,
                "spawn_failed": False,
                "s": None,
                "t0": ts.isoformat(),
                "t1": None,
            }
        elif key == ("run", "spawn_failed"):
            # Never seen in the corpus, so this path is exercised only by the
            # test suite. It still has to produce a lane rather than a crash.
            if cur["run"] is None:
                cur["_run_start"] = ts
                cur["run"] = {
                    "script": "", "timeout_s": None, "exit_code": None,
                    "timeout": False, "killed_by_supervise": False,
                    "stdout_bytes": None, "stderr_bytes": None,
                    "spawn_failed": True, "s": None,
                    "t0": ts.isoformat(), "t1": None,
                }
            else:
                cur["run"]["spawn_failed"] = True
            cur["_run_exit"] = ts
        elif key == ("run", "exit"):
            cur["_run_exit"] = ts
            if cur["run"] is None:
                cur["_run_start"] = ts
                cur["run"] = {
                    "script": "", "timeout_s": None, "spawn_failed": False,
                    "s": None, "t0": ts.isoformat(), "t1": None,
                }
            cur["run"].update({
                "exit_code": ev.get("exit_code"),
                "timeout": bool(ev.get("timeout")),
                "killed_by_supervise": bool(ev.get("killed_by_supervise")),
                "stdout_bytes": ev.get("stdout_bytes"),
                "stderr_bytes": ev.get("stderr_bytes"),
            })
        elif key == ("postjudge", "verdict"):
            cur["_verdict_at"] = ts
            cur["verdict"] = ev.get("verdict")
            cur["adjudicate"] = {
                "verdict": ev.get("verdict"),
                "next_action": ev.get("next_action"),
                "failure_code": ev.get("failure_code"),
                "s": None,
                "t0": None,
                "t1": ts.isoformat(),
            }
        elif key in _CLOSE_KINDS:
            cur["flag_gate"] = {
                "flags_count": ev.get("flags_count"),
                "tier": ev.get("tier") or "",
                "suppressed": bool(ev.get("suppressed")),
                "reason": ev.get("reason") or "",
                "terminal_capture": bool(ev.get("terminal_capture")),
            }
            cur["_t1"] = ts
            cur["t1"] = ts.isoformat()
            cur["open"] = False
            cur = None

    # Segment durations. Lane 1's agent segment anchors on the job's own start
    # rather than on itself, which is the whole reason the lanes reconcile: on
    # `5dcebc463810` that segment is 9,955 of the job's 10,016 seconds, and
    # anchoring it on the lane would report it as zero.
    prev_end: datetime | None = started
    for lane in lanes:
        agent_from = prev_end if prev_end is not None else lane["_t0"]
        agent_to = lane["_run_start"] or lane["_t1"]
        lane["agent"] = _span(agent_from, agent_to)
        if lane["run"] is not None and lane["_run_start"] is not None:
            span = _span(lane["_run_start"], lane["_run_exit"])
            if span:
                lane["run"]["s"] = span["s"]
                lane["run"]["t1"] = span["t1"]
        if lane["adjudicate"] is not None:
            # Ends at the FLAG GATE, not at the verdict: the gate is the last
            # step of judging an attempt, and the sliver between them belongs
            # to some segment or the lanes stop tiling the clock.
            span = _span(lane["_run_exit"], lane["_t1"] or lane["_verdict_at"])
            if span:
                lane["adjudicate"]["s"] = span["s"]
                lane["adjudicate"]["t0"] = span["t0"]
        prev_end = lane["_t1"] or lane["_verdict_at"] or lane["_run_exit"] or prev_end
    return lanes


def _append_tail_lane(lanes: list[dict], started: datetime | None,
                      ended: datetime | None) -> None:
    """The drafting that happened after the last execution.

    `44591f39ef9f` ran twice in 2.7 hours and `67bf6b06b8f6` left 18 minutes
    on the clock after its final gate. Without this the chart would end at the
    last flag gate and quietly lose that time, which is exactly the fact worth
    seeing. A job with no events at all becomes a single open lane spanning
    everything — "executed nothing" drawn as one bar rather than as an empty
    panel.
    """
    if ended is None:
        return
    last_close = None
    for lane in lanes:
        if not lane["open"]:
            last_close = lane["_t1"]
    anchor = last_close or started
    if anchor is None or ended <= anchor:
        return
    if lanes and lanes[-1]["open"]:
        return  # an in-flight attempt already covers the remainder
    lane = _lane_shell(len(lanes) + 1, anchor)
    lane["agent"] = _span(anchor, ended)
    lane["unreached"] = True
    lanes.append(lane)


def _attribute_injections(lanes: list[dict], events: list[dict]) -> dict:
    """Turns the orchestrator injected at a boundary, per lane and in total.

    Attributed by timestamp rather than by the event's own `attempt` field. The
    two agree today, but the lane is what the rest of this module is built on,
    and an injection fired between a flag gate and the next prejudge belongs to
    the lane it delayed -- which is the agent segment of the NEXT attempt, not
    the attempt whose counter it happened to carry.

    The rung matters more than the count: FINAL_DRAFT outranks OPERATOR STEER
    outranks soft-eject outranks EMPTY WAIT, so "the operator intervened twice"
    and "the budget ran out twice" are different facts that a bare total would
    merge.
    """
    totals: dict[str, int] = {}
    bounds = [(l["_t0"], l["_t1"], l) for l in lanes]
    for ev in events:
        if ev.get("phase") != "agent" or ev.get("kind") != "injected_turn":
            continue
        rung = ev.get("rung") or "?"
        totals[rung] = totals.get(rung, 0) + 1
        ts = _parse_ts(ev.get("ts"))
        target = None
        if ts is not None and bounds:
            for t0, t1, lane in bounds:
                if t0 is not None and ts < t0:
                    target = lane
                    break
                if t1 is None or ts < t1:
                    target = lane
                    break
            if target is None:
                target = bounds[-1][2]
        if target is not None:
            target["injections"][rung] = target["injections"].get(rung, 0) + 1
    return totals


def _attribute_usage(lanes: list[dict], usage: list[dict]) -> dict:
    """Assign every model call to the lane whose time window contains it.

    NOT joined on the ledger's `attempt` field. That counter is per
    `(role, stage)` — see `usage_ledger.next_attempt` — so on `340e62bdcd32`
    prejudge reaches 51 while postjudge reaches 26, and the two `attempt=7`
    rows are different attempts of different counters. Joining on it looks
    right and silently interleaves unrelated calls.
    """
    bounds: list[tuple[datetime | None, datetime | None, dict]] = [
        (lane["_t0"], lane["_t1"], lane) for lane in lanes
    ]
    totals: dict[str, int] = {}
    for row in usage:
        role = row.get("role") or "?"
        stage = row.get("stage") or "?"
        key = f"{role}/{stage}"
        totals[key] = totals.get(key, 0) + 1
        ts = _parse_ts(row.get("ts"))
        target: dict | None = None
        if ts is not None and bounds:
            for t0, t1, lane in bounds:
                if t0 is not None and ts < t0:
                    # Before this lane: belongs to the first lane, because the
                    # main agent's own row is stamped before prejudge opens.
                    target = lane
                    break
                if t1 is None or ts < t1:
                    target = lane
                    break
            if target is None:
                target = bounds[-1][2]
        if target is None:
            continue
        target["calls"][key] = target["calls"].get(key, 0) + 1
        target["tokens"] += _token_total(row.get("tokens"))
        cost = row.get("cost_usd")
        if row.get("cost_basis") == "reported" and isinstance(cost, (int, float)):
            target["cost_usd"] = (target["cost_usd"] or 0.0) + float(cost)
        else:
            # Codex reports usage once per SESSION, not per turn: every
            # `main` row in the corpus carries `cost_basis: "none"` and a null
            # cost. So an agent segment's cost is unattributable, not zero,
            # and a lane holding one must say so.
            target["cost_complete"] = False
    return totals


def _subagents(job_id: str) -> dict:
    """Subagent spawns and their tool calls, from the provider event stream.

    `agent_started` with a role other than `main` is a REAL spawn record --
    role, model, session id, timestamp. An earlier note in this feature said
    subagent spawns existed only as run.log prose and needed a new emit_event
    call to become drawable. That was wrong for GPT/Codex jobs, which is every
    job on this box: `gpt-events.jsonl` has carried them all along.

    It is the ONLY place they appear. They produce no usage ledger row, because
    codex bills a whole session once, and no events.jsonl entry, because that
    file tracks the exploit loop rather than the agent's own team.

    Absent is not zero here either: a job with no event stream returns
    `source: None`, which the view must render as "not recorded" rather than
    as a job that spawned nothing.
    """
    path = _jobs_dir() / Path(job_id).name / "gpt-events.jsonl"
    out: dict = {"roles": {}, "main_tools": 0, "available": [],
                 "never_invoked": [], "source": None}
    if not path.is_file():
        return out
    out["source"] = path.name
    roles: dict[str, dict] = {}
    try:
        with path.open(errors="replace") as fp:
            for line in fp:
                # Substring gate before json.loads: this file reaches 1.1 MB on
                # a long job and the detail panel re-polls every two seconds.
                # Only two of its event kinds matter here.
                if '"agent_started"' not in line and '"tool_started"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                kind = rec.get("kind")
                role = rec.get("role") or "?"
                if role == "main":
                    if kind == "tool_started":
                        out["main_tools"] += 1
                    continue
                slot = roles.setdefault(
                    role, {"spawns": 0, "tools": 0, "models": [],
                           "first_ts": None, "last_ts": None})
                ts = _parse_ts(rec.get("ts"))
                if ts is not None:
                    iso = ts.isoformat()
                    if slot["first_ts"] is None or iso < slot["first_ts"]:
                        slot["first_ts"] = iso
                    if slot["last_ts"] is None or iso > slot["last_ts"]:
                        slot["last_ts"] = iso
                if kind == "agent_started":
                    slot["spawns"] += 1
                    model = rec.get("model")
                    if model and model not in slot["models"]:
                        slot["models"].append(model)
                elif kind == "tool_started":
                    slot["tools"] += 1
    except OSError:
        return out
    out["roles"] = roles

    # Which roles the agent COULD have called. Reported so that "debugger does
    # not appear" reads as "it was available and never used" rather than as a
    # gap in this view -- across the corpus the agent had four roles and only
    # ever reached for recon.
    try:
        from modules.codex_cli import CODEX_AGENT_ROLES

        out["available"] = list(CODEX_AGENT_ROLES)
        out["never_invoked"] = [r for r in CODEX_AGENT_ROLES if r not in roles]
    except Exception:
        pass
    return out


def _manager_series(job_id: str) -> list[dict]:
    """Manager assessments over time, oldest first. Optional by design."""
    out = []
    for rec in _read_jsonl(_jobs_dir() / Path(job_id).name / "manager.jsonl"):
        ts = _parse_ts(rec.get("ts"))
        if ts is None:
            continue
        out.append({
            "ts": ts.isoformat(),
            "stage": rec.get("stage"),
            "steps_done": rec.get("steps_done"),
            "steps_total": rec.get("steps_total"),
            "flag_probability": rec.get("flag_probability"),
            "confidence": rec.get("confidence"),
            "next_step": rec.get("next_step"),
            "blocker": rec.get("blocker"),
        })
    out.sort(key=lambda r: r["ts"])
    return out


def _totals(lanes: list[dict], calls: dict) -> dict:
    agent_s = run_s = adj_s = 0.0
    runs = 0
    cost = 0.0
    cost_complete = True
    for lane in lanes:
        if lane["agent"]:
            agent_s += lane["agent"]["s"]
        if lane["run"] and lane["run"].get("s") is not None:
            run_s += lane["run"]["s"]
            runs += 1
        if lane["adjudicate"] and lane["adjudicate"].get("s") is not None:
            adj_s += lane["adjudicate"]["s"]
        if lane["cost_usd"] is not None:
            cost += lane["cost_usd"]
        if not lane["cost_complete"]:
            cost_complete = False
    return {
        "agent_s": agent_s,
        "run_s": run_s,
        "adjudicate_s": adj_s,
        "runs": runs,
        "lanes": len(lanes),
        "calls": calls,
        "cost_usd": cost if cost else None,
        "cost_complete": cost_complete,
    }


def _notes(lanes: list[dict], totals: dict, has_events: bool,
           started: datetime | None = None) -> list[str]:
    """Caveats the chart cannot express on its own.

    These are rendered next to the chart, not buried. Each states a fact that
    is checkable in the files; none of them names a mechanism that has not
    been verified — the gap between prejudge calls and executions is reported
    as two counts, without a story about why.
    """
    notes: list[str] = []
    if not has_events:
        notes.append(
            "이 job은 events.jsonl을 남기지 않았습니다. 구간을 나눌 근거가 없어 "
            "전체를 하나의 미실행 lane으로 그립니다."
        )
    if not totals["cost_complete"]:
        notes.append(
            "비용이 일부만 보고됐습니다. main 에이전트는 사용량을 세션 단위로 한 번만 "
            "보고하므로(cost_basis=none) agent 구간 비용은 0이 아니라 귀속 불가입니다."
        )
    pre = totals["calls"].get("judge/prejudge", 0)
    if pre and totals["runs"] and pre > totals["runs"]:
        notes.append(
            f"prejudge 모델 호출 {pre}회, 실제 실행 {totals['runs']}회. "
            "둘의 차이가 무엇 때문인지는 이 데이터로 판별되지 않습니다."
        )
    # A job with no injection events is ambiguous in a way the graph cannot
    # express, and the ambiguity has a hard edge: this instrumentation did not
    # exist before 2026-09-19, so on every job recorded until then "nothing was
    # injected" and "nothing was recorded" look identical. Say which one this
    # is not, rather than let an empty slot read as a fact.
    if (has_events and not totals.get("injections")
            and started is not None and started < _INJECTION_INSTRUMENTED_AT):
        notes.append(
            "주입 턴 이벤트가 없습니다. 이 job은 주입 계측"
            f"({_INJECTION_INSTRUMENTED_AT.isoformat()}) 이전에 시작됐으므로 "
            "'주입이 없었음'과 '기록되지 않았음'이 구분되지 않습니다."
        )
    span = totals["agent_s"] + totals["run_s"] + totals["adjudicate_s"]
    if span > 0 and totals["run_s"] / span < 0.10 and totals["runs"]:
        notes.append(
            f"실행에 쓴 시간은 전체의 {totals['run_s'] / span * 100:.1f}%입니다 "
            f"({totals['run_s']:.0f}초 / {span:.0f}초)."
        )
    return notes


def build_trace(job_id: str) -> dict:
    """Assemble one job's execution trace. Never raises.

    Observability must not be able to break the page that shows it, so a
    malformed file yields a thinner trace rather than a 500.
    """
    try:
        return _build_trace(job_id)
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "job_id": job_id,
            "lanes": [],
            "manager": [],
            "totals": _totals([], {}),
            "notes": [f"트레이스를 조립하지 못했습니다: {exc.__class__.__name__}"],
            "error": True,
        }


def _build_trace(job_id: str) -> dict:
    name = Path(job_id).name
    job_dir = _jobs_dir() / name
    meta: dict = {}
    try:
        meta = json.loads((job_dir / "meta.json").read_text(encoding="utf-8"))
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}

    events = read_events(name)
    started = _parse_ts(meta.get("started_at"))
    ended = _parse_ts(meta.get("stopped_at")) or _parse_ts(meta.get("finished_at"))
    running = ended is None
    now = datetime.now(timezone.utc)
    # An unfinished job is measured against the clock, so its open lane grows
    # between polls instead of ending at whatever its last event happened to be.
    horizon = ended or now

    lanes = _build_lanes(events, started)
    _append_tail_lane(lanes, started, horizon)
    for lane in lanes:
        if lane["open"] and lane["agent"] is None:
            lane["agent"] = _span(lane["_t0"], horizon)
        if lane["open"]:
            lane["_t1_effective"] = horizon
        # A run with a start and no exit because the JOB ended — stopped by
        # the operator, killed — still occupied the clock until it did. While
        # the job is live the same shape means "still executing" and `s=None`
        # is the honest answer, so this closes it only once the job is
        # terminal. Job `9cbb6601cd17` was stopped 2,718 s into such a run and
        # that time was attributed to nothing: agent 4,988.79 + run 0 against
        # a 7,707.09 s wall, which is the drift the footer prints.
        if (not running and lane["run"] is not None
                and lane["run"].get("s") is None
                and lane["_run_start"] is not None):
            span = _span(lane["_run_start"], horizon)
            if span:
                lane["run"]["s"] = span["s"]
                lane["run"]["t1"] = span["t1"]
                lane["run"]["unterminated"] = True

    calls = _attribute_usage(lanes, _read_jsonl(job_dir / "usage.jsonl"))
    injections = _attribute_injections(lanes, events)
    totals = _totals(lanes, calls)
    totals["injections"] = injections
    for lane in lanes:
        for key in ("_t0", "_t1", "_run_start", "_run_exit", "_verdict_at",
                    "_t1_effective"):
            lane.pop(key, None)

    wall = None
    if started is not None:
        wall = max(0.0, (horizon - started).total_seconds())

    return {
        "job_id": name,
        "status": meta.get("status"),
        "running": running,
        "started_at": started.isoformat() if started else None,
        "ended_at": ended.isoformat() if ended else None,
        "now": now.isoformat(),
        "wall_s": wall,
        "provider": meta.get("agent_provider"),
        "model": meta.get("model"),
        "lanes": lanes,
        "manager": _manager_series(name),
        "subagents": _subagents(name),
        "totals": totals,
        "other_events": _other_events(events),
        "notes": _notes(lanes, totals, bool(events), started),
    }
