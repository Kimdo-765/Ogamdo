"""The same wall, three times: a signal, never a stop.

WHAT THIS IS FOR

Measured over the twelve corpus jobs: 9.5 hours, 49 attempts and roughly $80
were spent AFTER the same postjudge verdict had already repeated three times in
a row. `340e62bdcd32` produced twelve identical verdicts and ran three and a
half more hours; `5efafb6ee9ab` produced twenty-six and ran nearly two. The job
that actually captured a flag, `ccf6d5838457`, never repeated a verdict once --
its longest run is 1. So the run length separates the jobs that were grinding
from the one that was working, which is the only reason it is worth reporting.

IT DOES NOT STOP ANYTHING. The operator is the only brake in this system by
design, and a self-declared halt would be a ceiling. This raises a flag at
attempt four on a job that used to reach attempt seventeen before a human woke
up and pressed stop. Both of those end with a person deciding; only one of them
costs three hours first.

THE AGENT'S OWN REASON, GATED

Borrowed from pentest-harness's goal tool, whose blocked contract is the part
of it worth taking: the model may declare itself blocked, but the claim is
MECHANICALLY REJECTED until the same condition has persisted for N consecutive
rounds, and it must name the concrete condition. Difficulty, uncertainty and
useful remaining work are explicitly not blocked.

A rejected claim is still RECORDED. That is deliberate: it is the only way to
find out whether the channel is used at all, and whether the model reaches for
it early. An unused channel that reports nothing looks identical to a channel
nobody needed.

WHAT IT IS NOT. It is not the evidence budget (`modules/_evidence.py`), which
bounds iterations against a finite alphabet and proves termination. That one
answers "can this run forever"; this one answers "has it been hitting the same
wall, and does anyone know". The evidence budget fired correctly on
340e62bdcd32 -- saturated at 4 distinct states, -10 against a limit of 3 -- and
nothing surfaced it where a person would see it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules._events import emit_event, read_events

# How many consecutive identical verdicts before the signal is raised, and
# before the agent's own claim stops being rejected. Three, because that is
# where the corpus separates: every job that ground on reached it, and the job
# that captured a flag never got past one.
BLOCKED_AFTER = 3
# Re-raise at each doubling rather than every attempt. 340e62bdcd32 would have
# reported at 3, 6 and 12 across its twelve-verdict run -- enough to be seen,
# not so much that it becomes wallpaper.
_ESCALATE_AT = (3, 6, 12, 24, 48)
_MAX_REASON = 2000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def verdict_run(job_id: str) -> tuple[str | None, int, int]:
    """(verdict, consecutive count, attempt index) for the CURRENT run.

    Counts backwards from the most recent `postjudge/verdict`, so a run that
    was broken by a different verdict is over and reported as length 1.
    Attempts with no verdict at all -- a prejudge block, an in-flight attempt --
    are not in this sequence and neither extend nor break a run.
    """
    verdicts = [e.get("verdict") for e in read_events(job_id)
                if e.get("phase") == "postjudge" and e.get("kind") == "verdict"]
    if not verdicts:
        return None, 0, 0
    last = verdicts[-1]
    n = 0
    for v in reversed(verdicts):
        if v != last:
            break
        n += 1
    return last, n, len(verdicts)


def read_signal(job_id: str) -> dict | None:
    """The signal currently recorded on this job, if any."""
    try:
        meta = json.loads(
            (_job_dir(job_id) / "meta.json").read_text(encoding="utf-8"))
        got = meta.get("blocked_signal")
        return got if isinstance(got, dict) else None
    except Exception:
        return None


def _job_dir(job_id: str) -> Path:
    from modules.storage import JOBS_DIR

    return JOBS_DIR / Path(job_id).name


def reason_path(work_dir: Path | str) -> Path:
    return Path(work_dir) / "blocked.json"


def read_agent_reason(work_dir: Path | str) -> dict | None:
    """The agent's own claim, as it wrote it. Never raises."""
    try:
        raw = reason_path(work_dir).read_text(encoding="utf-8", errors="replace")
        got = json.loads(raw)
    except Exception:
        return None
    if not isinstance(got, dict):
        return None
    text = got.get("reason") or got.get("blocked_reason") or ""
    if not isinstance(text, str) or not text.strip():
        return None
    return {"reason": text.strip()[:_MAX_REASON],
            "written_at": got.get("ts") if isinstance(got.get("ts"), str) else None}


def evaluate(job_id: str, work_dir: Path | str | None = None) -> dict:
    """The current state of this job's wall, whether or not it is signalling.

    Always returns a record so a caller can tell "checked, run of 1" from
    "never checked". `signalling` is the only field that means act.
    """
    verdict, run, total = verdict_run(job_id)
    claim = read_agent_reason(work_dir) if work_dir else None
    # The gate. An early claim is rejected and kept: whether the model reaches
    # for this channel, and how early, is the thing worth being able to look up.
    claim_state = None
    if claim:
        claim_state = "accepted" if run >= BLOCKED_AFTER else "rejected_too_early"
    return {
        "verdict": verdict,
        "run": run,
        "attempts_with_verdict": total,
        "threshold": BLOCKED_AFTER,
        "signalling": bool(verdict) and run >= BLOCKED_AFTER,
        "agent_reason": claim["reason"] if claim else None,
        "agent_reason_state": claim_state,
    }


def maybe_signal(job_id: str, work_dir: Path | str | None = None,
                 log_fn=None) -> dict:
    """Call once per concluded attempt. Records the wall; never ends the run.

    Emits at escalation points only. A run of twelve reports three times, not
    twelve: a line that appears after every attempt stops being read.

    Best-effort throughout -- a signal that can end a turn is worse than no
    signal, and this one has no authority to be worth that risk.
    """
    try:
        state = evaluate(job_id, work_dir)
    except Exception:
        return {"signalling": False, "error": True}

    prev = read_signal(job_id) or {}
    changed_wall = prev.get("verdict") != state["verdict"]
    last_emitted = 0 if changed_wall else int(prev.get("emitted_at_run") or 0)

    due = max((t for t in _ESCALATE_AT if state["run"] >= t), default=0)
    should_emit = bool(state["signalling"]) and due > last_emitted

    record = dict(state)
    record["emitted_at_run"] = due if should_emit else last_emitted
    record["first_seen_at"] = (
        _now() if (changed_wall or not prev.get("first_seen_at"))
        and state["signalling"] else prev.get("first_seen_at"))
    if not state["signalling"]:
        # The wall moved. Keep the shape so a reader can tell "checked and
        # clear" from "never checked", but drop the stale first_seen_at.
        record["first_seen_at"] = None
        record["emitted_at_run"] = 0

    try:
        from modules._common import write_meta

        write_meta(job_id, blocked_signal=record)
    except Exception:
        pass

    if should_emit:
        try:
            emit_event(job_id, "agent", "blocked_signal",
                       verdict=state["verdict"], run=state["run"],
                       threshold=BLOCKED_AFTER,
                       agent_reason_state=state["agent_reason_state"],
                       has_agent_reason=bool(state["agent_reason"]))
        except Exception:
            pass
        if log_fn:
            try:
                msg = (f"[blocked] verdict={state['verdict']!r} has repeated "
                       f"{state['run']}x in a row — this job has been hitting the "
                       f"same wall since attempt "
                       f"{state['attempts_with_verdict'] - state['run'] + 1}. "
                       f"NOT a stop; the operator decides.")
                log_fn(msg)
                if state["agent_reason"]:
                    log_fn(f"[blocked] agent says ({state['agent_reason_state']}): "
                           + state["agent_reason"][:300])
            except Exception:
                pass
    return record


# What the agent is told. Kept here beside the gate so the promise and the
# enforcement cannot drift apart: the prompt says a claim before the threshold
# is rejected, and `evaluate` is what rejects it.
BLOCKED_CHANNEL_PROMPT = """\
IF YOU ARE BLOCKED, SAY SO — IN A FILE, WITH THE CONDITION:

  printf '%s' '{"reason":"<the concrete condition, one sentence>"}' > ./blocked.json

This does NOT stop the job and is not a request to stop. It raises a flag the
operator can see, so a run that is hitting the same wall is noticed in minutes
rather than hours.

Write it ONLY when the SAME concrete condition has blocked you across at least
three consecutive exploit attempts, and name that condition: "the target closes
every connection after the banner", "the binary is not present and the bundle
ships no other artefact", "every request returns 403 regardless of credentials".

Difficulty is not blocked. Uncertainty is not blocked. Useful work remaining is
not blocked. A claim written earlier than three consecutive attempts is
recorded and REJECTED, so writing it early costs you the channel rather than
buying attention. Rewrite the file if the condition changes.\
"""
