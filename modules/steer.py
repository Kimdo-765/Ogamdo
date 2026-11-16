"""Operator steering: one message, delivered into a RUNNING job's own context.

WHAT THIS IS FOR

Everything else that can reach a running job stops it. `/stop` kills it;
`/retry` and `/resume` act only after it has ended and start a NEW session.
So an operator watching a job go the wrong way had exactly two options: let it
finish being wrong, or throw away everything it had learned.

Job 340e62bdcd32 is the argument. From 03:10 its own instruments were saying
it had stopped learning — the evidence budget saturated at 4 distinct states
and went to -10 against a limit of 3, and the orchestrator logged "main is not
acting on it" sixteen times. Every automated signal fired correctly and none
of them could act. It ran until 05:09, when a human woke up and pressed stop.
What was needed at 03:10 was neither halt nor continue: it was a sentence.

HOW IT ARRIVES

At the TURN BOUNDARY, never mid-turn. This is not a limitation worked around;
it is the same boundary a previous design decision settled on, and the rail
already exists — `run_main_agent_session` has an ordered ladder of user-turn
injections (FINAL_DRAFT, soft-eject, EMPTY WAIT) that all reach the model the
same way. Steering is one more rung, placed directly below FINAL_DRAFT: the
operator outranks every automated nudge, and does not outrank the last-chance
draft whose whole job is to stop the run ending with nothing.

A steer submitted during a nine-minute turn waits for that turn to end. A job
that finishes before the next boundary never consumes it, and `pending()` is
how the dashboard says so rather than letting the operator believe a message
landed that did not.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

STEER_FILE = "steer.json"

# One steer is a sentence or a paragraph, not a document. The cap is generous
# enough for a corrected hypothesis with a URL and small enough that a paste
# accident cannot flood the agent's context at a turn boundary.
MAX_TEXT = 4000
# Queued-but-undelivered messages. Ten is already more than an operator can
# usefully say between two turns; past that the oldest are the stale ones.
MAX_PENDING = 10


def _path(work_dir) -> Path:
    return Path(work_dir) / STEER_FILE


def sanitize(text: str) -> str:
    """Trim, drop control characters, cap length.

    NUL and the C0 range (tab and newline excepted) are removed rather than
    escaped: they carry no meaning for a human writing a sentence, and a
    terminal-control sequence in a prompt is a way to make the log lie about
    what was sent.
    """
    cleaned = "".join(
        ch for ch in (text or "")
        if ch in "\t\n" or (ord(ch) >= 0x20 and ord(ch) != 0x7F)
    )
    return cleaned.strip()[:MAX_TEXT]


def _read(work_dir) -> list[dict]:
    try:
        raw = _path(work_dir).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # A half-written file is not a reason to lose the job. Treat it as
        # empty; the operator sees the pending count drop and re-sends.
        return []
    return [m for m in data if isinstance(m, dict) and m.get("text")]


def pending(work_dir) -> list[dict]:
    """Queued messages not yet delivered. Safe to call from the api."""
    return _read(work_dir)


def queue(work_dir, text: str) -> dict:
    """Add one message. Returns {queued, dropped, id}.

    Raises ValueError on an empty message — an operator who pressed send on an
    empty box meant to type something, and silently queueing nothing would
    show them a pending count for a message that says nothing.
    """
    clean = sanitize(text)
    if not clean:
        raise ValueError("steer message is empty")
    work = Path(work_dir)
    if not work.is_dir():
        raise ValueError(f"no work directory for this job: {work}")

    msgs = _read(work)
    msgs.append({
        "id": uuid.uuid4().hex[:12],
        "text": clean,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    })
    dropped = max(0, len(msgs) - MAX_PENDING)
    if dropped:
        msgs = msgs[-MAX_PENDING:]

    tmp = work / f".{STEER_FILE}.tmp"
    tmp.write_text(json.dumps(msgs, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, _path(work))
    return {"queued": len(msgs), "dropped": dropped, "id": msgs[-1]["id"]}


def take(work_dir) -> list[dict]:
    """Read every queued message and clear the file. Returns [] if none.

    Clears by REPLACING with an empty list rather than unlinking: the api may
    be reading the file at this moment, and a missing file and an empty one
    are the same answer to it while a half-deleted one is not.
    """
    msgs = _read(work_dir)
    if not msgs:
        return []
    try:
        work = Path(work_dir)
        tmp = work / f".{STEER_FILE}.tmp"
        tmp.write_text("[]", encoding="utf-8")
        os.replace(tmp, _path(work))
    except OSError:
        # Delivering twice is worse than not clearing, so refuse to deliver
        # what we could not mark as taken.
        return []
    return msgs


def render_user_turn(msgs: list[dict]) -> str:
    """The user turn the agent actually receives.

    Says WHO is speaking, because the model has no other way to tell this from
    the orchestrator's automated nudges — and the difference matters: the
    operator can see the live log and the target, and is the one party in this
    system with information the agent does not have.
    """
    body = "\n\n".join(f"  {m['text']}" for m in msgs if m.get("text"))
    plural = "message" if len(msgs) == 1 else "messages"
    return (
        f"OPERATOR STEER — {len(msgs)} {plural} from the human running this "
        "job, delivered at this turn boundary.\n\n"
        f"{body}\n\n"
        "This is not an automated nudge. The operator is watching the live "
        "log and the target, and is acting on something you have not seen. "
        "Treat it as authoritative and change what you are doing NOW, even "
        "mid-plan.\n"
        "If following it is impossible — the endpoint does not exist, the "
        "primitive was already refuted with evidence — then say so in one "
        "line, cite the evidence, and act on the closest thing that IS "
        "possible. Silently continuing your previous plan is the one response "
        "that is never correct."
    )
