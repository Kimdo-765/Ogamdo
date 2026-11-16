"""Is the challenge's remote target still there — and holding the job if not.

WHY THIS EXISTS

Nothing checked. A Dreamhack instance expires and comes back on a different
port, and until an operator noticed, the job kept working against an address
that had stopped answering. Job 7599aaf936b0 ran to 75 turns that way and
ended only because a human pressed stop; `agent_error_kind` was None, because
from the inside nothing had gone wrong.

So the run now holds instead: status `hold`, the reason recorded, and the job
waits for a new target rather than spending on a dead one.

WHAT IT REFUSES TO DO: FIRE ON ONE FAILED CONNECT

A single refused connection means almost nothing. Job 1aedc9880862 logged
`Connection refused` against localhost:3000 THIRTEEN times while its challenge
was perfectly healthy — the agent had torn down its own container between
probes. A hold triggered by that is worse than no hold at all: the job stops
working and waits for a human who has no reason to be looking.

Two rules follow, and they are the whole design:

  * ONLY THE DECLARED REMOTE. `meta.target_url` / `target_urls`, never a
    loopback or private address. A locally rebuilt challenge going up and down
    is normal work, not a dead target.
  * N CONSECUTIVE FAILURES, SPACED. `_FAILS_TO_HOLD` misses in a row, each at
    least `_MIN_GAP_S` apart, with every one logged so an operator watching
    sees it coming rather than finding a held job later. Any success resets
    the count — a target that answers once is alive.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any
from urllib.parse import urlparse

# Three misses, spaced, before the run holds. Two is within the noise a
# rate-limiting challenge produces on its own; the corpus has no case of a
# live remote refusing three spaced connects in a row.
_FAILS_TO_HOLD = 3
_MIN_GAP_S = 45.0
_CONNECT_S = 5.0

# {job_id: {"fails": int, "last": float, "held": bool}}
_STATE: dict[str, dict[str, Any]] = {}


def _hostport(target: str | None) -> tuple[str, int] | None:
    t = str(target or "").strip()
    if not t:
        return None
    if "://" in t:
        u = urlparse(t)
        if not u.hostname:
            return None
        return u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    host, _, port = t.rpartition(":")
    if not host or not port.isdigit():
        return None
    return host, int(port)


def is_remote(target: str | None) -> bool:
    """A DECLARED remote, not this platform's own sandbox."""
    hp = _hostport(target)
    if not hp:
        return False
    host = hp[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return True          # a name we cannot resolve is still remote
    return not (ip.is_loopback or ip.is_private)


def _alive(target: str) -> bool:
    hp = _hostport(target)
    if not hp:
        return True              # unparseable: not our call to make
    try:
        with socket.create_connection(hp, timeout=_CONNECT_S):
            return True
    except OSError:
        return False


def check(job_id: str, meta: dict, log_fn=None) -> str | None:
    """Probe the declared remote(s). Returns a hold reason, or None.

    Never raises: a watchdog that can end a turn is a worse bug than the one
    it watches for.
    """
    try:
        st = _STATE.setdefault(str(job_id), {"fails": 0, "last": 0.0,
                                             "held": False})
        if st["held"]:
            return None          # already held; the loop owns it now
        targets = [meta.get("target_url")] + list(meta.get("target_urls") or [])
        targets = [t for t in targets if t and is_remote(t)]
        if not targets:
            return None          # local-only or targetless job: nothing to watch
        now = time.monotonic()
        if now - st["last"] < _MIN_GAP_S:
            return None
        st["last"] = now
        if any(_alive(t) for t in targets):
            if st["fails"]:
                if log_fn:
                    log_fn(f"[target-watch] {targets[0]} answered again — "
                           f"miss count reset from {st['fails']}")
                st["fails"] = 0
            return None
        st["fails"] += 1
        if log_fn:
            log_fn(f"[target-watch] {targets[0]} did not answer "
                   f"({st['fails']}/{_FAILS_TO_HOLD} consecutive, "
                   f">={int(_MIN_GAP_S)}s apart)")
        if st["fails"] < _FAILS_TO_HOLD:
            return None
        st["held"] = True
        return (f"the remote target stopped answering: {targets[0]} refused "
                f"{_FAILS_TO_HOLD} connects in a row, spaced at least "
                f"{int(_MIN_GAP_S)}s apart. The challenge instance has most "
                f"likely expired and been restarted on a different port.")
    except Exception:
        return None


def forget(job_id: str) -> None:
    """Drop a job's counters — used when a new target is supplied."""
    _STATE.pop(str(job_id), None)
