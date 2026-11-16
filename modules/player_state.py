"""What the AI Player has already created, so a re-run resumes.

The operator chose auto-create over approve-then-create. That choice moves one
requirement onto this file: a second run over the same site must not create a
second job for every challenge it already handled.

`tag` cannot serve as that key — `scripts/test_job_tag_is_display_only.py`
pins it as a display field, and two challenges on different sites can share a
name. So the identity is `(site, challenge_id)`, taken from the site's own id
for the challenge, and it is written **before** the create POST. A crash
between the write and the POST leaves a claim with no job, which the next run
reports as `pending` and retries; the reverse order would leave a job nothing
remembers and duplicate it forever.

The same file is the run manifest. Forty auto-created jobs with no list back
is forty manual `POST /api/jobs/{id}/stop` calls, so every claim keeps the job
id, the challenge name and when it was made.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def _root() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "player-state"


def _path(site: str) -> Path:
    safe = "".join(c for c in str(site or "").strip().lower()
                   if c.isalnum() or c in "._-")[:64]
    if not safe:
        safe = "unknown"
    return _root() / f"{safe}.json"


def _read(site: str) -> dict[str, Any]:
    try:
        data = json.loads(_path(site).read_text())
    except (OSError, ValueError):
        return {"site": site, "claims": {}}
    if not isinstance(data, dict):
        return {"site": site, "claims": {}}
    data.setdefault("claims", {})
    if not isinstance(data["claims"], dict):
        data["claims"] = {}
    return data


def _write(site: str, data: dict[str, Any]) -> None:
    path = _path(site)
    root = path.parent
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / f".{path.name}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    os.replace(tmp, path)


def claimed(site: str, challenge_id: str) -> dict[str, Any] | None:
    """The existing claim for this challenge, or None if it is unhandled."""
    return _read(site)["claims"].get(str(challenge_id))


def claim(site: str, challenge_id: str, *, name: str = "",
          module: str = "", url: str = "") -> bool:
    """Reserve a challenge BEFORE creating its job.

    Returns False when it was already claimed — the caller must then skip the
    create. Racing callers are not a concern here (one player run per site),
    but the read-modify-write is kept small anyway.
    """
    cid = str(challenge_id)
    data = _read(site)
    if cid in data["claims"]:
        return False
    data["claims"][cid] = {
        "challenge_id": cid,
        "name": str(name or ""),
        "module": str(module or ""),
        "url": str(url or ""),
        "job_id": None,
        "state": "pending",
        "claimed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    _write(site, data)
    return True


def settle(site: str, challenge_id: str, *, job_id: str | None,
           state: str = "created", detail: str = "") -> None:
    """Record the outcome of the create POST against an existing claim."""
    cid = str(challenge_id)
    data = _read(site)
    entry = data["claims"].get(cid)
    if entry is None:
        entry = {"challenge_id": cid}
        data["claims"][cid] = entry
    entry["job_id"] = job_id
    entry["state"] = state
    if detail:
        entry["detail"] = str(detail)[:400]
    entry["settled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    _write(site, data)


def release(site: str, challenge_id: str) -> None:
    """Drop a claim so the next run may try it again.

    Used when the create failed in a way a retry could fix. A claim that
    settled `created` is never released — that is the duplicate this file
    exists to prevent.
    """
    cid = str(challenge_id)
    data = _read(site)
    entry = data["claims"].get(cid)
    if entry and entry.get("state") != "created":
        data["claims"].pop(cid, None)
        _write(site, data)


def manifest(site: str) -> list[dict[str, Any]]:
    """Everything this site's player has created, newest claim last."""
    data = _read(site)
    rows = list(data["claims"].values())
    rows.sort(key=lambda r: str(r.get("claimed_at") or ""))
    return rows


def sites() -> list[str]:
    try:
        return sorted(p.stem for p in _root().glob("*.json"))
    except OSError:
        return []
