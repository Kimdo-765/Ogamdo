"""HTTP surface for the AI Player — the new operator-facing menu.

The player runs IN this process, not on a worker slot: the thing that creates
jobs must not compete for a slot with the jobs it creates. The api container
was verified on 2026-09-09 to carry `codex` and an authed `/root/.codex`, so
this needs no worker, no queue entry and no new image.

Credential ingress is here and nowhere else. The site password is written
straight into `modules/player_creds` (0600, its own directory) and is never
returned by any route — `GET /sites` lists usernames only.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.responses import JSONResponse

from modules import player_creds, player_state
from modules.player_agent import DEFAULT_EFFORT, DEFAULT_TIMEOUT_S, PlayerRun

router = APIRouter()

# One live run per site. A second run against the same site would race on the
# cookie jar and on the claim file, and the duplicate it produced would look
# exactly like the crash-window duplicate `player_state` already warns about.
_RUNS: dict[str, PlayerRun] = {}


def _run_for(site: str) -> Optional[PlayerRun]:
    return _RUNS.get(site)


@router.get("/sites")
def list_sites():
    """Saved site logins — usernames only, never a password."""
    rows = player_creds.known_sites()
    for row in rows:
        site = row["site"]
        claims = player_state.manifest(site)
        row["created"] = sum(1 for c in claims if c.get("state") == "created")
        row["claims"] = len(claims)
        run = _run_for(site)
        row["state"] = (run.status().get("state") if run else "idle")
    return {"sites": rows}


@router.post("/credentials")
def save_credentials(
    site_url: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    extra: Optional[str] = Form(None),
):
    """Store one CTF site login.

    Deliberately not in `data/settings.json`: that file holds `auth_token`,
    whose standing rule is that it may only ever be sent to 127.0.0.1. A site
    password's whole purpose is to be sent to a remote site, and filing the
    two together is how one rule gets applied to the wrong secret.
    """
    extras = {}
    if extra:
        for part in str(extra).split(","):
            if "=" in part:
                k, _, v = part.partition("=")
                if k.strip() and v.strip():
                    extras[k.strip()] = v.strip()
    try:
        site = player_creds.store(site_url, username, password, extra=extras)
    except player_creds.CredentialError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"site": site, "saved": True}


@router.delete("/credentials/{site}")
def forget_credentials(site: str):
    return {"site": site, "forgotten": player_creds.forget(site)}


@router.post("/start")
def start_player(
    site_url: str = Form(...),
    language: Optional[str] = Form("ko"),
    note: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    timeout_s: Optional[float] = Form(None),
):
    try:
        site = player_creds.site_key(site_url)
    except player_creds.CredentialError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not player_creds.load(site):
        raise HTTPException(
            status_code=400,
            detail=f"no stored login for {site} — save credentials first",
        )
    existing = _run_for(site)
    if existing and existing.status().get("state") == "running":
        raise HTTPException(status_code=409,
                            detail=f"a player run is already active for {site}")

    run_id = f"{site}-{time.strftime('%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
    run = PlayerRun(
        run_id, site_url,
        language=(language or "ko"),
        note=(note or ""),
        effort=(effort or "").strip() or DEFAULT_EFFORT,
        timeout_s=float(timeout_s) if timeout_s else DEFAULT_TIMEOUT_S,
    )
    try:
        run.start()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    _RUNS[site] = run
    return run.status()


@router.post("/stop")
def stop_player(site: str = Form(...)):
    run = _run_for(site)
    if not run:
        raise HTTPException(status_code=404, detail="no run for that site")
    return run.stop()


@router.get("/status")
def player_status(site: str = Query(...), lines: int = Query(200)):
    run = _run_for(site)
    claims = player_state.manifest(site)
    payload = {
        "site": site,
        "state": (run.status() if run else {"state": "idle"}),
        "created": sum(1 for c in claims if c.get("state") == "created"),
        "claims": claims[-200:],
        "log": (run.tail(max(1, min(int(lines or 200), 2000))) if run else []),
    }
    return JSONResponse(payload)


@router.get("/manifest")
def manifest(site: str = Query(...)):
    """Everything this site's player created — the list the operator needs to
    stop 40 auto-created jobs without hunting for their ids."""
    rows = player_state.manifest(site)
    return {"site": site, "count": len(rows),
            "created": sum(1 for r in rows if r.get("state") == "created"),
            "claims": rows}
