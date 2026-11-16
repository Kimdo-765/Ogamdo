"""One ingest for every jeopardy challenge. The operator classifies nothing.

This replaces eight `/analyze` endpoints that each asked the operator to have
already decided what kind of challenge they were holding — web or pwn or rev,
tick Docker, tick capture-remote-flag, tick auto-run. Those are judgements
about the bundle, and the bundle is in the request, so `modules._operator`
makes them instead.

The upload is STAGED here, not placed: where it belongs depends on the module
and the module is not known yet. It is streamed to `<job>/_ingest/<name>` and
`modules.ingest_placement` moves it to its real home once the agent has
answered. Streaming matters — a forensic image is measured in gigabytes and
must never be held in memory.

The seven per-module endpoints stay mounted. The AI Player posts to them
(`test_player_agent_contract`: "create posts to /api/modules/<mod>/analyze")
and this is not that caller.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import (
    job_dir, new_job_id, parse_targets, prepare_job_description, reject_job,
    stamp_job_tag, write_job_meta,
)
from modules.agent_provider import enrich_job_meta

router = APIRouter()

CHUNK = 4 * 1024 * 1024


def _stream_to(path: Path, upload: UploadFile) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with path.open("wb") as out:
        while True:
            chunk = upload.file.read(CHUNK)
            if not chunk:
                break
            out.write(chunk)
            total += len(chunk)
    return total


@router.post("/analyze")
async def analyze_jeopardy(
    file: Optional[UploadFile] = File(None),
    target_url: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    challenge_secret_key: Optional[str] = Form(None),
    challenge_secret_value: Optional[str] = Form(None),
    archive_passphrase: Optional[str] = Form(None),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    output_language: Optional[str] = Form(None),
    tag: Optional[str] = Form(None),
    flag_format: Optional[str] = Form(None),
):
    targets = parse_targets(target_url)
    first_target = targets[0] if targets else None
    has_file = bool(file and file.filename)
    if not has_file and not first_target:
        raise HTTPException(
            status_code=400,
            detail="Provide either a challenge file/archive or a target (or both).",
        )

    job_id = new_job_id()
    ingest_path = None
    if has_file:
        ingest_path = job_dir(job_id) / "_ingest" / Path(file.filename).name
        if _stream_to(ingest_path, file) == 0:
            reject_job(job_id, 400, "empty file")

    description = prepare_job_description(
        job_id, description, challenge_secret_key, challenge_secret_value
    )
    # The archive passphrase has its own typed entry point and must NOT travel
    # through the key/value secret ingress. modules/job_secrets.py records two
    # measured regressions from letting it in there: it overwrote a real CTFd
    # token, and it became a redaction needle that ate meta['filename'].
    if (archive_passphrase or "").strip():
        from modules.job_secrets import store_misc_passphrase

        store_misc_passphrase(job_id, archive_passphrase.strip())

    timeout = resolve_timeout(job_timeout)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        # Not a module yet. The operator agent overwrites this with a real one
        # before any analyzer runs; until then it says what the job IS, which
        # is a jeopardy challenge nobody has classified.
        "module": "jeopardy",
        "status": "queued",
        "filename": Path(file.filename).name if has_file else None,
        "ingest_path": str(ingest_path) if ingest_path else None,
        "target_url": first_target,
        "target_urls": targets if len(targets) >= 2 else None,
        "description": description,
        # No longer a choice. Every jeopardy job runs its exploit.
        "auto_run": True,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "flag_format": (flag_format or "").strip() or None,
        "src_root": None,
        "remote_only": not has_file,
    }
    stamp_job_tag(meta, tag)
    enrich_job_meta(meta, output_language=output_language)
    write_job_meta(job_id, meta)

    q = get_queue()
    q.enqueue(
        "modules._operator.route_job",
        job_id,
        job_id=job_id,
        # Covers BOTH halves: the routing decision and the solve it hands off
        # to run inside the same worker slot.
        job_timeout=hard_timeout_for(timeout),
    )
    return {"job_id": job_id, "status": "queued", "job_timeout": timeout,
            "model": chosen_model}
