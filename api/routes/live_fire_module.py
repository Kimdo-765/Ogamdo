"""HTTP submission boundary for the isolated live-fire patch pipeline."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from api.queue import get_queue, hard_timeout_for, normalize_effort, resolve_timeout
from api.storage import new_job_id, save_upload, write_job_meta, stamp_job_tag
from modules.agent_provider import enrich_job_meta
from modules.live_fire_contract import (
    LiveFireContractError,
    parse_live_fire_contract,
    unverified_contract,
)


router = APIRouter()


@router.post("/analyze")
async def analyze_live_fire(
    file: UploadFile = File(...),
    verification: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    job_timeout: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    effort: Optional[str] = Form(None),
    output_language: Optional[str] = Form(None),
    tag: Optional[str] = Form(None),
    # APPENDED, not inserted. Callers that pass this signature positionally
    # exist (scripts/test_live_fire_api_ui.py, test_live_fire_integration.py),
    # and putting a new parameter in the middle silently reassigns every one
    # after it — `job_timeout=100` arrived here as the vulnerability count.
    vulnerability_count: Optional[int] = Form(None),
    # APPENDED for the same reason vulnerability_count was, and the comment
    # above is the receipt: inserting a parameter mid-signature silently
    # reassigned every positional caller after it.
    live_fire_version: Optional[int] = Form(None),
):
    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="live-fire accepts one ZIP file")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="empty ZIP file")
    if not zipfile.is_zipfile(io.BytesIO(content)):
        raise HTTPException(status_code=400, detail="invalid ZIP file")

    # The organizer's one hint in an attack-and-defence round. Bounded rather
    # than trusted: it reaches the patch prompt, and "fix all 900 of them"
    # would spend the whole attempt window on an instruction nobody meant.
    known_count: int | None = None
    if vulnerability_count is not None:
        if not 1 <= int(vulnerability_count) <= 50:
            raise HTTPException(
                status_code=400,
                detail="vulnerability_count must be between 1 and 50",
            )
        known_count = int(vulnerability_count)

    job_id = new_job_id()
    timeout = resolve_timeout(job_timeout)
    # The contract is OPTIONAL. When a contest opens there is a service ZIP and
    # nothing else — no exploit, so no attack probe, so no contract anyone
    # could write honestly — and requiring one here meant the tool was unusable
    # in exactly the window where patching is cheapest. Blank runs the patch
    # loop and states plainly that nothing was verified; `ready_to_deploy` can
    # never come back true. A contract that IS supplied is parsed exactly as
    # strictly as before.
    try:
        if (verification or "").strip():
            contract, _ = parse_live_fire_contract(
                verification,
                job_id=job_id,
                job_timeout_s=timeout,
            )
        else:
            contract, _ = unverified_contract(
                job_id=job_id,
                job_timeout_s=timeout,
                known_vulnerabilities=known_count,
            )
    except LiveFireContractError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # v2 runs four independent agents and builds its own request/response
    # oracle, so it needs no verification contract from the operator. It keeps
    # the module id `live-fire` DELIBERATELY: the per-version feedback
    # endpoint (api/routes/jobs.py) and the patch-history panel
    # (web-ui/app.js) both key on that id, and a new one would silently take
    # the operator's whole interaction loop away.
    version = 2 if live_fire_version == 2 else 1
    if live_fire_version not in (None, 1, 2):
        raise HTTPException(
            status_code=400, detail="live_fire_version must be 1 or 2"
        )

    saved = save_upload(job_id, "input.zip", content)
    chosen_model = (model or "").strip() or None
    chosen_effort = normalize_effort(effort)
    meta = {
        "id": job_id,
        "module": "live-fire",
        "status": "queued",
        "stage": "queued",
        "filename": filename,
        "description": (description or "").strip() or None,
        "job_timeout": timeout,
        "model": chosen_model,
        "effort": chosen_effort,
        "src_archive": str(saved),
        "live_fire_contract": contract,
        "live_fire_version": version,
        "live_fire_known_vulnerabilities": known_count,
        "live_fire_verified": contract.get("verification_mode") != "unverified",
        "ready_to_deploy": None,
        "evidence_tiers": [],
    }
    stamp_job_tag(meta, tag)
    enrich_job_meta(meta, output_language=output_language)
    write_job_meta(job_id, meta)

    get_queue().enqueue(
        "modules.live_fire_v2_job.run_job" if version == 2
        else "modules.live_fire_job.run_job",
        job_id,
        str(saved),
        job_id=job_id,
        job_timeout=hard_timeout_for(timeout),
    )
    return {
        "job_id": job_id,
        "status": "queued",
        "job_timeout": timeout,
        "model": chosen_model,
        "live_fire_version": version,
    }


__all__ = ["analyze_live_fire", "router"]
