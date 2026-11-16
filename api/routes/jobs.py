import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timezone
import ast
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse

from api.queue import get_queue, get_redis
from api.storage import JOBS_DIR, UPLOADS_DIR, parse_targets, read_job_meta, write_job_meta
from api.stop_audit import append_operator_stop_audit

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

router = APIRouter()

_USAGE_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped",
                            "flag_ready"}

# Job IDs are always 12 hex chars (api.storage.new_job_id =
# uuid.uuid4().hex[:12]). Anything else — empty string, ".",
# "..", "%2E", path traversals — must be rejected BEFORE the
# Path(...).name + JOBS_DIR / safe construction, because
# Path(".").name returns "" → JOBS_DIR / "" == JOBS_DIR itself,
# and a subsequent rmtree wipes every job. Verified the hard
# way during a security audit on 2026-05-14.
_JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _validate_job_id(job_id: str) -> str:
    """Reject anything that isn't a canonical 12-hex job id.
    Returns the validated id unchanged."""
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(status_code=400, detail="invalid job id")
    return job_id


def _job_cost(job_id: str, meta: dict) -> float:
    """Read one scalar job's authoritative cost with the existing fallback."""
    try:
        cost = float(meta.get("cost_usd") or 0.0)
    except (TypeError, ValueError):
        cost = 0.0
    result_path = JOBS_DIR / job_id / "result.json"
    if cost == 0.0 and result_path.exists():
        try:
            result = json.loads(result_path.read_text())
            cost = float(result.get("cost_usd") or 0.0)
        except Exception:
            pass
    return cost


def _scalar_usage_cost_parts(job_id: str, meta: dict) -> tuple[float, float, bool]:
    """Return authoritative spend, terminal unpriced estimate, completeness.

    ``meta.cost_usd == 0`` is the legacy representation of both real zero and
    missing price.  In particular Codex ChatGPT OAuth returns
    ``total_cost_usd=None`` and the analyzers persist 0.  Treating that as a
    complete dollar total is the bug this split fixes.  A positive estimate is
    preserved in a separate unit and never folded into authoritative spend.
    """
    from modules.usage_ledger import (
        LEDGER_FILENAME,
        dollar_cost_parts,
        read_usage_path,
    )

    # meta.cost_usd is the existing main/subagent job scalar and main also has
    # ledger rows that mirror it. Judge and reviewer calls are separate
    # API/worker invocations recorded only in usage.jsonl, so add those roles;
    # summing the whole ledger would double-count a priced main session.
    records = read_usage_path(JOBS_DIR / job_id / LEDGER_FILENAME)
    auxiliary_spent, auxiliary_complete = dollar_cost_parts(
        records, roles={"judge", "reviewer"}
    )
    cost = _job_cost(job_id, meta)

    # Legacy analyzers promoted the token estimate into meta.cost_usd when a
    # terminal ResultMessage carried total_cost_usd=None.  That makes the same
    # estimate appear authoritative merely because it is positive (observed on
    # Codex OAuth job f2a5b2c71ac8: 18.422439 vs estimate 18.4224).  A null main
    # ledger row is the durable provenance signal: keep the value in the
    # estimate unit and do not compare it with an operator dollar budget.
    main_spent, main_complete = dollar_cost_parts(records, roles={"main"})
    main_rows = [row for row in records if str(row.get("role") or "") == "main"]
    try:
        parked_estimate = max(0.0, float(meta.get("cost_usd_estimate") or 0.0))
    except (TypeError, ValueError):
        parked_estimate = 0.0
    promoted_estimate = bool(
        cost > 0.0
        and parked_estimate > 0.0
        and main_rows
        and main_spent == 0.0
        and not main_complete
        # The heartbeat parks the same token estimate rounded to four decimal
        # places, while the legacy finalizer copied the unrounded value into
        # cost_usd.  Match only that quantization gap (at most half of $0.0001).
        # A cent-wide floor demoted real small-dollar prices: $0.20 vs $0.195
        # is 2.6% apart but still fell inside $0.01.
        and abs(cost - parked_estimate) <= 0.00005 + 1e-12
    )
    if promoted_estimate:
        return auxiliary_spent, parked_estimate, False
    if cost != 0.0:
        # The scalar is a session-total contract. A multi-model ledger may put
        # that reported total on the primary row and null on secondary rows
        # because it cannot invent a per-model split; that does not make the
        # already-reported scalar incomplete.
        return cost + auxiliary_spent, 0.0, auxiliary_complete
    if str(meta.get("status") or "") not in _USAGE_TERMINAL_STATUSES:
        return auxiliary_spent, 0.0, auxiliary_complete
    return auxiliary_spent, parked_estimate, False


def _job_usage_cost_parts(job_id: str, meta: dict) -> tuple[float, float, bool]:
    """Public-job cost parts."""
    return _scalar_usage_cost_parts(job_id, meta)


def rq_job_id_for(job_id: str, meta: dict | None = None) -> str:
    """The RQ id CURRENTLY backing `job_id` — which is not always `job_id`.

    A continue-in-place re-runs the same job under a NEW RQ id: RQ ids are
    unique and the original has already finished, so `_continue_in_place`
    enqueues under ``<job_id>-c<continue_count>`` (api/routes/retry.py) while
    the job directory, the meta and every URL keep the bare id.

    Everything that reaches into RQ must resolve through here. Signalling the
    bare id after a continue hits the *finished* original, which RQ ignores —
    Stop and Delete then report success while the live agent keeps running and
    keeps spending.
    """
    if meta is None:
        meta = read_job_meta(job_id) or {}
    try:
        n = int((meta or {}).get("continue_count") or 0)
    except (TypeError, ValueError):
        n = 0
    return f"{job_id}-c{n}" if n > 0 else job_id


def _rq_id_candidates(job_id: str, meta: dict | None = None) -> list[str]:
    """Resolved RQ id first, bare job id second (deduped).

    The bare id stays as a fallback so a meta whose `continue_count` ran ahead
    of what was actually enqueued — a continue that wrote meta and then failed
    to enqueue — cannot leave the original permanently unstoppable.
    """
    return list(dict.fromkeys([rq_job_id_for(job_id, meta), job_id]))


def _hard_stop_job(job_id: str) -> dict:
    """Try to actually halt work on a running job:
    1. Send STOP_JOB command to whichever worker is running it (RQ pub-sub).
    2. Find sibling docker containers labelled hextech_ctf_tool_job_id=<id> and
       force-remove them (decompiler / forensic / misc / runner).

    Still best-effort — a cleanup that raises would break the delete it is part
    of — but no longer SILENT. It used to swallow every failure including
    "docker unreachable", so a sweep that removed nothing was indistinguishable
    from one that had nothing to remove. Measured 2026-08-10: container
    609f3504b4d2 (runner, labelled job 9b8168b0ee29) outlived the deletion of
    its own job and its job directory, with nothing anywhere recording that the
    reap had not happened. `containers_failed` / `docker_error` are what make
    that case visible to the caller, which returns this dict in the DELETE
    response.
    """
    info: dict = {"sent_stop": False, "containers_killed": 0,
                  "containers_found": 0, "containers_failed": [],
                  "docker_error": None,
                  "rq_cancelled": False, "rq_ids": []}
    conn = get_redis()
    # 1) Tell RQ to interrupt the running job. send_stop_job_command works only
    #    on running jobs; for queued ones, plain cancel() is enough.
    #    Both candidate ids are signalled: the extra call costs one round trip
    #    and every failure mode here (no such job, already finished) raises and
    #    is swallowed, so it cannot make the stop worse — whereas guessing the
    #    wrong single id makes it a silent no-op.
    for rq_id in _rq_id_candidates(job_id):
        info["rq_ids"].append(rq_id)
        try:
            from rq.command import send_stop_job_command
            send_stop_job_command(conn, rq_id)
            info["sent_stop"] = True
        except Exception:
            pass
        try:
            from rq.job import Job
            rq_job = Job.fetch(rq_id, connection=conn)
            try:
                rq_job.cancel()
                info["rq_cancelled"] = True
            except Exception:
                pass
        except Exception:
            pass

    # 2) Kill any sibling containers spawned for this job
    try:
        import docker as _docker
        client = _docker.from_env()
        containers = client.containers.list(
            all=True,
            filters={"label": f"hextech_ctf_tool_job_id={job_id}"},
        )
        info["containers_found"] = len(containers)
        for c in containers:
            name = getattr(c, "name", None) or (getattr(c, "id", "") or "")[:12]
            try:
                c.kill()
            except Exception:
                # An already-exited container cannot be killed; that is the
                # normal case here, not a failure. Only the remove matters.
                pass
            try:
                # v=True: the anonymous volumes this container created are its
                # own and leak otherwise — 383 of them accumulated on
                # 2026-08-10 alone.
                c.remove(force=True, v=True)
                info["containers_killed"] += 1
            except Exception as e:
                info["containers_failed"].append(f"{name}: {type(e).__name__}")
    except Exception as e:
        # The whole block failing means the daemon was unreachable, which is
        # exactly when siblings survive. Recorded rather than swallowed.
        info["docker_error"] = f"{type(e).__name__}: {e}"

    return info


def _read_manager_assessment(job_id: str) -> dict | None:
    """`<job>/manager.json`, or None. Must never raise into the job list.

    Deliberately a plain file read rather than an import of modules._manager:
    the list endpoint is the hottest path in the api and has no other reason to
    pull that module in.
    """
    try:
        raw = (JOBS_DIR / job_id / "manager.json").read_text(encoding="utf-8")
        rec = json.loads(raw)
        return rec if isinstance(rec, dict) else None
    except Exception:
        return None


@router.get("")
def list_jobs():
    if not JOBS_DIR.exists():
        return {"jobs": []}
    out = []
    for d in sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = read_job_meta(d.name)
        if meta:
            meta["runnable_script"] = _detect_runnable_script(d)
            # Read from disk, never computed here: the manager agent owns the
            # assessment and this endpoint is polled every few seconds by every
            # open dashboard. Absent when the feature is off or a job has not
            # been assessed yet, and the UI renders the row without it.
            _mgr = _read_manager_assessment(d.name)
            if _mgr:
                meta["manager"] = _mgr
            out.append(meta)
    return {"jobs": out}


@router.get("/queue")
def queue_info():
    """Live worker + queue status. Used by the UI to show concurrency."""
    from rq import Worker
    conn = get_redis()
    q = get_queue()
    workers = Worker.all(connection=conn)
    busy = []
    idle = []
    for w in workers:
        info = {"name": w.name, "state": w.get_state()}
        if w.get_current_job_id():
            info["job_id"] = w.get_current_job_id()
        if info["state"] == "busy":
            busy.append(info)
        else:
            idle.append(info)
    return {
        "queued": q.count,
        "started": q.started_job_registry.count,
        "failed": q.failed_job_registry.count,
        "workers_total": len(workers),
        "workers_busy": len(busy),
        "workers_idle": len(idle),
        "workers": busy + idle,
    }


@router.get("/stats")
def get_stats():
    """Aggregate cost and counts across all jobs."""
    if not JOBS_DIR.exists():
        return {"total_cost_usd": 0.0, "by_module": {}, "count": 0}
    total = 0.0
    in_flight = 0.0          # token-estimated spend of jobs still running
    terminal_unpriced = 0.0  # terminal jobs whose provider reported no dollars
    spent_complete = True
    by_module: dict[str, dict] = {}
    count = 0
    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        count += 1
        module = meta.get("module", "unknown")
        bucket = by_module.setdefault(module, {"count": 0, "cost_usd": 0.0})
        bucket["count"] += 1
        cost, job_unpriced, job_complete = _job_usage_cost_parts(d.name, meta)
        terminal_unpriced += job_unpriced
        spent_complete = spent_complete and job_complete
        # LIVE jobs: surface the part of THIS session's spend that no
        # ResultMessage has confirmed yet. A CONTINUED session carries the
        # banked prior total in cost_usd from its first moment, so the old
        # `cost == 0` gate never fired for it and the operator watched a frozen
        # number for the whole session — the very "in-flight job reports $0"
        # complaint the estimate was added to fix.
        if (meta.get("status") or "") in ("running", "queued", "analyze"):
            _banked = float(meta.get("cost_usd_prior_sessions") or 0.0)
            _est = float(meta.get("cost_usd_estimate") or 0.0)
            _confirmed_this_session = max(0.0, cost - _banked)
            in_flight += max(0.0, _est - _confirmed_this_session)
        bucket["cost_usd"] += cost
        total += cost
    return {"total_cost_usd": round(total, 4), "by_module": by_module,
            "count": count, "in_flight_estimate_usd": round(in_flight, 4),
            "terminal_unpriced_estimate_usd": round(terminal_unpriced, 4),
            "spent_usd_complete": spent_complete}


@router.get("/usage")
def get_usage():
    """Top-bar usage pill data: cumulative SPENT cost vs an operator-set
    budget, plus account-global rate-limit status for Claude, Grok and Codex.

    Honest scope:
      * `remaining_usd` is `budget_usd - spent` against the OPERATOR'S
        configured budget only when `spent_usd_complete=true`; otherwise it
        and `pct_used` are null. A zero budget means spent-only. This is not the
        Claude account limit.
      * `rate_limit` is Claude's coarse subscription signal the Agent SDK
        emits (status + reset epoch; `utilization` is frequently absent
        for OAuth accounts).
      * `grok_rate_limit` is Grok SuperGrok weekly pool usage polled from
        cli-chat-proxy `/v1/billing?format=credits` (needs `grok login`
        OAuth mounted). Includes `remaining_pct` when available.
      * `codex_rate_limit` is the mounted ChatGPT OAuth account's usage,
        queried through Codex CLI app-server and cached for 15 seconds.
    """
    from modules.settings_io import get_setting
    from modules._common import read_rate_limit, read_grok_rate_limit
    from modules.codex_rate_limit import read_codex_rate_limit

    stats = get_stats()
    spent = float(stats.get("total_cost_usd") or 0.0)
    try:
        budget = float(get_setting("budget_usd") or 0.0)
    except (TypeError, ValueError):
        budget = 0.0
    spent_complete = bool(stats.get("spent_usd_complete", True))
    # A known-dollar subtotal is still useful evidence, but it is not a total.
    # Returning a numeric "left" or percentage for an incomplete sum falsely
    # claims the operator budget bounds the run.
    remaining = round(budget - spent, 4) if budget > 0 and spent_complete else None
    pct_used = (
        round(min(spent / budget * 100.0, 999.9), 1)
        if budget > 0 and spent_complete else None
    )
    return {
        "spent_usd": round(spent, 4),
        # Token-estimated spend of jobs still RUNNING (no ResultMessage yet, so
        # they contribute 0 to spent_usd). Deliberately NOT added to spent_usd
        # or to the budget maths: it is an estimate that runs high, and the
        # budget number must stay the authoritative one.
        "in_flight_estimate_usd": stats.get("in_flight_estimate_usd", 0.0),
        # A separate unit for terminal sessions whose backend reports no dollar
        # amount (notably Codex ChatGPT OAuth).  Never add this estimate to
        # spent_usd or budget maths; spent_usd_complete tells callers that the
        # authoritative dollar sum is partial.
        "terminal_unpriced_estimate_usd": stats.get(
            "terminal_unpriced_estimate_usd", 0.0
        ),
        "spent_usd_complete": spent_complete,
        "budget_usd": round(budget, 4),
        "remaining_usd": remaining,
        "pct_used": pct_used,
        "count": stats.get("count", 0),
        "rate_limit": read_rate_limit(),
        "grok_rate_limit": read_grok_rate_limit(),
        "codex_rate_limit": read_codex_rate_limit(),
    }


def _script_missing_siblings(script: Path) -> list[str]:
    """Sibling files the script REQUIRES that are not there.

    "A file named exploit.py exists" was the whole test for `runnable_script`,
    and it is not the same question. A job shipped an uploader skeleton that
    began by loading a compiled sibling it did not ship, e.g.

        payload_path = Path(__file__).resolve().with_name("payload_bin")
        if not payload_path.exists():
            raise SystemExit("build the helper first")

    — so "Run in sandbox" offered to run something that could only exit. The
    operator reads that button as "there is an exploit"; it meant "there is a
    filename".

    Deliberately narrow. It resolves LITERAL sibling names only, via
    `.with_name("x")` and `open("x")` / `Path("x")` with no separator, and says
    nothing about a script that builds its payload at run time. A wrong "this
    is fine" is the failure that matters here, so the analysis only reports
    what it can actually see.
    """
    try:
        tree = ast.parse(script.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    wanted: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        elif isinstance(node.func, ast.Name):
            name = node.func.id
        if name not in {"with_name", "open", "Path"}:
            continue
        for arg in node.args[:1]:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                continue
            v = arg.value
            if not v or "/" in v or v.startswith(".") or len(v) > 100:
                continue
            wanted.append(v)
    here = script.parent
    return sorted({v for v in wanted if not (here / v).exists()})


def _detect_runnable_script(job_dir: Path) -> str | None:
    # Primary: <jobdir>/<name> (populated by the analyzer's carry step at
    # the end of a run). Fallback: <jobdir>/work/<name> — present even
    # when the carry hasn't run yet (e.g. a collector OOB capture marked
    # the job finished while the main agent was still mid-analyze, or the
    # run was stopped before stage=done). The /file/{name} route already
    # has this work/ fallback, so the link resolves either way.
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (job_dir / name).is_file() or (job_dir / "work" / name).is_file():
            return name
    return None


@router.get("/{job_id}")
def get_job(job_id: str):
    meta = read_job_meta(job_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    rq_status = None
    rq_worker_name = None
    try:
        q = get_queue()
        # Same resolution as the stop path: after a continue the live RQ record
        # is <job_id>-c<n>, so probing the bare id reported rq_status=None and
        # no worker — which the UI reads as "no worker heartbeat" on a job that
        # is in fact running.
        rq_job = None
        for _rq_id in _rq_id_candidates(job_id, meta):
            rq_job = q.fetch_job(_rq_id)
            if rq_job is not None:
                break
        if rq_job is not None:
            rq_status = rq_job.get_status(refresh=True)
            rq_worker_name = rq_job.worker_name
    except Exception:
        pass

    # `rq_worker_heartbeat_at` used to be computed here, from
    # `rq:worker:<name>.last_heartbeat`, purely to drive the UI's liveness
    # chip. Both are gone. The field was semantically wrong as well as unused:
    # a worker name is permanently bound to a slot and reused by every job that
    # runs there, so it answered "is the process called htct-sN-w0 alive?" and
    # not "is THIS job alive?" — after a work horse is SIGKILLed without
    # writing a terminal status, the slot's container returns under the same
    # name and heartbeats every 30 s, so the field stayed fresh for a job that
    # was gone. `rq_status` (below) is the honest per-job signal and is kept.
    #
    # If a per-job heartbeat is ever wanted, RQ does keep one:
    # `rq:job:<id>.last_heartbeat`, written by Worker.maintain_heartbeats for
    # that specific job. Read THAT, not the worker's.

    # Always derive a `runnable_script` field from the filesystem so the UI
    # can show the run-now button even on jobs whose meta was written before
    # the field existed (or whose orchestrator didn't set it).
    _jd = JOBS_DIR / Path(job_id).name
    runnable_script = _detect_runnable_script(_jd)
    # A script can exist and still be unable to run. Reported alongside rather
    # than folded into `runnable_script`, so the /file/ link and the retry
    # paths that key off the name are untouched — only the UI's claim changes.
    script_missing = []
    if runnable_script:
        for _cand in (_jd / runnable_script, _jd / "work" / runnable_script):
            if _cand.is_file():
                script_missing = _script_missing_siblings(_cand)
                break

    # WHY_STOPPED.md only exists on abnormal stops (judge_stop / agent_error /
    # no_hint / budget) — written by write_why_stopped() to the work tree and
    # carried to root at stage=done. Surface a presence flag so the UI can show
    # its file link only when it exists (unlike report.md/exploit.py which are
    # always linked), avoiding a dead 404 link on clean flag-capture runs.
    has_why_stopped = (
        (_jd / "WHY_STOPPED.md").is_file()
        or (_jd / "work" / "WHY_STOPPED.md").is_file()
    )

    # The agent's own "I am structurally blocked, here is why" claim. Read from
    # disk rather than stamped at conclusion on purpose: every module is told
    # to write it (the channel is appended to CTF_PREAMBLE, which all of them
    # share), but the only consumer was `_blocked.maybe_signal`, and that is
    # called from `run_main_agent_session` alone. Modules with no judge ladder
    # — misc, forensic — therefore wrote the file and nothing ever read it:
    # all three claims in this box came from misc jobs, each naming the exact
    # obstacle the run died on. Surfacing it here needs no lifecycle hook, no
    # per-module call site, and works on jobs that already finished.
    #
    # This is NOT the escalation signal. That one asks whether the PLATFORM
    # sees a wall (N identical judge verdicts) and is deliberately left alone;
    # this asks only what the agent said, which is a fact on its own.
    blocked_reason = None
    for _bp in (_jd / "blocked.json", _jd / "work" / "blocked.json"):
        try:
            if _bp.is_file():
                _claim = json.loads(_bp.read_text(encoding="utf-8"))
                _reason = str((_claim or {}).get("reason") or "").strip()
                if _reason:
                    blocked_reason = _reason[:2000]
                    break
        except Exception:
            continue

    return {
        **meta,
        "rq_status": rq_status,
        # kept: scripts/job-status.sh prints it, and it identifies the slot
        "rq_worker_name": rq_worker_name,
        "runnable_script": runnable_script,
        "script_missing": script_missing,
        "has_why_stopped": has_why_stopped,
        "blocked_reason": blocked_reason,
    }


@router.delete("")
def bulk_delete_jobs(
    status: str | None = None,
    module: str | None = None,
    all: bool = False,
):
    """Bulk delete jobs.

    Query params:
      - status: only delete jobs with this status (queued/running/finished/failed)
      - module: only delete jobs from this module
      - all=true: also cancel queued/running jobs (in addition to filesystem cleanup)

    Without any filter, deletes finished + failed only (safe default — leaves
    queued/running jobs alone).
    """
    if not JOBS_DIR.exists():
        return {"deleted": 0, "skipped": 0, "ids": []}

    safe_default_statuses = {"finished", "failed", "no_flag"}
    deleted_ids: list[str] = []
    skipped = 0

    for d in JOBS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta = read_job_meta(d.name)
        if not meta:
            continue
        st = meta.get("status")
        mod = meta.get("module")
        # Filter
        if status and st != status:
            continue
        if module and mod != module:
            continue
        if not status and not all and st not in safe_default_statuses:
            skipped += 1
            continue
        # Halt running/queued jobs: stop the worker + kill sibling containers.
        if st in ("queued", "running"):
            _hard_stop_job(d.name)
        upload_dir = UPLOADS_DIR / d.name
        if upload_dir.exists():
            try:
                shutil.rmtree(upload_dir)
            except Exception:
                skipped += 1
                continue
        try:
            shutil.rmtree(d)
            from modules.job_secrets import delete_job_secrets

            delete_job_secrets(d.name)
            deleted_ids.append(d.name)
        except Exception:
            skipped += 1

    return {"deleted": len(deleted_ids), "skipped": skipped, "ids": deleted_ids}


@router.delete("/{job_id}")
def delete_job(job_id: str):
    safe = _validate_job_id(job_id)
    d = JOBS_DIR / safe
    # Defense in depth: ensure the resolved path is a direct
    # child of JOBS_DIR. Catches the case where JOBS_DIR is
    # itself a symlink that resolves outside the expected root.
    jobs_root = JOBS_DIR.resolve()
    try:
        d_resolved = d.resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid job id")
    if d_resolved.parent != jobs_root:
        raise HTTPException(status_code=400, detail="invalid job id")
    if not d.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe)
    halt_info = None
    if meta and meta.get("status") in ("queued", "running"):
        halt_info = _hard_stop_job(safe)
    upload_dir = UPLOADS_DIR / safe
    if upload_dir.exists():
        shutil.rmtree(upload_dir)
    shutil.rmtree(d)
    from modules.job_secrets import delete_job_secrets

    delete_job_secrets(safe)
    return {"deleted": safe, "halt": halt_info}


@router.post("/{job_id}/runner/stop")
async def stop_runner(job_id: str, request: Request):
    """Stop the IN-FLIGHT sandbox run — not the job.

    The expensive failure this answers: a sandbox grinding for ten minutes on
    an exploit the operator has already stopped believing in. Until now the
    only lever was `/stop`, which ends the session and takes the work tree's
    context with it; the agent then has to be rebuilt from a retry rather than
    simply moving on.

    This kills the container, hands the FACT to postjudge — an operator stop
    is neither a failure nor a success, and the judge is told not to read the
    missing result as a negative one — and lets the loop continue into the
    next main turn with everything else intact.
    """
    safe = _validate_job_id(job_id)
    jd = JOBS_DIR / safe
    if not jd.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe) or {}
    if meta.get("status") != "running":
        raise HTTPException(
            status_code=409,
            detail=f"job is {meta.get('status')!r}, so no run is in flight")
    reason = ""
    try:
        body = await request.json()
        reason = str((body or {}).get("reason") or "")
    except Exception:
        pass
    from modules._runner import request_runner_stop

    ok = request_runner_stop(jd, reason)
    if not ok:
        raise HTTPException(status_code=500, detail="could not file the stop")
    return {"requested": safe, "reason": reason.strip()[:400]}


@router.post("/{job_id}/stop")
def stop_job(job_id: str):
    """Pure stop: halt a queued/running job WITHOUT deleting it — keep the job
    record and ./work/ artifacts, just stop the work.

    Cancels the RQ job (so it won't auto-resume on a worker restart) via the
    same _hard_stop_job used by DELETE and by 'stop & resume', then rewrites
    meta.status='stopped' so the UI no longer shows it live. Distinct from:
      * DELETE /{job_id}        — halts AND removes the job entirely.
      * 'stop & resume' (retry) — halts THIS job and forks a fresh one.
    On an already-terminal job it just stamps status=stopped (no re-halt). No
    error/error_kind is set — a user stop is a clean terminal state, not a
    failure, so the detail view shows a plain 'stopped' pill (not an error
    banner). Mirrors retry._halt_source_job minus the resume."""
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    was = meta.get("status")
    halt_info = None
    if was in ("queued", "running"):
        from modules.codex_turn_guard import request_turn_stop

        request_turn_stop(JOBS_DIR / safe / "work")
        halt_info = _hard_stop_job(safe)
    stopped_meta = append_operator_stop_audit({
        **meta,
        "status": "stopped",
        "stopped_at": datetime.now(timezone.utc).isoformat(),
    }, action="stop", previous_status=was, halt=halt_info,
        termination_acknowledged=None)
    write_job_meta(safe, stopped_meta)
    return {
        "stopped": safe,
        "prev_status": was,
        "status": "stopped",
        "halt": halt_info,
    }


@router.post("/{job_id}/flags/delete")
async def delete_job_flags(job_id: str, request: Request):
    """Prune operator-selected entries from a job's captured ``flags``.

    Some challenges pad stdout with flag-shaped noise (ASCII-art banners,
    decoys) so the scanner stuffs ``meta.flags`` with dozens of dummies
    around the one real flag (see job 8806b284d740). This lets the operator
    delete the junk by index. Body::

        {"indices": [<int>, ...]}   # positions in the CURRENT meta.flags

    Returns the surviving flags. ``status`` is left untouched — the operator
    is curating the captured list, not re-adjudicating success. Out-of-range
    indices are ignored so a stale UI can't 500 the call.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    indices = body.get("indices")
    if not isinstance(indices, list) or not all(isinstance(i, int) for i in indices):
        raise HTTPException(status_code=400, detail="`indices` must be a list of integers")

    flags = list(meta.get("flags") or [])
    remove = {i for i in indices if 0 <= i < len(flags)}
    new_flags = [f for j, f in enumerate(flags) if j not in remove]

    if len(new_flags) != len(flags):
        from modules._common import write_meta
        write_meta(safe, flags=new_flags)
        # Keep result.json in sync so a later download / result view does
        # not resurrect the pruned entries.
        try:
            rp = JOBS_DIR / safe / "result.json"
            if rp.exists():
                rj = json.loads(rp.read_text())
                if isinstance(rj, dict) and "flags" in rj:
                    rj["flags"] = new_flags
                    rp.write_text(json.dumps(rj, indent=2))
        except Exception:
            pass

    return {
        "flags": new_flags,
        "removed": len(flags) - len(new_flags),
        "status": meta.get("status"),
    }


@router.post("/{job_id}/flag-verdict")
async def flag_verdict(job_id: str, request: Request):
    """The operator's true/false-positive call on what a run produced.

    Two entry points, one verdict::

        {"verdict": "ok"}      # the candidate/flag is the real one
        {"verdict": "wrong"}   # it is not — this run did not solve it

    From ``flag_ready`` (candidates recorded, none promoted) ``ok`` promotes
    them into ``meta.flags`` and finishes the job; ``wrong`` files it as
    ``no_flag``. From ``finished`` (a flag was promoted automatically)
    ``wrong`` demotes it back out — job 8d132bba21fc and its two retry
    children all read ``finished`` while carrying an answer the operator
    later ruled wrong, and nothing in the record said so.

    ``wrong`` never starts a retry itself. It records the verdict and reports
    ``retry_suggested``; the caller drives the existing retry endpoint, which
    owns the guards (module support, in-flight refusal, target resolution)
    that a second launcher here would have to duplicate and would eventually
    duplicate wrongly.

    The rejected values are kept in ``meta.flag_rejected`` rather than
    dropped. A later run that re-derives the same string is repeating a known
    dead end, and that is worth being able to see.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    try:
        body = await request.json()
    except Exception:
        body = {}
    verdict = str(body.get("verdict") or "").strip().lower()
    if verdict not in ("ok", "wrong"):
        raise HTTPException(
            status_code=400, detail='`verdict` must be "ok" or "wrong"'
        )

    status = str(meta.get("status") or "")
    if status not in ("flag_ready", "finished", "no_flag"):
        # A live job has no verdict to give yet, and saying so beats writing a
        # status the worker is about to overwrite from under us.
        raise HTTPException(
            status_code=409,
            detail=f"job is {status or 'unknown'}; a verdict needs a terminal run",
        )

    flags = [f for f in (meta.get("flags") or []) if f]
    candidates = [c for c in (meta.get("flag_candidates") or []) if c]
    rejected = [r for r in (meta.get("flag_rejected") or []) if r]

    from modules._common import write_meta

    if verdict == "ok":
        # `rejected` is a promotion source too, so a mis-click on "wrong" is
        # undoable. When it is the source, the value must LEAVE the rejected
        # list: `flags` and `flag_rejected` have to stay mutually exclusive or
        # the exploit-library gate below refuses to save a flag the operator
        # just confirmed, on the grounds that they once refused it.
        promoted = flags or candidates or rejected
        if not promoted:
            raise HTTPException(
                status_code=409, detail="nothing to confirm — no flag or candidate"
            )
        # Optional `flag`: confirm ONE value instead of the whole list.
        #
        # Without it "ok" is all-or-nothing, and a run that recorded several
        # mutually exclusive candidates has no correct answer available. Job
        # 2e778201fe66 is what that looks like in production — it reads
        # `finished` carrying TWO mutually exclusive candidates that share a
        # prefix, and at most one of them can be the flag, but "ok" wrote both
        # into meta.flags. The same trap catches a job whose only candidate
        # is junk and whose real answer was just promoted from the grain:
        # confirming both would file the junk in the exploit library beside
        # the answer.
        #
        # Omitting it keeps the previous behaviour exactly, so every existing
        # caller is unaffected.
        chosen = str(body.get("flag") or "").strip()
        if chosen:
            if chosen not in flags and chosen not in candidates and chosen not in rejected:
                raise HTTPException(
                    status_code=400,
                    detail="`flag` must be one of this job's flags, candidates "
                           "or previously rejected values",
                )
            promoted = [chosen]
        still_rejected = [r for r in rejected if r not in promoted]
        write_meta(
            safe,
            flags=promoted,
            flag_rejected=still_rejected,
            status="finished",
            flag_verdict="ok",
        )
        _sync_result_flags(safe, promoted)
        return {
            "status": "finished",
            "flags": promoted,
            "retry_suggested": False,
        }

    # wrong — demote whatever was on offer and remember that it was refused.
    #
    # The candidates have to be CLEARED, not just demoted. `no_flag_status`
    # asks "is there a candidate worth a verdict?", so leaving them in place
    # sends the job straight back to `flag_ready` the next time anything
    # recomputes its status — a verdict the operator already gave, asked
    # again, with no new run behind it. `flag_rejected` is where they live
    # now, which is also what makes the refusal survive.
    refused = flags or candidates
    new_rejected = rejected + [r for r in refused if r not in rejected]
    write_meta(
        safe,
        flags=[],
        flag_candidates=[c for c in candidates if c not in new_rejected],
        status="no_flag",
        flag_verdict="wrong",
        flag_rejected=new_rejected,
    )
    _sync_result_flags(safe, [])
    return {
        "status": "no_flag",
        "flags": [],
        "rejected": new_rejected,
        "retry_suggested": True,
    }


@router.post("/{job_id}/flag-grain/promote")
async def promote_flag_grain(job_id: str, request: Request):
    """Raise one harvester finding into ``meta.flag_candidates`` by hand.

        {"flag": "DH{...}"}

    THE GAP THIS CLOSES. `flag_grain.txt` is advisory and cannot write a
    status — that restriction is the harvester's whole safety argument, and it
    stays. But job 3a6670825945 showed what it costs when the regex tier also
    misses: the run finished `flag_ready` carrying the single candidate
    `{value}` — a template artefact, now blocked at the source by
    `_is_template_artifact` — while the operator-confirmed answer sat in the
    grain at 0.93 confidence with no route out of it. The operator had a
    correct flag on screen and no button that could register it.

    So the promotion is a MANUAL act with a machine-checked source. The value
    must appear verbatim as a `flag=` entry in this job's own grain file; an
    arbitrary string is refused. That containment check is the entire security
    property of this endpoint — the harvester still cannot promote itself, and
    the operator still cannot promote something no run ever produced.

    The status is written explicitly rather than recomputed. `no_flag_status`
    runs at finish time, not on a mutation, so a `no_flag` job would otherwise
    gain a candidate it could never be asked a verdict about.

    A previously rejected value is un-rejected on promotion, mirroring the
    `ok` branch of `flag_verdict`: `flags` and `flag_rejected` have to stay
    mutually exclusive or the exploit-library gate refuses to save a flag the
    operator just chose. It is reported back as `unrejected` rather than done
    silently.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")

    try:
        body = await request.json()
    except Exception:
        body = {}
    wanted = str(body.get("flag") or "").strip()
    if not wanted:
        raise HTTPException(status_code=400, detail="`flag` is required")

    status = str(meta.get("status") or "")
    if status == "finished":
        raise HTTPException(
            status_code=409,
            detail="job is already finished — rule the recorded flag wrong "
                   "first, then promote",
        )
    if status not in ("flag_ready", "no_flag"):
        raise HTTPException(
            status_code=409,
            detail=f"job is {status or 'unknown'}; a promotion needs a terminal run",
        )

    from modules._harvester import grain_flag_values

    grain = grain_flag_values(safe)
    if not grain:
        raise HTTPException(
            status_code=404,
            detail="this job's flag_grain.txt holds no findings to promote",
        )
    if wanted not in grain:
        raise HTTPException(
            status_code=400,
            detail="that value is not a `flag=` entry in this job's flag_grain.txt",
        )

    candidates = [c for c in (meta.get("flag_candidates") or []) if c]
    rejected = [r for r in (meta.get("flag_rejected") or []) if r]
    already = wanted in candidates
    if not already:
        candidates = candidates + [wanted]
    unrejected = wanted in rejected

    from modules._common import write_meta

    write_meta(
        safe,
        flag_candidates=candidates,
        flag_rejected=[r for r in rejected if r != wanted],
        status="flag_ready",
        flag_grain_promoted=sorted(
            {*(meta.get("flag_grain_promoted") or []), wanted}
        ),
    )
    return {
        "status": "flag_ready",
        "flag": wanted,
        "flag_candidates": candidates,
        "already_candidate": already,
        "unrejected": unrejected,
    }


# Terminal states: a steer queued here would sit in the work tree forever,
# and the operator would believe a message landed that never will. Refusing is
# the only answer that does not quietly lie.
_STEER_TERMINAL = {"finished", "stopped", "failed", "flag_ready", "no_flag"}


@router.post("/{job_id}/steer")
async def steer_job(job_id: str, request: Request):
    """Put one operator message into a RUNNING job's next turn.

        {"text": "the instance is dead — get a fresh one before analysing"}

    Delivered at the next TURN BOUNDARY, ranked directly below the
    FINAL_DRAFT last-chance injection and above every automated nudge. See
    modules/steer.py for why that placement, and for the job that argued for
    this rail existing at all.

    Not a stop and not a retry: those are the two things an operator could
    already do, and both throw away the session. This changes direction
    without losing what the agent has learned.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    status = str(meta.get("status") or "").strip().lower()
    if status in _STEER_TERMINAL:
        raise HTTPException(
            status_code=409,
            detail=(f"job is {status} — a steer would never be read. "
                    "Use /retry with a hint to start a new run from here."),
        )

    try:
        body = await request.json()
    except Exception:
        body = {}
    from modules import steer as _steer

    try:
        out = await run_in_threadpool(
            _steer.queue, JOBS_DIR / safe / "work", str(body.get("text") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"could not queue: {e}")

    # Best effort, and deliberately lazy: `log_line` lives in modules/_common,
    # a 670 KB module this request path has no other reason to import. The
    # authoritative record of a steer is the orchestrator's own
    # "injecting OPERATOR STEER" line when it is CONSUMED; this one only
    # confirms the round trip to an operator watching the live log.
    try:
        from modules._common import log_line as _log_line

        _log_line(safe, f"[operator] steer queued ({out['queued']} pending): "
                        f"{_steer.sanitize(str(body.get('text') or ''))[:120]}")
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True, "status": status, **out}


@router.get("/{job_id}/steer")
async def steer_pending(job_id: str):
    """Messages queued but NOT yet delivered.

    The dashboard shows this so a steer that a job ended before consuming is
    visible as undelivered rather than assumed to have landed.
    """
    safe = _validate_job_id(job_id)
    if read_job_meta(safe) is None:
        raise HTTPException(status_code=404, detail="job not found")
    from modules import steer as _steer

    msgs = await run_in_threadpool(_steer.pending, JOBS_DIR / safe / "work")
    return {"pending": msgs, "count": len(msgs)}


@router.get("/{job_id}/trace")
async def job_trace(job_id: str):
    """The shape this job actually took, as attempt lanes.

    Assembled from files the pipeline already writes — no new instrumentation
    and no model call, so this is cheap enough for the 2s detail poll. The
    lanes reconcile to the job's wall clock, which is the property that makes
    the chart checkable rather than decorative.
    """
    safe = _validate_job_id(job_id)
    if read_job_meta(safe) is None:
        raise HTTPException(status_code=404, detail="job not found")
    from modules._trace import build_trace

    return await run_in_threadpool(build_trace, safe)


@router.post("/{job_id}/live-fire/feedback")
async def record_live_fire_feedback(job_id: str, request: Request):
    """How many attacks a submitted patch version actually blocked.

        {"attempt": 1, "blocked": 3, "note": "tick 4"}

    An attack-and-defence round gives the defender exactly two numbers: how
    many vulnerabilities were planted, and — each tick — how many attacks
    their current patch blocked. The first is a create-time hint. The second
    only exists AFTER a patch has been uploaded and scored, so it cannot be
    asked for up front and it is worthless if it only reaches a human: it is
    the single piece of ground truth about whether the last patch worked.

    So it is recorded against the patch version it describes —
    `patched-attempt-N.zip`, the file the operator actually uploaded — and the
    next attempt in the job reads it. `attempt` must name a snapshot that
    exists, which is what keeps this from becoming a free-text field attached
    to nothing.

    Re-recording an attempt overwrites it: a tick can be re-scored, and the
    operator correcting a typo must not leave two contradictory rows.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    if str(meta.get("module") or "") != "live-fire":
        raise HTTPException(status_code=400, detail="not a live-fire job")

    try:
        body = await request.json()
    except Exception:
        body = {}
    try:
        attempt = int(body.get("attempt"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="`attempt` must be an integer")
    try:
        blocked = int(body.get("blocked"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="`blocked` must be an integer")
    if not 0 <= blocked <= 10000:
        raise HTTPException(status_code=400, detail="`blocked` is out of range")
    note = str(body.get("note") or "").strip()[:300]
    # SLA PASS IS GROUND TRUTH THE VALIDATOR CANNOT SEE. Its corpus is a guess
    # at what the scoring server asks; the scoring server's own verdict is the
    # only thing that says whether that guess was right. Tri-state on purpose:
    # None means "the operator has not said", which is different from "it
    # failed" and must not be read as one.
    sla_raw = body.get("sla_pass", None)
    if sla_raw is None:
        sla_pass = None
    elif isinstance(sla_raw, bool):
        sla_pass = sla_raw
    else:
        raise HTTPException(
            status_code=400, detail="`sla_pass` must be true, false, or absent"
        )

    jd = JOBS_DIR / safe
    from modules.live_fire_patch_loop import PROGRESS_NAME

    try:
        snapshots = json.loads((jd / PROGRESS_NAME).read_text()).get("snapshots") or []
    except (OSError, ValueError):
        snapshots = []
    known = {int(row.get("attempt")) for row in snapshots
             if isinstance(row, dict) and isinstance(row.get("attempt"), int)}
    if attempt not in known:
        raise HTTPException(
            status_code=400,
            detail=f"no patch snapshot for attempt {attempt}; "
                   f"recorded attempts: {sorted(known) or 'none'}",
        )

    path = jd / "patch-feedback.json"
    try:
        entries = json.loads(path.read_text()).get("entries") or []
    except (OSError, ValueError):
        entries = []
    entries = [e for e in entries
               if not (isinstance(e, dict) and e.get("attempt") == attempt)]
    entries.append({
        "attempt": attempt,
        "blocked": blocked,
        "sla_pass": sla_pass,
        "note": note,
        "at": datetime.now(timezone.utc).isoformat(),
    })
    entries.sort(key=lambda e: e.get("attempt", 0))
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"entries": entries}, indent=2) + "\n")
    os.replace(tmp, path)
    return {"attempt": attempt, "blocked": blocked,
            "sla_pass": sla_pass, "entries": entries}


@router.post("/{job_id}/live-fire/fix")
async def start_live_fire_fix(job_id: str):
    """Run another patch cycle on this job, using the operator's feedback.

    THE SAME JOB, CONTINUED — not a new one. The workspace, the vulnerability
    board, the blueteam trees and the version history are all still on disk,
    so the next bundle is V(n+1) in one history the operator can read top to
    bottom, and a patch that already passed validation is carried rather than
    re-derived.

    Refused without feedback. The whole point of the cycle is to act on what
    the scoring server said; starting one with nothing new to go on would ask
    the same agents the same question and bill for the same answer.
    """

    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    if str(meta.get("module") or "") != "live-fire":
        raise HTTPException(status_code=400, detail="not a live-fire job")
    if int(meta.get("live_fire_version") or 1) != 2:
        raise HTTPException(
            status_code=400,
            detail="the FIX cycle needs the v2 engine; v1 has no board to resume",
        )
    if str(meta.get("status") or "") in {"running", "queued"}:
        raise HTTPException(status_code=409, detail="this job is still running")

    jd = JOBS_DIR / safe
    try:
        entries = json.loads(
            (jd / "patch-feedback.json").read_text()).get("entries") or []
    except (OSError, ValueError):
        entries = []
    if not entries:
        raise HTTPException(
            status_code=400,
            detail="record the blocked count and SLA result for at least one "
                   "version first — a FIX cycle acts on that feedback",
        )

    # Imported here, not at module scope: suites stub `api.queue` with a
    # partial fake, and a top-level import of a name that fake does not
    # define breaks every test that imports this module.
    from api.queue import hard_timeout_for

    archive = str(meta.get("src_archive") or (jd / "src" / "input.zip"))
    timeout = int(meta.get("job_timeout") or 3600)
    write_job_meta(safe, {**meta, "status": "queued", "stage": "queued-fix",
                          "error": None})
    get_queue().enqueue(
        "modules.live_fire_v2_job.run_job",
        safe,
        archive,
        resume=True,
        job_id=safe,
        job_timeout=hard_timeout_for(timeout),
    )
    return {"job_id": safe, "status": "queued", "resumed": True,
            "feedback_versions": [e.get("attempt") for e in entries]}


def _sync_result_flags(job_id: str, flags: list) -> None:
    """Keep result.json's copy in step so a later view cannot resurrect it.

    Best-effort for the same reason `delete_job_flags` treats it that way: a
    missing or malformed result.json must not fail the operator's verdict,
    which is the part that has to land.
    """
    try:
        rp = JOBS_DIR / job_id / "result.json"
        if rp.exists():
            rj = json.loads(rp.read_text())
            if isinstance(rj, dict) and "flags" in rj:
                rj["flags"] = list(flags)
                rp.write_text(json.dumps(rj, indent=2))
    except Exception:
        pass


@router.get("/{job_id}/log", response_class=PlainTextResponse)
def get_job_log(job_id: str, tail: int | None = None):
    """Return run.log. With ?tail=N (bytes), returns at most the last N
    bytes — used by the polling UI so multi-MB logs don't get re-shipped
    every 2s after the agent does verbose Read/Bash output. The cut is
    aligned to the next newline so we never start mid-line.
    """
    log = JOBS_DIR / job_id / "run.log"
    if not log.exists():
        return PlainTextResponse("", status_code=200)
    if tail and tail > 0:
        try:
            size = log.stat().st_size
        except OSError:
            return PlainTextResponse("", status_code=200)
        if size > tail:
            with log.open("rb") as fp:
                fp.seek(size - tail)
                fp.readline()  # skip partial line
                data = fp.read()
            text = data.decode("utf-8", errors="replace")
            header = (
                f"…(showing last {len(data)} of {size} bytes — "
                f"download full log via /api/jobs/{job_id}/file/run.log)…\n"
            )
            return PlainTextResponse(header + text)
    return PlainTextResponse(log.read_text(errors="replace"))


@router.get("/{job_id}/monitor")
async def get_job_monitor(job_id: str, tail: int | None = None):
    """Curated MONITOR feed for a job — the filtered, LLM-narrated signal
    entries from <job>/monitor.jsonl. Each entry carries a `text` map keyed
    by language ({"ko": "...", "en": "..."}); the client picks which to show,
    so switching language is instant with no refetch. With ?tail=N, returns
    only the last N entries. Opening this (or the SSE /stream) also ensures
    the job's live monitor task is running — for every provider. This route
    used to answer `enabled: false` for GPT on the grounds that the Timeline
    replaced the narrator; the backend's GPT narrator was complete the whole
    time, so the operator's choice was being overruled here rather than
    honoured."""
    safe = _validate_job_id(job_id)
    try:
        from modules._monitor import ensure_monitor
        ensure_monitor(safe)
    except Exception:
        pass
    p = JOBS_DIR / safe / "monitor.jsonl"
    entries: list[dict] = []
    if p.exists():
        try:
            for line in p.read_text(errors="replace").splitlines():
                s = line.strip()
                if not s:
                    continue
                try:
                    entries.append(json.loads(s))
                except json.JSONDecodeError:
                    continue
        except OSError:
            entries = []
    if tail and tail > 0:
        entries = entries[-tail:]
    return {"entries": entries}


@router.get("/{job_id}/timeline")
def get_timeline(job_id: str, tail: int | None = None):
    """Structured activity for ANY provider.

    GPT keeps its own richer path (roster, presets, wait accounting) and this
    delegates to it unchanged. Claude and grok are normalised from sdk.jsonl
    into the same event vocabulary, so one renderer draws all three — a second
    renderer would drift from the first, which is what two placement policies
    already taught this repo.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    if str(meta.get("agent_provider") or "").lower() == "gpt":
        payload = get_gpt_timeline(job_id, tail)
    else:
        from modules._timeline import build_timeline

        payload = build_timeline(safe, tail)
    # Where the clock went, attached to the view that shows the work. The
    # trace already computes this and the two must not disagree, so it is the
    # same call rather than a second reckoning.
    try:
        from modules._trace import build_trace

        tr = build_trace(safe)
        tt = tr.get("totals") or {}
        tok = meta.get("agent_tokens") or {}
        cache_read = int(tok.get("cache_read_input_tokens") or 0)
        seen = (int(tok.get("input_tokens") or 0)
                + int(tok.get("cache_creation_input_tokens") or 0) + cache_read)
        payload["stats"] = {
            "turns": meta.get("agent_turns"),
            "steps": len(payload.get("events") or []),
            "agent_s": tt.get("agent_s"),
            "run_s": tt.get("run_s"),
            "adjudicate_s": tt.get("adjudicate_s"),
            "wall_s": tr.get("wall_s"),
            # None, not 0: a job that has read no context has no hit RATE,
            # and 0% would read as a cache that is failing.
            "cache_hit_pct": round(cache_read / seen * 100, 1) if seen else None,
            "input_tokens": seen or None,
            "output_tokens": int(tok.get("output_tokens") or 0) or None,
        }
    except Exception:
        payload["stats"] = None
    return payload


@router.get("/{job_id}/gpt-timeline")
def get_gpt_timeline(job_id: str, tail: int | None = None):
    """Structured activity for GPT jobs only.

    Claude and Grok deliberately do not enter this path: their existing
    ``run.log`` and Monitor behavior remains byte-for-byte unchanged.  A GPT
    job created before ``gpt-events.jsonl`` existed receives a read-only
    projection of its existing run.log so an in-flight job becomes useful
    immediately without rewriting evidence.
    """
    safe = _validate_job_id(job_id)
    meta = read_job_meta(safe)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    if str(meta.get("agent_provider") or "").lower() != "gpt":
        return {"enabled": False, "events": [], "agents": [], "source": "disabled"}

    configured_models: dict[str, str] = {}
    configured_providers: dict[str, str] = {}
    preset_name = ""
    try:
        from modules.agent_provider import default_model_for
        from modules.model_presets import CONFIGURABLE_ROLES, get_provider_store

        snapshot = meta.get("gpt_role_models")
        bucket = get_provider_store("gpt")
        preset_name = str(meta.get("gpt_preset") or bucket.get("active") or "")
        preset = (
            snapshot if isinstance(snapshot, dict)
            else (bucket.get("presets") or {}).get(preset_name) or {}
        )
        main = str(meta.get("model") or preset.get("main") or default_model_for("gpt"))
        judge = str(preset.get("judge") or main)
        fallbacks = {
            "main": main,
            "judge": judge,
            "reviewer": str(preset.get("reviewer") or judge),
            "recon": str(preset.get("recon") or main),
            "debugger": str(preset.get("debugger") or main),
            "triage": str(preset.get("triage") or main),
            "report": str(preset.get("report") or main),
        }
        # A role routed to another backend does NOT run the GPT preset's model
        # for it. Reporting the GPT entry there made the Timeline claim every
        # agent was GPT on a hybrid job — the one thing an operator turns
        # hybrid on to be able to see.
        from modules.agent_provider import provider_for_role, role_model_for

        configured_models = {}
        configured_providers = {}
        _timeline_roles = [
            role for role in CONFIGURABLE_ROLES
            if role != "monitor" and fallbacks.get(role)
        ]
        for role in _timeline_roles:
            where = provider_for_role(job_id, role)
            configured_providers[role] = where
            configured_models[role] = (
                fallbacks[role] if where == "gpt"
                else role_model_for(role, where, None)
            )
    except Exception:
        configured_models = {}
        configured_providers = {}

    from modules.gpt_run_events import (
        read_gpt_timeline, summarize_agent_activity, summarize_agents,
    )

    bounded_tail = max(1, min(int(tail or 600), 2000))
    all_events, source = read_gpt_timeline(
        safe,
        started_at=meta.get("started_at"),
    )
    events = all_events[-bounded_tail:]
    agent_cards = summarize_agents(all_events, configured_models,
                                   configured_providers)
    return {
        "enabled": True,
        "source": source,
        "preset": preset_name,
        "events": events,
        "agents": agent_cards,
        # How many agents are working right now. Derived here rather than in
        # the browser so every client agrees, and kept beside `agents` so the
        # two can be read against each other.
        "activity": summarize_agent_activity(all_events, agent_cards),
    }


_TERMINAL_META_STATUSES = {"finished", "failed", "no_flag", "stopped",
                           "flag_ready"}


@router.get("/{job_id}/stream")
async def stream_job(job_id: str, request: Request, backfill: str = "full"):
    """Server-Sent Events live feed of a job's run.log + meta updates.

    `backfill` selects how much history is replayed on connect:
      "full"  (default) — meta + run.log + monitor + sdk. The original
                          contract: a client can render everything from the
                          stream alone, with no separate fetch.
      "sdk"             — meta + sdk only. For a client that ALREADY fetches
                          /log and /monitor, which the web UI does.

    WHY THE SECOND MODE EXISTS. The UI does both: renderJob fetches
    /jobs/{id}/log?tail=262144 AND opens this stream, so it paid for the same
    bytes twice — and the second time one SSE frame per line. Measured on
    19cf9578a0fc: 2,807 frames, 433,392 bytes, every one of them dropped on
    arrival by `if (payload.backfill) return;` in _appendLiveLogLine (and the
    same for the monitor replay in _appendMonitorEntry).

    The cost was not just the bytes. The sdk replay runs LAST, so the
    "live agent activity" panel — which stays hidden until its first event —
    only appeared once all of that had been sent, parsed and discarded. The
    operator reported it exactly that way: about three seconds of lag, and the
    panel popping in at the end of it. `backfill_done` is also what widens the
    poll interval, so the UI kept doing full 2s re-renders throughout.

    Multiplexes three Redis pubsub channels into one HTTP stream:
      - `job:<id>:log`  → SSE event `log`   {ts, line}
      - `job:<id>:meta` → SSE event `meta`  {...}
      - `job:<id>:sdk`  → SSE event `sdk`   {...}  (Phase 4)

    On connect we replay the current run.log + meta.json so the client
    can render the full state without a separate fetch. After backfill,
    it streams new events as they're published. The connection holds
    open until the client disconnects OR the job reaches a terminal
    status (then we emit one final `done` event and close).

    Heartbeat: a comment line (`: ping`) every 15s keeps any proxy
    between client and api from culling the long-lived connection.
    """
    safe = _validate_job_id(job_id)
    jd = JOBS_DIR / safe
    if not jd.exists():
        raise HTTPException(status_code=404, detail="job not found")

    log_path = jd / "run.log"
    meta_path = jd / "meta.json"
    initial_meta = read_job_meta(safe) or {}

    def sse(name: str, data) -> bytes:
        return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()

    async def event_gen():
        # Every live stream also guarantees its monitor task is running
        # (belt-and-suspenders with the always-on supervisor).
        try:
            from modules._monitor import ensure_monitor
            ensure_monitor(safe)
        except Exception:
            pass
        from redis import asyncio as aioredis
        r = aioredis.from_url(REDIS_URL)
        pubsub = r.pubsub()
        try:
            # Subscribe BEFORE backfill so any event published between
            # backfill-read and subscribe is buffered (Redis pubsub is
            # ephemeral but the gap here is microseconds).
            channels = [
                f"job:{safe}:log",
                f"job:{safe}:meta",
                f"job:{safe}:sdk",
            ]
            channels.append(f"job:{safe}:monitor")
            await pubsub.subscribe(*channels)

            # --- Backfill --------------------------------------------
            # Send current meta.json so the UI has tokens/status from
            # the moment of connect.
            try:
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text())
                    yield sse("meta", {"backfill": True, "meta": meta})
            except Exception:
                pass

            # Send the existing run.log line-by-line. Each line keeps
            # its on-disk timestamp prefix so the frontend can parse
            # it the same way it parses live events.
            replay_history = backfill != "sdk"
            try:
                if replay_history and log_path.exists():
                    # Cap backfill at last 256 KB so a 100MB log doesn't
                    # block the stream open.
                    size = log_path.stat().st_size
                    cap = 256 * 1024
                    with log_path.open("rb") as fp:
                        if size > cap:
                            fp.seek(size - cap)
                            fp.readline()  # skip partial
                        data = fp.read().decode("utf-8", errors="replace")
                    if size > cap:
                        yield sse("log", {
                            "backfill": True,
                            "line": f"…(showing last ~{cap // 1024}KB of {size} bytes — full log via /api/jobs/{safe}/file/run.log)…",
                            "ts": "",
                        })
                    for line in data.splitlines():
                        # Each on-disk line looks like "[HH:MM:SS] <body>".
                        m = re.match(r"^\[(\d\d:\d\d:\d\d)\] (.*)$", line)
                        if m:
                            ts, body = m.group(1), m.group(2)
                        else:
                            ts, body = "", line
                        yield sse("log", {
                            "backfill": True,
                            "ts": ts,
                            "line": body,
                        })
            except Exception:
                pass

            # Backfill the curated monitor feed (last 400 entries) so the
            # Monitor view renders instantly on connect, same as the run log.
            if replay_history:
                try:
                    mon = jd / "monitor.jsonl"
                    if mon.exists():
                        lines = mon.read_text(errors="replace").splitlines()[-400:]
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            entry["backfill"] = True
                            yield sse("monitor", entry)
                except Exception:
                    pass

            # Replay the live-agent-activity feed.
            #
            # The panel is fed by the `sdk` channel, which was pubsub-only:
            # anything said before the browser connected was simply gone, so
            # leaving the job view and returning showed an empty box on a run
            # that had been talking for forty minutes. modules/_common.publish_sdk
            # now mirrors every event to <job>/sdk.jsonl, and this replays the
            # tail — the same shape the monitor feed above already uses.
            #
            # Bounded twice, because these carry model prose: at most the last
            # 400 events, and at most 512 KB read off the end of the file. The
            # cap is on the REPLAY, not on what is written, so the file stays a
            # complete record for anyone who wants to read it directly.
            try:
                sdkp = jd / "sdk.jsonl"
                if sdkp.exists():
                    with sdkp.open("rb") as fp:
                        fp.seek(0, 2)
                        size = fp.tell()
                        fp.seek(max(0, size - 512 * 1024))
                        chunk = fp.read()
                    text = chunk.decode("utf-8", errors="replace")
                    if size > 512 * 1024:
                        # A partial first line is not JSON; drop it.
                        text = text.split("\n", 1)[-1]
                    for line in text.splitlines()[-400:]:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        entry["backfill"] = True
                        yield sse("sdk", entry)
            except Exception:
                pass

            yield sse("backfill_done", {})

            # If the job is already terminal at backfill time, close
            # immediately — no live updates will come.
            try:
                if meta_path.exists():
                    status = json.loads(meta_path.read_text()).get("status")
                    if status in _TERMINAL_META_STATUSES:
                        yield sse("done", {"status": status})
                        return
            except Exception:
                pass

            # --- Live loop -------------------------------------------
            last_ping = asyncio.get_event_loop().time()
            HEARTBEAT_S = 15.0
            while True:
                if await request.is_disconnected():
                    return
                # Wait up to 5s for the next pubsub message.
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=5.0,
                )
                now = asyncio.get_event_loop().time()
                if msg is None:
                    # Heartbeat to keep proxies/clients from cutting us.
                    if now - last_ping >= HEARTBEAT_S:
                        yield b": ping\n\n"
                        last_ping = now
                    continue

                channel = msg["channel"].decode("utf-8", "replace")
                # channel = "job:<id>:<suffix>"
                suffix = channel.rsplit(":", 1)[-1]
                try:
                    payload = json.loads(msg["data"])
                except Exception:
                    payload = {"raw": msg["data"].decode("utf-8", "replace")}

                yield sse(suffix, payload)
                last_ping = now

                # If we just saw a terminal status, close cleanly.
                if suffix == "meta":
                    su = payload.get("status_update") or {}
                    new_status = su.get("status")
                    if new_status in _TERMINAL_META_STATUSES:
                        yield sse("done", {"status": new_status})
                        return
        finally:
            try:
                await pubsub.unsubscribe()
                await pubsub.close()
            except Exception:
                pass
            try:
                await r.close()
            except Exception:
                pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/{job_id}/file/{name}")
def get_job_file(job_id: str, name: str):
    safe = Path(name).name
    jd = JOBS_DIR / job_id
    # Primary location: <jobdir>/<name>, populated by the analyzer's
    # carry step at the end of _run_agent. If the run was killed mid-
    # flight (RQ stop / Stop&Resume / SIGKILL) the carry never ran but
    # the artifact is still in <jobdir>/work/<name>. Fall back there
    # so the UI's file links work for stopped jobs too.
    candidates = [jd / safe, jd / "work" / safe]
    for f in candidates:
        if f.is_file():
            return FileResponse(str(f))
    raise HTTPException(status_code=404, detail="file not found")


# ------------------------------------------------------------ file browser
#
# WHY A BROWSER AND NOT MORE LINKS
# The job panel used to hard-code one link per artifact per module
# (`exploit.py.stdout`, `solver.py.stdout`, …). The runner names its artifacts
# after the script it actually ran, so a crypto Sage job produces
# `solver.sage.stdout` — a name no hard-coded list contained, and its links
# 404'd while the file sat on disk. Listing the directory removes the guess:
# whatever the runner wrote is what the operator sees.
#
# LAZY, ONE DIRECTORY AT A TIME. Measured 2026-08-11 across 74 job dirs: the
# median holds 85 files, but the largest holds 8,520 across 1.1 GB at depth 14
# (a decompiler run). A recursive dump would be that whole tree in one
# response, so this lists exactly one level and the UI asks again on expand.
_FILE_LIST_CAP = 2000


def _job_subpath(job_id: str, rel: str) -> Path:
    """Resolve `rel` inside a job directory, or raise 404/403.

    The guard is `realpath` containment, NOT string prefixing, because a job
    directory holds agent-authored content: `work/` is writable by the agent
    and by challenge code running as root in the sandbox, so a symlink like
    `work/x -> /` is something this has to survive rather than assume away.
    Resolving first and then testing ancestry means a link that escapes is
    refused even though its literal path looked fine.
    """
    safe_id = Path(job_id).name
    if not safe_id:
        raise HTTPException(status_code=404, detail="job not found")
    root = (JOBS_DIR / safe_id).resolve()
    if not root.is_dir():
        raise HTTPException(status_code=404, detail="job not found")
    target = (root / (rel or "")).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status_code=403, detail="path escapes the job directory")
    return target


@router.get("/{job_id}/files")
def list_job_files(job_id: str, path: str = ""):
    """One directory of a job's working tree.

    Entries are ordered directories-first then by name, which is the order an
    operator scans for "where did the run put things".
    """
    target = _job_subpath(job_id, path)
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="not a directory")

    root = (JOBS_DIR / Path(job_id).name).resolve()
    entries = []
    truncated = False
    try:
        with os.scandir(target) as it:
            for de in it:
                if len(entries) >= _FILE_LIST_CAP:
                    truncated = True
                    break
                # follow_symlinks=False: a broken or escaping link must still
                # be listable (so the operator can see it exists) without this
                # call following it off the tree.
                try:
                    st = de.stat(follow_symlinks=False)
                    is_dir = de.is_dir(follow_symlinks=True)
                except OSError:
                    continue
                entries.append({
                    "name": de.name,
                    "path": str(Path(path or "") / de.name).replace("\\", "/"),
                    "is_dir": is_dir,
                    "is_link": de.is_symlink(),
                    "size": None if is_dir else st.st_size,
                    "mtime": datetime.fromtimestamp(
                        st.st_mtime, timezone.utc).isoformat(),
                })
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")

    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    rel = "" if target == root else str(target.relative_to(root)).replace("\\", "/")
    return {
        "job_id": Path(job_id).name,
        "path": rel,
        "parent": "" if not rel else str(Path(rel).parent).replace("\\", "/").lstrip("."),
        "entries": entries,
        "truncated": truncated,
        "cap": _FILE_LIST_CAP,
    }


@router.get("/{job_id}/blob")
def get_job_blob(job_id: str, path: str):
    """Serve one file by its path RELATIVE to the job directory.

    Separate from `/file/{name}`, which takes a bare basename and probes
    `<job>/` then `<job>/work/`. That route is left exactly as it is: existing
    links depend on its fallback, and widening it to accept slashes would
    change what those links resolve to. This one is for the browser, where the
    path is already known exactly.
    """
    target = _job_subpath(job_id, path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(str(target), filename=target.name)


@router.get("/{job_id}/result")
def get_job_result(job_id: str):
    f = JOBS_DIR / job_id / "result.json"
    if f.exists():
        return json.loads(f.read_text())
    # result.json is only written by the analyzer's carry step at
    # stage=done. A collector OOB capture can mark the job
    # finished/success BEFORE that point (the bot calls in while the
    # main agent is still mid-analyze), so for ~minutes there is a
    # finished job with flags but no result.json and the UI's result
    # link 404s. Synthesize a minimal result from meta so the link
    # always resolves; the real file overwrites this view once carry
    # runs.
    meta = read_job_meta(Path(job_id).name)
    if meta is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {
        "synthesized_from_meta": True,
        "status": meta.get("status"),
        "flags": meta.get("flags") or [],
        "cost_usd": meta.get("cost_usd"),
        "agent_error": meta.get("error"),
        "agent_error_kind": meta.get("error_kind"),
    }


@router.post("/{job_id}/run")
def post_run_script(job_id: str, target: str | None = None):
    """Manually re-run the produced exploit/solver script in the runner
    sandbox. Useful when the user didn't enable auto-run, when the
    earlier auto-run failed, or when they want to retry against a
    different target.

    Request can supply `?target=...` to override the stored target.
    Returns the sandbox result (stdout/stderr/exit_code) and updated
    flag list. Updates meta.status accordingly.
    """
    safe = Path(job_id).name
    jd = JOBS_DIR / safe
    if not jd.exists():
        raise HTTPException(status_code=404, detail="job not found")
    meta = read_job_meta(safe) or {}

    # Pick the script the agent produced
    script = None
    for name in ("exploit.py", "solver.py", "solver.sage"):
        if (jd / name).is_file():
            script = name
            break
    if not script:
        raise HTTPException(
            status_code=400,
            detail="no exploit.py / solver.py / solver.sage in this job",
        )
    use_sage = script.endswith(".sage")
    # An explicit ?target= override is PERSISTED to meta before the run
    # (below, right after the write_meta import). attempt_sandbox_run
    # proactively prefers meta.target_url over the argv target we hand it
    # (see modules/_runner._refresh_target_from_meta), so an un-persisted
    # override would be clobbered straight back to the STALE stored value —
    # exactly why "Run in sandbox" appeared to ignore a fresh target on
    # dreamhack-style jobs whose instance had rotated. Mirrors PATCH /target.
    _override = (target or "").strip()
    target = (_override or meta.get("target_url") or "").strip() or None

    # Sandbox runner spawn (same path the orchestrators use)
    from modules._common import scan_job_for_flags, write_meta
    from modules._runner import attempt_sandbox_run, remote_target_start_gate
    from modules.settings_io import apply_to_env

    # Persist an operator-supplied target override so the proactive
    # meta-refresh inside attempt_sandbox_run keeps it instead of reverting
    # to the stale stored value (see the _override note above).
    if _override and _override != (meta.get("target_url") or "").strip():
        write_meta(safe, target_url=_override)

    # Pull settings (CALLBACK_URL etc.) into this process's env so the
    # runner spawn picks them up, mirroring what worker run_job() does.
    apply_to_env()

    def _log(line: str):
        log = jd / "run.log"
        ts = __import__("datetime").datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {line}\n")

    _log(f"[manual-run] executing {script} (target={target}, sage={use_sage})")
    remote_target_start_gate(
        safe, meta.get("module") or "", target, _log, manual=True,
    )
    try:
        res = attempt_sandbox_run(safe, script, target, _log, use_sage=use_sage)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sandbox spawn failed: {e}")
    if res is None:
        raise HTTPException(status_code=500, detail="script missing at run time")

    flags = scan_job_for_flags(safe)
    from modules._common import no_flag_status as _no_flag_status
    new_status = "finished" if flags else _no_flag_status(safe)
    write_meta(safe, status=new_status, flags=flags, manual_run=True)
    return {"sandbox": res, "flags": flags, "status": new_status}


@router.patch("/{job_id}/target")
async def patch_target(job_id: str, request: Request):
    """Update only `target_url` on an existing job's meta — no retry,
    no resume, no new job enqueued.

    The next manual `/run` (and the default of any future `/retry` /
    `/resume`) picks up the new value. Useful when the original target
    was wrong / the challenge moved / you want to point a finished
    job at a fresh remote without forking the conversation.

    Body (JSON): {"target": "<new>"} — pass the literal string
    "(none)" or an empty string to CLEAR the target.

    Returns: {"ok": true, "target_url": <new>, "prior": <old>}.
    """
    # `Path(job_id).name` strips path separators but doesn't reject
    # ".."/"."/"" — those would resolve to JOBS_DIR's parent or itself.
    # Be explicit so the audit-log open() can't punch out of the dir.
    safe = Path(job_id).name
    if safe in ("", ".", "..") or "/" in safe or "\\" in safe:
        raise HTTPException(status_code=400, detail="invalid job_id")
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    try:
        body = await request.json()
    except Exception:
        body = {}
    if "target" not in body and "target_url" not in body:
        raise HTTPException(
            status_code=400,
            detail='request body must include "target" (use "(none)" to clear)',
        )
    raw = body.get("target")
    if raw is None:
        raw = body.get("target_url")
    clean = ("" if raw is None else str(raw)).strip()
    if clean.lower() in ("(none)", "none", ""):
        new_target: str | None = None
        new_targets: list[str] | None = None
    else:
        # Accept several targets (newline / comma separated) — primary is
        # argv[1]/target_url; the rest ride along in target_urls so the next
        # run's TARGETS env still has the full multi-target list.
        parsed = parse_targets(clean)
        new_target = parsed[0] if parsed else None
        new_targets = parsed if len(parsed) >= 2 else None

    prior = meta.get("target_url")
    # IMPORTANT: use modules._common.write_meta (read-merge-write at
    # WRITE time), not api.storage.write_job_meta (which would overwrite
    # the entire file from this snapshot). The worker holds the meta
    # for in-flight jobs and writes heartbeat + cost + status updates
    # constantly; full overwrite from here would clobber any keys the
    # worker added between our read and our write.
    from modules._common import write_meta as _merge_write_meta
    _merge_write_meta(safe, target_url=new_target, target_urls=new_targets)

    # Audit trail in run.log so the change is visible to the reviewer
    # on a future retry and to anyone tailing the run.
    log = JOBS_DIR / safe / "run.log"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    try:
        with log.open("a") as fp:
            extra = (
                f" (+{len(new_targets) - 1} more)" if new_targets else ""
            )
            fp.write(
                f"[{ts}] [meta] target_url updated by user: "
                f"{prior!r} -> {new_target!r}{extra}\n"
            )
    except OSError:
        pass

    # Status-aware guidance. A RUNNING/queued job's live agent has its target
    # baked into the spawn-time prompt and never re-reads meta mid-run, so this
    # PATCH does NOT reach the in-flight agent — it only affects the next
    # /retry|/resume and the orchestrator's final sandbox run (and that run only
    # if the exploit reads argv[1] — a hardcoded host stays stale). Surface that
    # so the operator isn't misled into thinking a running job just switched
    # targets. (Operator report: "Change Target before a remote test didn't
    # reflect in context.")
    status = (meta.get("status") or "").lower()
    live = status in ("running", "queued", "analyzing", "analyze")
    if new_target is None:
        note = "Target cleared."
    elif status == "running":
        # Two mechanisms reach a LIVE agent, and the difference matters to the
        # operator because one of them can lag for hours:
        #   * the PreToolUse stale-target guard (modules/_common.
        #     stale_target_reason) runs MID-TURN — it denies the agent's very
        #     next Bash call at the superseded endpoint and names the new one.
        #   * the orchestrator's turn-boundary watchdog only runs after
        #     `receive_response()` returns, and ONE receive_response spans the
        #     agent's whole agentic turn. Job 6e434e820b3f sat inside a single
        #     turn for two hours, so it never fired at all.
        # An earlier version of this note promised only the boundary path "so
        # no Retry is needed", which read as "it landed" while main went on
        # polling the dead port. Say what actually bounds the delay.
        note = (
            f"Target set to {new_target}. This job is running: the agent's next "
            "connection attempt at the old endpoint is blocked mid-turn and told "
            "to use this one, so the change lands by the next remote Bash call — "
            "not instantly, and not while it is only thinking. The sandbox runner "
            "also re-reads the target, so an argv[1]-driven exploit picks it up "
            "with no edit; a hardcoded host:port needs the agent to rewrite it. "
            "If the agent is deep in a long non-remote stretch and you need the "
            "switch now, Stop then Continue re-spawns it with the new target."
        )
    elif live:
        note = (
            f"Target set to {new_target} in meta — this job is {status}, so no "
            "agent session exists yet; it will start with the new value."
        )
    else:
        note = (
            f"Target set to {new_target}. The next /retry or /resume picks it "
            "up; 'fresh start' avoids re-inheriting the old target from the "
            "prior conversation."
        )

    return {
        "ok": True,
        "target_url": new_target,
        "target_urls": new_targets,
        "prior": prior,
        "job_status": status,
        # `running` now DOES apply live (the orchestrator injects the new
        # endpoint at the next turn boundary); queued/analyzing has no
        # session yet, so the value is simply read when one starts.
        "applies_live": (not live) or status == "running",
        # The UI used to alert only when applies_live was false, so making
        # `running` live-applying silently removed the ONLY feedback that a
        # target change on a running job landed. Decouple the two: this says
        # "show the note", applies_live says what actually happens.
        "show_note": bool(live),
        "note": note,
    }


def _record_decision(safe: str, decision: str, log_msg: str) -> dict:
    """Clear the awaiting_decision flag and append a run.log line. Returns
    the merged meta on success."""
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    merged = {
        **meta,
        "awaiting_decision": False,
        "timeout_decision": decision,
    }
    write_job_meta(safe, merged)

    # Append to run.log so the user can see the decision in the live log
    from datetime import datetime
    log = JOBS_DIR / safe / "run.log"
    try:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with log.open("a") as fp:
            fp.write(f"[{ts}] {log_msg}\n")
    except Exception:
        pass
    return merged


@router.post("/{job_id}/timeout/continue")
def timeout_continue(job_id: str):
    """User chose to keep the job running past its soft timeout. The
    watchdog has already fired once and will NOT re-fire — the agent
    runs to natural completion (or hits RQ's hard kill ceiling)."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    if not meta.get("awaiting_decision"):
        return {"ok": True, "noop": True, "decision": meta.get("timeout_decision")}
    _record_decision(
        safe, "continue",
        "User chose CONTINUE — job keeps running past the soft timeout.",
    )
    return {"ok": True, "decision": "continue"}


@router.post("/{job_id}/timeout/kill")
def timeout_kill(job_id: str):
    """User chose to halt the job. Runs the same hard-stop path as
    DELETE: signals RQ, kills sibling containers."""
    safe = Path(job_id).name
    meta = read_job_meta(safe)
    if not meta:
        raise HTTPException(status_code=404, detail="job not found")
    _record_decision(
        safe, "kill",
        "User chose STOP — halting the job at soft timeout.",
    )
    halt_info = _hard_stop_job(safe)
    # Reflect the cancellation in meta so list/detail endpoints don't
    # keep showing it as 'running'.
    final = read_job_meta(safe) or {}
    write_job_meta(safe, {**final, "status": "failed", "error": "Stopped by user at soft timeout"})
    return {"ok": True, "decision": "kill", "halt": halt_info}
