import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from modules.storage import (
    DATA_DIR,
    JOBS_DIR,
    UPLOADS_DIR,
    extract_if_archive,
    new_job_id,
)

# Split an operator target field into individual targets. Newlines are the
# documented separator (the UI target box is a textarea — one per line);
# commas are also accepted for the single-line retry/continue override inputs.
# A CTF target (`host:port`, `nc host port`, `http://host:port/path`) does not
# contain a raw comma, so comma-splitting is safe in practice.
_TARGET_SPLIT_RE = re.compile(r"[\r\n,]+")


def parse_targets(raw: Optional[str], *, limit: int = 32) -> list[str]:
    """Parse a raw target field into a deduped, order-preserving list.

    Empty / whitespace-only input → []. Each target is stripped; blanks are
    dropped; duplicates are collapsed (first occurrence wins). Capped at
    `limit` so a paste accident can't enqueue an unbounded list. The first
    element is the PRIMARY target (argv[1] / meta.target_url); the full list
    is exposed to the exploit via the TARGETS env var (see modules/_runner).
    """
    if not raw:
        return []
    out: list[str] = []
    for piece in _TARGET_SPLIT_RE.split(raw):
        t = piece.strip()
        if t and t not in out:
            out.append(t)
            if len(out) >= limit:
                break
    return out


# Operator-facing job TAG. Display only: it names the challenge in the job
# list so an operator running eight jobs can tell them apart at a glance.
#
# It is deliberately NOT an agent input. `build_user_prompt()` in every module
# takes explicit named arguments (description, flag_format, target ...) and is
# never handed the meta dict, so a new meta key cannot reach a prompt by
# construction — test_job_tag_never_reaches_the_agent.py pins that, because
# "nothing splats meta today" is a property that a future refactor can quietly
# break. Keep the tag out of description: the description IS given to the
# agent, and a label like "day2-hard" spent as prompt tokens is noise that
# steers nothing.
#
# Sanitising is about storage hygiene, not HTML: newlines and control
# characters would break the single-line row the tag is rendered into, and an
# unbounded paste would push the row off screen. Escaping is the renderer's
# job (web-ui escapeHtml, text context only) — do NOT strip `<` here, because
# a tag like `web<->pwn` is a legitimate thing for an operator to type.
_TAG_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
JOB_TAG_MAX = 64


def sanitize_job_tag(raw: Optional[str]) -> Optional[str]:
    """Normalise an operator tag, or None when it carries no content."""
    # isinstance, not truthiness: a route called directly in a test (see
    # scripts/test_live_fire_api_ui.py) passes the unresolved `Form(None)`
    # default object, which is truthy and would str() into a nonsense tag.
    # FastAPI hands this a str or None in production; anything else is not a
    # tag an operator typed.
    if not isinstance(raw, str) or not raw:
        return None
    tag = _TAG_CTRL_RE.sub(" ", raw)
    tag = " ".join(tag.split())          # collapse runs of whitespace
    if not tag:
        return None
    return tag[:JOB_TAG_MAX]


def stamp_job_tag(meta: dict, raw: Optional[str]) -> dict:
    """Attach a sanitised operator tag to job metadata, if one was given.

    Absent rather than null when unset, so `read_job_meta()` on the thousands
    of pre-tag jobs already on disk and a new untagged job look identical to
    the UI (`job.tag ? ... : ""`).
    """
    tag = sanitize_job_tag(raw)
    if tag:
        meta["tag"] = tag
    else:
        meta.pop("tag", None)
    return meta


# Where a job's REPORT-PHASE findings document lives, newest name first.
#
# The five analyzer-shaped modules (web/pwn/crypto/web3/rev) and forensic write
# `findings.json`. misc cannot: its work_dir IS the job root and its
# pre-analysis SWEEP already owns that name there — the misc prompt tells the
# agent to "Read findings.json FIRST" and misc/orchestrator.py parses
# `strings.flag_candidates` out of it — so misc's report phase writes
# `report_findings.json` beside it (modules/_common.py run_report_phase,
# `out_name`).
#
# ORDER MATTERS, and only in one direction: for a misc job BOTH files exist and
# only the first is the report schema. Reading `findings.json` first would find
# the sweep — a valid JSON document with none of the harvested keys — and
# return an all-None result without ever looking further.
_REPORT_FINDINGS_NAMES = ("report_findings.json", "findings.json")


def report_findings_path(job_dir_path: Path) -> Optional[Path]:
    """The report-phase findings document for a job, or None if it has none."""
    for name in _REPORT_FINDINGS_NAMES:
        f = job_dir_path / name
        if f.is_file():
            return f
    return None


def prepare_job_description(
    job_id: str,
    description: Optional[str],
    secret_key: Optional[str],
    secret_value: Optional[str],
) -> Optional[str]:
    """Move challenge credentials out of request prose before persistence."""

    from modules.job_secrets import SecretIngressError, prepare_job_secret

    try:
        return prepare_job_secret(
            job_id,
            description,
            secret_key=secret_key,
            secret_value=secret_value,
        )
    except SecretIngressError as exc:
        reject_job(job_id, 400, str(exc))
        raise AssertionError("reject_job always raises")

# Operator-curated library of past exploits/solvers a future job can
# consult when stuck on technique / leak-vector choice. Filesystem-
# backed (no SQLite) so `tar -czf - data/exploits/` is a complete
# portable dump — see api/routes/exploits.py for export/import.
EXPLOITS_DIR = DATA_DIR / "exploits"


def exploit_dir(exploit_id: str) -> Path:
    return EXPLOITS_DIR / exploit_id


def job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def reject_job(job_id: str, status_code: int, detail: str) -> None:
    """Refuse a create request AND remove the directory it already made.

    `job_dir()` mkdirs, and a create route has to call it before it can judge a
    streamed upload — an empty image is only empty once you have read it. That
    left one `data/jobs/<id>/` behind for every 400: pwn/rev/misc/forensic all
    did it. The TTL reaper does eventually collect a meta-less directory, but
    "eventually" is up to the configured TTL — seven days by default, and never
    at all when it is set to 0.

    Never raises from the cleanup: the caller asked to refuse the request, and a
    failure to tidy must not turn a 400 into a 500. But it does not stay silent
    about it either — `ignore_errors=True` alone made a surviving directory
    indistinguishable from a successful one, and the 7-day TTL reaper is not a
    substitute (it is configurable to 0, and a week is a long time to carry an
    orphan nobody knows about). A survivor is logged with the job id, the path
    and the cause.

    Nothing is logged when the cleanup succeeds, and nothing when there was no
    directory to begin with — a warning that fires on the normal path is a
    warning nobody reads.
    """
    import logging
    import shutil

    from fastapi import HTTPException

    target = JOBS_DIR / job_id
    if target.exists():
        causes: list[str] = []

        def _collect(_func, path, exc_info):
            exc = exc_info[1]
            causes.append(f"{path}: {type(exc).__name__}: {exc}")

        shutil.rmtree(target, onerror=_collect)
        if target.exists():
            logging.getLogger(__name__).warning(
                "reject_job(%s): refused with %s but the job directory survived "
                "at %s — %s",
                job_id, status_code, target,
                "; ".join(causes) or "path still present after rmtree",
                # The path is also carried as a structured field. The rendered
                # message is for a human; a test that has to parse it ends up
                # asserting the wording, and three attempts at doing that were
                # each defeated by a different rewording. `reject_job_dir` says
                # which directory survived in a way no phrasing change touches.
                extra={"reject_job_dir": str(target)},
            )
    from modules.job_secrets import delete_job_secrets

    delete_job_secrets(job_id)
    raise HTTPException(status_code=status_code, detail=detail)


_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped", "flag_ready"}


def write_job_meta(job_id: str, meta: dict[str, Any]) -> None:
    from modules.job_secrets import redact_job_value

    meta = redact_job_value(job_id, meta)
    f = job_dir(job_id) / "meta.json"
    prev: dict[str, Any] = {}
    if f.exists():
        try:
            prev = json.loads(f.read_text())
        except Exception:
            prev = {}
    now_iso = datetime.now(timezone.utc).isoformat()
    # Auto-stamp lifecycle timestamps so the UI can show elapsed /
    # duration without each call site having to remember to set them.
    new_status = meta.get("status")
    if (
        new_status == "running"
        and not meta.get("started_at")
        and not prev.get("started_at")
    ):
        meta["started_at"] = now_iso
    if (
        new_status in _TERMINAL_STATUSES
        and not meta.get("finished_at")
        and not prev.get("finished_at")
    ):
        meta["finished_at"] = now_iso
    meta = {**meta, "updated_at": now_iso}
    f.write_text(json.dumps(meta, indent=2))


def read_job_meta(job_id: str) -> Optional[dict[str, Any]]:
    f = JOBS_DIR / job_id / "meta.json"
    if not f.exists():
        return None
    meta = json.loads(f.read_text())
    # The directory name IS the canonical job id. Some old / half-written
    # meta.json files (e.g. one clobbered by an early agent_heartbeat write
    # before the creation meta landed) lack an "id" key — the UI then renders
    # the job as "undefined" and DELETE /api/jobs/undefined 400s, so it can
    # never be removed. Inject it here (the single reader both list_jobs and
    # get_job route through); callers rebuild meta as {**read_job_meta(...)}
    # so the id also self-heals to disk on the next write.
    if isinstance(meta, dict):
        meta.setdefault("id", job_id)
    return meta


def save_upload(job_id: str, filename: str, content: bytes) -> Path:
    src_dir = job_dir(job_id) / "src"
    src_dir.mkdir(exist_ok=True)
    target = src_dir / filename
    target.write_bytes(content)
    return target


def cleanup_job(job_id: str) -> None:
    from modules.job_secrets import delete_job_secrets

    p = JOBS_DIR / job_id
    if p.exists():
        shutil.rmtree(p)
    delete_job_secrets(job_id)
