"""Where an uploaded challenge file has to LAND, per module.

Every module wants the upload in a different place and shape: web/crypto/web3
want it extracted under `src/`, pwn and rev want an executable at `bin/<name>`
(and rev unpacks a zip and picks the real binary out of it), forensic and misc
want it sitting in the job root under its own name. That policy used to live
seven times, once inside each `/analyze` handler.

It has to move HERE because of the operator agent. The agent picks the module,
and it picks it AFTER the file has been uploaded -- so the ingest endpoint
cannot know where the file belongs, and the placement has to be callable from
the worker. The worker mounts `./modules` and not `./api`, which is the same
reason `pick_challenge_binary` already lives in `modules/_common.py`.

The upload arrives as a path, never as bytes: a forensic image is measured in
gigabytes and the two streaming handlers exist for that reason. Placement moves
that file rather than copying it, so a multi-gigabyte image is not written
twice.

KNOWN DUPLICATION. The seven `/analyze` routes do NOT call this yet -- they
still place their own uploads, and they are still reachable, because the AI
Player posts to them (`test_player_agent_contract`: "create posts to
/api/modules/<mod>/analyze"). Refactoring seven production endpoints was not
part of the change that created this file, so there are two copies of the
policy. That is exactly the shape the comment on `_first_binary_in` warns
about, and `test_operator_agent` carries a tripwire that fails if the two ever
disagree on which directory a module's upload belongs in. Folding the routes
into this function is the fix; the tripwire is the guard until then.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from modules.storage import JOBS_DIR, extract_if_archive

# Every module this can place for. `hybrid` is deliberately absent: it is a
# coordinator over child jobs, not a destination for an upload.
PLACEABLE = ("web", "pwn", "forensic", "misc", "crypto", "rev", "web3")

# Which modules keep their source extracted under `src/`.
_SRC_MODULES = ("web", "crypto", "web3")
# Which modules want one executable at `bin/<name>`.
_BIN_MODULES = ("pwn", "rev")
# Which modules want the artefact in the job root under its own name.
_ROOT_MODULES = ("forensic", "misc")


# --- safe extraction ---------------------------------------------------------
# Challenge bundles are challenge-authored and therefore hostile by assumption
# -- the same sentence style.css already uses about inline SVG. Three concrete
# things were reproduced on this box before these limits were written:
#
#   * `tarfile.extractall` walks out of its directory. A member named
#     `../escaped.txt` landed outside the output dir on Python 3.10, which has
#     no `filter=` parameter (that arrived in 3.12). An absolute member only
#     failed on the host because of permissions; the runner is root.
#   * A tar member can be a SYMLINK. `link -> /etc` was created, and a later
#     member writing through `link/` writes to /etc.
#   * A 499 KB zip expanded to 524 MB — 1,027x. `extract_if_archive` has no
#     size cap at all, so web/crypto/web3 have been exposed to this the whole
#     time.
#
# zipfile.extractall DOES sanitise paths on 3.10 (verified), but it is given
# the same treatment so one reading covers both formats.
MAX_EXTRACT_BYTES = 2 * 1024 * 1024 * 1024   # 2 GiB uncompressed, total
MAX_EXTRACT_ENTRIES = 20_000
MAX_EXTRACT_RATIO = 200                       # uncompressed / compressed


class UnsafeArchive(RuntimeError):
    """The archive asks for something an ingest must not do."""


def _safe_member_path(out: Path, name: str) -> Path | None:
    """Resolved destination inside `out`, or None if the member escapes it."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return None
    dest = (out / name).resolve()
    try:
        dest.relative_to(out.resolve())
    except ValueError:
        return None
    return dest


def is_archive(path: Path) -> str | None:
    """"zip" / "tar" / None, from the file's MAGIC rather than its name.

    A challenge that names a zip `flag.png` is a normal challenge; a name is
    not evidence of a format.
    """
    try:
        with path.open("rb") as fp:
            head = fp.read(262)
    except OSError:
        return None
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")):
        return "tar"          # compressed stream; tarfile sniffs the rest
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def safe_extract(src: Path, out: Path) -> dict:
    """Extract `src` into `out` under hard limits. Returns what it did.

    Regular files and directories only. A symlink, hardlink, device or fifo is
    SKIPPED, not followed -- an ingest has no reason to create one and every
    reason not to. Nothing is written until the member has been checked.
    """
    kind = is_archive(src)
    if kind is None:
        raise UnsafeArchive("not an archive")
    comp = max(1, src.stat().st_size)

    def _check(total: int) -> None:
        if total > MAX_EXTRACT_BYTES:
            raise UnsafeArchive(
                f"uncompressed size passed {MAX_EXTRACT_BYTES // (1024 * 1024)} MiB")
        if total // comp > MAX_EXTRACT_RATIO and total > 64 * 1024 * 1024:
            raise UnsafeArchive(f"compression ratio passed {MAX_EXTRACT_RATIO}x")

    # PRE-FLIGHT, before a single byte is written. Checking as it goes meant a
    # refused bomb still landed 560 MB on disk before the ratio tripped --
    # measured. Both formats declare member sizes in their headers, so the
    # total is knowable without decompressing anything.
    _declared = _declared_total(src, kind)
    _check(_declared)

    out.mkdir(parents=True, exist_ok=True)
    created = out
    written = files = 0
    skipped: list[str] = []

    def _guard(size: int) -> None:
        # Still enforced during the write: a header can lie about its size.
        nonlocal written
        written += max(0, size)
        _check(written)

    try:
        return _extract_members(src, out, kind, _guard, skipped)
    except Exception:
        # A refusal must not leave a half-extracted tree: the caller decides
        # the archive is unusable, and a partial one is worse than none.
        shutil.rmtree(created, ignore_errors=True)
        raise


def _declared_total(src: Path, kind: str) -> int:
    """Sum of the member sizes the archive claims, without extracting."""
    total = 0
    try:
        if kind == "zip":
            with zipfile.ZipFile(src) as zf:
                for info in zf.infolist():
                    total += max(0, info.file_size)
        else:
            with tarfile.open(src) as tf:
                for member in tf:
                    if member.isfile():
                        total += max(0, member.size)
    except UnsafeArchive:
        raise
    except Exception:
        # Unreadable here means unreadable later; the extract call reports it.
        return 0
    return total


def _extract_members(src: Path, out: Path, kind: str, _guard, skipped: list) -> dict:
    written = files = 0
    if kind == "zip":
        with zipfile.ZipFile(src) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_EXTRACT_ENTRIES:
                raise UnsafeArchive(f"more than {MAX_EXTRACT_ENTRIES} entries")
            for info in infos:
                if info.is_dir():
                    continue
                dest = _safe_member_path(out, info.filename)
                if dest is None:
                    skipped.append(info.filename)
                    continue
                _guard(info.file_size)
                written += max(0, info.file_size)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as fsrc, dest.open("wb") as fdst:
                    shutil.copyfileobj(fsrc, fdst)
                files += 1
    else:
        with tarfile.open(src) as tf:
            for member in tf:
                if files > MAX_EXTRACT_ENTRIES:
                    raise UnsafeArchive(f"more than {MAX_EXTRACT_ENTRIES} entries")
                if member.isdir():
                    continue
                if not member.isfile():
                    # symlink, hardlink, device, fifo
                    skipped.append(member.name)
                    continue
                dest = _safe_member_path(out, member.name)
                if dest is None:
                    skipped.append(member.name)
                    continue
                _guard(member.size)
                dest.parent.mkdir(parents=True, exist_ok=True)
                fsrc = tf.extractfile(member)
                if fsrc is None:
                    skipped.append(member.name)
                    continue
                with fsrc, dest.open("wb") as fdst:
                    shutil.copyfileobj(fsrc, fdst)
                files += 1
                written += max(0, member.size)
    return {"kind": kind, "files": files, "bytes": written, "skipped": skipped}


class PlacementError(RuntimeError):
    """The upload cannot be placed for this module."""


def _job_dir(job_id: str) -> Path:
    p = JOBS_DIR / Path(job_id).name
    p.mkdir(parents=True, exist_ok=True)
    return p


def _move(src: Path, dst: Path) -> None:
    """Move within the data volume, falling back to a copy across devices."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(src, dst)
    except OSError:
        shutil.move(str(src), str(dst))


def empty_slots() -> dict[str, Any]:
    """The full key set, all unset.

    Returned for a job with no upload so callers see the same shape either
    way -- a remote-only job has no `binary_name`, and that is different from
    a key that was never considered.
    """
    return {"filename": None, "src_root": None, "binary_name": None,
            "image_name": None, "fname": None, "unpacked": None,
            "unpacked_root": None, "unpack_refused": None}


def place_upload(module: str, job_id: str, raw_path: Path,
                 filename: str) -> dict[str, Any]:
    """Put `raw_path` where `module` expects it. Returns the meta slots it set.

    `raw_path` is consumed: after this call it no longer exists at that path.
    """
    if module not in PLACEABLE:
        raise PlacementError(f"no placement policy for module {module!r}")
    raw_path = Path(raw_path)
    if not raw_path.is_file():
        raise PlacementError(f"upload is missing at {raw_path}")
    if raw_path.stat().st_size == 0:
        raise PlacementError("empty file")

    name = Path(filename).name
    if not name:
        raise PlacementError("upload has no filename")
    out = empty_slots()
    out["filename"] = name
    jd = _job_dir(job_id)

    if module in _SRC_MODULES:
        dst = jd / "src" / name
        _move(raw_path, dst)
        # Was `extract_if_archive`, which has no size, entry or ratio limit --
        # a 499 KB zip reaching 524 MB went straight through it. The archive
        # itself is kept beside the extraction; a bundle's own structure is
        # sometimes the evidence.
        if is_archive(dst):
            try:
                got = safe_extract(dst, dst.parent / "extracted")
                out["src_root"] = str(dst.parent / "extracted")
                out["unpacked"] = got
                return out
            except UnsafeArchive as exc:
                out["unpack_refused"] = str(exc)
        out["src_root"] = str(dst.parent)
        return out

    if module in _BIN_MODULES:
        bin_dir = jd / "bin"
        dst = bin_dir / name
        _move(raw_path, dst)
        dst.chmod(0o755)
        out["binary_name"] = name
        # pwn unpacks now as well. It ships the same shape rev does -- one
        # binary, its libs, a Dockerfile -- and leaving the archive sealed made
        # `binary_name` the zip, so the prompt's `./bin/<name>` pointed at an
        # archive. Job 013dfdc4d8e4 landed exactly that.
        #
        # Detected by MAGIC, not by suffix: a challenge that names its zip
        # `flag.png` is a normal challenge, and the old `.zip` check missed it.
        if module in _BIN_MODULES and is_archive(dst):
            # zip-preferred upload: unpack into bin/, then re-resolve the name
            # to the real challenge so the prompt's `./bin/<name>` points at it
            # instead of at the archive. Verbatim from the rev route, including
            # the deliberate absence of a "must contain ELF/PE" gate -- a zip
            # of .class/.pyc/wasm/dex still has to proceed.
            try:
                out["unpacked"] = safe_extract(dst, bin_dir)
            except UnsafeArchive as exc:
                # Refused, not fatal: the sealed archive stays at bin/<name>
                # and the agent can open it itself with whatever limits it
                # likes. An ingest refusing to be a decompression bomb is not
                # a reason to refuse the job.
                out["unpack_refused"] = str(exc)
                return out
            dst.unlink(missing_ok=True)
            from modules._common import pick_challenge_binary

            pick = pick_challenge_binary(bin_dir)
            if pick is None:
                # Degenerate (empty zip / only nested archives) -- proceed with
                # no specific target; the agent explores ./bin/.
                out["binary_name"] = None
            else:
                flat = bin_dir / pick.name
                if pick.resolve() != flat.resolve():
                    shutil.move(str(pick), str(flat))
                flat.chmod(0o755)
                out["binary_name"] = flat.name
        return out

    # _ROOT_MODULES. These two do NOT unpack in place, and the reason is
    # different for each:
    #
    #   misc     the archive IS often the artefact. `_spawn_misc` hands the
    #            original file to the tool sweep with `--passphrase`, and the
    #            prompt names "archives with extra entries" as a hiding place.
    #            An encrypted archive cannot be opened here at all, and the
    #            passphrase belongs to the tools, not to ingest.
    #   forensic the collector takes ONE image path and parses the format
    #            itself (`--type auto`). Replacing the image with a directory
    #            leaves nothing to pass it, and these are gigabytes.
    #
    # So the original stays exactly where the module expects it, and a COPY of
    # the contents lands beside it for the agent to read. Additive: nothing
    # that worked before receives anything different.
    dst = jd / name
    _move(raw_path, dst)
    if module == "forensic":
        out["image_name"] = name
    else:
        out["fname"] = name
    if is_archive(dst):
        try:
            got = safe_extract(dst, jd / "unpacked")
            out["unpacked"] = got
            out["unpacked_root"] = str(jd / "unpacked")
        except UnsafeArchive as exc:
            out["unpack_refused"] = str(exc)
    return out


# How each module's worker entry point is called. Kept beside the placement
# because the two have to agree: `rev` takes no target, and `forensic`/`misc`
# take parameters no other module has.
#
# `retry.py` holds its own copy of this dispatch and rebuilds from an existing
# job's meta rather than from an upload, so it is not folded in here -- it
# answers a different question (what did this job already have on disk).
RUN_JOB: dict[str, str] = {
    "web": "modules.web.analyzer.run_job",
    "pwn": "modules.pwn.analyzer.run_job",
    "crypto": "modules.crypto.analyzer.run_job",
    "rev": "modules.rev.analyzer.run_job",
    "web3": "modules.web3.analyzer.run_job",
    "forensic": "modules.forensic.orchestrator.run_job",
    "misc": "modules.misc.orchestrator.run_job",
}


def run_args(module: str, slots: dict, *, target: str | None,
             description: str | None, model: str | None,
             auto_run: bool = True, passphrase: str | None = None) -> tuple:
    """Positional arguments for `RUN_JOB[module]`, after `job_id`.

    Each shape is the one that module's own /analyze route passes. `rev` gets
    no target. `forensic` gets image_type/target_os as "auto" -- the same
    default its form carries, so the module keeps inferring them itself -- and
    bulk_extractor/skip_claude False.
    """
    if module in ("web", "crypto", "web3"):
        return (slots["src_root"], target, description, auto_run, model)
    if module == "pwn":
        return (slots["binary_name"], target, description, auto_run, model)
    if module == "rev":
        return (slots["binary_name"], description, auto_run, model)
    if module == "forensic":
        return (slots["image_name"], "auto", "auto", description, False,
                False, model)
    if module == "misc":
        return (slots["fname"], passphrase, description, False, model)
    raise PlacementError(f"no run signature for module {module!r}")
