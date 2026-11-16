"""Run the ghiant/Ghidra decompiler against a binary by spawning a sibling
container. The worker has docker.sock mounted, so volumes must reference
HOST paths (HOST_DATA_DIR), not the worker's internal mount points."""

import json
import os
import zipfile
from pathlib import Path

import docker

DECOMPILER_IMAGE = "hextech_ctf_tool-decompiler"
DECOMPILER_TIMEOUT_S = 900  # 15 min — Ghidra auto-analysis can be slow
DECOMPILER_XREFS_TIMEOUT_S = 300  # 5 min — xrefs reuses cached project
DECOMPILER_MEM = "4g"
# Ghidra's analysis is multi-threaded and takes every core it is offered. This
# container is a SIBLING of the worker slot, so neither the slot's cap nor the
# docker shim (which only sees the agent's CLI) bounds it. Imported rather than
# redeclared so the decompiler cannot drift away from the sandbox's cap.
from modules._runner import runner_nano_cpus


def host_path_for(job_id: str) -> str:
    host_root = os.environ.get("HOST_DATA_DIR")
    if not host_root:
        raise RuntimeError(
            "HOST_DATA_DIR not set on worker — required to bind-mount into sibling containers"
        )
    return f"{host_root.rstrip('/')}/jobs/{job_id}"


def run_decompiler(job_id: str, binary_rel: str) -> tuple[Path, str]:
    """Decompile <jobdir>/<binary_rel> into <jobdir>/decomp/.
    Returns (decomp_dir, container_logs).
    """
    job_dir = Path(f"/data/jobs/{job_id}")
    decomp_zip = job_dir / "decomp.zip"
    decomp_dir = job_dir / "decomp"

    # Wipe any prior run
    if decomp_zip.exists():
        decomp_zip.unlink()
    if decomp_dir.exists():
        for p in decomp_dir.glob("*"):
            p.unlink()

    client = docker.from_env()
    host_job = host_path_for(job_id)

    container = client.containers.run(
        image=DECOMPILER_IMAGE,
        command=[f"/job/{binary_rel}", "-o", "/job/decomp.zip"],
        volumes={host_job: {"bind": "/job", "mode": "rw"}},
        mem_limit=DECOMPILER_MEM,
        # memswap == mem: with mem alone docker grants swap up to 2x the
        # cap, and slow swap thrash is what wedged this VM twice.
        memswap_limit=DECOMPILER_MEM,
        nano_cpus=runner_nano_cpus(),
        network_mode="none",
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "decompiler"},
    )
    try:
        result = container.wait(timeout=DECOMPILER_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        if result.get("StatusCode", 1) != 0:
            raise RuntimeError(
                f"decompiler exited with code {result.get('StatusCode')}\n--- logs ---\n{logs[-4000:]}"
            )
    finally:
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass

    if not decomp_zip.exists():
        raise RuntimeError(f"decompiler produced no decomp.zip\n--- logs ---\n{logs[-4000:]}")

    decomp_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(decomp_zip, "r") as zf:
        zf.extractall(decomp_dir)

    return decomp_dir, logs


def run_decompiler_xrefs(
    job_id: str, binary_rel: str, target: str, *, limit: int = 50,
) -> tuple[dict, str]:
    """Query Ghidra for cross-references to `target` (symbol name or hex
    address) inside <jobdir>/<binary_rel>. Spawns the decompiler image
    in xrefs mode, which auto-bootstraps a full analysis if no cached
    project exists yet, then reuses it on subsequent calls. Output JSON
    lands at <jobdir>/.ghidra_proj/xrefs.json (overwritten each call).

    Returns (parsed_json, container_logs).
    """
    job_dir = Path(f"/data/jobs/{job_id}")
    proj_dir = job_dir / ".ghidra_proj"
    proj_dir.mkdir(exist_ok=True)
    out_rel = ".ghidra_proj/xrefs.json"
    out_abs = job_dir / out_rel
    if out_abs.exists():
        out_abs.unlink()

    client = docker.from_env()
    host_job = host_path_for(job_id)

    container = client.containers.run(
        image=DECOMPILER_IMAGE,
        # The decompiler container's ENTRYPOINT is
        #   python3 /opt/ghiant/ghidra_decompile.py /opt/ghidra
        # so this command list is the tail of argv.
        command=[
            "xrefs",
            f"/job/{binary_rel}", target,
            "-o", f"/job/{out_rel}",
            "--limit", str(limit),
        ],
        volumes={host_job: {"bind": "/job", "mode": "rw"}},
        mem_limit=DECOMPILER_MEM,
        # memswap == mem: with mem alone docker grants swap up to 2x the
        # cap, and slow swap thrash is what wedged this VM twice.
        memswap_limit=DECOMPILER_MEM,
        nano_cpus=runner_nano_cpus(),
        network_mode="none",
        detach=True,
        labels={"hextech_ctf_tool_job_id": job_id, "hextech_ctf_tool_role": "decompiler"},
    )
    try:
        result = container.wait(timeout=DECOMPILER_TIMEOUT_S)
        logs = container.logs().decode("utf-8", errors="replace")
        if result.get("StatusCode", 1) != 0:
            raise RuntimeError(
                f"xrefs decompiler exited with code {result.get('StatusCode')}\n--- logs ---\n{logs[-4000:]}"
            )
    finally:
        try:
            container.remove(force=True, v=True)
        except Exception:
            pass

    if not out_abs.exists():
        raise RuntimeError(
            f"xrefs query produced no output file at {out_abs}\n--- logs ---\n{logs[-4000:]}"
        )
    try:
        payload = json.loads(out_abs.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"xrefs output not parseable as JSON ({e})\n--- file ---\n"
            f"{out_abs.read_text()[:1000]}"
        )
    return payload, logs


# ---------------------------------------------------------------------------
# Background decompile
#
# `run_decompiler` above spawns the sibling with detach=True and then blocks in
# container.wait(). For a small binary that is the right trade: 1-3 minutes and
# the caller has ./decomp/ in hand. For a large one it is not a trade at all —
# on a multi-megabyte binary, pre-recon sat in that wait for 7m17s, Ghidra
# never finished, and the phase reported "no evidence" about directions it
# never examined. Waiting did not buy the analysis; it only spent the triage
# budget and then published a conclusion that time, not analysis, produced.
#
# So the split: START it, keep triaging, HARVEST it when the decomp is wanted.
# The container was always detached — the only thing removed here is the wait.
#
# The completion signal is a FILE, `decomp/.ghiant.done`, not a return code.
# The spawning process exits long before the analysis ends, so the signal has
# to outlive it, and a file is the one thing an agent can check from Bash in a
# later turn without holding any handle.
# ---------------------------------------------------------------------------

BG_STATE_REL = ".ghidra_proj/ghiant_bg.json"
BG_DONE_REL = "decomp/.ghiant.done"
# Overridable so the property suite can drive a real job tree in a tmpdir.
# The synchronous helpers above keep their inline literal — they are proven and
# out of this change's blast radius.
JOBS_ROOT = "/data/jobs"


def _bg_paths(job_id: str) -> tuple[Path, Path, Path]:
    job_dir = Path(JOBS_ROOT) / job_id
    return job_dir, job_dir / BG_STATE_REL, job_dir / BG_DONE_REL


def start_decompiler_async(job_id: str, binary_rel: str) -> dict:
    """Spawn the decompiler and return immediately.

    Returns the state dict that was persisted. Raises only if the container
    could not be created at all — everything after that is the harvester's
    problem, because this call is not around to see it.
    """
    import time as _time

    job_dir, state_path, done_path = _bg_paths(job_id)
    decomp_zip = job_dir / "decomp.zip"

    # A previous run's artifacts would otherwise look like this run's result.
    for stale in (decomp_zip, done_path):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    client = docker.from_env()
    host_job = host_path_for(job_id)
    container = client.containers.run(
        image=DECOMPILER_IMAGE,
        command=[f"/job/{binary_rel}", "-o", "/job/decomp.zip"],
        volumes={host_job: {"bind": "/job", "mode": "rw"}},
        mem_limit=DECOMPILER_MEM,
        memswap_limit=DECOMPILER_MEM,
        nano_cpus=runner_nano_cpus(),
        network_mode="none",
        detach=True,
        labels={
            "hextech_ctf_tool_job_id": job_id,
            "hextech_ctf_tool_role": "decompiler",
        },
    )
    state = {
        "container_id": container.id,
        "binary_rel": binary_rel,
        "started_at": _time.time(),
        "timeout_s": DECOMPILER_TIMEOUT_S,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state))
    return state


def harvest_decompiler(job_id: str) -> tuple[str, str]:
    """Collect a finished background decompile. Returns (status, detail).

    status is one of:
      none     — nothing was ever started (or it was already harvested)
      running  — still analyzing
      done     — decomp/ is populated and decomp/.ghiant.done exists
      failed   — container exited non-zero, timed out, or produced no zip

    Safe and cheap to call unconditionally: with no state file it stats one
    path and returns. That matters because the harvest has to happen on EVERY
    ghiant invocation, not just an explicit status query — the phase that
    starts the analysis is usually not the phase that wants the output, and a
    result nobody collects is the same as no result.
    """
    import time as _time

    job_dir, state_path, done_path = _bg_paths(job_id)
    if not state_path.exists():
        return ("done", str(done_path)) if done_path.exists() else ("none", "")

    try:
        state = json.loads(state_path.read_text())
    except Exception as e:
        state_path.unlink(missing_ok=True)
        return "failed", f"unreadable background state ({e})"

    cid = state.get("container_id") or ""
    binary_rel = state.get("binary_rel") or "?"
    started = float(state.get("started_at") or 0)
    timeout_s = float(state.get("timeout_s") or DECOMPILER_TIMEOUT_S)
    elapsed = max(0.0, _time.time() - started)

    try:
        client = docker.from_env()
        container = client.containers.get(cid)
    except Exception:
        state_path.unlink(missing_ok=True)
        return "failed", (
            f"decompiler container for {binary_rel} is gone after {elapsed:.0f}s "
            "(removed, or the daemon restarted) — no decomp was produced"
        )

    status = (getattr(container, "status", "") or "").lower()
    if status in ("created", "running", "restarting", "paused"):
        if elapsed > timeout_s:
            _force_remove(container)
            state_path.unlink(missing_ok=True)
            return "failed", (
                f"decompiler for {binary_rel} exceeded {timeout_s:.0f}s and was "
                "killed; Ghidra does not finish this binary under the current cap"
            )
        return "running", f"{binary_rel}: analyzing for {elapsed:.0f}s"

    # Exited — read the verdict before removing the container.
    try:
        code = int((container.attrs.get("State") or {}).get("ExitCode", 1))
    except Exception:
        code = 1
    try:
        logs = container.logs().decode("utf-8", errors="replace")
    except Exception:
        logs = ""
    _force_remove(container)
    state_path.unlink(missing_ok=True)

    decomp_zip = job_dir / "decomp.zip"
    if code != 0:
        return "failed", (
            f"decompiler for {binary_rel} exited {code} after {elapsed:.0f}s\n"
            f"--- logs ---\n{logs[-2000:]}"
        )
    if not decomp_zip.exists():
        return "failed", (
            f"decompiler for {binary_rel} exited 0 but produced no decomp.zip\n"
            f"--- logs ---\n{logs[-2000:]}"
        )

    decomp_dir = job_dir / "decomp"
    decomp_dir.mkdir(exist_ok=True)
    try:
        with zipfile.ZipFile(decomp_zip, "r") as zf:
            zf.extractall(decomp_dir)
    except Exception as e:
        # A truncated zip is a failure, not a silent empty decomp/ — the whole
        # point of the marker is that its presence means the files are there.
        return "failed", f"decomp.zip for {binary_rel} is not readable ({e})"

    n = sum(1 for _ in decomp_dir.glob("*.c"))
    done_path.write_text(
        json.dumps({"binary_rel": binary_rel, "files": n, "elapsed_s": round(elapsed, 1)})
    )
    return "done", f"{binary_rel}: {n} decompiled functions in {elapsed:.0f}s"


def _force_remove(container) -> None:
    try:
        container.remove(force=True, v=True)
    except Exception:
        pass
