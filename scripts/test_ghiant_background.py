#!/usr/bin/env python3
"""A decompile must never spend a whole triage phase and then report nothing.

WHY THIS EXISTS

`ghiant` spawns Ghidra in a sibling container. The container was always
detached; `run_decompiler` then blocked in `container.wait()` for up to 15
minutes. On a normal challenge binary that is the right trade — you pay 1-3
minutes and the caller gets ./decomp/.

On a very large binary that wait can outlast the whole triage phase: pre-recon
once sat in it for 7m17s, Ghidra never finished, and the phase reported "no
evidence" about directions it never examined. The damage is not the lost time;
it is that running out of time was reported as evidence.

So: start it, keep triaging, harvest later. Two things make that safe, and
this suite exists for those two things.

1. THE COMPLETION SIGNAL MUST OUTLIVE THE PROCESS THAT STARTED IT.
   The spawning `ghiant` exits within a second. Whatever says "the decomp is
   ready" has to be on disk, and every later entrypoint has to collect it —
   the phase that starts an analysis is not the phase that reads it.

2. THE REAPER MUST KNOW THE CONTAINER.
   `reap_chal_containers` filters on `hextech_job=<id>`; decompile.py labels
   with `hextech_ctf_tool_job_id=<id>`. Different keys — the reaper never saw
   these containers. That was survivable only because the blocking path
   removes the container in a `finally`. Backgrounding deletes that guarantee,
   so a job killed mid-analysis would orphan a 4 GB-capped Ghidra container
   that nothing cleans up. On this host that resurfaces later as slot
   pressure, which reads as an OOM, not as a leak.

Run:
    python3 scripts/test_ghiant_background.py
    python3 scripts/test_ghiant_background.py --mutate spawn-waits
"""
from __future__ import annotations

import argparse
import ast
import json
import shutil
import sys
import tempfile
import types
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DECOMP = ROOT / "modules" / "pwn" / "decompile.py"
COMMON = ROOT / "modules" / "_common.py"
CLI = ROOT / "worker" / "ghiant_cli.py"
PROMPTS = ROOT / "modules" / "_prompts.py"

D = DECOMP.read_text()
C = COMMON.read_text()
L = CLI.read_text()
P = PROMPTS.read_text()

MUTATIONS = (
    "reaper-drops-decompiler",   # reaper stops filtering the decompiler label
    "label-drift",               # decompile.py labels with a different key
    "spawn-waits",               # the "async" spawn blocks after all
    "spawn-keeps-stale",         # a previous run's zip survives into this one
    "harvest-ignores-exit-code", # a crashed Ghidra counts as done
    "harvest-no-timeout",        # a wedged container is reported as running forever
    "truncated-zip-is-done",     # unreadable zip yields an empty decomp/, called done
    "decomp-does-not-harvest",   # a finished background run is re-run from scratch
    "prompt-unconditional",      # the prompt goes back to "run it ONCE, 1-3 min"
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

# host_path_for() refuses to build a bind-mount spec without this. The real
# worker gets it from compose; the suite only needs it to be non-empty.
import os as _os
_os.environ.setdefault("HOST_DATA_DIR", "/tmp/ghiant-suite-host")
_D0, _C0, _L0, _P0 = D, C, L, P

if args.mutate == "reaper-drops-decompiler":
    C = C.replace('            f"label=hextech_ctf_tool_job_id={job_id}",\n', "", 1)
elif args.mutate == "label-drift":
    D = D.replace('"hextech_ctf_tool_job_id": job_id,\n            "hextech_ctf_tool_role": "decompiler",',
                  '"hextech_decompiler_job": job_id,\n            "hextech_ctf_tool_role": "decompiler",', 1)
elif args.mutate == "spawn-waits":
    D = D.replace("    state = {\n        \"container_id\": container.id,",
                  "    container.wait(timeout=DECOMPILER_TIMEOUT_S)\n"
                  "    state = {\n        \"container_id\": container.id,", 1)
elif args.mutate == "spawn-keeps-stale":
    D = D.replace("    for stale in (decomp_zip, done_path):", "    for stale in ():", 1)
elif args.mutate == "harvest-ignores-exit-code":
    D = D.replace("    if code != 0:", "    if False:", 1)
elif args.mutate == "harvest-no-timeout":
    D = D.replace("        if elapsed > timeout_s:", "        if False:", 1)
elif args.mutate == "truncated-zip-is-done":
    D = D.replace('        return "failed", f"decomp.zip for {binary_rel} is not readable ({e})"',
                  "        pass", 1)
elif args.mutate == "decomp-does-not-harvest":
    L = L.replace('    if _harvest_first(job_id, out_dir) == "done":', "    if False:", 1)
elif args.mutate == "prompt-unconditional":
    i = P.index("   * Decomp triage:")
    j = P.index("   * Skip ghiant for small SOs")
    P = P[:i] + ("   * Decomp triage: PREFER `./decomp/*.c` Read over `objdump`. If\n"
                 "     `./decomp/` is empty, run `ghiant ./bin/<n>` ONCE (1-3 min cold,\n"
                 "     5-10s warm — project caches under `./.ghidra_proj/`).\n") + P[j:]

if args.mutate and (D, C, L, P) == (_D0, _C0, _L0, _P0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor no longer matches. "
        "A mutation that does not apply proves nothing."
    )

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# ---------------------------------------------------------------------------
# Load the MUTATED decompile.py with a fake docker daemon.
# Importing modules.pwn.decompile would load the real file and ignore every
# mutation above.
# ---------------------------------------------------------------------------
class FakeContainer:
    def __init__(self, cid="c0ffee", status="running", exit_code=0, on_run=None):
        self.id = cid
        self.status = status
        self.attrs = {"State": {"ExitCode": exit_code}}
        self.removed = False
        self.waited = False
        self._on_run = on_run

    def wait(self, timeout=None):
        self.waited = True
        return {"StatusCode": self.attrs["State"]["ExitCode"]}

    def logs(self):
        return b"ghidra log"

    def remove(self, force=False, v=False):
        self.removed = True


class FakeContainers:
    def __init__(self, box):
        self.box = box

    def run(self, **kw):
        self.box["run_kwargs"] = kw
        c = self.box["container"]
        if self.box.get("on_run"):
            self.box["on_run"]()
        return c

    def get(self, cid):
        if self.box.get("gone"):
            raise RuntimeError("no such container")
        return self.box["container"]


def load_decompile(box):
    fake_docker = types.ModuleType("docker")
    fake_docker.from_env = lambda: types.SimpleNamespace(containers=FakeContainers(box))
    fake_runner = types.ModuleType("modules._runner")
    fake_runner.runner_nano_cpus = lambda: 1_000_000_000
    saved = {k: sys.modules.get(k) for k in ("docker", "modules._runner")}
    sys.modules["docker"] = fake_docker
    sys.modules["modules._runner"] = fake_runner
    try:
        mod = types.ModuleType("decompile_under_test")
        mod.__dict__["__name__"] = "decompile_under_test"
        exec(compile(D, str(DECOMP), "exec"), mod.__dict__)
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


def make_job(tmp, job_id="J"):
    root = Path(tmp) / "jobs"
    (root / job_id / ".ghidra_proj").mkdir(parents=True, exist_ok=True)
    (root / job_id / "decomp").mkdir(parents=True, exist_ok=True)
    return root, job_id


def write_zip(path, names=("main_401000.c", "sub_401100.c"), truncate=False):
    with zipfile.ZipFile(path, "w") as zf:
        for n in names:
            zf.writestr(n, "int main(){}\n")
    if truncate:
        data = path.read_bytes()
        path.write_bytes(data[: len(data) // 2])


# ---------------------------------------------------------------------------
def _leak_checks():
    """The reaper and the spawner must name the SAME label key."""
    print("\nL — the container the reaper could not see")
    key = "hextech_ctf_tool_job_id"
    check("L1 decompile.py labels its container with the job key",
          f'"{key}": job_id' in D)
    check("L2 the reaper filters on that key",
          f"label={key}={{job_id}}" in C)
    # Derived, not two literals: the point of the bug was that they drifted.
    import re as _re
    labels = set(_re.findall(r'"(hextech[A-Za-z_]*)":\s*job_id', D))
    filters = set(_re.findall(r"label=(hextech[A-Za-z_]*)=\{job_id\}", C))
    check("L3 every label the spawner sets is a label the reaper filters",
          bool(labels) and labels <= filters, True)


def _async_checks(tmp):
    print("\nA — the async contract")
    box = {"container": FakeContainer()}
    mod = load_decompile(box)
    root, job = make_job(tmp)
    mod.JOBS_ROOT = str(root)

    # A1 — the spawn must not block. Anything else is the old behaviour with
    # a new name, and the 7m17s comes straight back.
    src = ast.get_source_segment(D, next(
        n for n in ast.parse(D).body
        if isinstance(n, ast.FunctionDef) and n.name == "start_decompiler_async"))
    check("A1 start_decompiler_async never waits on the container",
          "container.wait(" not in src)

    # A2 — a previous run's zip must not be mistaken for this run's output.
    zip_path = root / job / "decomp.zip"
    write_zip(zip_path)
    (root / job / "decomp" / ".ghiant.done").write_text("{}")
    mod.start_decompiler_async(job, "bin/chal")
    check("A2 spawning clears a stale decomp.zip", not zip_path.exists())
    check("A2 ...and a stale completion marker",
          not (root / job / "decomp" / ".ghiant.done").exists())
    check("A2 ...and records state for the harvester",
          (root / job / ".ghidra_proj" / "ghiant_bg.json").exists())

    # A3 — cheap no-op when nothing is pending.
    root2, job2 = make_job(tmp, "K")
    mod.JOBS_ROOT = str(root2)
    check("A3 nothing started -> none", mod.harvest_decompiler(job2)[0], "none")

    # A4 — still analyzing.
    mod.JOBS_ROOT = str(root)
    box["container"] = FakeContainer(status="running")
    check("A4 a running container -> running", mod.harvest_decompiler(job)[0], "running")

    # A5 — wedged past the cap: killed and reported, not waited on forever.
    st = root / job / ".ghidra_proj" / "ghiant_bg.json"
    s = json.loads(st.read_text()); s["started_at"] = 0.0; st.write_text(json.dumps(s))
    box["container"] = FakeContainer(status="running")
    got = mod.harvest_decompiler(job)
    check("A5 a container past its timeout -> failed", got[0], "failed")
    check("A5 ...and it is removed, not left running", box["container"].removed)

    # A6 — the happy path.
    mod.start_decompiler_async(job, "bin/chal")
    write_zip(root / job / "decomp.zip")
    box["container"] = FakeContainer(status="exited", exit_code=0)
    status, detail = mod.harvest_decompiler(job)
    check("A6 exit 0 with a zip -> done", status, "done")
    check("A6 ...decomp/ is populated",
          len(list((root / job / "decomp").glob("*.c"))), 2)
    check("A6 ...and the completion marker exists",
          (root / job / "decomp" / ".ghiant.done").exists())
    check("A6 ...state is cleared so it is harvested once", not st.exists())

    # A7 — Ghidra crashed. Reporting that as done publishes whatever partial
    # zip it left behind as if it were a finished analysis.
    #
    # The zip below is deliberate: without it the missing-zip check (A8) also
    # returns "failed", so dropping the exit-code check entirely would still
    # look correct here. A check that cannot fail alone is not a check — the
    # first draft of this suite let that mutation escape.
    mod.start_decompiler_async(job, "bin/chal")
    write_zip(root / job / "decomp.zip")
    box["container"] = FakeContainer(status="exited", exit_code=137)
    check("A7 a non-zero exit -> failed EVEN WITH a zip on disk",
          mod.harvest_decompiler(job)[0], "failed")
    check("A7 ...and no completion marker is written",
          not (root / job / "decomp" / ".ghiant.done").exists())

    # A8 — exited clean but produced nothing.
    mod.start_decompiler_async(job, "bin/chal")
    box["container"] = FakeContainer(status="exited", exit_code=0)
    check("A8 exit 0 with no zip -> failed", mod.harvest_decompiler(job)[0], "failed")

    # A9 — a truncated zip must not become a silent empty decomp/. The marker
    # promises the files are there; it may only be written when they are.
    mod.start_decompiler_async(job, "bin/chal")
    write_zip(root / job / "decomp.zip", truncate=True)
    box["container"] = FakeContainer(status="exited", exit_code=0)
    status, _ = mod.harvest_decompiler(job)
    check("A9 an unreadable zip -> failed", status, "failed")
    check("A9 ...and no completion marker is written",
          not (root / job / "decomp" / ".ghiant.done").exists())

    # A10 — the daemon restarted, or something else removed it.
    mod.start_decompiler_async(job, "bin/chal")
    box["gone"] = True
    check("A10 a vanished container -> failed", mod.harvest_decompiler(job)[0], "failed")
    box["gone"] = False


def _wiring_checks():
    print("\nW — every entrypoint collects")
    for fn in ("cmd_decomp", "cmd_xrefs"):
        seg = ast.get_source_segment(L, next(
            n for n in ast.parse(L).body
            if isinstance(n, ast.FunctionDef) and n.name == fn))
        check(f"W1 {fn} harvests a finished background run", "_harvest_first(" in seg)
    seg = ast.get_source_segment(L, next(
        n for n in ast.parse(L).body
        if isinstance(n, ast.FunctionDef) and n.name == "cmd_status"))
    check("W1 cmd_status harvests", "harvest_decompiler(" in seg)
    check("W2 status exit codes distinguish running from none",
          '"running": 3, "none": 4' in L)
    check("W3 the CLI writes the marker the prompt names",
          '".ghiant.done"' in L)


def _prompt_checks():
    print("\nR — the instruction that caused the wait")
    check("R1 the prompt no longer claims an unconditional 1-3 min decompile",
          "run `ghiant ./bin/<n>` ONCE (1-3 min cold," not in P)
    check("R2 it offers the background form", "ghiant bg ./bin/<n>" in P)
    check("R3 it names a size threshold", "8 MiB" in P)
    check("R4 it names the completion signal the CLI actually writes",
          "./decomp/.ghiant.done" in P)
    check("R5 it records the measurement that justifies the rule", "7m17s" in P)
    check("R6 it tells the agent to diff large upstream binaries, not decompile them",
          "PATCH" in P and "version string" in P)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        _leak_checks()
        _async_checks(tmp)
        _wiring_checks()
        _prompt_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
