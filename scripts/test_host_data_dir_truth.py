#!/usr/bin/env python3
"""A wrong HOST_DATA_DIR does not fail — it mounts an empty directory.

HOST_DATA_DIR is a HOST path. The worker hands it to `docker run -v` when it
bind-mounts a job into a sibling container: modules/_runner.py `_host_path`
for every sandboxed exploit run, worker/chal_engine_shim.sh for every
relocated kernel boot, and the recipe AUTOBOOT.md gives the agent for its own
docker calls.

When the value is wrong the daemon does not error. It CREATES the missing
source and mounts it EMPTY, so the container comes up against a directory with
no ./chal, no bzImage, no exploit — and everything downstream still logs
normally.

WHAT HAPPENED HERE

.env.example ships the line as a placeholder:

    HOST_DATA_DIR=/home/youruser/HexTech_CTF_TOOL/data

start.sh only WARNED that it had to be edited. On this deployment it never
was. `/home/youruser/HexTech_CTF_TOOL/data` was found on disk — root-owned,
created by the daemon, holding nothing but empty `work/` dirs for three job
ids — while shim.log recorded nineteen boots as "RELOCATED into chal_<id>"
and the sandbox reported ordinary exit codes. The only reason it surfaced is
that three boots happened to fail a DIFFERENT precondition and said so.

THE FIX, IN THREE PLACES
  * the daemon is asked what this container's /data really is, and that
    answer wins over the variable (authoritative by construction: it is the
    same mount the job tree is read through)
  * start.sh derives the value instead of advising the operator to
  * the shim's log stops claiming an outcome it cannot observe

Run from the repository root::

    python3 scripts/test_host_data_dir_truth.py
    python3 scripts/test_host_data_dir_truth.py --mutate trust-the-env
"""
from __future__ import annotations

import argparse
import ast
import re
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "modules" / "_runner.py"
SHIM = ROOT / "worker" / "chal_engine_shim.sh"
START = ROOT / "start.sh"
EXAMPLE = ROOT / ".env.example"

MUTATIONS = ("trust-the-env", "shim-trusts-the-env", "start-only-warns")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

R = RUNNER.read_text()
S = SHIM.read_text()
T = START.read_text()

if args.mutate == "trust-the-env":
    R = R.replace(
        'host_root = _true_host_data_dir() or os.environ.get("HOST_DATA_DIR")',
        'host_root = os.environ.get("HOST_DATA_DIR")', 1)
elif args.mutate == "shim-trusts-the-env":
    S = re.sub(r'_true_data_src="\$\(docker inspect.*?\nfi\n', "", S, count=1, flags=re.S)
elif args.mutate == "start-only-warns":
    T = T.replace('  export HOST_DATA_DIR="$_want_data"', "  :", 1)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


def main() -> int:
    # --- the runner: the daemon's answer beats the variable ------------------
    tree = ast.parse(R)
    fns = {n.name: ast.get_source_segment(R, n) for n in tree.body
           if isinstance(n, ast.FunctionDef)}
    check("R0 _true_host_data_dir exists", "_true_host_data_dir" in fns, True)
    check("R1 _host_path prefers it over the env var",
          "_true_host_data_dir() or os.environ.get" in R, True)
    check("R1 ...and still falls back, so a docker-less context is not broken",
          'os.environ.get("HOST_DATA_DIR")' in R, True)

    # Behaviour, with a stubbed daemon: a WRONG env var must not win.
    ns = types.ModuleType("_hdd_ns")
    import os as _os
    ns.__dict__.update({"os": _os})
    exec(compile(fns["_true_host_data_dir"] + "\n\n" + fns["_host_path"],
                 str(RUNNER), "exec"), ns.__dict__)
    ns.__dict__["_TRUE_DATA_SRC"] = ["/real/checkout/data"]   # daemon answered
    _os.environ["HOST_DATA_DIR"] = "/home/youruser/HexTech_CTF_TOOL/data"
    check("R2 a placeholder env var loses to the real mount",
          ns.__dict__["_host_path"]("j1"), "/real/checkout/data/jobs/j1")
    ns.__dict__["_TRUE_DATA_SRC"] = [None]                    # no daemon
    check("R3 ...and with no daemon answer the env var is still used",
          ns.__dict__["_host_path"]("j1"),
          "/home/youruser/HexTech_CTF_TOOL/data/jobs/j1")
    check("R4 the lookup is cached, not run per sandbox launch",
          "_TRUE_DATA_SRC" in R and "if _TRUE_DATA_SRC:" in R, True)

    # --- the shim: same rule, same reason ------------------------------------
    check("S1 the shim asks the daemon for its own /data source",
          "docker inspect" in S and '"/data"' in S, True)
    check("S1 ...and overrides a disagreeing env var",
          'HOST_DATA_DIR="$_true_data_src"' in S, True)
    check("S2 ...and says so, because a silent correction hid this once",
          "HOST_DATA_DIR CORRECTED" in S, True)
    check("S3 the relocation log no longer claims an outcome",
          '_log_shim "RELOCATED into' in S, False)

    # --- start.sh: derive, do not advise -------------------------------------
    check("T1 start.sh sets HOST_DATA_DIR itself",
          'export HOST_DATA_DIR="$_want_data"' in T, True)
    check("T1 ...to this checkout's own data dir",
          '_want_data="$PWD/data"' in T, True)
    check("T2 ...and it happens before the stack comes up",
          T.find("_want_data=") < T.find("up -d --build"), True)

    # --- and the trap that started it ---------------------------------------
    # Keep the placeholder OUT of the shipped example, or the next operator
    # copies the same booby trap.
    # Look at ASSIGNMENTS, not prose. The comment above the line names the
    # bad path on purpose — that is the incident being recorded, and an
    # earlier version of this check counted it as the trap itself.
    ex = EXAMPLE.read_text()
    live = [ln for ln in ex.splitlines()
            if re.match(r"\s*HOST_DATA_DIR\s*=", ln)]
    check("E1 .env.example ships no ACTIVE HOST_DATA_DIR assignment",
          live, [])
    check("E1 ...and the sample that remains is commented and generic",
          any(ln.startswith("#HOST_DATA_DIR=") and "/home/youruser" not in ln
              for ln in ex.splitlines()), True)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
