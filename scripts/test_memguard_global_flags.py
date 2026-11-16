#!/usr/bin/env python3
"""A docker global flag must not carry the memory cap away with it.

worker/docker_memguard.sh sits on PATH ahead of the real docker inside every
worker, and injects `--memory` / `--cpus` / the job label into `docker run`
and `docker create`. It found the subcommand by taking the first argument that
does not begin with '-'.

A handful of docker's GLOBAL flags carry their value in a SEPARATE argument,
and that value does not begin with '-':

    docker -H unix:///var/run/docker.sock run --rm img
                ^^^^^^^^^^^^^^^^^^^^^^^^^ read as the subcommand

It matches neither `run` nor `create`, so the guard exec'd the real docker
untouched: the container came up with NO memory cap, NO cpu cap and NO job
label — uncapped and unattributable, one `docker -H` away from the agent's own
Bash. On this host an over-committed VM is not theoretical; worker-slots.sh
records WSL freezing twice from exactly that.

The script exposes DOCKER_MEMGUARD_REAL for this purpose ("Overridable ONLY so
the guard can be tested by pointing it at a recorder that prints its argv
instead of starting a container"), so these checks run the SHIPPED script and
read the argv it would have exec'd. Nothing is started.

Run from the repository root::

    python3 scripts/test_memguard_global_flags.py
    python3 scripts/test_memguard_global_flags.py --mutate first-non-dash
"""
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "worker" / "docker_memguard.sh"

MUTATIONS = ("first-non-dash", "forget-equals-form")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

SRC = GUARD.read_text()
if args.mutate == "first-non-dash":
    # The original scan: any leading flag's VALUE becomes the subcommand.
    SRC = SRC.replace(
        '        -*) if _takes_value "${args[$i]}"; then i=$((i+2)); else i=$((i+1)); fi ;;',
        '        -*) i=$((i+1)) ;;', 1)
elif args.mutate == "forget-equals-form":
    # `--context=default` is self-contained; treating it as value-taking eats
    # the real subcommand that follows.
    SRC = SRC.replace(
        "        -H|--host|-c|--context|-l|--log-level|--config|\\\n"
        "        --tlscacert|--tlscert|--tlskey) return 0 ;;",
        "        -*) return 0 ;;", 1)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


def _argv(cli_args: list[str]) -> list[str]:
    """Run the guard with a recorder in place of docker; return its argv."""
    with tempfile.TemporaryDirectory() as td:
        rec = Path(td) / "docker"
        rec.write_text('#!/bin/bash\nfor a in "$@"; do printf "%s\\n" "$a"; done\n')
        rec.chmod(0o755)
        guard = Path(td) / "guard.sh"
        guard.write_text(SRC)
        env = dict(os.environ,
                   DOCKER_MEMGUARD_REAL=str(rec),
                   JOB_ID="testjob")
        out = subprocess.run(["bash", str(guard)] + cli_args,
                             capture_output=True, text=True, env=env)
        return out.stdout.splitlines()


def _capped(argv: list[str]) -> bool:
    return "--memory" in argv and "--cpus" in argv


def main() -> int:
    # The plain case must keep working, or the rest proves nothing.
    check("G1 a bare `run` is capped", _capped(_argv(["run", "--rm", "img"])), True)
    check("G1 ...and labelled for the job sweep",
          "hextech_ctf_tool_job_id=testjob" in _argv(["run", "--rm", "img"]), True)

    # THE REGRESSION: each of these puts a non-dash value before `run`.
    for flag, value in (("-H", "unix:///var/run/docker.sock"),
                        ("--host", "tcp://x:1"),
                        ("-c", "default"),
                        ("--context", "default"),
                        ("-l", "debug"),
                        ("--log-level", "debug"),
                        ("--config", "/tmp/cfg")):
        argv = _argv([flag, value, "run", "--rm", "img"])
        check(f"G2 `docker {flag} <value> run` is still capped", _capped(argv), True)

    # The self-contained spelling must not eat the subcommand after it.
    for spelling in ("--context=default", "--log-level=debug", "--host=tcp://x:1"):
        argv = _argv([spelling, "run", "--rm", "img"])
        check(f"G3 `docker {spelling} run` is still capped", _capped(argv), True)

    # create is capped for the same reason run is.
    check("G4 `create` is capped too", _capped(_argv(["create", "img"])), True)

    # ...and a subcommand that owns no cgroup is left alone.
    ps = _argv(["ps", "-a"])
    check("G5 a non-run subcommand is passed through untouched",
          (ps, _capped(ps)), (["ps", "-a"], False))
    inspect = _argv(["-H", "tcp://x:1", "images"])
    check("G5 ...including behind a global flag",
          (inspect, _capped(inspect)), (["-H", "tcp://x:1", "images"], False))

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
