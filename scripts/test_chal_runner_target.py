#!/usr/bin/env python3
"""The runner stands the LOCAL challenge back up and tells the exploit where.

A job whose bundle ships its own Dockerfile and whose operator supplied no
remote has no target at all by the time `exploit.py` runs: the agent builds
the container during its turn and tears it down when it is done reasoning
about it, and the runner executes minutes later in a different sandbox. The
script then reports `network_error` -- which is also what a dead REMOTE
reports, so the one verdict that has to stay trustworthy gets muddied by a
target that was never there.

Run:
    python3 scripts/test_chal_runner_target.py
    python3 scripts/test_chal_runner_target.py --mutate chal-guesses-a-port
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "detection-forked",
    "chal-ignores-remote-target",
    "chal-guesses-a-port",
    "chal-picks-first-of-many",
    "chal-hardcodes-gateway",
    "runner-does-not-inject",
    "runner-ignores-its-own-network",
    "prompt-keeps-hardcoded-address",
    "sweep-finds-labels-only",
    "sweep-forces-removal",
    "build-unlabelled",
    "reap-log-hides-images",
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


COM = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
RUN = (ROOT / "modules" / "_runner.py").read_text(encoding="utf-8")

if args.mutate == "detection-forked":
    COM = COM.replace("    found, truncated = find_chal_build_files(job_id)",
                      "    found, truncated = [], 0", 1)
elif args.mutate == "chal-ignores-remote-target":
    COM = COM.replace(
        '    if str(meta.get("target_url") or "").strip() or (meta.get("target_urls") or []):\n'
        "        return {}\n", "", 1)
elif args.mutate == "chal-guesses-a-port":
    COM = COM.replace('        if not port:\n', "        if False:\n", 1)
elif args.mutate == "chal-picks-first-of-many":
    COM = COM.replace("        if len(dockerfiles) > 1:", "        if False:", 1)
elif args.mutate == "chal-hardcodes-gateway":
    COM = COM.replace("    host = _chal_gateway(network)",
                      '    host = "172.17.0.1"', 1)
elif args.mutate == "runner-does-not-inject":
    RUN = RUN.replace('        env["CHAL_HOST"] = str(_chal["host"])', "        pass", 1)
elif args.mutate == "runner-ignores-its-own-network":
    RUN = RUN.replace("_ensure_chal(job_id, network=network, log_fn=log_fn)",
                      '_ensure_chal(job_id, network="bridge", log_fn=log_fn)', 1)
elif args.mutate == "sweep-finds-labels-only":
    COM = COM.replace("                    if any(job_id in str(t).split(\":\", 1)[0]",
                      "                    if any(False", 1)
elif args.mutate == "sweep-forces-removal":
    COM = COM.replace("client.images.remove(image=img.id, force=False, noprune=False)",
                      "client.images.remove(image=img.id, force=True, noprune=False)", 1)
elif args.mutate == "build-unlabelled":
    COM = COM.replace('                          "--label", label,\n', "", 1)
elif args.mutate == "reap-log-hides-images":
    COM = COM.replace('    if any(res[k] for k in ("containers", "networks", "images", "volumes")):',
                      '    if any(res[k] for k in ("containers", "networks")):', 1)
elif args.mutate == "prompt-keeps-hardcoded-address":
    COM = COM.replace("DO NOT HARDCODE THAT ADDRESS", "Feel free to hardcode", 1)

# The whole function body, so a guard cannot be fooled by the same words
# appearing in an unrelated place -- and so a growing docstring above the code
# cannot slide the code out of a fixed slice.
_ENS = COM.split("def ensure_chal_container(", 1)
ENS = _ENS[1].split("\ndef ", 1)[0] if len(_ENS) > 1 else ""

print("1. one detector, not two")
check("the bundle scan is its own function", "def find_chal_build_files(" in COM)
check("...and the PROMPT uses it rather than its own copy",
      "found, truncated = find_chal_build_files(job_id)" in COM)
check("...and so does the runner path", "find_chal_build_files(job_id)" in ENS)
# The pruning rules are the expensive part: they encode a forensic hazard and
# a pwn carve-out that were each paid for by a real job.
_fcb = COM.split("def find_chal_build_files(", 1)[1].split("\ndef ", 1)[0]
check("...and the scan still prunes carved evidence", '"work"' in _fcb and "_noise" in _fcb)
check("...while keeping pwn's operator-unpack dir",
      'job_root / "work" / "chal"' in _fcb)

print("\n2. it does nothing unless it should")
check("opt-in is still the operator's box", 'meta.get("docker_challenge")' in ENS)
check("a REMOTE target wins — never shadowed by a local stand-in",
      'meta.get("target_url")' in ENS and 'meta.get("target_urls")' in ENS)
check("...and that check returns instead of continuing",
      bool(re.search(r'target_urls.*\n\s*return \{\}', ENS)))

print("\n3. it refuses to guess")
check("no Dockerfile -> hand back to the agent", "no Dockerfile in the bundle" in ENS)
check("several Dockerfiles -> ambiguous, not a coin flip",
      "len(dockerfiles) > 1" in ENS and "ambiguous" in ENS)
# Anchored on the CONTROL FLOW, not the log line: a mutation that deletes the
# guard and keeps the message would otherwise read as passing.
_np = ENS.find("if not port:")
check("no stated port -> not guessing one",
      _np >= 0 and "return {}" in ENS[_np:_np + 260] and "_chal_expose_port" in ENS)
# A guessed port publishes a socket nothing binds, and the exploit's failure
# then reads exactly like a dead remote.
_port = COM.split("def _chal_expose_port(", 1)[1].split("\ndef ", 1)[0]
check("the port is READ from EXPOSE or the compose file",
      "EXPOSE" in _port and "return None" in _port)
check("...and there is no fallback constant",
      not re.search(r"return\s+(?:80|443|1337|8080|9999)\b", _port))

print("\n4. the address is the SANDBOX's, not the worker's")
check("the gateway is asked of the network the sandbox joins",
      "_chal_gateway(network)" in ENS)
_gw = COM.split("def _chal_gateway(", 1)[1].split("\ndef ", 1)[0]
check("...from the daemon, not a second copy of the arithmetic",
      '"network", "inspect"' in _gw and "Gateway" in _gw)
check("...and no bridge address is hardcoded anywhere in the path",
      "172.17.0.1" not in ENS and "172.18.0.1" not in ENS)
check("the host port is assigned by the daemon, not fixed",
      '"-p", str(port)' in ENS)

print("\n5. reuse before rebuild, and the reaper still owns cleanup")
check("a container already up is reused",
      '"ps", "-q", "--filter"' in ENS and "running" in ENS)
check("...keyed on the SAME label the reaper sweeps",
      'f"hextech_job={job_id}"' in ENS and 'f"hextech_job={job_id}"' in COM)
check("...and named the way the prompt prescribes", 'f"chal_{job_id}"' in ENS)
check("a build cannot hang the run forever", "CHAL_BUILD_TIMEOUT_S" in COM)
check("a freshly built service is waited for, not assumed",
      "CHAL_READY_TIMEOUT_S" in COM and "create_connection" in ENS)

print("\n6. the runner hands the address over")
check("the runner ensures a target before it runs anything",
      "ensure_chal_container as _ensure_chal" in RUN)
check("...for the network THIS sandbox will join",
      "_ensure_chal(job_id, network=network" in RUN)
check("...and injects it", all(k in RUN for k in ("CHAL_HOST", "CHAL_PORT", "CHAL_ADDR")))
_inj = RUN.split("_ensure_chal(", 1)[1][:900] if "_ensure_chal(" in RUN else ""
check("...only when there is something to inject",
      '_chal.get("host")' in _inj and '_chal.get("port")' in _inj)
check("...and a failure here never takes the run down with it",
      "except Exception:" in _inj and "_chal = {}" in _inj)

print("\n7. the agent is told not to hardcode what it computed")
check("the prompt says so", "DO NOT HARDCODE THAT ADDRESS" in COM)
check("...and names the variables the runner actually sets",
      "CHAL_HOST" in COM and "CHAL_PORT" in COM)
check("...explaining that the sandbox is a different network",
      "DIFFERENT network" in COM)

print("\n8. the images a job built die with the job")
# They did not. Two label conventions live on this box -- the orchestrator's
# `hextech_ctf_tool_job_id` and the `hextech_job` the PROMPT teaches the agent
# -- and the image sweep only knew the first. Measured 2026-09-21: 17 `chal_*`
# images from long-finished jobs, both reapers working exactly as written.
_SIB = COM.split("def reap_job_siblings(", 1)[1].split("\ndef ", 1)[0]
check("the sweep knows the orchestrator's label", "_JOB_LABEL" in _SIB)
check("...AND the label the prompt teaches the agent",
      'f"hextech_job={job_id}"' in _SIB)
check("...AND an unlabelled build, by the job id in its repository name",
      'job_id in str(t).split(":", 1)[0]' in _SIB)
check("...deduped, so one image is not removed three times", "_found[img.id]" in _SIB)
# force=False is what stops a finished job deleting a RUNNING one's base
# image: labels are inherited, so a child image carries the parent's job id.
# Narrow to the IMAGE call: containers are force-removed on purpose, so a
# blanket "no force=True anywhere" reads the wrong statement.
check("image removal is still refusable, never forced",
      "client.images.remove(image=img.id, force=False" in _SIB)
# Scoped to the BUILD call. `"--label", label` also appears in the `docker
# run` a few lines down, so searching the whole function passed happily with
# the build label deleted -- the right words in the wrong statement.
_bld = ENS.split('_chal_docker(["build"', 1)[1][:400] if '_chal_docker(["build"' in ENS else ""
check("what WE build carries both keys so either sweep finds it",
      '"--label", label,' in _bld
      and '"--label", f"hextech_ctf_tool_job_id={job_id}"' in _bld)
check("...and the agent is told to do the same for its own builds",
      "LABEL WHAT YOU BUILD" in COM and "hextech_ctf_tool_job_id=$JOB_ID" in COM)
_RAT = COM.split("def _reap_after_terminal(", 1)[1].split("\ndef ", 1)[0]
# The CONDITION, not the loop below it: the loop still names every kind even
# when the guard above it has been narrowed back to containers and networks.
check("the sweep reports images and volumes, not just containers",
      'for k in ("containers", "networks", "images", "volumes")' in _RAT)
check("...and fires on exactly the terminal statuses",
      '_TERMINAL_STATUSES = {"finished", "failed", "no_flag", "stopped", FLAG_READY}' in COM)

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
