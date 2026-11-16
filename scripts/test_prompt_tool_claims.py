#!/usr/bin/env python3
"""A prompt that names a tool the image does not have costs a turn, twice.

WHY THIS EXISTS

`modules/misc/prompts.py` told the agent that the heavy stego tools "ARE in
the sibling misc image" and listed `stegseek` among them. It is not there —
not on PATH, not on disk, no package record — while every other name on that
line is. An agent reading that spends a call discovering it, and the honest
alternative (`steghide` with a wordlist) is the one it did not reach for.

The same list is written twice: once in the prompt the agent reads and once
in `worker/misc_recarve.py`, the module that actually runs them. Two copies
of a fact drift, so the first thing this pins is that they agree.

WHAT IT DOES NOT CLAIM

Absence from this list is not absence from the platform. Tools run in three
different images — worker, misc, forensic — and checking the wrong one is how
`zsteg` got reported missing when it was installed all along. When docker is
reachable this suite asks the MISC image itself; when it is not, it says so
and checks nothing rather than guessing.

Run from the repository root::

    python3 scripts/test_prompt_tool_claims.py
    python3 scripts/test_prompt_tool_claims.py --mutate name-a-tool-that-is-absent
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MISC_IMAGE = "hextech_ctf_tool-misc"
MUTATIONS = ("name-a-tool-that-is-absent", "let-the-two-lists-drift")

ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


def tools_in(path: Path, marker: str) -> list[str]:
    """The slash-separated tool names on the line carrying `marker`, and the
    continuation lines under it."""
    text = path.read_text(encoding="utf-8")
    i = text.find(marker)
    assert i >= 0, f"{path}: marker not found -- did the wording change?"
    chunk = text[i:i + 400]
    chunk = chunk[:chunk.find(")")] if ")" in chunk else chunk
    # (?<![A-Za-z]) or "The" hands back "he" and the diff is a parsing bug
    # dressed up as a drift report.
    return [w for w in re.findall(r"(?<![A-Za-z])[a-z0-9][a-z0-9_.+-]*", chunk)
            if w not in ("misc", "extraction", "tools", "the", "image", "in",
                         "are", "not", "your", "container", "but", "sibling")]


prompt_tools = tools_in(ROOT / "modules" / "misc" / "prompts.py",
                        "(zsteg / steghide / binwalk")
runner_tools = tools_in(ROOT / "worker" / "misc_recarve.py",
                        "The misc extraction tools (zsteg")

if args.mutate == "name-a-tool-that-is-absent":
    prompt_tools = prompt_tools + ["stegseek"]
    runner_tools = runner_tools + ["stegseek"]
elif args.mutate == "let-the-two-lists-drift":
    # The guard is one-way, so the mutation has to push the way it guards:
    # the illustrative list gaining a name the authoritative one lacks.
    runner_tools = runner_tools + ["stegseek"]

print("\n1. the two lists do not contradict each other")
# They are not the same list and were never meant to be: the prompt enumerates,
# the module docstring illustrates and ends in an ellipsis. The invariant that
# matters is one-way -- the illustrative list must not name something the
# authoritative one does not.
check("the prompt list was parsed at all", len(prompt_tools) >= 4, True)
check("the module names nothing the prompt omits",
      sorted(set(runner_tools) - set(prompt_tools)), [])

print("\n2. every named tool is in the image it is promised in")
# /snap/bin/docker FIRST: `docker` on PATH here is a Docker Desktop shim that
# cannot see these images, and trusting it turns a real check into a skip.
docker = next((c for c in ("/snap/bin/docker", shutil.which("docker"))
               if c and Path(c).exists()), None)
have_docker = docker is not None
image_ok = False
if have_docker:
    probe = subprocess.run(
        [docker, "image", "inspect", MISC_IMAGE],
        capture_output=True, text=True)
    image_ok = probe.returncode == 0
if not image_ok:
    # Saying "skipped" is the honest outcome. A pass here would assert that
    # tools exist in an image this run never opened.
    print(f"  skip {MISC_IMAGE} not reachable from here — nothing verified")
else:
    names = sorted(set(prompt_tools))
    out = subprocess.run(
        [docker, "run", "--rm", "--entrypoint", "sh", MISC_IMAGE, "-lc",
         "for t in " + " ".join(names) + "; do "
         "command -v \"$t\" >/dev/null 2>&1 || echo MISSING:$t; done"],
        capture_output=True, text=True, timeout=180)
    missing = sorted(l.split(":", 1)[1] for l in out.stdout.splitlines()
                     if l.startswith("MISSING:"))
    check(f"none of {len(names)} promised tools is missing from the image",
          missing, [])

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
