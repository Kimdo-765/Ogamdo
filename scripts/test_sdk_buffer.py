#!/usr/bin/env python3
"""A photograph must not be able to kill a session.

WHY THIS EXISTS

Job a6d33960680b was an OSINT challenge: the whole task is to LOOK at a
picture. The agent did the careful thing — downscaled a 3,305,640-byte PNG to
a 630,721-byte JPEG — and `Read` on that JPEG produced an SDK message over
1,048,576 bytes. `SDKJSONDecodeError` is not a tool error the agent can see
and retry; it comes out of `receive_messages()` and ends the session. Three
turns in, the job was `failed`.

The image was never too big for the model: 1556x1061 is inside the API's own
limit and costs ~2,200 tokens to view. Only the transport refused it.

WHAT THIS SUITE PROTECTS

  * EVERY session, not the one that happened to break. Bash output is
    truncated by the CLI before it reaches the buffer, which is why 3,900
    tool calls across pwn/rev/web never met this wall — `Read` on an image
    is the path that does, and misc/forensic are not the only modules that
    can take one.
  * A NEW CONSTRUCTION SITE MUST NOT SILENTLY OMIT IT. There are fourteen,
    spread over ten files. The failure mode of a scattered constant is that
    the fifteenth is written without it and nothing complains until a job
    dies, so this walks the source rather than trusting a grep done once.
  * THE CEILING CLEARS THE MEASURED CASE. 1 MB did not. A number that only
    just clears 630,721 bytes would not survive the next, slightly larger
    photograph either.

Run from the repository root::

    python3 scripts/test_sdk_buffer.py
    python3 scripts/test_sdk_buffer.py --mutate one-site-left-behind
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("one-site-left-behind", "ceiling-back-to-default",
             "ceiling-just-above-the-jpeg")
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


# ---- the measured facts this ceiling answers to -------------------------
SDK_DEFAULT = 1024 * 1024          # claude_agent_sdk subprocess_cli default
JPEG_THAT_DIED = 630_721           # bytes, job a6d33960680b
OBSERVED_EXPANSION = 1.66          # >1MB message from that file; >= this

from modules._sdk_buffer import AGENT_MAX_BUFFER_BYTES as CEIL  # noqa: E402

if args.mutate == "ceiling-back-to-default":
    CEIL = SDK_DEFAULT
elif args.mutate == "ceiling-just-above-the-jpeg":
    CEIL = JPEG_THAT_DIED + 1

print("\n1. the ceiling clears the case that actually died")
check("it is above the SDK default that failed", CEIL > SDK_DEFAULT, True)
check("...and above the message that 630,721 bytes produced",
      CEIL > JPEG_THAT_DIED * OBSERVED_EXPANSION, True)
# A ceiling that only just clears one photograph is not a ceiling. Require
# room for an artifact several times larger at the SAME measured expansion.
check("...with room for a ~2 MB artifact at the measured expansion",
      CEIL >= 2 * 1024 * 1024 * OBSERVED_EXPANSION, True)
check("it is still bounded — a runaway must not be unlimited",
      CEIL <= 64 * 1024 * 1024, True)

print("\n2. every construction site passes it")
OPEN = re.compile(r"ClaudeAgentOptions\(\s*$")
sites, missing = 0, []
for path in sorted((ROOT / "modules").rglob("*.py")):
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(lines):
        if not OPEN.search(ln):
            continue
        sites += 1
        window = "\n".join(lines[i + 1:i + 12])
        if args.mutate == "one-site-left-behind" and path.name == "_monitor.py":
            window = window.replace("max_buffer_size=AGENT_MAX_BUFFER_BYTES,", "")
        if "max_buffer_size=" not in window:
            missing.append(f"{path.relative_to(ROOT)}:{i + 1}")
check("the sites were found at all (a zero here means the scan broke)",
      sites >= 10, True)
check("none of them omits the ceiling", missing, [])

print("\n3. the value lives in one place")
hard = []
for path in sorted((ROOT / "modules").rglob("*.py")):
    if path.name == "_sdk_buffer.py":
        continue
    for i, ln in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if re.search(r"max_buffer_size\s*=\s*\d", ln):
            hard.append(f"{path.relative_to(ROOT)}:{i + 1}")
check("no site hard-codes a number beside the shared constant", hard, [])

print("\n4. the SDK really takes this argument")
try:
    import dataclasses
    from claude_agent_sdk import ClaudeAgentOptions
    names = {f.name for f in dataclasses.fields(ClaudeAgentOptions)}
    check("ClaudeAgentOptions exposes max_buffer_size",
          "max_buffer_size" in names, True)
except ImportError:
    # The SDK is installed in the worker image, not on the host. Skipping is
    # honest; claiming a pass that never ran is not.
    print("  skip the SDK is not importable here (worker-only dependency)")

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
