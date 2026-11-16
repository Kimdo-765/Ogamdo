#!/usr/bin/env python3
"""A stored callback URL that never reaches the agent is worse than none.

WHY THIS EXISTS

Job 48fadce3dde7 (web, XSS bot) ran 4h22m and 1,499 turns, logged 835
`ConnectionRefusedError`, and never captured the flag. Nothing was broken:

    callback_url setting : ' https://…trycloudflare.com'   (stored, live)
    tunnel probe         : HTTP 200                        (answering)
    worker os.environ    : CALLBACK_URL was set            (after apply_to_env)
    agent's actual usage : https://collector.invalid   x48
                           http://172.18.0.1:32881     x31  (closed)

The address existed, worked, and was already in the agent's environment. The
agent invented `collector.invalid` — a reserved TLD that can never resolve —
because NOTHING TOLD IT the variable existed. `modules/_prompts.py` contained
no mention of a collector, a callback, or a tunnel.

Two defects, both guarded here:

1. THE PROMPT NEVER NAMED IT. A setting whose only reference in the entire
   repo is its own SCHEMA declaration is not a feature, it is a stored string.
   grep for `callback_url` found exactly one line: settings_io.py:190.

2. THE VALUE CARRIED A LEADING SPACE. `' https://…'` — invisible in the UI,
   fatal to `curl "$CALLBACK_URL"`. String settings arrive from form fields
   and pastes, so the fix is at the coercion, not at one accessor.

Run:
    python3 scripts/test_callback_reaches_agent.py
    python3 scripts/test_callback_reaches_agent.py --mutate no-strip
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SETTINGS = ROOT / "modules" / "settings_io.py"
PROMPTS = ROOT / "modules" / "_prompts.py"
CODEX = ROOT / "modules" / "codex_cli.py"

S = SETTINGS.read_text()
P = PROMPTS.read_text()
C = CODEX.read_text()

MUTATIONS = (
    "no-strip",           # a pasted leading space survives into $CALLBACK_URL
    "prompt-silent",      # the agent is never told the variable exists
    "no-collector-path",  # the base URL is named but not what to append
    "no-readback",        # an iterative oracle cannot see which beacon fired
    "recon-only",         # the section sits in a prompt main never receives
    "env-not-inherited",  # the subprocess stops inheriting os.environ
    "no-invented-host-warning",  # nothing stops the agent guessing a host again
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_S0, _P0, _C0 = S, P, C

if args.mutate == "no-strip":
    S = S.replace("        return str(value).strip()", "        return str(value)", 1)
elif args.mutate == "prompt-silent":
    i = P.index("OUT-OF-BAND CALLBACK (XSS / SSRF / blind injection)")
    j = P.index("Tool catalogue & invocation patterns")
    P = P[:i] + P[j:]
elif args.mutate == "no-collector-path":
    P = P.replace('BEACON="$CALLBACK_URL/api/collector/$JOB_ID"',
                  'BEACON="$CALLBACK_URL"', 1)
elif args.mutate == "recon-only":
    # The first fix put the section in RECON_AGENT_PROMPT. Every substring
    # check passed and the agent that writes the exploit never saw a word of
    # it — "the file contains the text" is not "the agent is told".
    i = P.index("OUT-OF-BAND CALLBACK")
    j = P.index("Tool catalogue & invocation patterns", i)
    blk = P[i:j]
    P = P[:i] + P[j:]
    P = P.replace("RECON_AGENT_PROMPT = \"\"\"\\\n", "RECON_AGENT_PROMPT = \"\"\"\\\n" + blk, 1)
elif args.mutate == "no-readback":
    P = P.replace('  curl -s "$CALLBACK_URL/api/collector/$JOB_ID/_hits?since=0"\n', "", 1)
elif args.mutate == "env-not-inherited":
    C = C.replace("        env = {k: str(v) for k, v in os.environ.items()}",
                  "        env = {}", 1)
elif args.mutate == "no-invented-host-warning":
    P = P.replace("  DO NOT invent a callback host.", "  Feel free to improvise a host.", 1)

if args.mutate and (S, P, C) == (_S0, _P0, _C0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor no longer matches."
    )

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


def _coerce_from(src: str):
    """Exec the MUTATED _coerce. Importing settings_io would load the real one."""
    i = src.index("def _coerce(")
    j = src.index("\ndef ", i + 1)
    ns: dict = {"Any": object}
    exec(src[i:j], ns)
    return ns["_coerce"]


def _strip_checks():
    print("\nS — the value must survive a paste")
    coerce = _coerce_from(S)
    # The exact stored value that would have broken the first real use.
    check("S1 a leading space is removed",
          coerce(" https://example-tunnel-name.trycloudflare.com", str),
          "https://example-tunnel-name.trycloudflare.com")
    check("S2 a trailing newline too", coerce("https://x.example\n", str), "https://x.example")
    check("S3 an already-clean value is untouched",
          coerce("https://x.example", str), "https://x.example")
    check("S4 an empty setting stays empty", coerce("   ", str), "")
    # Stripping lives at the coercion so it covers every string setting and
    # both directions, not one accessor someone remembered to call.
    check("S5 the fix is at the coercion, not a per-key accessor",
          "if typ is str:" in S and "return str(value).strip()" in S)


def _prompt_checks():
    print("\nP — the agent has to be TOLD")
    check("P1 the prompt names the variable", "$CALLBACK_URL" in P)
    # Anchor on the BEACON assignment, not on the bare path: the same path
    # also appears in the read-back curl below, so a check for the substring
    # alone stayed green with the beacon pointing at the bare base URL.
    check("P2 the beacon the payload targets carries the collector path",
          'BEACON="$CALLBACK_URL/api/collector/$JOB_ID"' in P)
    check("P3 ...and how to read back what arrived",
          "_hits?since=" in P)
    check("P4 ...and tells it to confirm the value first",
          'echo "$CALLBACK_URL"' in P)
    # The specific failure, named, so the instruction carries its evidence.
    check("P5 it forbids inventing a host", "DO NOT invent a callback host" in P)
    check("P6 ...citing the job that proved why", "48fadce3dde7" in P)
    check("P7 ...and the placeholder that was actually used", "collector.invalid" in P)
    # Whitespace-insensitive: prompt prose is hard-wrapped, so a literal
    # substring check fails on a phrase that happens to straddle a line break
    # — which is a property of the formatter, not of the instruction.
    flat = re.sub(r"\s+", " ", P)
    check("P8 an empty CALLBACK_URL is an explicit dead end, not a prompt to guess",
          "treat OOB as unavailable" in flat)
    check("P8 ...and guessing is ruled out in the same breath",
          "do not substitute a guess" in flat)


def _reaches_main_checks():
    """The section must live where the MAIN agent reads it.

    First attempt put it in RECON_AGENT_PROMPT — the read-only triage
    subagent. Every text check in this suite passed while the agent that
    actually writes exploit.py was never told the variable existed, which is
    the precise defect the whole file is about, reproduced by its own fix.
    Assert the real objects the modules import, not the file's bytes.
    """
    print("\nM — it must reach the agent that writes the exploit")
    # Build the constants from the MUTATED source, not by importing the real
    # module — an import would ignore every mutation above and these checks
    # would pass no matter what the suite did to the prompts.
    ns: dict = {}
    try:
        exec(compile(P, str(PROMPTS), "exec"), ns)
    except Exception as e:
        check(f"M0 the mutated prompt module still loads ({type(e).__name__})", False)
        return
    for name in ("TOOLS_WEB", "TOOLS_PWN", "TOOLS_REV", "TOOLS_CRYPTO",
                 "TOOLS_FORENSIC", "TOOLS_MISC"):
        t = ns.get(name, "")
        check(f"M1 {name} carries the callback section", "$CALLBACK_URL" in t)
        check(f"M1 ...with the beacon path", "/api/collector/$JOB_ID" in t)
    # Recon is read-only triage; it does not fire payloads, and putting the
    # section only there is exactly how this was got wrong.
    check("M2 it is NOT only in the recon prompt",
          "$CALLBACK_URL" in ns.get("RECON_AGENT_PROMPT", ""), False)


def _delivery_checks():
    print("\nD — the value actually reaches the agent's shell")
    # apply_to_env pushes every SCHEMA row with an env_key into os.environ,
    # and the agent subprocess starts FROM os.environ. Both halves must hold;
    # either one alone leaves the variable unset where it matters.
    check("D1 callback_url is declared with an env name",
          '("callback_url", "CALLBACK_URL", str, "")' in S)
    check("D2 apply_to_env pushes SCHEMA rows that have one",
          "for key, env_key, typ, _ in SCHEMA:" in S and "if not env_key:" in S)
    check("D3 the agent subprocess inherits os.environ",
          "env = {k: str(v) for k, v in os.environ.items()}" in C)
    # Explicit per-session env must ADD to that inheritance, never replace it.
    m = re.search(r"def _environment\(self\).*?return env", C, re.S)
    body = m.group(0) if m else ""
    check("D4 ...and per-session env updates rather than replaces",
          "env.update(" in body)


def main() -> int:
    _strip_checks()
    _prompt_checks()
    _reaches_main_checks()
    _delivery_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
