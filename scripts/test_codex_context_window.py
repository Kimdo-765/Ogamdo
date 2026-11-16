#!/usr/bin/env python3
"""Codex context-window settings must reach the children too, not just main.

modules/codex_cli.py starts the Codex CLI with ``--ignore-user-config``, so the
operator's own ~/.codex/config.toml never reaches it: a setting that is not
passed by this adapter does not exist for the run. That makes the adapter the
single source of truth for

    model_context_window            = 1050000
    model_auto_compact_token_limit  = 240000

and it has to state them TWICE, because a spawned child does not inherit the
parent's config. The file already records that lesson in its own words, next
to ``developer_instructions``:

    "Child agents do not automatically receive the main agent's developer
     prompt. Put the same immutable job-language policy in every role overlay
     so native Codex delegation cannot drift."

The same is true of the context window. Setting it only on main's argv looks
correct from the outside — the flag IS on the command line — while every
recon / triage / judge / debugger subagent silently runs on the default
window. On a kernel-pwn job the subagents are the ones reading disassembly and
kernel configs, so they are precisely the processes that need the room.

WHAT THIS SUITE PINS
  * both keys are on main's argv, as TOML integers
  * both keys are in EVERY role overlay this adapter writes
  * the two places agree, and agree with the module constants
  * --ignore-user-config is still passed (else the pinning is pointless
    because a stray user config could override it)

Run from the repository root::

    python3 scripts/test_codex_context_window.py
    python3 scripts/test_codex_context_window.py --mutate main-only
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SRC = (ROOT / "modules" / "codex_cli.py").read_text()

MUTATIONS = ("main-only", "children-only", "quoted-as-string")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

if args.mutate:
    text = SRC
    if args.mutate == "main-only":
        # Drop the role-overlay half: the exact regression this file exists
        # for — main looks configured, every child runs on the default.
        text = text.replace(
            '            f"model_context_window = {CODEX_MODEL_CONTEXT_WINDOW}",\n'
            '            "model_auto_compact_token_limit = "\n'
            '            f"{CODEX_AUTO_COMPACT_TOKEN_LIMIT}",\n', "", 1)
    elif args.mutate == "children-only":
        text = text.replace(
            '        common.extend(\n'
            '            (\n'
            '                "--config",\n'
            '                f"model_context_window={CODEX_MODEL_CONTEXT_WINDOW}",\n'
            '                "--config",\n'
            '                "model_auto_compact_token_limit="\n'
            '                f"{CODEX_AUTO_COMPACT_TOKEN_LIMIT}",\n'
            '            )\n'
            '        )\n', "", 1)
    elif args.mutate == "quoted-as-string":
        # TOML types matter: a quoted integer is a string and Codex would
        # reject it (or worse, take it and mean something else).
        text = text.replace(
            'f"model_context_window={CODEX_MODEL_CONTEXT_WINDOW}"',
            'f\'model_context_window="{CODEX_MODEL_CONTEXT_WINDOW}"\'', 1)
    mod_path = ROOT / "modules" / "codex_cli_mutated_tmp.py"
    mod_path.write_text(text)
    import importlib
    sys.modules.pop("modules.codex_cli", None)
    codex = importlib.import_module("modules.codex_cli_mutated_tmp")
else:
    mod_path = None
    import modules.codex_cli as codex

from modules.gpt_responses import GptSessionOptions  # noqa: E402

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


WINDOW = codex.CODEX_MODEL_CONTEXT_WINDOW
COMPACT = codex.CODEX_AUTO_COMPACT_TOKEN_LIMIT


def _config_values(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]


def main() -> int:
    check("C0 the window is the agreed 1_050_000", WINDOW, 1050000)
    check("C0 the compact limit is the agreed 240_000", COMPACT, 240000)

    with tempfile.TemporaryDirectory() as td:
        opts = GptSessionOptions(system_prompt="x", model="gpt-test",
                                 cwd=td, effort="high", enable_subagents=True)
        client = codex.CodexCLIClient(opts)
        client._codex_bin = "/usr/bin/true"
        argv = client._command(resuming=False)
        cfg = _config_values(argv)

        # MAIN. Bare integers: TOML types are not decorative here.
        check("M1 main's argv sets model_context_window",
              f"model_context_window={WINDOW}" in cfg, True)
        check("M1 main's argv sets model_auto_compact_token_limit",
              f"model_auto_compact_token_limit={COMPACT}" in cfg, True)
        check("M2 ...as TOML integers, not quoted strings",
              [c for c in cfg
               if c.startswith(("model_context_window",
                                "model_auto_compact_token_limit"))
               and '"' in c], [])
        # Pinning is only meaningful while the user's own config is ignored.
        check("M3 --ignore-user-config is still passed",
              "--ignore-user-config" in argv, True)

        # CHILDREN. The half that is easy to forget.
        roles = codex._write_codex_agent_configs(td, "gpt-test", "high", "")
        check("K0 role overlays were written at all", bool(roles), True)
        missing_w = [r for r, p in roles.items()
                     if f"model_context_window = {WINDOW}" not in Path(p).read_text()]
        missing_c = [r for r, p in roles.items()
                     if f"model_auto_compact_token_limit = {COMPACT}"
                     not in Path(p).read_text()]
        check("K1 EVERY role overlay sets model_context_window", missing_w, [])
        check("K1 EVERY role overlay sets model_auto_compact_token_limit",
              missing_c, [])
        # Overlays are TOML files Codex parses; a stray quote makes the value
        # a string and the setting silently wrong.
        bad_type = []
        for r, p in roles.items():
            for line in Path(p).read_text().splitlines():
                if line.startswith(("model_context_window",
                                    "model_auto_compact_token_limit")):
                    if not re.match(r"^\w+ = \d+$", line):
                        bad_type.append(f"{r}: {line}")
        check("K2 ...as bare integers in the overlay TOML", bad_type, [])

    # The two sites must not drift apart into two different numbers.
    check("D1 both sites read the same module constants",
          SRC.count("CODEX_MODEL_CONTEXT_WINDOW") >= 3, True)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


try:
    rc = main()
finally:
    if mod_path is not None:
        mod_path.unlink(missing_ok=True)
raise SystemExit(rc)
