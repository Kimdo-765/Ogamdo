#!/usr/bin/env python3
"""Do not advertise a toolset that only wastes the model's time.

WHAT WAS MEASURED

`spawn_agent` is not registered in this deployment — established outside the
platform on two models. `wait` IS registered, and it returns
{"receiver_thread_ids": [], "agents_states": {}} every single time. Across
three jobs' event streams:

    549fcc1195ff   27 wait events,  9 empty rosters
    e1d465aad6f5    9 wait events,  3 empty rosters
    d18ff191928a   60 wait events, 20 empty rosters

Every empty roster is main sleeping on a roster that cannot fill; job
d18ff191928a spent 497 s that way and never delegated once.

Probed on codex-cli 0.152.1 with the same prompt, twice:

    with    features.multi_agent_v2=true  -> the model answers "DONE",
                                             i.e. it believes it called wait
    without the flag                      -> the model answers "NO_WAIT_TOOL"

The `agents.*` overlays this block also registers serve Codex's OWN
spawn_agent children. Delegate children here take their model from `--model`
(run_pre_recon -> resolve_role_model), so withdrawing the advertisement costs
the file channel nothing.

Run:
    python3 scripts/test_multi_agent_v2_optional.py
    python3 scripts/test_multi_agent_v2_optional.py --mutate always-advertises
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CODEX = ROOT / "modules" / "codex_cli.py"
SETTINGS = ROOT / "modules" / "settings_io.py"
COMMON = ROOT / "modules" / "_common.py"
X = CODEX.read_text()
S = SETTINGS.read_text()
C = COMMON.read_text()

MUTATIONS = ("always-advertises", "default-off", "fails-closed",
             "ignores-enable-subagents", "child-loses-its-model")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_X0, _S0, _C0 = X, S, C

if args.mutate == "always-advertises":
    # The conjunction moved into `_native_subagents_enabled`; this drops its
    # policy half, which is what the old one-line anchor used to express.
    X = X.replace("            return codex_multi_agent_v2_enabled()",
                  "            return True", 1)
elif args.mutate == "default-off":
    S = S.replace('("codex_multi_agent_v2", "CODEX_MULTI_AGENT_V2", bool, True)',
                  '("codex_multi_agent_v2", "CODEX_MULTI_AGENT_V2", bool, False)', 1)
elif args.mutate == "fails-closed":
    # An unreadable policy must not silently change what main is told it has.
    X = X.replace("        except Exception:\n"
                  "            return True          # unreadable policy keeps today's behaviour",
                  "        except Exception:\n            return False", 1)
elif args.mutate == "ignores-enable-subagents":
    # ...and this drops its child half.
    X = X.replace("        if not self.options.enable_subagents:\n"
                  "            return False\n", "", 1)
elif args.mutate == "child-loses-its-model":
    C = C.replace("        gpt_model = resolve_role_model(role, gpt_model, \"gpt\")",
                  "        pass", 1)

if args.mutate and (X, S, C) == (_X0, _S0, _C0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} DID NOT APPLY — its anchor is gone. "
        "Fix the anchor; do not delete the mutation."
    )

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got={got!r}\n        want={want!r}")


def _setting_checks() -> None:
    check("S1 the advertisement is an operator setting",
          '("codex_multi_agent_v2", "CODEX_MULTI_AGENT_V2", bool, True)' in S, True)
    check("S1 ...defaulting ON, so an upgrade changes nobody's tool surface",
          "bool, True)" in S.split('"CODEX_MULTI_AGENT_V2"')[1][:30], True)
    check("S2 ...with a reader that is not captured at import",
          "def codex_multi_agent_v2_enabled()" in S, True)

    import modules.settings_io as sio
    real = sio.get_setting
    try:
        sio.get_setting = lambda k: (_ for _ in ()).throw(RuntimeError("x"))
        check("S3 an unreadable policy keeps advertising",
              sio.codex_multi_agent_v2_enabled(), True)
        sio.get_setting = lambda k: None
        check("S3 ...and so does a key nobody set",
              sio.codex_multi_agent_v2_enabled(), True)
    finally:
        sio.get_setting = real


def _gate_checks() -> None:
    cmd = next((ast.get_source_segment(X, n) for n in ast.walk(ast.parse(X))
                if isinstance(n, ast.FunctionDef) and n.name == "_command"), "")
    # UPDATED for bd33eb9. These used to pin the setting read INLINE in
    # `_command` (`_mav2 = codex_multi_agent_v2_enabled()`, then
    # `if self.options.enable_subagents and _mav2:`). That inline copy was the
    # bug: `_instructions` decided the addendum on a DIFFERENT predicate
    # (effort == "ultra" alone), so with the shipped config — gpt_effort ultra,
    # codex_multi_agent_v2 False — the prompt advertised native mode while the
    # CLI registered none of it. One fact, read in two places, is what this
    # file now pins against.
    helper = next((ast.get_source_segment(X, n) for n in ast.walk(ast.parse(X))
                   if isinstance(n, ast.FunctionDef)
                   and n.name == "_native_subagents_enabled"), "")
    check("G1 the setting is read in exactly one place",
          X.count("codex_multi_agent_v2_enabled()"), 1)
    check("G1 ...and that place is the shared predicate",
          "codex_multi_agent_v2_enabled()" in helper, True)
    check("G2 the multi-agent block is gated on that predicate",
          "if self._native_subagents_enabled():" in cmd, True)
    # A child never had this block; keep it that way. The check moved INTO the
    # predicate, so assert it there rather than at the call site.
    check("G2 ...so a child (enable_subagents=False) still gets none of it",
          "if not self.options.enable_subagents:" in helper
          and "return False" in helper, True)
    # ast.get_source_segment() ends at the last node, so a trailing same-line
    # comment is cut from `helper`. Assert the fallback in the segment and its
    # rationale against the module text.
    check("G3 an unreadable policy keeps today's behaviour",
          "except Exception:" in helper and "return True" in helper
          and "unreadable policy keeps today's behaviour" in X, True)
    # What the block registers, and therefore what is withdrawn together.
    for flag in ("features.multi_agent_v2", "multi_agent_v2.tool_namespace",
                 "agents.{role}.config_file", "agents.", "config_file"):
        if flag in ("agents.", "config_file"):
            check(f"G4 the block still registers {flag}", flag in cmd, True)


def _child_is_unaffected() -> None:
    """The overlays serve spawn_agent. A delegate child's model comes from
    `--model`, so withdrawing them must not silently unmodel the children."""
    fn = next((ast.get_source_segment(C, n) for n in ast.walk(ast.parse(C))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == "run_pre_recon"), "")
    check("D1 a delegate child resolves its own model",
          "resolve_role_model(role, gpt_model" in fn, True)
    check("D1 ...and passes it as the session model",
          "model=gpt_model," in fn, True)
    check("D2 ...with subagents off, so it never sees the block at all",
          "enable_subagents=False," in fn, True)


def main() -> int:
    _setting_checks()
    _gate_checks()
    _child_is_unaffected()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
