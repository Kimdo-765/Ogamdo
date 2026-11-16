#!/usr/bin/env python3
"""Solve-derived prompt text stays on this machine; the tree carries a generic version.

Run: python3 scripts/test_private_prompt_overlay.py [--mutate <name>]

WHY THIS EXISTS (2026-11-15)

Some prompt text was distilled from the operator's own solves: the JS-engine
block's stage notes, the recon triage example, and a dozen shorter spans in
the pwn, web and live-fire prompts. Solve material must never reach a remote, and this repository has one,
so that text moved to `data/private-prompts/<slot>.md` (`data/` is untracked
and bind-mounted at /data). Each call site keeps a generic fallback:

    private_prompt("<slot>") or "<generic text>"

so a deployment that has the files renders exactly what it rendered before,
and one without them renders the fallback.

The failure this file is for is SILENT: a slot whose name is misspelt at the
call site, or whose file is misnamed, just renders the fallback, and every
prompt still looks fine. So the slot list below is written out by hand, and
each slot is checked from both sides. This file holds no private text; it
writes its own synthetic slot files into a temporary directory.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

# slot -> the module whose prompt renders it
SLOTS = {
    "js_engine_stage_notes": "modules/_common.py",
    "js_engine_stage_map": "modules/_common.py",
    "js_engine_runner_note": "modules/_common.py",
    "pwn_env_knob_example": "modules/pwn/analyzer.py",
    "pwn_env_knob_claims": "modules/pwn/analyzer.py",
    "pwn_int_wrap_trace": "modules/pwn/analyzer.py",
    "pwn_mmap_threshold_note": "modules/pwn/analyzer.py",
    "pwn_wrapper_traps": "modules/pwn/analyzer.py",
    "pwn_recon_gadget_hunt": "modules/pwn/prompts.py",
    "pwn_recon_arch_recipes": "modules/pwn/prompts.py",
    "recon_triage_example": "modules/_prompts.py",
    "recon_logic_examples": "modules/_prompts.py",
    "web_fw_validation_focus": "modules/web/analyzer.py",
    "web_exfil_typing_limit": "modules/web/analyzer.py",
    "web_callback_filter_note": "modules/web/prompts.py",
    "web_logic_examples": "modules/web/prompts.py",
    "live_fire_config_note_1": "modules/live_fire_orchestrator.py",
    "live_fire_config_note_2": "modules/live_fire_orchestrator.py",
}

MUTATIONS = (
    "none",
    "ignore-private",     # always use the generic notes, as if the file were never read
    "no-fallback",        # render no stage notes at all when the file is absent
    "wrong-default-dir",  # look for the private file somewhere it is never put
    "slot-typo",          # one call site asks for a slot name no file has
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True) -> None:
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}")


def _mutate(src: str, anchor: str, replacement: str) -> str:
    if anchor not in src:
        print(f"MUTATION DID NOT APPLY: {anchor!r}")
        sys.exit(2)
    return src.replace(anchor, replacement, 1)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def marker(slot: str) -> str:
    return f"<<SYNTHETIC SLOT {slot}>>"


TMP = pathlib.Path(tempfile.mkdtemp(prefix="private-prompt-"))
SYNTH_DIR = TMP / "synthetic"
SYNTH_DIR.mkdir()
for _slot in SLOTS:
    (SYNTH_DIR / f"{_slot}.md").write_text(marker(_slot))
EMPTY_DIR = TMP / "empty"
EMPTY_DIR.mkdir()

# ---- the loader, run against a temporary DATA_DIR ----------------------------
loader_src = _read("modules/private_prompts.py")
if args.mutate == "wrong-default-dir":
    loader_src = _mutate(loader_src, 'DATA_DIR / "private-prompts"', 'DATA_DIR / "private_prompts"')
loader_ns = {"os": os, "Path": pathlib.Path, "DATA_DIR": TMP}
_loader_def = [n for n in ast.parse(loader_src).body
               if isinstance(n, ast.FunctionDef) and n.name == "private_prompt"]
exec(compile(ast.Module(body=_loader_def, type_ignores=[]), "modules/private_prompts.py", "exec"), loader_ns)
private_prompt = loader_ns["private_prompt"]


def use(directory: pathlib.Path | None) -> None:
    if directory is None:
        os.environ.pop("HEXTECH_PRIVATE_PROMPTS", None)
    else:
        os.environ["HEXTECH_PRIVATE_PROMPTS"] = str(directory)


# ---- the JS-engine block ------------------------------------------------------
src = _read("modules/_common.py")
if args.mutate == "ignore-private":
    src = _mutate(src, '_private_prompt("js_engine_stage_notes")', '""')
elif args.mutate == "no-fallback":
    src = _mutate(src, "or _JS_ENGINE_STAGE_NOTES_GENERIC)", 'or "")')

JOBS = TMP / "jobs"
NAMES = {"_JS_ENGINE_ANCHORS", "_JS_ENGINE_SHELLS", "_JS_ENGINE_STAGE_NOTES_GENERIC", "js_engine_block"}
nodes = [n for n in ast.parse(src).body
         if (isinstance(n, ast.FunctionDef) and n.name in NAMES)
         or (isinstance(n, ast.Assign) and any(getattr(t, "id", "") in NAMES for t in n.targets))]
ns = {"os": os, "Path": pathlib.Path, "JOBS_DIR": JOBS, "DATA_DIR": TMP, "_private_prompt": private_prompt}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "modules/_common.py", "exec"), ns)
block = ns["js_engine_block"]
GENERIC = ns["_JS_ENGINE_STAGE_NOTES_GENERIC"]

# A job whose bundle ships a prebuilt engine: the anchor file beside an executable.
ENGINE_JOB = "e" * 12
bin_dir = JOBS / ENGINE_JOB / "work" / "bin"
bin_dir.mkdir(parents=True)
(bin_dir / "snapshot_blob.bin").write_bytes(b"\0")
(bin_dir / "d8").write_bytes(b"\x7fELF")
(bin_dir / "d8").chmod(0o755)
PLAIN_JOB = "f" * 12
(JOBS / PLAIN_JOB / "bin").mkdir(parents=True)

SYNTH = "SYNTHETIC STAGE NOTES (test only)\n"
PRIVATE = TMP / "private"
PRIVATE.mkdir()
EMPTY = TMP / "empty-private"
EMPTY.mkdir()


def render(private_dir: pathlib.Path | None, job: str = ENGINE_JOB) -> str:
    use(private_dir)
    return block(job)


print("--- with a private file, its text is the stage notes " + "-" * 6)
(PRIVATE / "js_engine_stage_notes.md").write_text(SYNTH)
out = render(PRIVATE)
check("the private text is rendered", SYNTH in out)
check("...instead of the generic notes, not beside them", GENERIC in out, False)
check("...in the stage-notes slot: after the stage map, before the offsets rule",
      0 < out.find("  5. RCE") < out.find(SYNTH) < out.find("DERIVE THE OFFSETS"), True)

for _slot in ("js_engine_stage_map", "js_engine_runner_note"):
    (PRIVATE / f"{_slot}.md").write_text(marker(_slot))
out = render(PRIVATE)
check("the stage-map and runner slots render inside the block too",
      marker("js_engine_stage_map") in out and marker("js_engine_runner_note") in out, True)
check("...the stage-map slot between stage 2 and the stage notes",
      0 < out.find("  2. PRIMITIVE") < out.find(marker("js_engine_stage_map")) < out.find(SYNTH), True)
for _slot in ("js_engine_stage_map", "js_engine_runner_note"):
    (PRIVATE / f"{_slot}.md").unlink()

print("")
print("--- without one, the generic notes and the stage map remain " + "-" * 0)
out = render(EMPTY)
check("the generic notes are rendered", GENERIC in out)
check("...and the five-stage map with them", "STAGE MAP" in out and "  5. RCE" in out)
check("...in the same slot",
      0 < out.find("  5. RCE") < out.find(GENERIC) < out.find("DERIVE THE OFFSETS"), True)
out_default = render(None)
check("with no override and nothing at the default location, the generic notes are used",
      GENERIC in out_default, True)

print("")
print("--- production reads DATA_DIR/private-prompts " + "-" * 13)
# The deployment sets no override: the worker finds the file under /data. This
# is the path that has to work, and a wrong directory name would fall back to
# the generic notes without a word.
DEFAULT_TEXT = "SYNTHETIC NOTES AT THE DEFAULT LOCATION (test only)\n"
(TMP / "private-prompts").mkdir()
(TMP / "private-prompts" / "js_engine_stage_notes.md").write_text(DEFAULT_TEXT)
check("a file at DATA_DIR/private-prompts is used when no override is set",
      DEFAULT_TEXT in render(None), True)
check("...and an override still takes precedence over it", SYNTH in render(PRIVATE), True)
(TMP / "private-prompts" / "js_engine_stage_notes.md").unlink()

print("")
print("--- a file that cannot serve counts as absent " + "-" * 14)
(EMPTY / "js_engine_stage_notes.md").write_text("  \n")
check("an empty private file falls back to the generic notes", GENERIC in render(EMPTY))
(EMPTY / "js_engine_stage_notes.md").write_bytes(b"\xff\xfe\x00bad")
check("an undecodable private file falls back too", GENERIC in render(EMPTY))
(EMPTY / "js_engine_stage_notes.md").unlink()
SPACING = TMP / "spacing"
SPACING.mkdir()
(SPACING / "s.md").write_text(" a\nb ")
use(SPACING)
check("a slot inside a sentence keeps its exact bytes, spacing included",
      private_prompt("s"), " a\nb ")
use(None)

print("")
print("--- no engine, no block " + "-" * 35)
check("a job without an engine gets nothing, private file or not",
      render(PRIVATE, PLAIN_JOB), "")

# ---- every slot, from both sides ---------------------------------------------
print("")
print("--- every call site names a listed slot and has a fallback " + "-" * 1)
SOURCES = {rel: _read(rel) for rel in sorted(set(SLOTS.values()))}
if args.mutate == "slot-typo":
    SOURCES["modules/pwn/analyzer.py"] = _mutate(
        SOURCES["modules/pwn/analyzer.py"], 'private_prompt("pwn_wrapper_traps")',
        'private_prompt("pwn_wrapper_trap")')
found: dict[str, str] = {}
no_fallback: list[str] = []
for path in sorted((ROOT / "modules").rglob("*.py")):
    rel = str(path.relative_to(ROOT))
    text = SOURCES.get(rel) or path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    callers_with_fallback = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and len(node.values) >= 2:
            callers_with_fallback.add(id(node.values[0]))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in ("private_prompt", "_private_prompt")):
            name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            found[str(name)] = rel
            if id(node) not in callers_with_fallback:
                no_fallback.append(f"{rel}:{node.lineno}")
check("the slots the code asks for are exactly the listed ones", sorted(found), sorted(SLOTS))
check("...each in the module the list names",
      {s: found.get(s) for s in SLOTS}, dict(SLOTS))
check("every call site falls back with `or`", no_fallback, [])

print("")
print("--- each slot's text renders where the module puts it " + "-" * 6)
# The analyzers' prompts are built inside functions whose modules import the
# whole agent stack, so the expressions are lifted out and evaluated here.


class _Dummy(str):
    def __getattr__(self, k):
        return _Dummy(f"<{self}.{k}>")

    def __call__(self, *a, **k):
        return _Dummy(f"<{self}()>")

    def __getitem__(self, k):
        return _Dummy(f"<{self}[]>")


def pwn_pre_recon(directory: pathlib.Path) -> str:
    sys.path.insert(0, str(ROOT))
    from modules.pwn.libc_targets import render_fsop_leak_table, render_rce_table
    from modules.pwn.prompts import kernel_launcher_available
    text = SOURCES["modules/pwn/analyzer.py"]
    want_funcs = {"_keyword_hit", "_kernel_challenge_present", "_heap_signals_present",
                  "_build_pre_recon_prompt"}
    want_assign = {"_HEAP_SOURCE_KEYWORDS", "_HEAP_STRONG_KEYWORDS", "_HEAP_BUG_KEYWORDS",
                   "_KERNEL_IMAGE_NAMES", "_IDENT_CHAR"}
    body = [n for n in ast.parse(text).body
            if (isinstance(n, ast.FunctionDef) and n.name in want_funcs)
            or (isinstance(n, ast.Assign) and any(getattr(t, "id", "") in want_assign for t in n.targets))]
    pns = {"re": re, "Path": pathlib.Path, "kernel_launcher_available": kernel_launcher_available,
           "render_rce_table": render_rce_table, "render_fsop_leak_table": render_fsop_leak_table,
           "private_prompt": private_prompt}
    exec(compile(ast.Module(body=body, type_ignores=[]), "modules/pwn/analyzer.py", "exec"), pns)
    use(directory)
    try:
        return pns["_build_pre_recon_prompt"](
            binary_name="prob", target="h:1", heap_advanced=True, chal_unpacked=True,
            custom_libs=["libwrap.so"], libc_version="2.35")
    finally:
        use(None)


def web_recon(directory: pathlib.Path) -> str:
    use(directory)
    out = []
    try:
        for node in ast.walk(ast.parse(SOURCES["modules/web/analyzer.py"])):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and getattr(node.targets[0], "id", "") in ("_fw_recon_section", "recon_question")
                    and not (isinstance(node.value, ast.Constant) and node.value.value == "")):
                names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                wns = {n: _Dummy(n) for n in names}
                wns.update(private_prompt=private_prompt, __builtins__=__builtins__)
                out.append(str(eval(compile(ast.Expression(node.value), "web", "eval"), wns)))
    finally:
        use(None)
    return "\n".join(out)


def module_level(directory: pathlib.Path) -> dict:
    # A fresh interpreter: these prompts are module constants, read at import.
    code = ("import json, sys; sys.path.insert(0, sys.argv[1]);"
            "import modules.pwn.prompts as p, modules.web.prompts as w, modules.live_fire_orchestrator as o;"
            "import modules._prompts as r;"
            "print(json.dumps({'modules/pwn/prompts.py': p.SYSTEM_PROMPT,"
            " 'modules/_prompts.py': r.RECON_AGENT_PROMPT,"
            " 'modules/web/prompts.py': w.SYSTEM_PROMPT,"
            " 'modules/live_fire_orchestrator.py': o.CONFIG_SURFACE}))")
    env = dict(os.environ, HEXTECH_PRIVATE_PROMPTS=str(directory))
    r = subprocess.run([sys.executable, "-c", code, str(ROOT)], capture_output=True, text=True,
                       env=env, cwd=str(TMP))
    if r.returncode != 0:
        print(r.stderr[-2000:])
        return {}
    return json.loads(r.stdout)


def rendered(directory: pathlib.Path) -> dict:
    out = module_level(directory)
    out["modules/pwn/analyzer.py"] = pwn_pre_recon(directory)
    out["modules/web/analyzer.py"] = web_recon(directory)
    return out


with_synth = rendered(SYNTH_DIR)
without = rendered(EMPTY_DIR)
for slot, rel in SLOTS.items():
    if rel == "modules/_common.py":
        continue          # covered by the stage-notes checks above
    check(f"{slot}: its text renders in {rel}", marker(slot) in with_synth.get(rel, ""), True)
check("without the files, no slot text renders anywhere",
      [rel for rel, text in without.items() if "<<SYNTHETIC SLOT" in text], [])
check("...and every prompt still renders",
      sorted(rel for rel, text in without.items() if len(text) > 200),
      sorted(set(SLOTS.values()) - {"modules/_common.py"}))

print("")
print("--- this machine: every slot has its file, every file is a slot " + "-" * 0)
# Only where a private directory exists. On a machine without one, the
# fallbacks are what renders, and that is correct.
deployed = [d for d in (ROOT / "data" / "private-prompts", pathlib.Path("/data/private-prompts"))
            if d.is_dir() and any(d.glob("*.md"))]
if not deployed:
    print("SKIP  no private-prompt directory on this machine")
for d in deployed:
    have = sorted(p.stem for p in d.glob("*.md"))
    check(f"{d}: no slot is missing its file", sorted(set(SLOTS) - set(have)), [])
    check(f"{d}: no file is left without a slot", sorted(set(have) - set(SLOTS)), [])

print("")
print("--- the private directory is never tracked " + "-" * 16)
r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q",
                    "data/private-prompts/js_engine_stage_notes.md"])
check("git ignores data/private-prompts/", r.returncode, 0)

print("")
print(f"private-prompt-overlay: {passed} passed, {failed} failed; mutation={args.mutate}")
sys.exit(1 if failed else 0)
