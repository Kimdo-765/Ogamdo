#!/usr/bin/env python3
"""The secrets guard must not go green where it cannot check, and must see fragments.

Run: python3 scripts/test_secret_guard_no_corpus.py [--mutate <name>]

WHAT WAS OPEN (2026-08)

`data/` is never tracked, so no clone and no CI runner has a source of real
flags. `_live_jobs_dir()` returned None there, the accepted-flag oracle printed
SKIP, and the run exited 0. An adversarial audit planted each of 28 accepted
flags into a TRACKED artefact of a fresh clone, one at a time, and 17 left the
guard green. The fix then was a digest pin of the two job-derived artefacts.

WHAT CHANGED (2026-11-14)

Those artefacts left the tree (they carried solve narratives of real
challenges), so there is nothing left to pin. A run that reaches no source of
real flags has established nothing, and the guard now FAILS there with
UNVERIFIED. Where a source exists it must catch an accepted value written
whole, and also any 12-character run of its body: the incident that prompted
this had truncated and split flags in comments that an exact-value check passed.
A body made only of lowercase words has no usable run, so its whole body is the
needle. Captures that never reached any `flags` list come from the operator's
private list, which is a source in its own right.

The guard runs here with HEXTECH_FLAG_SOURCES_EXCLUSIVE=1 and a throwaway HOME,
so it sees only the sources this file builds: the operator's real data and
private list can neither satisfy nor leak into the verdict.

This test writes no real flag. It builds a synthetic library and a synthetic
private list holding invented values, and plants those.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = (
    "none",
    "silent-skip",       # let a run with no source pass, as the 2026-08 guard did
    "exact-only",        # drop fragment matching, as the guard before 2026-11-14 did
    "no-body-fallback",  # a lowercase-only body is matched only with its braces
    "no-private-list",   # captures outside every `flags` list are not read
    "not-exclusive",     # default locations are searched even when told not to
    "no-prompt-window-check",  # a tracked quote of a private prompt goes unseen
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS, default="none")
args = parser.parse_args()

passed = 0
failed = 0


def check(label: str, got, want=True, *, detail=None) -> None:
    """Compare got to want. Diagnostics go in `detail`, never in `want`."""
    global passed, failed
    if got == want:
        passed += 1
        print(f"PASS  {label}")
    else:
        failed += 1
        print(f"FAIL  {label}\n      got  = {got!r}\n      want = {want!r}"
              + (f"\n      detail = {detail!r}" if detail is not None else ""))


GUARD = "scripts/test_no_committed_secrets.py"
PLANT_IN = "README.md"
# Invented, and generated at run time on purpose: this file is tracked, so a
# spelled-out value would be an accepted flag sitting in a tracked file the
# moment the synthetic library below is the oracle — the guard caught exactly
# that in the first draft. Mixed case and digits, like the bodies it exists for.
_ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
_BODY = "".join(_ALPH[(i * 17 + 5) % len(_ALPH)] for i in range(26))
SYNTH_FLAG = "SYNTH{" + _BODY + "}"
SYNTH_BODY_RUN = _BODY[4:16]               # a 12-character run of its body
# Only lowercase letters: every 12-character run of it looks like prose and is
# skipped, so nothing but the whole-body needle can catch a brace-less copy.
LOWER_BODY = "".join("abcdefghijklmnopqrstuvwxyz"[(i * 11 + 7) % 26] for i in range(20))
SYNTH_LOWER = "SYNTH{" + LOWER_BODY + "}"
# Known only to the private list, as a capture read off a run.log would be.
SYNTH_PRIVATE = "SYNTH{" + "".join(_ALPH[(i * 23 + 11) % len(_ALPH)] for i in range(24)) + "}"
# Sits at the default private-list location under the throwaway HOME. Reaching
# it at all means the guard looked where it was told not to.
SYNTH_HOME = "SYNTH{" + "".join(_ALPH[(i * 29 + 2) % len(_ALPH)] for i in range(22)) + "}"
# An invented private prompt, also built at run time: the word list below is
# in alphabetical order and the prompt walks it with a stride of 11, so no
# 10-word window of the prompt appears in this tracked file.
_WORDS = ("amber", "basalt", "cobalt", "delta", "ember", "fjord", "garnet",
          "harbor", "indigo", "jasper", "krypton", "lagoon", "marble", "nickel",
          "onyx", "pewter", "quartz", "russet", "sienna", "topaz", "umber",
          "violet", "walnut", "xenon", "yarrow", "zircon")
PROMPT_TEXT = " ".join(_WORDS[(i * 11 + 4) % len(_WORDS)] for i in range(40))
PROMPT_PLANT = " ".join(PROMPT_TEXT.split()[5:17])    # 12 consecutive words
NEVER_PRINTED = (SYNTH_FLAG, _BODY, SYNTH_BODY_RUN, SYNTH_LOWER, LOWER_BODY,
                 SYNTH_PRIVATE, SYNTH_HOME, PROMPT_PLANT)

_TMP = tempfile.TemporaryDirectory(prefix="guard-no-corpus-")
CLONE = Path(_TMP.name) / "clone"
NO_DATA = Path(_TMP.name) / "no-data-here"
SYNTH_DATA = Path(_TMP.name) / "synth-data"
PRIVATE_LIST = Path(_TMP.name) / "private-flags.txt"
FAKE_HOME = Path(_TMP.name) / "home"
PROMPTS = Path(_TMP.name) / "private-prompts"


def _git(cmd, cwd):
    r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(cmd[:3]), r.returncode,
                                                   r.stderr.strip()[-200:]))
    return r.stdout


def _mutate(s: str, anchor: str, replacement: str) -> str:
    if anchor not in s:
        raise RuntimeError("mutation anchor not found in the guard: %r" % anchor)
    return s.replace(anchor, replacement)


def build_clone() -> None:
    """A tracked-files-only copy: exactly what a clone gets, minus data/."""
    CLONE.mkdir(parents=True)
    files = [p for p in _git(["git", "ls-files", "-z"], ROOT).split("\0") if p]
    if not files:
        raise RuntimeError("git ls-files listed nothing; the clone would be empty")
    for rel in files:
        src = ROOT / rel
        if not src.is_file():
            continue
        dst = CLONE / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    guard = CLONE / GUARD
    s = guard.read_text()
    if args.mutate == "silent-skip":
        s = _mutate(s, "    bool(accepted), sorted(sources))",
                    "    True, sorted(sources))")
    if args.mutate == "exact-only":
        s = _mutate(s, "_RUN = 12", "_RUN = 10 ** 6")
    if args.mutate == "no-body-fallback":
        s = _mutate(s, "        elif len(body) >= _RUN and len(set(body)) >= 4:",
                    "        elif False:")
    if args.mutate == "no-private-list":
        s = _mutate(s, "    pf = _private_flags_file()", "    pf = None")
    if args.mutate == "no-prompt-window-check":
        s = _mutate(s, "if not _prompt_windows:", "if True:")
    if args.mutate == "not-exclusive":
        s = _mutate(s, '_EXCLUSIVE = os.environ.get("HEXTECH_FLAG_SOURCES_EXCLUSIVE") == "1"',
                    "_EXCLUSIVE = False")
    guard.write_text(s)
    _git(["git", "init", "-q", "."], CLONE)
    _git(["git", "add", "-A"], CLONE)
    _git(["git", "-c", "user.email=t@t", "-c", "user.name=t",
          "commit", "-qm", "base"], CLONE)
    entry = SYNTH_DATA / "exploits" / "synth-case"
    entry.mkdir(parents=True)
    (entry / "meta.json").write_text(json.dumps({"flags": [SYNTH_FLAG, SYNTH_LOWER]}))
    PRIVATE_LIST.write_text("# synthetic\n" + SYNTH_PRIVATE + "\n")
    home_list = FAKE_HOME / "ogamdo-private" / "known-flags.txt"
    home_list.parent.mkdir(parents=True)
    home_list.write_text(SYNTH_HOME + "\n")
    PROMPTS.mkdir()
    (PROMPTS / "synthetic_notes.md").write_text(PROMPT_TEXT + "\n")


OUTPUTS: list[str] = []


def run_guard(data_dir: Path, private: Path | None = None,
              prompts: Path | None = None):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    # Leave the resolver nowhere else to go: only what this test names, no
    # default location (this host has a /data, and the operator a private list).
    env["HEXTECH_FLAG_SOURCES_EXCLUSIVE"] = "1"
    env["HOME"] = str(FAKE_HOME)
    env["HEXTECH_LIVE_JOBS"] = "/nonexistent-corpus-for-this-test"
    env["HEXTECH_DATA_DIR"] = str(data_dir)
    env.pop("HEXTECH_PRIVATE_FLAGS", None)
    env.pop("HEXTECH_PRIVATE_PROMPTS", None)
    if private is not None:
        env["HEXTECH_PRIVATE_FLAGS"] = str(private)
    if prompts is not None:
        env["HEXTECH_PRIVATE_PROMPTS"] = str(prompts)
    r = subprocess.run([sys.executable, GUARD], cwd=str(CLONE),
                       capture_output=True, text=True, env=env, timeout=900)
    OUTPUTS.append(r.stdout + r.stderr)
    return r.returncode, r.stdout + r.stderr


build_clone()

print("--- the clone really has no data " + "-" * 26)
check("data/ is not part of a checkout", (CLONE / "data").exists(), False)
check("the guard came along", (CLONE / GUARD).is_file())
check("no lineage artefact came along",
      any((CLONE / "scripts").glob("lineage_equivalence_*.json")), False)

print("")
print("--- no source of real flags: red, and it says why " + "-" * 10)
rc0, out0 = run_guard(NO_DATA)
check("a run that reaches no accepted-flag source FAILS", rc0 != 0, detail=out0[-400:])
check("...and says it could not verify", "UNVERIFIED" in out0, detail=out0[-300:])

print("")
print("--- a source exists: clean tree green, planted value red " + "-" * 3)
rc1, out1 = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("an unmodified tree passes when a source is reachable", rc1, 0, detail=out1[-400:])
plant = CLONE / PLANT_IN
before = plant.read_text()
plant.write_text(before + "\n" + SYNTH_FLAG + "\n")
rc2, out2 = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("an accepted value written whole is refused", rc2 != 0)
check("...naming the file", PLANT_IN in out2, detail=out2[-400:])
plant.write_text(before + "\nsee `" + SYNTH_BODY_RUN + "…` in the log\n")
rc3, out3 = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("a 12-character run of its body, with no prefix or braces, is refused",
      rc3 != 0, detail=out3[-400:])
plant.write_text(before + "\nthe answer was " + LOWER_BODY + " all along\n")
rc5, out5 = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("a lowercase-only body with no prefix or braces is refused, though "
      "none of its runs is usable", rc5 != 0, detail=out5[-400:])
plant.write_text(before + "\n" + SYNTH_PRIVATE + "\n")
rc6, out6 = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("a value known only to the private list is refused", rc6 != 0,
      detail=out6[-400:])
plant.write_text(before)
rc4, _ = run_guard(SYNTH_DATA, PRIVATE_LIST)
check("restoring the file restores the pass", rc4, 0)

print("")
print("--- a private prompt quoted in a tracked file is refused " + "-" * 2)
rc7, out7 = run_guard(SYNTH_DATA, PRIVATE_LIST, PROMPTS)
check("with a private prompt reachable, the unmodified tree still passes", rc7, 0,
      detail=out7[-400:])
plant.write_text(before + "\n" + PROMPT_PLANT + "\n")
rc8, out8 = run_guard(SYNTH_DATA, PRIVATE_LIST, PROMPTS)
check("twelve consecutive words of a private prompt in a tracked file are refused",
      rc8 != 0, detail=out8[-400:])
check("...naming the file", PLANT_IN in out8, detail=out8[-400:])
plant.write_text(before)

print("")
print("--- the guard never prints what it guards " + "-" * 17)
echoed = sorted({i for i, s in enumerate(NEVER_PRINTED)
                 for out in OUTPUTS if s in out})
check("no run's output holds a planted value, body or run (reported by index)",
      echoed, [])

print("")
print(f"secret-guard-no-corpus: {passed} passed, {failed} failed; "
      f"mutation={args.mutate}")
sys.exit(1 if failed else 0)
