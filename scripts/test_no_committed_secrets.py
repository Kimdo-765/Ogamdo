#!/usr/bin/env python3
"""No committed file may carry a credential.

Run: python3 scripts/test_no_committed_secrets.py

THE INCIDENT

scripts/concept_benchmark.json is built from live job data, and job
descriptions are free text an operator types. One of them contained a live
CTFd API token. The builder copied descriptions verbatim, so the token was
committed and pushed before review caught it.

`modules.job_secrets.redact_job_value` already existed and did not help: it
replaces secrets that were REGISTERED for a job through the upload form. A
credential the operator merely typed into the description was never registered,
so there was nothing to match against.

The builder now runs both layers -- registered-secret redaction and a broad
pattern scrub. This file is the thing that would have caught it: it reads the
committed artefacts as bytes and fails on anything credential-shaped,
regardless of which layer was supposed to have removed it.

Deliberately broad. A false positive costs one line in a fixture; a false
negative costs a credential, and this repository has a remote.

THE THIRD INCIDENT, 2026-11-14

The guard was green while the public mirror carried real flags. Comments and
test literals quoted captures that never reached `meta.flags` of a live job,
truncated or split copies passed an exact-value check, the two tracked lineage
artefacts held attempt-by-attempt solve narratives from which one flag could be
rebuilt whole, and ALLOWED_SUBSTRINGS itself listed half of a real flag. So:
the lineage corpus left the tree (nothing job-derived is tracked; see
GENERATED), the oracle now reads every reachable source of real flags — the
live job corpus, the Exploit Library and the measured-job records — and also
matches any 12-character run of a flag body, and a run with no source FAILS
instead of passing on a digest of artefacts that no longer exist.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Scan EVERY tracked text file, not a list of the ones I happened to think of.
# The leak was in a file built from live job data, and naming that file would
# only protect the case already known. A sweep of all 237 tracked files found
# no other real credential -- the six other matches are digests and test
# placeholders, listed below by exact value so a NEW one cannot hide behind a
# path-level exemption.
# Artefacts BUILT FROM LIVE JOB DATA and committed. Add a file here the moment
# anything generated from data/jobs becomes tracked.
#
# THE SECOND INCIDENT, 2026-08-26. `fafa7a1` tracked the two files below. They
# are written by reading every attempt of every retry lineage — findings,
# solvers, reports, run.log — so they inherit whatever those artefacts say. The
# labelled one carried three ACCEPTED flags (verified present in `meta.flags` of
# finished jobs 90bd949f3c34 / d12c1e2f9a3e, f52c4049fec9, 9d2e4099d5ba) and one
# rejected candidate of the same shape. The commit was made without running this
# file; a read-only eyeball scan ran instead and searched only for `DH{`, so it
# reported "no real flags" while two `pokactf2024{...}` captures sat in the same
# artefact. That is the same lesson as the first incident in a new costume: the
# sweep below is what catches it, and it only runs if someone runs it.
#
# 2026-11-14: those two files are no longer tracked. Beyond flags they carried
# solve narratives of real challenges, which no scrubber can make safe, so they
# moved to a private directory outside the tree (see
# scripts/test_lineage_equivalence_coverage.py) and .gitignore keeps them out.
# The list stays so a future job-derived artefact still gets the targeted
# checks below — but the answer for one is "do not track it", not "scrub it".
GENERATED: list[str] = []
# A pathspec, not two file names: a renamed or re-split corpus file is the same
# leak and must trip the same check.
UNTRACKED_FOR_GOOD = ["scripts/lineage_equivalence_*.json"]

# Known-benign, allowlisted by VALUE rather than by file. A commit SHA and a
# hash of the empty string are credential-shaped and are not credentials.
ALLOWED_SUBSTRINGS = {
    # docs/hardening-s1-baseline.json — provenance digests, each verified by
    # reading the JSON key it sits under: base_commit, base_tree, two
    # `sha256:`-prefixed file hashes, and manifest_sha256.
    "b172d6d13461beb0d603ca170ae84822ab",
    "6f952dfa5cd11f576f0ec0268d787395fc",
    "59f979038dbc4a67f4625e6203e3ac937e",
    "e52da33a2f8cd33901982baed5274179d2",
    "ce8590edf720994c0a899298d163ef173c",
    "e3b0c44298fc1c149afbf4c8996fb924",            # sha256 of the empty string
    "da39a3ee5e6b4b0d3255bfef95601890",            # sha1 of the empty string
    "sk-test-secret-value-123456789",              # explicit test placeholder
    "0123456789abcdef",                            # synthetic fixture
    "bcdaad21d4635931d1bd3b54",                    # synthetic fixture
}


def _tracked_text_files():
    import subprocess
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                         capture_output=True, text=True)
    for rel in out.stdout.split("\0"):
        if not rel:
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            yield rel, p.read_text(errors="strict")
        except (UnicodeDecodeError, OSError):
            continue                               # binary


# Only the locations the environment names, nothing found by default. A test
# that builds its own synthetic source sets this, so the operator's real data
# and private list cannot leak into (or quietly satisfy) its verdict.
_EXCLUSIVE = os.environ.get("HEXTECH_FLAG_SOURCES_EXCLUSIVE") == "1"
_READ_FAILURES: list[str] = []


def _main_checkout():
    """The main checkout when ROOT is a linked worktree, else None."""
    common = ROOT / ".git"
    if common.is_file():
        try:
            line = common.read_text().strip()
            if line.startswith("gitdir:"):
                git_dir = pathlib.Path(line.split(":", 1)[1].strip())
                for ancestor in git_dir.parents:
                    if ancestor.name == ".git":
                        return ancestor.parent
        except OSError:
            pass
    return None


def _data_roots():
    """Every place a data/ directory can be reached from, worktrees included."""
    roots = []
    if os.environ.get("HEXTECH_DATA_DIR"):
        roots.append(pathlib.Path(os.environ["HEXTECH_DATA_DIR"]))
    if _EXCLUSIVE:
        return roots
    roots.extend((ROOT / "data", pathlib.Path("/data")))
    main = _main_checkout()
    if main is not None:
        roots.append(main / "data")
    return roots


def _private_flags_file():
    """Confirmed real values that never reached any `flags` list.

    A capture read off a run.log, or found only by a reviewer, is in no job's
    `meta.flags`, so the corpus cannot know it. The operator keeps those in an
    untracked file, one value per line (`#` starts a comment).
    """
    if os.environ.get("HEXTECH_PRIVATE_FLAGS"):
        return pathlib.Path(os.environ["HEXTECH_PRIVATE_FLAGS"])
    if _EXCLUSIVE:
        return None
    return pathlib.Path.home() / "ogamdo-private" / "known-flags.txt"


def _private_flags(path):
    try:
        text = path.read_text()
    except FileNotFoundError:
        return set()
    except (OSError, UnicodeDecodeError):
        _READ_FAILURES.append(str(path))
        return set()
    return {line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")}


def _private_prompt_files():
    """Operator-private prompt files (see modules/private_prompts.py).

    `$HEXTECH_PRIVATE_PROMPTS` when set, else `private-prompts/*.md` under every
    data root. Exclusive mode reads only the environment's directory.
    """
    dirs = []
    if os.environ.get("HEXTECH_PRIVATE_PROMPTS"):
        dirs.append(pathlib.Path(os.environ["HEXTECH_PRIVATE_PROMPTS"]))
    elif not _EXCLUSIVE:
        dirs.extend(root / "private-prompts" for root in _data_roots())
    files, seen = [], set()
    for d in dirs:
        try:
            if not d.is_dir() or d.resolve() in seen:
                continue
            seen.add(d.resolve())
            files.extend(sorted(d.glob("*.md")))
        except OSError:
            _READ_FAILURES.append(str(d))
    return files


def _accepted_flag_sources():
    """Every reachable source of REAL flags, by name -> set of exact values.

    The live job corpus (`jobs/<id>/meta.json`), the Exploit Library
    (`exploits/<id>/meta.json`) and the measured-job records
    (`job-measurements/<id>/meta.json`) all keep accepted values under `flags`,
    and each is read under EVERY data root (a worktree and its main checkout
    can hold different job trees). None of them is tracked, so a clone has none
    of them. The operator's private list adds what no `flags` ever held.
    """
    dirs = []
    if os.environ.get("HEXTECH_LIVE_JOBS"):
        dirs.append(pathlib.Path(os.environ["HEXTECH_LIVE_JOBS"]))
    for root in _data_roots():
        dirs.extend(root / sub for sub in ("jobs", "exploits", "job-measurements"))
    sources = {}
    seen = set()
    for d in dirs:
        try:
            if not d.is_dir():
                continue
            key = d.resolve()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        values, n = _accepted_flag_oracle(d)
        if values:
            sources["%s (%d trees)" % (d, n)] = values
    pf = _private_flags_file()
    if pf is not None:
        values = _private_flags(pf)
        if values:
            sources["private list %s" % pf] = values
    return sources


# Fragments count. A flag truncated in a comment, split across two backticked
# halves, or wrapped inside a longer token is still the answer, and the exact
# check let every one of those through. Any RUN-character window of a flag body
# is an oracle hit — except an all-lowercase word run, which real bodies (leet
# digits, capitals, symbols) almost never consist of and prose constantly does.
_RUN = 12
_WORDISH = re.compile(r"[a-z_ ]+")


def _accepted_flag_oracle(jobs_dir):
    """Exact accepted values; no prefix or flag-shape assumption.

    A file that exists and cannot be read is counted in _READ_FAILURES rather
    than skipped in silence: its flags are missing from the oracle.
    """
    accepted = set()
    scanned = 0
    try:
        entries = sorted(jobs_dir.iterdir())
    except OSError:
        _READ_FAILURES.append(str(jobs_dir))
        return accepted, scanned
    for job_dir in entries:
        meta_path = job_dir / "meta.json"
        try:
            if not meta_path.is_file():
                continue
        except OSError:                  # e.g. a root-owned tree from a worker
            _READ_FAILURES.append(str(meta_path))
            continue
        scanned += 1
        for path in (meta_path, job_dir / "result.json"):
            try:
                payload = json.loads(path.read_text())
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                _READ_FAILURES.append(str(path))
                continue
            flags = payload.get("flags") if isinstance(payload, dict) else None
            if isinstance(flags, str):
                flags = [flags]          # iterating a str would add single chars
            for value in flags if isinstance(flags, list) else []:
                if isinstance(value, str) and value:
                    accepted.add(value)
    return accepted, scanned

PATTERNS = [
    ("vendor token", re.compile(
        r"\b(?:ctfd|ghp|gho|ghu|ghs|ghr|glpat|xox[baprs])_[A-Za-z0-9_\-]{10,}")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{12,}")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("labelled credential", re.compile(
        r"(?i)\b(?:token|api[_-]?key|apikey|secret|passwd|password|bearer)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}")),
    ("long hex blob", re.compile(r"\b[A-Fa-f0-9]{40,}\b")),
]

checks = 0
fails = 0


def _digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def chk(label, cond, got=None):
    global checks, fails
    checks += 1
    if cond:
        print("PASS  %s" % label)
    else:
        fails += 1
        print("FAIL  %s\n        got=%r" % (label, got))


print("--- generated artefacts must not carry credentials " + "-" * 8)
for rel in GENERATED:
    p = ROOT / rel
    chk("%s exists" % rel, p.is_file())
    if not p.is_file():
        continue
    raw = p.read_text(errors="replace")
    for name, pat in PATTERNS:
        found = pat.findall(raw)
        chk("%s carries no %s" % (rel, name), not found,
            [_digest(f) for f in found[:3]])

print("")
print("--- and NO tracked file carries an unrecognised one " + "-" * 7)
unknown = []
scanned = 0
for rel, raw in _tracked_text_files():
    scanned += 1
    for name, pat in PATTERNS:
        for m in pat.finditer(raw):
            hit = m.group(0)
            if any(a in hit for a in ALLOWED_SUBSTRINGS):
                continue
            # a digest, not a prefix: a failing run's log must not hold a
            # readable piece of the credential it found
            unknown.append((rel, name, _digest(hit)))
chk("scanned a plausible number of tracked files", scanned > 100, scanned)
chk("no unrecognised credential-shaped string in any tracked file",
    not unknown, unknown[:5])

print("")
print("--- accepted flags are an exact-value oracle, fragments included " + "-" * 0)
# `data/` is never tracked, so a clone has no source of real flags. This half
# used to print SKIP and exit 0 there (an audit then planted 28 accepted flags
# into a fresh clone one at a time and 17 stayed green), and later carried that
# verification on a digest of the generated artefacts. Those artefacts are gone
# from the tree, so there is nothing left to pin: a run that reaches no source
# has established nothing and FAILS. The credential PATTERNS above carry no flag
# shape, and a shape is the wrong oracle anyway — artefacts legitimately hold
# REJECTED candidates that look identical to real flags. Only exact values work,
# and the values cannot be committed (that would be the leak), so the check can
# only run where the untracked data is.
sources = _accepted_flag_sources()
accepted = set().union(*sources.values()) if sources else set()
for name in sorted(sources):
    print("      source %s: %d values" % (name, len(sources[name])))
if _READ_FAILURES:
    print("      %d source file(s) could not be read; their flags are NOT in the "
          "oracle (first: %s)" % (len(_READ_FAILURES), _READ_FAILURES[0]))
if not accepted:
    print("UNVERIFIED  no accepted-flag source is reachable here "
          "(data/ is untracked, so a clone has none)")
chk("an accepted-flag source was reachable — without one nothing about "
    "tracked flags can be established, so this fails instead of passing",
    bool(accepted), sorted(sources))
if accepted:
    runs = {}
    bodies = {}
    by_runs = by_body = exact_only = 0
    for value in accepted:
        body = value
        if "{" in value and value.endswith("}"):
            body = value[value.index("{") + 1:-1]
        has_run = False
        for i in range(len(body) - _RUN + 1):
            window = body[i:i + _RUN]
            # skip word runs and low-entropy runs (one flag body holds twelve
            # equal digits, which every `333333333333` test job id then matched)
            if not _WORDISH.fullmatch(window) and len(set(window)) >= 4:
                runs.setdefault(window, value)
                has_run = True
        if has_run:
            by_runs += 1
        elif len(body) >= _RUN and len(set(body)) >= 4:
            # an all-lowercase body has no usable run; without this its
            # brace-less copy would pass, so the whole body is the needle
            bodies.setdefault(body, value)
            by_body += 1
        else:
            exact_only += 1
    print("      coverage: %d values by %d-character runs, %d by whole body, "
          "%d by exact value only" % (by_runs, _RUN, by_body, exact_only))
    accepted_hits = []
    for rel, raw in _tracked_text_files():
        found = next((v for v in accepted if v in raw), None)
        if found is None:
            found = next((v for b, v in bodies.items() if b in raw), None)
        if found is None:
            for i in range(len(raw) - _RUN + 1):
                found = runs.get(raw[i:i + _RUN])
                if found is not None:
                    break
        if found is not None:
            accepted_hits.append((rel, _digest(found)))
    chk("no accepted flag — whole, or any %d-character run of its body — is "
        "tracked; prefix-agnostic, so brace-less, truncated and wrapped copies "
        "all count" % _RUN, not accepted_hits, accepted_hits[:8])

print("")
print("--- operator-private prompt text is not tracked " + "-" * 10)
# Some prompt guidance is distilled from the operator's own solves. It lives in
# data/private-prompts/*.md and is swapped in at runtime; the tree carries a
# generic version. The point is that it never reaches a remote, so no tracked
# file may quote it: any 10-word window of a private prompt is a leak. Absent
# on a machine without the files, which is normal, so this half only SKIPs.
_WORD = re.compile(r"[a-z0-9_]+")
_prompt_windows = {}
for _pf in _private_prompt_files():
    try:
        _toks = _WORD.findall(_pf.read_text(encoding="utf-8").lower())
    except (OSError, UnicodeDecodeError):
        _READ_FAILURES.append(str(_pf))
        continue
    for _i in range(len(_toks) - 9):
        _prompt_windows.setdefault(" ".join(_toks[_i:_i + 10]), _pf.name)
if not _prompt_windows:
    print("SKIP  no private prompt file is reachable here")
else:
    print("      private prompt windows: %d" % len(_prompt_windows))
    _prompt_hits = []
    for rel, raw in _tracked_text_files():
        _toks = _WORD.findall(raw.lower())
        for _i in range(len(_toks) - 9):
            _w = " ".join(_toks[_i:_i + 10])
            if _w in _prompt_windows:
                _prompt_hits.append((rel, _prompt_windows[_w], _digest(_w)))
                break
    chk("no tracked file quotes an operator-private prompt (any 10-word window)",
        not _prompt_hits, _prompt_hits[:8])

print("")
print("--- the generated-artefact list has not gone stale " + "-" * 6)
# This half used to exercise scripts/build_concept_benchmark.py's `_scrub`.
# That builder was the ONLY producer of a committed artefact made from live job
# data, and it was deleted with the ranker its benchmark scored — so the
# scrubber it defined has no subject and no caller. Reading it anyway is not a
# stricter test; it is a FileNotFoundError that killed this file before it
# printed a verdict, which is exactly how a security guard stops guarding
# without anyone noticing.
#
# The sweep above is the part that would have caught the original incident, and
# it does not depend on knowing which file was generated: it reads every
# tracked file as bytes. What is left to assert is that GENERATED describes
# reality, so that adding a new job-data-derived artefact cannot skip the
# targeted checks by simply not being listed.
for rel in GENERATED:
    chk("listed generated artefact %s exists" % rel, (ROOT / rel).is_file())
chk("no generated artefact is listed that does not exist",
    all((ROOT / rel).is_file() for rel in GENERATED), GENERATED)
_gone = [rel for rel in ("scripts/concept_benchmark.json",
                         "scripts/build_concept_benchmark.py",
                         "scripts/run_concept_benchmark.py")
         if (ROOT / rel).exists()]
chk("the deleted concept-benchmark files stayed deleted — if one returns it "
    "is job-derived again and needs a GENERATED entry plus a scrubber",
    not _gone, _gone)
import subprocess as _sp
_ls = _sp.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", *UNTRACKED_FOR_GOOD],
              capture_output=True, text=True)
_retracked = [p for p in _ls.stdout.split("\0") if p]
chk("the lineage corpus stays untracked — it quotes solve narratives of real "
    "challenges and lives in a private directory outside the tree",
    _ls.returncode == 0 and not _retracked, (_ls.returncode, _retracked))

print("")
print("%d checks, %d failed" % (checks, fails))
sys.exit(1 if fails else 0)
