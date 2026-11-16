#!/usr/bin/env python3
"""Manual promotion of a harvester finding into a job's flag candidates.

WHAT IS BEING PROTECTED

`flag_grain.txt` is written by a model and is advisory BY CONSTRUCTION — the
harvester cannot write `meta.flags`, cannot set a status, cannot end a job, and
`modules/_harvester.py` spends its opening docstring on the three jobs that
paid for loosening that. `POST /{job_id}/flag-grain/promote` is the first thing
that lets a grain value reach `meta.flags` at all, so the restriction now rests
on exactly one property:

    the promoted value must appear VERBATIM as a `flag=` entry in that job's
    own grain file.

Break that check and the endpoint becomes "write any string the caller likes
into the flag state". Check E3 is the one that must never be allowed to pass by
accident, which is why mutation 3 exists.

Second thing protected: `flag_verdict`'s `ok` promotes `flags or candidates or
rejected` — the WHOLE list. Job 2e778201fe66 sits in production reading
`finished` while carrying two mutually exclusive candidates with the same
prefix, because nothing could say which one. The optional `flag` field is the fix, and
V1 pins that omitting it still behaves exactly as before.

HOW IT RUNS

Every check runs in a SUBPROCESS against the real source tree. That is
deliberate: `api.routes.jobs` and `modules._harvester` are both cached by their
packages as attributes, and an earlier suite in this repo silently MISSED five
of nine mutations because `sys.modules.pop()` alone left `pc1 is pc2` true. A
fresh interpreter cannot have that bug.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOBS_PY = ROOT / "api" / "routes" / "jobs.py"
HARVESTER_PY = ROOT / "modules" / "_harvester.py"
APP_JS = ROOT / "web-ui" / "app.js"

_FAILED: list[str] = []


def chk(cid: str, ok: bool, label: str) -> None:
    if ok:
        print(f"PASS  [{cid}] {label}")
    else:
        print(f"FAIL  [{cid}] {label}")
        _FAILED.append(cid)


# ---------------------------------------------------------------------------
# The checks. Run with --checks inside a throwaway DATA_DIR.
# ---------------------------------------------------------------------------
def _stub_heavy_imports() -> None:
    """The api package pulls redis/docker; neither is installed on the host and
    neither is reached by this endpoint. Stub them so the module imports."""
    import types

    class _Any:
        def __init__(self, *a, **k):
            pass

        def __getattr__(self, n):
            return _Any()

        def __call__(self, *a, **k):
            return _Any()

        @classmethod
        def from_url(cls, *a, **k):
            return _Any()

    for name in ("redis", "docker", "rq"):
        mod = types.ModuleType(name)
        mod.__getattr__ = lambda _n: _Any
        sys.modules[name] = mod


class _Req:
    """Minimal stand-in for starlette's Request — the endpoint uses .json()."""

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        if self._payload is _NO_BODY:
            raise ValueError("no body")
        return self._payload


_NO_BODY = object()


def jid(name: str) -> str:
    """A canonical 12-hex job id. `_validate_job_id` rejects anything else, so
    a readable stub name like "e4" would 400 before reaching the code under
    test — and every status check would then look like it passed."""
    return hashlib.sha256(name.encode()).hexdigest()[:12]


def _mkjob(root: Path, jid: str, *, status: str, grain: str | None,
           candidates=None, rejected=None, flags=None) -> None:
    d = root / "jobs" / jid
    d.mkdir(parents=True, exist_ok=True)
    meta = {"id": jid, "status": status, "module": "rev"}
    if candidates is not None:
        meta["flag_candidates"] = candidates
    if rejected is not None:
        meta["flag_rejected"] = rejected
    if flags is not None:
        meta["flags"] = flags
    (d / "meta.json").write_text(json.dumps(meta))
    if grain is not None:
        (d / "flag_grain.txt").write_text(grain)


def _meta(root: Path, jid: str) -> dict:
    return json.loads((root / "jobs" / jid / "meta.json").read_text())


def _call(fn, jid, payload):
    """Run one endpoint coroutine; return ("ok", body) or ("http", status)."""
    import asyncio

    from fastapi import HTTPException

    try:
        return ("ok", asyncio.run(fn(jid, _Req(payload))))
    except HTTPException as exc:
        return ("http", exc.status_code)


def run_checks() -> bool:
    tmp = Path(tempfile.mkdtemp(prefix="grainpromote-"))
    os.environ["DATA_DIR"] = str(tmp)
    os.environ["JOBS_DIR"] = str(tmp / "jobs")
    sys.path.insert(0, str(ROOT))
    _stub_heavy_imports()

    from modules._harvester import grain_flag_values

    # ---- parser ----------------------------------------------------------
    # Invented. Real accepted flags never enter the tree —
    # scripts/test_no_committed_secrets.py treats them as an exact-value
    # oracle, and a test fixture is not a reason to publish one.
    REAL = "DH{779g_628p3_hjk_h6gg_q72_73m_2qh_snp}"
    _mkjob(tmp, jid("p1"), status="no_flag", grain=(
        f"flag={REAL}\tconfidence=0.93\tat=14:40:14\twhy=seen in exploit output\n"
        "tally\tat=14:45:11\tadjudicated=16\taccepted=1\tfailed=0\tdropped=0\n"
    ))
    chk("P1", grain_flag_values(jid("p1")) == [REAL],
        "a flag= row yields exactly its value")
    chk("P2", "tally" not in "".join(grain_flag_values(jid("p1")))
        and len(grain_flag_values(jid("p1"))) == 1,
        "the tally row is not a candidate")

    # An error detail is free text and may itself contain a tab and a `flag=`.
    _mkjob(tmp, jid("p3"), status="no_flag", grain=(
        "error\tat=01:02:03\tdetail=TimeoutError while reading\tflag=SPOOFED{x}\n"
    ))
    chk("P3", grain_flag_values(jid("p3")) == [],
        "an error row cannot smuggle a flag through its detail")

    # base64 padding is routine inside a flag body.
    _mkjob(tmp, jid("p4"), status="no_flag", grain="flag=CTF{YWJjZA==}\tconfidence=0.8\n")
    chk("P4", grain_flag_values(jid("p4")) == ["CTF{YWJjZA==}"],
        "only the FIRST = splits, so an = inside the flag survives")

    _mkjob(tmp, jid("p5"), status="no_flag", grain=(
        "flag=A{1}\tconfidence=0.7\nflag=B{2}\tconfidence=0.7\nflag=A{1}\tconfidence=0.9\n"
    ))
    chk("P5", grain_flag_values(jid("p5")) == ["A{1}", "B{2}"],
        "repeats collapse and file order is kept")

    _mkjob(tmp, jid("p6"), status="no_flag", grain=None)
    chk("P6", grain_flag_values(jid("p6")) == [], "no grain file is empty, not an error")
    chk("P7", grain_flag_values("../../etc") == [],
        "a traversing job id reads nothing")

    # ---- endpoint --------------------------------------------------------
    import api.routes.jobs as J

    promote = J.promote_flag_grain
    verdict = J.flag_verdict

    chk("E1", _call(promote, jid("absent"), {"flag": REAL}) == ("http", 404),
        "unknown job is 404")

    _mkjob(tmp, jid("e2"), status="no_flag", grain=f"flag={REAL}\tconfidence=0.9\n")
    chk("E2", _call(promote, jid("e2"), {}) == ("http", 400),
        "a missing `flag` is refused")

    # THE security property: the grain file is the only permitted source.
    chk("E3", _call(promote, jid("e2"), {"flag": "DH{not_in_the_grain}"}) == ("http", 400),
        "a value absent from the grain cannot be promoted")

    _mkjob(tmp, jid("e4"), status="running", grain=f"flag={REAL}\tconfidence=0.9\n")
    chk("E4", _call(promote, jid("e4"), {"flag": REAL}) == ("http", 409),
        "a live job is 409, not a silent write under the worker")

    _mkjob(tmp, jid("e5"), status="finished", grain=f"flag={REAL}\tconfidence=0.9\n",
           flags=["DH{already}"])
    chk("E5", _call(promote, jid("e5"), {"flag": REAL}) == ("http", 409),
        "a finished job must be ruled wrong before a promotion")

    # no_flag -> flag_ready, explicitly, or the operator can never be asked.
    _mkjob(tmp, jid("e6"), status="no_flag", grain=f"flag={REAL}\tconfidence=0.9\n")
    kind, out = _call(promote, jid("e6"), {"flag": REAL})
    m6 = _meta(tmp, jid("e6"))
    chk("E6", kind == "ok" and m6.get("status") == "flag_ready"
        and REAL in (m6.get("flag_candidates") or []),
        "a no_flag job gains the candidate AND becomes flag_ready")

    # The junk candidate stays. Scrubbing it is a separate act nobody asked for.
    _mkjob(tmp, jid("e7"), status="flag_ready", grain=f"flag={REAL}\tconfidence=0.9\n",
           candidates=["{value}"])
    _call(promote, jid("e7"), {"flag": REAL})
    chk("E7", _meta(tmp, jid("e7")).get("flag_candidates") == ["{value}", REAL],
        "promotion appends; it does not rewrite the existing candidates")

    _mkjob(tmp, jid("e8"), status="no_flag", grain=f"flag={REAL}\tconfidence=0.9\n",
           rejected=[REAL, "DH{other}"])
    kind, out8 = _call(promote, jid("e8"), {"flag": REAL})
    m8 = _meta(tmp, jid("e8"))
    chk("E8", kind == "ok" and out8.get("unrejected") is True
        and m8.get("flag_rejected") == ["DH{other}"]
        and REAL in (m8.get("flag_candidates") or []),
        "promoting a rejected value un-rejects it, and says so")

    kind, out9 = _call(promote, jid("e6"), {"flag": REAL})
    chk("E9", kind == "ok" and out9.get("already_candidate") is True
        and _meta(tmp, jid("e6"))["flag_candidates"].count(REAL) == 1,
        "a second promotion is idempotent, not a duplicate")

    chk("E10", REAL in (_meta(tmp, jid("e6")).get("flag_grain_promoted") or []),
        "the promotion is recorded as provenance")

    # ---- verdict: naming ONE value ---------------------------------------
    A, B = "somectf2024{g2qt_svwv2_p}", "somectf2024{w8qm_3rmw3_8p}"

    _mkjob(tmp, jid("v1"), status="flag_ready", grain=None, candidates=[A, B])
    kind, o1 = _call(verdict, jid("v1"), {"verdict": "ok"})
    chk("V1", kind == "ok" and _meta(tmp, jid("v1")).get("flags") == [A, B],
        "omitting `flag` keeps the old all-of-them behaviour exactly")

    _mkjob(tmp, jid("v2"), status="flag_ready", grain=None, candidates=[A, B])
    kind, o2 = _call(verdict, jid("v2"), {"verdict": "ok", "flag": B})
    chk("V2", kind == "ok" and _meta(tmp, jid("v2")).get("flags") == [B],
        "naming a value promotes that one ALONE")

    _mkjob(tmp, jid("v3"), status="flag_ready", grain=None, candidates=[A, B])
    chk("V3", _call(verdict, jid("v3"), {"verdict": "ok", "flag": "DH{invented}"})
        == ("http", 400),
        "a named value the job never produced is refused")

    _mkjob(tmp, jid("v4"), status="no_flag", grain=None, rejected=[A, B])
    kind, o4 = _call(verdict, jid("v4"), {"verdict": "ok", "flag": A})
    m4 = _meta(tmp, jid("v4"))
    chk("V4", kind == "ok" and m4.get("flags") == [A]
        and m4.get("flag_rejected") == [B],
        "un-rejecting one value leaves the other rejected")

    # ---- the UI actually calls it ----------------------------------------
    js = APP_JS.read_text()
    # Both SITES, not the class name once: the render and the delegated
    # handler each mention it, so a bare substring test survives renaming the
    # rendered button and leaves a control nothing can click.
    chk("U1", 'class="btn btn-sm flag-grain-promote"' in js
        and 'closest(".flag-grain-promote")' in js
        and "/flag-grain/promote" in js,
        "the rendered button, the delegated handler and the endpoint agree")
    chk("U2", "vb.dataset.flag ? { verdict, flag: vb.dataset.flag }" in js,
        "the verdict button forwards the chosen value")
    chk("U3", 'data-flag="${escapeHtml(String(v))}"' in js
        and "verdictValues.length <= 1" in js
        and "(verdictValues.length > 1)" in js
        and "awaiting && verdictValues.length > 1" not in js,
        "per-value buttons replace the single Ok, on finished jobs too")
    chk("U5", 'querySelectorAll(".verdict-values code")' in js
        and "there is no per-value Wrong" in js,
        "the Wrong dialog names every value it is about to reject")
    chk("U4", "_GRAIN_CACHE.delete(id)" in js,
        "the repaint guard is dropped after a promotion")

    return not _FAILED


# ---------------------------------------------------------------------------
# Mutations. Each must be caught by the check named beside it.
# ---------------------------------------------------------------------------
MUTATIONS = [
    ("parser splits on every =", HARVESTER_PY,
     'key, sep, value = chunk.partition("=")',
     'key, sep, value = (chunk.split("=") + ["", ""])[0], "=" in chunk, chunk.split("=")[1] if "=" in chunk else ""',
     "P4"),
    ("parser stops skipping tally/error rows", HARVESTER_PY,
     'if "error" in fields or "tally" in fields:\n            continue',
     'if False:\n            continue',
     "P3"),
    ("endpoint drops the grain membership check", JOBS_PY,
     'if wanted not in grain:',
     'if False:',
     "E3"),
    ("endpoint stops writing the status", JOBS_PY,
     '        status="flag_ready",\n        flag_grain_promoted=sorted(',
     '        flag_grain_promoted=sorted(',
     "E6"),
    ("endpoint replaces the candidates instead of appending", JOBS_PY,
     'candidates = candidates + [wanted]',
     'candidates = [wanted]',
     "E7"),
    ("endpoint leaves the value in flag_rejected", JOBS_PY,
     'flag_rejected=[r for r in rejected if r != wanted],',
     'flag_rejected=rejected,',
     "E8"),
    ("endpoint accepts a live job", JOBS_PY,
     'if status not in ("flag_ready", "no_flag"):',
     'if False:',
     "E4"),
    ("verdict ignores the chosen value", JOBS_PY,
     '            promoted = [chosen]',
     '            pass',
     "V2"),
    ("verdict accepts any chosen value", JOBS_PY,
     'if chosen not in flags and chosen not in candidates and chosen not in rejected:',
     'if False:',
     "V3"),
    ("the UI button is never rendered", APP_JS,
     'class="btn btn-sm flag-grain-promote"',
     'class="btn btn-sm flag-grain-copy2"',
     "U1"),
    ("the verdict button stops forwarding the value", APP_JS,
     'vb.dataset.flag ? { verdict, flag: vb.dataset.flag }',
     'false ? { verdict, flag: vb.dataset.flag }',
     "U2"),
]


def _run_subprocess() -> tuple[int, list[str]]:
    # `-B` and the purge together, not either alone. Two mutations that replace
    # different lines of the SAME length produce files of identical size, and if
    # they land in the same second Python's mtime+size check reuses the stale
    # .pyc from the previous one — the mutation appears to be "caught" by the
    # previous mutation's check. That is a harness reporting a green run for
    # code it never executed, which is the one failure mode a mutation harness
    # must not have. `-B` stops new bytecode being written; the purge removes
    # what is already there, and only the second half fixes a stale read.
    for cache in ROOT.rglob("__pycache__"):
        for pyc in cache.glob("*.pyc"):
            try:
                pyc.unlink()
            except OSError:
                pass
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--checks"],
        capture_output=True, text=True, cwd=str(ROOT), env=env,
    )
    failed = [ln.split("[", 1)[1].split("]", 1)[0]
              for ln in proc.stdout.splitlines() if ln.startswith("FAIL  [")]
    return proc.returncode, failed


def main() -> int:
    if "--checks" in sys.argv:
        ok = run_checks()
        print(f"\n{len(_FAILED)} failed")
        return 0 if ok else 1

    originals = {p: p.read_text() for p in (JOBS_PY, HARVESTER_PY, APP_JS)}
    digests = {p: hashlib.sha256(t.encode()).hexdigest()
               for p, t in originals.items()}

    print("--- baseline ------------------------------------------------")
    rc, failed = _run_subprocess()
    if rc != 0:
        print(f"BASELINE FAILED: {failed}")
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--checks"],
                       cwd=str(ROOT))
        return 1
    print("PASS  every check passes on the real tree")

    print("\n--- mutations -----------------------------------------------")
    bad = 0
    try:
        for label, path, old, new, expect in MUTATIONS:
            src = originals[path]
            if src.count(old) != 1:
                print(f"FAIL  [{expect}] mutation anchor is not unique: {label}")
                bad += 1
                continue
            path.write_text(src.replace(old, new))
            try:
                rc, failed = _run_subprocess()
            finally:
                path.write_text(src)
            if expect in failed:
                print(f"PASS  caught: {label}  (via {expect})")
            elif rc != 0:
                print(f"FAIL  wrong check caught {label!r}: "
                      f"expected {expect}, got {failed}")
                bad += 1
            else:
                print(f"FAIL  MISSED: {label}  ({expect} still passed)")
                bad += 1
    finally:
        for p, text in originals.items():
            if hashlib.sha256(p.read_text().encode()).hexdigest() != digests[p]:
                p.write_text(text)
                print(f"note: restored {p.relative_to(ROOT)}")

    print(f"\n{len(MUTATIONS)} mutations, {bad} not caught")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
