#!/usr/bin/env python3
"""The repo agent — N independent patches in, one integrated bundle out.

WHY MERGING IS THE REAL WORK AND NOT BOOKKEEPING.
v1 had one agent editing one candidate tree, so "the patch" and "the tree"
were the same object and integration did not exist. v2 has N blueteam agents
each working on its OWN copy of base — which is what stops them overwriting
each other mid-flight — so what arrives here is N INDEPENDENT DIFFS AGAINST A
COMMON BASE. Two touching the same file is not exotic: one source file can
hold two vulnerabilities, or more.

THE THREE PROPERTIES THIS FILE DEFENDS.

1. A CONFLICT IS REFUSED, NEVER GUESSED. Picking a winner line-by-line ships a
   file neither blueteam wrote and neither validator checked. M-family.

2. A LOSER IS DEFERRED, NEVER DROPPED. A silently discarded patch is a
   vulnerability the operator believes is fixed — the worst artefact this
   system can produce. A deferral is a work item instead: the plan agent
   re-tasks that blueteam against the MERGED tree, where the conflict is gone
   because the other fix is already in it. I-family.

3. AN UNVERIFIED BUNDLE IS NEVER PUBLISHED. Two individually safe patches can
   break together — one escapes a value the other now double-escapes, one
   renames a helper the other calls. The operator uploads what the REPO AGENT
   produced, not what any blueteam produced, so the integrated bundle is what
   must be checked. P-family.

AND IT ALL WORKS ON BYTES. A source file need not be valid UTF-8, and
decoding one raised UnicodeDecodeError inside the v1 loop, which is how an
unexplained change shipped on job bf8d00c76ed8. B1 uses a synthetic
non-UTF-8 file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REPO_PY = ROOT / "modules" / "live_fire_repo.py"

from modules.live_fire_repo import (  # noqa: E402
    PatchSubmission,
    RepoAgent,
    RepoError,
    integrate,
    merge_three_way,
)

_FAILED: list[str] = []
TMP = Path(os.environ.get("CLAUDE_JOB_DIR", "/tmp")) / "lf-repo-test"

BASE = b"<?php\nfunction a() {\n  echo 1;\n}\nfunction b() {\n  echo 2;\n}\n"
ADMIN = "src/web/pages/board.php"
DRYAD = "src/api/main.py"
ADMINX = "src/web/lib/legacy.php"


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


def sub(vid, path, files, **kw):
    return PatchSubmission(
        vulnerability_id=vid,
        bug_class=kw.get("bug_class", "xss"),
        path=path,
        summary=kw.get("summary", "fixed it"),
        mitigation_class=kw.get("mitigation_class", "root-cause-fix"),
        files=files,
        priority=kw.get("priority", 99),
    )


# ----------------------------------------------------------------- merge


def t_merge() -> None:
    left = BASE.replace(b"  echo 1;", b"  echo htmlspecialchars(1);")
    right = BASE.replace(b"  echo 2;", b"  echo htmlspecialchars(2);")

    both = merge_three_way(BASE, left, right)
    check("M1", both is not None
          and b"htmlspecialchars(1)" in both and b"htmlspecialchars(2)" in both,
          "two fixes in different functions of one file merge — the common "
          "case when a file holds more than one vulnerability")

    rival = BASE.replace(b"  echo 1;", b"  echo (int)1;")
    check("M2", merge_three_way(BASE, left, rival) is None,
          "two fixes to the SAME line conflict rather than being blended — "
          "guessing ships a file neither blueteam wrote and neither validator "
          "checked")

    check("M3", merge_three_way(BASE, left, left) == left,
          "identical edits are not a conflict")

    # THE ARTIFACT. Inside a run of identical lines `_changed_ranges` splits a
    # one-line substitution into an insertion plus a deletion, and the deletion
    # half lands at the SAME base range for both sides whichever occurrence
    # each actually edited. An earlier fix read that shared hunk as agreement
    # and dropped one copy — deleting the very entry whose `start < cursor`
    # test detects the overlap — and the two patches merged into a four-line
    # file neither blueteam wrote. `git merge-file` calls this a conflict too.
    check("M8", merge_three_way(b"A\nA\nA", b"H\nA\nA", b"A\nH\nA") is None,
          "two edits inside a run of identical lines CONFLICT: their opcode "
          "lists share a hunk by alignment accident, and sharing a hunk is not "
          "the same statement as having made the same change")

    # …and the rebase this must not break: a patch handed the winner's file and
    # rewritten on top carries the winner's hunk verbatim, so one list CONTAINS
    # the other. That is agreement, and it is what lets a deferred patch land.
    won = BASE.replace(b"  echo 1;", b"  echo SAFE(1);")
    ontop = won.replace(b"  echo 2;", b"  echo SAFE(2);")
    rebased = merge_three_way(BASE, won, ontop)
    check("M9", rebased == ontop,
          "one side CONTAINING the other is a rebase, not a conflict — "
          "without this the retry loses the same merge it lost the first time")
    check("M4", merge_three_way(BASE, left, BASE) == left
          and merge_three_way(BASE, BASE, right) == right,
          "an untouched side never blocks the other")

    ins_a = BASE.replace(b"function a() {\n", b"function a() {\n  // guard\n")
    ins_b = BASE.replace(b"function a() {\n", b"function a() {\n  // other\n")
    check("M5", merge_three_way(BASE, ins_a, ins_b) is None,
          "two insertions at the SAME point conflict: their order is not "
          "decidable, and picking one silently reorders somebody's code")

    far_a = BASE.replace(b"function a() {\n", b"function a() {\n  // guard\n")
    far_b = BASE.replace(b"function b() {\n", b"function b() {\n  // other\n")
    merged = merge_three_way(BASE, far_a, far_b)
    check("M6", merged is not None and b"// guard" in merged and b"// other" in merged,
          "…but insertions at different points both land")

    # An insertion that starts exactly where a replacement starts is NOT a
    # collision: one blueteam adds a guard clause in front of a block while
    # another rewrites the block, and both belong in the bundle. Only two
    # INSERTIONS at one point are undecidable.
    guard = BASE.replace(b"  echo 2;\n", b"  // guard\n  echo 2;\n")
    rewrite = BASE.replace(b"  echo 2;\n", b"  echo esc(2);\n  log();\n")
    mixed = merge_three_way(BASE, guard, rewrite)
    check("M7", mixed is not None and b"// guard" in mixed and b"esc(2)" in mixed,
          "an insertion at the same point as a REPLACEMENT merges — treating "
          "every edit as an insertion would reject a pairing that is ordinary")


def t_binary() -> None:
    blob = b"<?php\n\x80\x81\x82\xff\xfe binary payload \x00\x01\n?>\n"
    left = blob.replace(b"binary payload", b"binary PAYLOAD")
    check("B1", merge_three_way(blob, left, blob) == left,
          "a non-UTF-8 file merges when only one side touched it — "
          "decoding such a file is what raised UnicodeDecodeError inside "
          "the v1 loop")
    other = blob.replace(b"binary payload", b"binary Payload")
    check("B2", merge_three_way(blob, left, other) is None,
          "…and conflicts honestly when both did")


# ------------------------------------------------------------- integrate


def t_integrate() -> None:
    base = {ADMIN: BASE, DRYAD: b"x = 1\ny = 2\n"}
    a = sub("V1", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo esc(1);")})
    b = sub("V2", DRYAD, {DRYAD: b"x = 1\ny = safe(2)\n"})
    result = integrate(base, [a, b])
    check("I1", result.accepted == ("V1", "V2") and not result.deferred
          and sorted(result.files) == sorted([ADMIN, DRYAD]),
          "independent patches to different files all land")

    c = sub("V3", ADMIN, {ADMIN: BASE.replace(b"  echo 2;", b"  echo esc(2);")})
    two = integrate(base, [a, c])
    check("I2", two.accepted == ("V1", "V3") and not two.deferred
          and b"esc(1)" in two.files[ADMIN] and b"esc(2)" in two.files[ADMIN],
          "two patches to different regions of ONE file both land, merged")
    check("I2b", two.merged_paths == (ADMIN,),
          "…and the co-edited file is named, because it is the one a reviewer "
          "should look at twice")

    rival = sub("V4", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo (int)1;")})
    clash = integrate(base, [a, rival])
    check("I3", clash.accepted == ("V1",) and len(clash.deferred) == 1
          and clash.deferred[0].vulnerability_id == "V4",
          "a conflicting patch is DEFERRED, not dropped — a silently "
          "discarded patch is a vulnerability the operator believes is fixed")
    check("I3b", "overlaps" in clash.deferred[0].reason
          and "V1" in clash.deferred[0].reason,
          "…and the deferral says what it collided with, so the plan agent "
          "can re-task that blueteam against the merged tree")

    check("I4", integrate(base, [rival, a]).accepted == ("V1",),
          "order is by vulnerability id, not arrival: two runs of the same "
          "job must produce the same bundle")

    # SEVERITY STOPPED BEING IMPLIED BY THE ID. Ids were handed out in
    # priority order within a round, so sorting by id put the worst bug first
    # for free. Plan replies are merged as they land now, so an id records
    # WHEN a lead arrived and nothing else — and V4 here is the worse bug.
    worse = sub("V4", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo (int)1;")},
                priority=1)
    milder = sub("V1", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo esc(1);")},
                 priority=4)
    check("I4b", integrate(base, [milder, worse]).accepted == ("V4",)
          and integrate(base, [worse, milder]).accepted == ("V4",),
          "when two patches are mutually exclusive the WORSE vulnerability "
          "keeps the path, whichever order they arrive in — sorting on the id "
          "alone would have given it to V1 because 1 sorts before 4")

    ghost = sub("V5", "nope.php", {"nope.php": b"x"})
    added = integrate(base, [ghost])
    check("I5", not added.accepted and len(added.deferred) == 1,
          "a patch that adds a file absent from the original bundle is "
          "refused — the ZIP is rebuilt from the input manifest, so it would "
          "vanish silently")

    # Atomicity: a submission touching two files, one of which conflicts.
    pair = sub("V6", ADMIN, {
        ADMIN: BASE.replace(b"  echo 1;", b"  echo (int)1;"),
        DRYAD: b"x = 1\ny = other(2)\n",
    })
    atomic = integrate(base, [a, pair])
    check("I6", atomic.accepted == ("V1",) and DRYAD not in atomic.files,
          "a submission is ATOMIC: half a fix is worse than none, because the "
          "validator checked the pair of edits together and not one of them")

    # ADJACENT EDITS, AND THE ORDER THEY ARE FOLDED IN MUST NOT MATTER.
    # Re-diffing the accumulated file asks SequenceMatcher to describe a file
    # whose history it has not seen: two accepted hunks a line apart come back
    # as ONE wider hunk, and a third patch landing strictly inside that
    # invented span is deferred although it overlaps neither. Acceptance then
    # depends on how many patches have already been folded into the file —
    # and one file holding several vulnerabilities is the ordinary case.
    wide = b"\n".join(b"line%d" % i for i in range(25))
    def _edit(fn):
        rows = wide.split(b"\n")
        fn(rows)
        return b"\n".join(rows)
    trio = {
        "V9": _edit(lambda r: r.__delitem__(slice(17, 19))),
        "V10": _edit(lambda r: r.__setitem__(16, b"FIXED16")),
        "V14": _edit(lambda r: r.insert(17, b"NEW")),
    }
    shapes = set()
    for order in (("V9", "V10", "V14"), ("V14", "V9", "V10"),
                  ("V10", "V14", "V9"), ("V14", "V10", "V9")):
        folded = integrate({ADMIN: wide},
                           [sub(v, ADMIN, {ADMIN: trio[v]}) for v in order])
        shapes.add((tuple(sorted(folded.accepted)), folded.files.get(ADMIN)))
    check("I11", shapes == {(("V10", "V14", "V9"), next(iter(shapes))[1])},
          "three edits that overlap NOTHING all land, and the fold order "
          "changes neither the verdict nor the bytes — several "
          "vulnerabilities per file is the normal case, so non-monotonic "
          "acceptance is not an edge")

    # The retry path end to end: the loser, rewritten on the winner's file.
    # The WINNER is numbered lower so it claims the path first — that is the
    # order `_id_order` produces in the job, and it is the order in which the
    # loser's rebased payload is the one carrying the extra edits.
    winner = sub("V2", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo w(1);")})
    on_top = BASE.replace(b"  echo 1;", b"  echo w(1);").replace(
        b"  echo 2;", b"  echo l(2);")
    retry = integrate({ADMIN: BASE}, [winner, sub("V6", ADMIN, {ADMIN: on_top})])
    check("I12", sorted(retry.accepted) == ["V2", "V6"]
          and b"w(1)" in retry.files[ADMIN] and b"l(2)" in retry.files[ADMIN],
          "a deferred patch rewritten on top of the winner lands, and the "
          "winner's edit survives — the whole point of seeding that agent "
          "with the candidate instead of the original")

    ghost = sub("V8", DRYAD, {DRYAD: b"x = 1\ny = ghost(2)\n"})
    after = integrate(base, [a, pair, ghost])
    check("I6b", "V8" in after.accepted
          and b"ghost(2)" in after.files[DRYAD],
          "…and a deferred submission leaves NOTHING behind: the next patch to "
          "that file is merged against the base, not against the edit of a "
          "submission that never landed")

    noop = sub("V7", ADMIN, {ADMIN: BASE})
    check("I7", integrate(base, [noop]).accepted == ("V7",)
          and not integrate(base, [noop]).files,
          "a patch identical to base is accepted but changes nothing")

    # NATURAL ORDER, and it decides who survives a conflict. Sorting the ids
    # as text put V10 ahead of V2 -- and the loser of a merge is dropped
    # whole, so the sort was quietly choosing which fix the operator keeps.
    early = sub("V2", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo two(1);")})
    late = sub("V10", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo ten(1);")})
    order = integrate(base, [late, early])
    check("I8", order.accepted == ("V2",) and len(order.deferred) == 1
          and order.deferred[0].vulnerability_id == "V10",
          "V2 claims the path before V10: lexicographic order made the "
          "higher-numbered, later-found patch win and un-fixed the earlier one")

    guarded = integrate(base, [early, late], protected=["V10"])
    check("I9", guarded.accepted == ("V10",) and len(guarded.deferred) == 1
          and guarded.deferred[0].vulnerability_id == "V2",
          "a patch already in a published bundle claims its path first, "
          "whatever its number: what shipped may not be taken back")

    # The retry path: a deferred patch rewritten ON TOP of the winner.
    won = BASE.replace(b"  echo 1;", b"  echo ten(1);")
    rebased = sub("V2", ADMIN, {
        ADMIN: won.replace(b"  echo 2;", b"  echo two(2);")})
    retry = integrate(base, [late, rebased])
    check("I10", retry.accepted == ("V2", "V10") and not retry.deferred
          and b"ten(1)" in retry.files[ADMIN] and b"two(2)" in retry.files[ADMIN],
          "a deferred patch that carries the winner's hunk verbatim MERGES — "
          "without this the retry is byte-for-byte the try and the same "
          "vulnerability is deferred every round forever")


# --------------------------------------------------------------- publish


class _Validation:
    def __init__(self, ok, unexplained=()):
        self.ok = ok
        self.unexplained = unexplained

    def as_dict(self):
        return {"ok": self.ok}


class _Workspace:
    def __init__(self, root: Path):
        self.root = root
        self.original = root / "original"
        self.candidate = root / "candidate"


def _fresh_ws() -> _Workspace:
    if TMP.exists():
        shutil.rmtree(TMP)
    ws = _Workspace(TMP / "ws")
    for side in (ws.original, ws.candidate):
        (side / Path(ADMIN).parent).mkdir(parents=True)
        (side / ADMIN).write_bytes(BASE)
    return ws


def _builder(counter):
    def build(_ws, target: Path):
        counter["n"] += 1
        target.write_bytes(b"ZIP" + str(counter["n"]).encode())
    return build


def t_publish() -> None:
    ws = _fresh_ws()
    out = TMP / "out"
    agent = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=out)
    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")
    merge = integrate({ADMIN: BASE}, [sub("V1", ADMIN, {ADMIN: patched})])
    counter = {"n": 0}

    refused = agent.publish(merge, validation=_Validation(False, ("x",)),
                            submissions=[sub("V1", ADMIN, {ADMIN: patched})],
                            builder=_builder(counter))
    check("P1", refused is None and not agent.history and counter["n"] == 0,
          "a bundle the validator refused publishes NOTHING — handing the "
          "operator a refused bundle is worse than handing them nothing, "
          "because they will upload it")

    try:
        agent.publish(merge, validation=None,
                      submissions=[], builder=_builder(counter))
        check("P2", False, "publish() accepted a missing verdict")
    except RepoError as exc:
        check("P2", "integrated" in str(exc),
              "the verdict is REQUIRED and must be about the integrated "
              "bundle: two individually safe patches can break together")

    entry = agent.publish(merge, validation=_Validation(True),
                          submissions=[sub("V1", ADMIN, {ADMIN: patched})],
                          builder=_builder(counter))
    check("P3", entry and entry["version"] == 1 and entry["vuln_clear"] == 1
          and entry["verified"] is True,
          "a verified bundle cuts V1 — and `verified` can finally be true, "
          "which it never could in v1")
    check("P4", entry["zip"] == "patched-v1.zip"
          and (out / "patched-v1.zip").is_file()
          and json.loads((out / "patch-progress.json").read_text())["snapshots"],
          "the history file is the SAME shape the job UI already renders and "
          "already takes per-version operator feedback against")

    same = agent.publish(merge, validation=_Validation(True),
                         submissions=[sub("V1", ADMIN, {ADMIN: patched})],
                         builder=lambda _w, t: t.write_bytes(b"ZIP1"))
    check("P5", same is None and len(agent.history) == 1,
          "a byte-identical bundle is not a version: d9fef25b2216 published "
          "V3, V4 and V5 all sharing V2's sha256 — three more uploads of the "
          "same patch, read as stalled progress")

    empty = integrate({ADMIN: BASE}, [])
    # A VIRGIN AGENT. On one that has already published, the regression guard
    # below refuses this merge first and the check proves nothing.
    virgin = RepoAgent(job_id="bf8d00c76ed8", workspace=ws,
                       output_root=TMP / "out-virgin")
    check("P6", virgin.publish(empty, validation=_Validation(True),
                               submissions=[], builder=_builder(counter)) is None,
          "nothing accepted means there is no version to cut")

    # V1 is in the published bundle. A merge that no longer carries it is a
    # bundle that RE-OPENS a vulnerability the operator was told was fixed.
    other = BASE.replace(b"  echo 2;", b"  echo esc(2);")
    dropped = sub("V9", ADMIN, {ADMIN: other})
    without = integrate({ADMIN: BASE}, [dropped])
    check("P7", agent.publish(without, validation=_Validation(True),
                              submissions=[dropped],
                              builder=_builder(counter)) is None
          and len(agent.history) == 1,
          "a bundle that un-fixes something already shipped is REFUSED: job "
          "586ba6888920 published v20 without the V6 and V8 fixes, both of "
          "which shipped in v9")


def t_tree() -> None:
    ws = _fresh_ws()
    agent = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=TMP / "o")
    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")

    (ws.candidate / ADMIN).write_bytes(b"LEFTOVER FROM AN EARLIER VERSION")
    merge = integrate({ADMIN: BASE}, [sub("V1", ADMIN, {ADMIN: patched})])
    agent.materialise(merge)
    check("T1", (ws.candidate / ADMIN).read_bytes() == patched,
          "the merged tree is what lands in the candidate")

    agent.restore([ADMIN])
    check("T2", (ws.candidate / ADMIN).read_bytes() == BASE,
          "restore puts a path back to original — without it a deferred patch "
          "leaks into the next bundle, present in the zip and absent from the "
          "history")

    (ws.candidate / ADMIN).write_bytes(b"A CANDIDATE THAT DRIFTED")
    base_read = agent.base_files([ADMIN, "missing.php"])
    check("T3", base_read == {ADMIN: BASE},
          "the merge is anchored to ORIGINAL, which create_workspace made "
          "read-only, so no agent can have moved the baseline under it")


def t_leak() -> None:
    """V2 must not carry V1's edit for a vulnerability that got deferred.

    THE SCENARIO, and it is not hypothetical in shape: V1 merges a fix to
    pages/foo.php. In the next round that vulnerability's blueteam is deferred
    — a conflict, or its patch failed validation — so the path is absent from
    V2's merge. But the file on disk still holds V1's edit and
    build_patched_zip reads the CANDIDATE TREE, so V2 ships a change present
    in no finding and no history entry. That is the unexplained_paths defect
    job bf8d00c76ed8 hit, reproduced structurally rather than by accident.
    """

    ws = _fresh_ws()
    agent = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=TMP / "lk")
    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")

    v1 = integrate({ADMIN: BASE}, [sub("V1", ADMIN, {ADMIN: patched})])
    agent.materialise(v1)
    check("L1", (ws.candidate / ADMIN).read_bytes() == patched,
          "V1's fix lands in the candidate")

    # V2: that vulnerability is deferred, so nothing touches ADMIN this round.
    v2 = integrate({ADMIN: BASE}, [])
    agent.materialise(v2)
    check("L2", (ws.candidate / ADMIN).read_bytes() == BASE,
          "…and V2, which merged nothing for that path, ships BASE content — "
          "not V1's edit riding along unexplained")


def t_durable() -> None:
    ws = _fresh_ws()
    out = TMP / "dur"
    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")
    one = sub("V1", ADMIN, {ADMIN: patched})
    merge = integrate({ADMIN: BASE}, [one])
    first = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=out)
    first.publish(merge, validation=_Validation(True), submissions=[one],
                  builder=lambda _w, t: t.write_bytes(b"ZIP-A"))

    resumed = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=out)
    check("D1", len(resumed.history) == 1 and resumed.history[0]["version"] == 1,
          "the version history is read back from patch-progress.json — a job "
          "that dies mid-run must not restart at V1 and overwrite the bundle "
          "the operator already has")
    entry = resumed.publish(merge, validation=_Validation(True),
                            submissions=[one],
                            builder=lambda _w, t: t.write_bytes(b"ZIP-B"))
    check("D2", entry and entry["version"] == 2,
          "…so the next version continues the numbering")
    check("D3", ADMIN in resumed._touched,
          "and the paths earlier versions touched are known again, so the "
          "reset in materialise still works after a resume")


def t_staging() -> None:
    ws = _fresh_ws()
    out = TMP / "stg"
    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")
    one = sub("V1", ADMIN, {ADMIN: patched})
    merge = integrate({ADMIN: BASE}, [one])
    agent = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=out)
    handed: list[str] = []

    def build(_w, t: Path):
        handed.append(t.name)
        t.write_bytes(b"SAME")

    agent.publish(merge, validation=_Validation(True), submissions=[one],
                  builder=build)
    agent.publish(merge, validation=_Validation(True), submissions=[one],
                  builder=build)
    # Checked at the NAME the builder was handed, not at what survives: a
    # version-named file that exists and is then unlinked leaves no trace
    # afterwards, but the operator may already have been downloading it.
    check("S1", handed and all(n.startswith(".") and n.endswith(".tmp")
                               for n in handed)
          and (out / "patched-v1.zip").is_file()
          and not (out / "patched-v2.zip").exists(),
          "the bundle is always built under a staging name and only RENAMED "
          "once it is known to be a new version")
    check("S2", not list(out.glob(".*tmp")),
          "…and the staging file does not survive either")


def t_report() -> None:
    ws = _fresh_ws()
    agent = RepoAgent(job_id="bf8d00c76ed8", workspace=ws, output_root=TMP / "r")
    check("R1", "No version was published" in agent.report([]),
          "an empty history says so rather than rendering an empty success")

    patched = BASE.replace(b"  echo 1;", b"  echo esc(1);")
    one = sub("V1", ADMIN, {ADMIN: patched}, bug_class="sqli",
              mitigation_class="input-filter")
    rival = sub("V2", ADMIN, {ADMIN: BASE.replace(b"  echo 1;", b"  echo (int)1;")})
    merge = integrate({ADMIN: BASE}, [one, rival])
    agent.publish(merge, validation=_Validation(True), submissions=[one, rival],
                  builder=lambda _w, t: t.write_bytes(b"Z"))
    text = agent.report([one, rival])
    check("R2", "V1 — 1 vuln clear" in text and "sqli" in text
          and "input-filter" in text,
          "the report names the version, the class, and the mitigation class")
    check("R3", "DEFERRED" in text and "V2" in text,
          "and the DEFERRED patch appears in the report — it is the operator's "
          "only sign that a vulnerability is still open")
    path = agent.write_report([one, rival])
    check("R4", path.is_file() and path.name == "report.md",
          "the report is written where the job already looks for it")


def run_checks() -> bool:
    _FAILED.clear()
    TMP.mkdir(parents=True, exist_ok=True)
    for fn in (t_merge, t_binary, t_integrate, t_publish, t_tree,
               t_leak, t_durable, t_staging, t_report):
        fn()
    return not _FAILED


MUTATIONS = [
    ("overlapping edits are blended instead of refused", REPO_PY,
     "        if start < cursor:\n            return None",
     "        if False:\n            return None",
     "M2"),
    ("two insertions at one point are silently ordered", REPO_PY,
     "            if last_insert_at == start:\n                return None",
     "            if False:\n                return None",
     "M5"),
    ("every insertion is treated as a same-point collision", REPO_PY,
     "        if start == end:",
     "        if True:",
     "M7"),
    ("a rebase is read as a conflict, so the retry can never land", REPO_PY,
     "    if _contains(right_edits, left_edits):\n        return right",
     "    if False:\n        return right",
     "M9"),
    ("containment stops being containment, so identical edits conflict",
     REPO_PY,
     "    remaining = [tuple((s, e, tuple(r))) for s, e, r in outer]",
     "    return False\n    remaining = [tuple((s, e, tuple(r))) for s, e, r in outer]",
     "M3"),
    ("a shared hunk is taken as agreement again, so a real overlap merges",
     REPO_PY,
     "    remaining = [tuple((s, e, tuple(r))) for s, e, r in outer]\n"
     "    for edit in inner:\n"
     "        key = (edit[0], edit[1], tuple(edit[2]))\n"
     "        if key not in remaining:\n"
     "            return False\n"
     "        remaining.remove(key)\n"
     "    return True",
     "    keys = {(e[0], e[1], tuple(e[2])) for e in outer}\n"
     "    return any((e[0], e[1], tuple(e[2])) in keys for e in inner)",
     "M8"),
    ("a conflicting patch is dropped instead of deferred", REPO_PY,
     "        if blocked is not None:\n            deferred.append(blocked)\n            continue",
     "        if blocked is not None:\n            continue",
     "I3"),
    ("the deferral stops saying what it collided with", REPO_PY,
     '                    f"overlaps the edit already applied for "\n'
     '                    f"{owner.get(path, \'an earlier patch\')}",',
     '                    "conflict",',
     "I3b"),
    ("the merge re-diffs the accumulated file, so applied hunks coalesce",
     REPO_PY,
     "            incoming = _changed_ranges(_lines(base), _lines(payload))",
     "            incoming = _changed_ranges(_lines(merged.get(path, base)),\n"
     "                                       _lines(payload))",
     "I11"),
    ("a rebased patch is not recognised, so the retry loses again", REPO_PY,
     "            if _contains(incoming, current):",
     "            if False:",
     "I12"),
    ("the merge stops preferring the worse vulnerability", REPO_PY,
     "            s.priority,\n",
     "",
     "I4b"),
    ("integration order follows arrival instead of id", REPO_PY,
     "    ordered = sorted(\n        submissions,\n        key=lambda s: (\n"
     "            0 if s.vulnerability_id in shipped else 1,\n"
     "            s.priority,\n"
     "            _id_order(s.vulnerability_id),\n        ),\n    )",
     "    ordered = list(submissions)",
     "I4"),
    ("the id sorts as text again, so V10 outranks V2", REPO_PY,
     "            _id_order(s.vulnerability_id),",
     "            s.vulnerability_id,",
     "I8"),
    ("a published patch stops claiming its path first", REPO_PY,
     "            0 if s.vulnerability_id in shipped else 1,",
     "            0,",
     "I9"),
    ("a bundle may quietly un-fix what already shipped", REPO_PY,
     "        if regressed:",
     "        if False:",
     "P7"),
    ("a file the bundle never had is treated as empty instead of refused",
     REPO_PY,
     '                blocked = Deferral(\n'
     '                    submission.vulnerability_id,\n'
     '                    path,\n'
     '                    "the patch adds a file that is not in the original bundle",\n'
     '                )\n'
     '                break',
     '                base = b""',
     "I5"),
    ("half a submission is applied when the other half conflicts", REPO_PY,
     "                staged[path] = (base, incoming)\n"
     "                continue\n"
     "            if _contains(incoming, current):",
     "                applied[path] = incoming\n"
     "                staged[path] = (base, incoming)\n"
     "                continue\n"
     "            if _contains(incoming, current):",
     "I6b"),
    ("a refused bundle is published anyway", REPO_PY,
     '        if not getattr(validation, "ok", False):',
     "        if False:",
     "P1"),
    ("the validator verdict becomes optional", REPO_PY,
     "        if validation is None:\n            raise RepoError(",
     "        if False:\n            raise RepoError(",
     "P2"),
    ("a byte-identical bundle is cut as a new version", REPO_PY,
     "        if digest == previous:",
     "        if False:",
     "P5"),
    ("an empty merge still cuts a version", REPO_PY,
     "        if not merge.accepted:",
     "        if False:",
     "P6"),
    ("the candidate keeps a deferred vulnerability's earlier edit", REPO_PY,
     "        self.restore(self._touched - set(merge.files))",
     "        pass",
     "L2"),
    ("the set of touched paths stops growing", REPO_PY,
     "        self._touched |= set(written)",
     "        pass",
     "L2"),
    ("the version history is not read back from disk", REPO_PY,
     "        self.history: list[dict[str, Any]] = self._load_history()",
     "        self.history: list[dict[str, Any]] = []",
     "D1"),
    ("a no-op version is built under the version name", REPO_PY,
     '        staging = self.output_root / f".patched-v{version}.zip.tmp"',
     '        staging = self.output_root / f"patched-v{version}.zip"',
     "S1"),
    ("restore stops putting a path back", REPO_PY,
     "            (candidate / path).write_bytes(source.read_bytes())",
     "            pass",
     "T2"),
    ("the merge anchors to the candidate instead of the original", REPO_PY,
     "        root = Path(self.workspace.original)\n        out: dict[str, bytes] = {}",
     "        root = Path(self.workspace.candidate)\n        out: dict[str, bytes] = {}",
     None),
    ("deferred patches vanish from the report", REPO_PY,
     '            for deferral in entry.get("deferred") or []:',
     "            for deferral in []:",
     "R3"),
]


def _subprocess() -> tuple[int, list[str]]:
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

    originals = {REPO_PY: REPO_PY.read_text()}
    digests = {p: hashlib.sha256(t.encode()).hexdigest() for p, t in originals.items()}

    print("--- baseline ------------------------------------------------")
    rc, failed = _subprocess()
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
                print(f"FAIL  [{expect}] anchor not unique ({src.count(old)}): {label}")
                bad += 1
                continue
            path.write_text(src.replace(old, new))
            try:
                rc, failed = _subprocess()
            finally:
                path.write_text(src)
            if expect is None:
                if rc != 0:
                    print(f"PASS  caught: {label}  "
                          + (f"(via {failed})" if failed else "(the suite cannot run)"))
                else:
                    print(f"FAIL  MISSED: {label}  (the suite ran clean)")
                    bad += 1
            elif expect in failed:
                print(f"PASS  caught: {label}  (via {expect})")
            elif rc != 0:
                print(f"FAIL  wrong check caught {label!r}: want {expect}, "
                      f"got {failed or 'a crash'}")
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
