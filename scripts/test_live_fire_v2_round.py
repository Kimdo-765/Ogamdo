#!/usr/bin/env python3
"""One round of live-fire v2, driven without a model or a container.

The round runner owns no policy — whether a patch is good is the validator's
call, whether it fits is the merge's, whether a vulnerability is still open is
the board's. What it owns is SEQUENCE, and the failures that live there are
not the ones the other suites cover.

FOUR PROPERTIES.

1. A ROUND THAT PUBLISHES NOTHING MUST NOT SAY IT FIXED SOMETHING. If the
   integrated bundle fails validation, or is byte-identical to the last one,
   nothing reached the operator — so the accepted patches are NOT integrated,
   however cleanly they merged. Marking them would stop the board working on
   those vulnerabilities forever while the count still read as coverage.
   A DEFERRAL is true either way: the merge really could not take that patch.
   M-family.

2. THE BUDGET IS TAKEN AROUND THE STACK, NOT AROUND THE AGENT. An agent call
   is minutes of a model and costs docker nothing; a validation is a whole
   compose stack, containers and bridges both. Bound the wrong one and the
   round either starves or exhausts docker's address pool — and that second
   failure takes out every OTHER job on the host. S-family.

3. ONE BLUETEAM'S FAILURE IS ITS OWN. An agent that raises, changes nothing,
   or gets refused by the validator costs that assignment an attempt and
   nothing else; the others' work still reaches the bundle. B-family.

4. A FILE THE AGENT ADDED IS IGNORED, NOT FATAL. The ZIP is rebuilt from the
   input manifest, so an added file vanishes anyway — carrying it into a
   submission would make `integrate` defer the whole thing atomically and lose
   a good fix because of a scratch file. C-family.
"""

from __future__ import annotations

import hashlib
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ROUND_PY = ROOT / "modules" / "live_fire_v2_round.py"

from modules.live_fire_orchestrator import (  # noqa: E402
    AssignmentBoard,
    DEFERRED,
    FAILED,
    INTEGRATED,
    SlotBudget,
    Vulnerability,
)
from modules.live_fire_repo import RepoAgent  # noqa: E402
from modules.live_fire_v2_round import (  # noqa: E402
    BlueteamOutcome,
    LiveFireV2Runner,
    RETRY_RESERVE_S,
    _bundle_root,
    _rows_for,
    _scope_of,
    collect_changes,
    protected_paths,
)

_FAILED: list[str] = []
TMP = Path(os.environ.get("CLAUDE_JOB_DIR", "/tmp")) / "lf-v2round-test"

BUNDLE = "fo_src"
A_PHP = f"{BUNDLE}/src/a.php"
B_JS = f"{BUNDLE}/src/b.js"
BASE_A = b"<?php\nfunction a() {\n  echo 1;\n}\nfunction b() {\n  echo 2;\n}\n"
BASE_B = b"var x = 1;\nvar y = 2;\n"


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


class _Workspace:
    def __init__(self, root: Path):
        self.root = root
        self.original = root / "original"
        self.candidate = root / "candidate"


def fresh_workspace(name: str) -> _Workspace:
    root = TMP / name
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    ws = _Workspace(root)
    for side in (ws.original, ws.candidate):
        (side / BUNDLE / "src").mkdir(parents=True)
        (side / A_PHP).write_bytes(BASE_A)
        (side / B_JS).write_bytes(BASE_B)
        (side / BUNDLE / "docker-compose.yml").write_bytes(b"services: {}\n")
    return ws


@dataclasses.dataclass
class _Sla:
    """The half of the real SlaVerdict the round actually reaches into."""

    ok: bool = True
    checked: int = 10
    total: int = 10
    findings: tuple = ()
    unstable: tuple = ()
    broken: tuple = ()


@dataclasses.dataclass
class _Verdict:
    """A dataclass, like the real ValidationResult.

    It was a plain class that carried three attributes, which let the round
    reach for `verdict.broken` in a test and get an AttributeError instead of
    a verdict -- and made `dataclasses.replace` impossible. A stub thinner
    than the type it stands in for hides exactly the code that reads the
    missing parts.
    """

    ok: bool = True
    unexplained: tuple = ()
    availability: bool = True
    verdict: _Sla = None
    explained: tuple = ()

    def __post_init__(self):
        if self.verdict is None:
            # unexplained is a SUBSET of findings in the real type, so a stub
            # whose findings were empty while unexplained was not would let a
            # second stack "fail to reproduce" a finding it was handed.
            self.verdict = _Sla(ok=self.ok, findings=tuple(self.unexplained))

    def as_dict(self):
        return {"ok": self.ok}


class _Validator:
    """Stands in for the real validator; records what it was asked about."""

    def __init__(self, verdicts=None, budget=None):
        self.verdicts = verdicts or {}
        self.calls: list[tuple[str, list[str]]] = []
        self.budget = budget
        self.budget_at_call: list[int] = []

    def validate(self, tree, changed_paths, *, suffix, **kw):
        self.calls.append((suffix, list(changed_paths)))
        if self.budget is not None:
            self.budget_at_call.append(self.budget.in_use)
        result = self.verdicts.get(suffix)
        if callable(result):
            return result()
        return result if result is not None else _Verdict(True)


def make_runner(ws, *, invoke, verdicts=None, slots=2, board=None,
                zip_bytes=b"ZIP"):
    """A runner with a CLOCK, because the retry loop has no other bound.

    Nothing counts attempts any more, so a fixture whose blueteam is refused
    forever and whose patch differs every time would run until the suite was
    killed — and a mutation of the repeat guard has to be CAUGHT, not survived
    by hanging. The default lets about five attempts through, which is more
    than any check here wants and far less than forever. A check that cares
    about the clock sets its own afterwards.
    """

    budget = SlotBudget(slots)
    validator = _Validator(verdicts, budget)
    repo = RepoAgent(job_id="bf8d00c76ed8", workspace=ws,
                     output_root=ws.root / "out")
    counter = {"n": 0}

    def builder(_w, target: Path):
        counter["n"] += 1
        target.write_bytes(zip_bytes + str(counter["n"]).encode()
                           if zip_bytes is not None else b"Z")

    tick = {"t": 0.0}

    def clock():
        tick["t"] += 400.0
        return tick["t"]

    runner = LiveFireV2Runner(
        job_id="bf8d00c76ed8", workspace=ws, validator=validator, repo=repo,
        work_dir=ws.root / "work", invoke=invoke, board=board, budget=budget,
        zip_builder=builder, deadline=RETRY_RESERVE_S * 3, now=clock,
    )
    return runner, validator, budget


def plan_reply(*ids_paths):
    return json.dumps({
        "vulnerabilities": [
            # `attack` is required now: a lead nobody can attack is not
            # reported, so a fixture without one names nothing.
            {"id": vid, "bug_class": "xss", "path": path,
             "evidence": "line 3", "patch_direction": "escape it",
             "attack": "anonymous GET /?q=<script>alert(1)</script> comes back "
                       "unescaped in the page"}
            for vid, path in ids_paths
        ]
    })


def edit(tree: Path, rel: str, payload: bytes) -> None:
    (tree / rel).write_bytes(payload)


# ------------------------------------------------------------------ changes


def t_changes() -> None:
    ws = fresh_workspace("chg")
    patched = TMP / "chg-tree"
    if patched.exists():
        shutil.rmtree(patched)
    shutil.copytree(ws.original, patched)
    edit(patched, A_PHP, BASE_A.replace(b"echo 1;", b"echo esc(1);"))
    (patched / BUNDLE / "notes.txt").write_bytes(b"scratch")

    changed, added = collect_changes(ws.original, patched)
    check("C1", list(changed) == [A_PHP] and b"esc(1)" in changed[A_PHP],
          "only the edited file is collected")
    check("C2", added == [f"{BUNDLE}/notes.txt"],
          "a file the agent ADDED is reported separately, not folded into the "
          "submission — the ZIP is rebuilt from the input manifest so it "
          "vanishes anyway, and carrying it would make integrate() defer the "
          "whole submission and lose a good fix over a scratch file")
    check("C3", collect_changes(ws.original, ws.original) == ({}, []),
          "an untouched tree yields nothing")


# -------------------------------------------------------------------- round


def t_round_happy() -> None:
    ws = fresh_workspace("happy")
    seen: list[str] = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        seen.append(role)
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        if cwd is not None:
            target = A_PHP if "a.php" in prompt else B_JS
            payload = (BASE_A.replace(b"echo 1;", b"echo esc(1);")
                       if target == A_PHP else BASE_B.replace(b"y = 2", b"y = esc(2)"))
            edit(Path(cwd), target, payload)
        return "done"

    runner, validator, budget = make_runner(ws, invoke=invoke)
    result = runner.run_round(index=1, known=4)

    check("R1", result.identified == ("V1", "V2"),
          "the plan agent's leads become assignments")
    check("R2", all(o.submission is not None for o in result.outcomes),
          "both blueteams produced a validated patch")
    check("R3", result.published and result.published["vuln_clear"] == 2,
          "a version is cut carrying both")
    check("R4", runner.board.integrated() == ["V1", "V2"],
          "and the board records them as in the bundle")
    check("R5", result.remaining[0] == 2 and "2 of 4" in result.remaining[1],
          "the operator's count drives what is left")
    check("R6", seen.count("plan") == 1 and seen.count("blueteam") == 2,
          "one plan call, one blueteam per assignment")
    suffixes = [s for s, _ in validator.calls]
    check("R7", sorted(x for x in suffixes if x.startswith("bt"))
          == ["btv1", "btv2"]
          and any(x.startswith("integrated") for x in suffixes),
          "every patch is validated ALONE and the INTEGRATED bundle as well — "
          "two patches that each pass can still break together, and a bundle "
          "that fails with no attribution is a round nobody can act on")


def t_ship_early() -> None:
    """A validated patch ships when it validates, not when the round ends.

    Job 3d0cf9b6e883: V7 passed at 01:50:20 and sat unshipped for seven
    minutes while the round waited on two blueteams still retrying. V6, V4
    and V3 piled up behind it, and a scoring tick went by with
    four validated patches in hand and nothing submitted. The module already
    holds this principle for `patch-progress.json`; the bundle was the one
    thing still waiting for the end of the round.
    """

    ws = fresh_workspace("shipearly")
    started = threading.Event()
    release = threading.Event()
    versions_when_slow_was_still_running = {"n": None}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        if "V2" in prompt:
            # The slow one. It waits until the fast patch has had every
            # chance to ship, then records what the operator would have had.
            started.set()
            release.wait(timeout=10)
            versions_when_slow_was_still_running["n"] = len(runner.repo.history)
        edit(Path(cwd), A_PHP if "a.php" in prompt else B_JS, b"X\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke, slots=4)

    def unblock():
        started.wait(timeout=10)
        # Give the fast blueteam room to validate and ship.
        for _ in range(200):
            if runner.repo.history:
                break
            time.sleep(0.02)
        release.set()

    helper = threading.Thread(target=unblock)
    helper.start()
    result = runner.run_round(index=1, known=2)
    helper.join(timeout=10)

    check("R10", versions_when_slow_was_still_running["n"],
          "a patch that passed is published while the round is STILL "
          "RUNNING — the slowest blueteam does not hold the finished ones "
          "hostage, and a scoring tick that lands mid-round finds a bundle")
    check("R11", result.published is not None
          and runner.board.integrated() == ["V1", "V2"],
          "…and the round still reports what it shipped: the final bundle is "
          "byte-identical to one already published, so a round that read its "
          "verdict from that call alone would mark nothing integrated")


def t_round_refused() -> None:
    ws = fresh_workspace("refused")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        target = A_PHP if "a.php" in prompt else B_JS
        edit(Path(cwd), target, b"CHANGED\n")
        return "done"

    runner, validator, _ = make_runner(
        ws, invoke=invoke,
        verdicts={"btv1": _Verdict(False, unexplained=("x",))})
    result = runner.run_round(index=1, known=2)

    by_id = {o.vulnerability_id: o for o in result.outcomes}
    check("B1", by_id["V1"].submission is None
          and by_id["V1"].validation is not None,
          "a patch the validator refuses never becomes a submission, and the "
          "verdict travels with the outcome")
    check("B2", by_id["V2"].submission is not None,
          "…and the other blueteam's work is untouched by it")
    check("B3", runner.board.assignments["V1"].state == FAILED
          and runner.board.assignments["V1"].attempts == 2
          and by_id["V1"].reason == "repeated the refused patch",
          "a refusal is handed straight back to the SAME blueteam, and the "
          "loop ends when it returns the identical patch rather than on a "
          "count — paying another stack for the same verdict buys nothing")
    check("B4", result.published and result.published["vuln_clear"] == 1,
          "the round still ships what passed")


def t_retry_in_round() -> None:
    """A refusal is one model call away from a fix, not one round away.

    Job f432f9d8e16d: round 2 passed more patches than round 1.
    The blueteams did not get better — the plan agent spent 733 and
    453 seconds, and 25 of its 43 round-2 tool calls, digging the validator's
    findings off disk so it could rewrite `patch_direction` with them. That
    was the only channel through which "your patch changed this response line"
    reached the agent holding the file. Here it arrives directly, and the
    retry costs one model call and one stack instead of a whole round.
    """

    ws = fresh_workspace("retry")
    seen: list[str] = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        seen.append(prompt)
        # First try is wrong; once told what differed, it writes something
        # else — which is what a blueteam with the findings can actually do.
        payload = b"WRONG\n" if len(seen) == 1 else b"RIGHT\n"
        edit(Path(cwd), A_PHP, payload)
        return "done"

    calls = {"n": 0}

    def verdict_for_bt():
        calls["n"] += 1
        return _Verdict(True) if calls["n"] > 1 else _Verdict(
            False, unexplained=(_Finding("report_page",
                                         "body-extra-line", "<b>oops</b>"),))

    runner, _, _ = make_runner(ws, invoke=invoke,
                              verdicts={"btv1": verdict_for_bt})
    result = runner.run_round(index=1, known=1)

    check("Y1", len(seen) == 2,
          "a refused blueteam is handed the file again inside the same round")
    check("Y2", "body-extra-line" in seen[1]
          and "report_page" in seen[1]
          and "<b>oops</b>" in seen[1],
          "…and it is told the LINES that differed, not that there were 1 of "
          "them — a count is a number nobody can act on")
    check("Y3", "WHAT YOU CHANGED LAST TIME" in seen[1],
          "…together with its own last patch, because the tree is rebuilt "
          "from base for every attempt")
    check("Y4", "body-extra-line" not in seen[0],
          "the first attempt carries no findings, because there are none yet")
    # THE DIFF THE OPERATOR READS IS THE ONE THAT SHIPPED. The first attempt
    # wrote WRONG and was refused; the second wrote RIGHT and integrated.
    # `patch_one` computes the diff on each attempt, and a version that
    # reused whatever was already stored would leave the panel showing a
    # patch the bundle does not contain.
    check("Y9", "RIGHT" in runner.patches["V1"]["diff"]
          and "WRONG" not in runner.patches["V1"]["diff"],
          "the stored diff is the accepted attempt's, not the refused one's")
    check("Y5", result.outcomes[0].submission is not None
          and runner.board.assignments["V1"].state == INTEGRATED
          and result.published is not None,
          "the retry is what ships it — the same round integrates and cuts a "
          "version, where before this the vulnerability waited behind a plan "
          "agent that cost 733 seconds")
    check("Y6", not runner.board.assignments["V1"].findings,
          "and a vulnerability that passed carries no stale findings into the "
          "plan agent's next prompt")


def t_retry_out_of_time() -> None:
    """A retry that cannot be judged before the deadline is not started."""

    ws = fresh_workspace("retrytime")
    seen: list[str] = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        seen.append(prompt)
        # A new patch on the second try, then the same one forever: the loop
        # must end because the blueteam ran out of NEW work, not because a
        # counter did.
        edit(Path(cwd), A_PHP, f"TRY{min(len(seen), 2)}\n".encode())
        return "done"

    runner, _, _ = make_runner(
        ws, invoke=invoke,
        verdicts={"btv1": _Verdict(False, unexplained=("x",))})
    runner.deadline = 100.0
    runner.now = lambda: 0.0
    runner.run_round(index=1, known=1)
    check("Y7", len(seen) == 1,
          "a retry needs a blueteam call and the stack that judges it, so "
          "one that cannot finish before the deadline leaves its stack up "
          "when the job is killed — the failure ROUND_RESERVE_S exists for")

    ws = fresh_workspace("retrytime2")
    seen.clear()
    runner2, _, _ = make_runner(
        ws, invoke=invoke,
        verdicts={"btv1": _Verdict(False, unexplained=("x",))})
    # A clock that MOVES and a deadline far enough out that three attempts fit
    # easily. Without the deadline this check would be the only thing standing
    # between a mutation of the repeat guard and a suite that never returns —
    # a mutation has to be caught, not survived by hanging.
    tick = {"t": 0.0}

    def clock():
        tick["t"] += 400.0
        return tick["t"]

    runner2.deadline = RETRY_RESERVE_S * 4
    runner2.now = clock
    runner2.run_round(index=1, known=1)
    check("Y8", len(seen) == 3 and tick["t"] < runner2.deadline,
          "…while a runner with no deadline keeps handing it back until the "
          "blueteam stops producing new work — nothing counts attempts, and "
          "the operator is the only brake")


def t_sinks_in_plan_prompt() -> None:
    """The grep the plan agent used to run every round, handed to it instead."""

    ws = fresh_workspace("sinks")
    # A real sink in the workspace the runner reads.
    (Path(ws.original) / A_PHP).write_bytes(
        b"<?php\necho $_GET['x'];\n")
    # …and a compose file, because reachability is half of what makes a
    # connection a vulnerability and the runner reads it from the tree.
    (Path(ws.original) / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    ports:\n"
        "      - 80:80\n"
        "    networks:\n"
        "      - front\n"
        "      - back\n"
        "  worker:\n"
        "    networks:\n"
        "      - back\n",
        encoding="utf-8",
    )
    plans: list[str] = []
    calls = {"n": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            plans.append(prompt)
            calls["n"] += 1
            return plan_reply(("V1", A_PHP)) if calls["n"] == 1 else plan_reply()
        edit(Path(cwd), A_PHP, b"<?php\necho esc($_GET['x']);\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    runner.run_round(index=1, known=1)
    runner.run_round(index=2, known=1)

    check("K3", "echoes request data" in plans[0]
          and f"{A_PHP}:2" in plans[0],
          "the plan agent is handed every place request data reaches a sink, "
          "with the file and line, instead of spending turns grepping for "
          "them — 70% of a plan call is model time and 6% is running commands")
    check("K4", "not a finding" in plans[0] or "place to look" in plans[0],
          "…and told it is noisy on purpose, so a hit is somewhere to look "
          "rather than something to report")
    check("K6", "WHERE REQUEST DATA ENTERS" in plans[0],
          "…and the DOORS as well as the sinks: a vulnerability whose sink is "
          "an ordinary library call is invisible from the sink end")
    check("K7", "WHAT CAN REACH WHAT" in plans[0]
          and "REACHABLE FROM OUTSIDE" in plans[0],
          "…and which service the internet can reach, because a call to a "
          "host the request named is only a finding when the caller stands "
          "somewhere the attacker does not")
    # A SENTINEL, because "the digest is still there in round two" is true
    # whether it was re-used or computed again — and computing it again is
    # a tree walk per round for an answer that cannot have changed.
    runner._sinks = "SENTINEL-DIGEST"
    runner.run_round(index=3, known=1)
    check("K5", "SENTINEL-DIGEST" in plans[2],
          "the tree does not change under the plan agent's feet, so the "
          "digest is computed once per JOB and re-used, not per round")


def t_single_agent_listing() -> None:
    """When the fan-out collapses, the one agent still sees the whole tree.

    `summarise_tree` caps at 400 paths, which was fine when this branch meant
    "a small bundle". It does not mean that: every named part folding — a
    bundle of many small services, or one whose parts are all protected —
    lands here too, and on a tree past the cap every file beyond it was
    silently dropped. Those files reached no agent at all and nothing said so.
    """

    ws = fresh_workspace("onescope")
    root = Path(ws.original)
    # The fixture's two loose files would each land in `other` and make a
    # second scope, which is the branch this check is NOT about.
    (root / A_PHP).unlink()
    (root / B_JS).unlink()
    (root / BUNDLE / "src" / "app").mkdir(parents=True, exist_ok=True)
    for i in range(430):
        (root / BUNDLE / "src" / "app" / f"f{i:03d}.php").write_bytes(b"<?php\n")
    plans: list[str] = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            plans.append(prompt)
            return plan_reply()
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    # ONE scope, which is what every named part folding produces — a bundle of
    # many small services, or one whose parts are all protected. Stubbed
    # rather than coaxed out of a fixture, so the check is about the branch
    # and not about how many loose files the fixture happens to leave behind.
    only = [rel for rel, in [(f"{BUNDLE}/src/app/f{i:03d}.php",)
                             for i in range(430)]]
    runner.plan_scopes = lambda: [("app", only)]
    runner.identify(known=None, feedback="")
    listed = sum(1 for line in plans[0].splitlines() if line.endswith(".php"))
    check("F5", len(plans) == 1 and listed >= 430,
          "the single-agent branch lists EVERY path: `summarise_tree`'s "
          "four-hundred cap was silently dropping the tail of any bundle "
          "whose parts all folded, and an agent cannot report a file it was "
          "never shown")


def t_dependency_manifest_gate() -> None:
    """A pinned version is data, and the only place a dependency fix can live.

    The patch gate lets a pinned dependency manifest (a lockfile or a
    requirements list) through anywhere except under seed, fixture,
    migration, test, database and initdb directories; the scope fold makes
    no such exception.
    """

    check("F3", not protected_paths(["env/svc/requirements.txt"],
                                    allow_dependency_manifests=True)
          and protected_paths(["env/svc/requirements.txt"]),
          "the PATCH GATE lets a dependency manifest through and the SCOPE "
          "FOLD does not: the fold asks whether a directory is worth a plan "
          "agent, and a directory of lockfiles is not")
    blocked = ["db/seed/package.json", "db/seeds/Gemfile",
               "deploy/api/build.gradle", "tests/requirements.txt",
               "db/seeds/package-lock.json", "env/db/01_init.sql",
               "docker-compose.yml"]
    still = protected_paths(blocked, allow_dependency_manifests=True)
    check("F4", sorted(still) == sorted(blocked),
          "…and nothing else moves. A node seed directory IS a package.json "
          "whose scripts decide what accounts get planted, a Gemfile and a "
          "build.gradle execute, and a manifest under a seed, fixture, "
          "migration or test directory stays refused whatever its name")


def t_scope_budget() -> None:
    """Each plan agent gets its OWN budget, not the tail of somebody else's.

    The cap used to sit on the whole-tree walk and the partition happened
    afterwards, so the budget was spent in path-alphabetical order: the first
    service ate it and every later one got nothing. It was silent, too — the
    global "stopped at N" marker was copied into every scope, so the string was
    never empty, the prompt still rendered the section header, and the agent
    was told the grep had been done for it over one line saying it had stopped.
    """

    digest = "\n".join(
        [f"aaa/f{i}.php:{i}  [echoes request data]  echo $_GET['q'];"
         for i in range(150)]
        + [f"zzz/g{i}.php:{i}  [runs a shell]  system($cmd);" for i in range(5)]
        + ["... (stopped at 120 hits; read the tree for the rest)"]
    )
    late = _rows_for(digest, "zzz", "\n".join(f"zzz/g{i}.php" for i in range(5)),
                     limit=120)
    check("K12", len([r for r in late.splitlines() if "zzz/" in r]) == 5
          and "stopped at" not in late,
          "the alphabetically-last scope still gets ITS rows, and carries no "
          "truncation notice it did not earn — a scope that sorted late on a "
          "real bundle used to receive zero")
    early = _rows_for(digest, "aaa", "\n".join(f"aaa/f{i}.php" for i in range(150)),
                      limit=120)
    rows = early.splitlines()
    check("K13", len(rows) == 121 and rows[-1].startswith("...")
          and "120" in rows[-1],
          "…and a scope that overruns ITS OWN cap says so, in its own words — "
          "the global marker used to be copied into every scope whether that "
          "scope had been truncated or not")


def t_scope_all_protected() -> None:
    """A part with nothing a blueteam may edit does not get its own agent.

    A deployment directory is the shape: Dockerfiles and seed SQL, all on the
    protected list. Giving it a scope spends a whole plan call -- the round's
    longest serial step -- on files no patch may touch. The rule existed and
    had no check of its own, so the mutation that deletes it was caught only
    by whichever unrelated test happened to notice the extra agent, which is
    to say sometimes.
    """

    ws = fresh_workspace("scopes")
    root = Path(ws.original)
    (root / BUNDLE / "src" / "app").mkdir(parents=True, exist_ok=True)
    for name in ("one.php", "two.php", "three.php"):
        (root / BUNDLE / "src" / "app" / name).write_bytes(b"<?php\n")
    (root / BUNDLE / "src" / "env").mkdir(parents=True, exist_ok=True)
    for name in ("Dockerfile", "init.sql", "seed.sql"):
        (root / BUNDLE / "src" / "env" / name).write_bytes(b"x\n")

    runner, _, _ = make_runner(ws, invoke=lambda *a, **k: "")
    scopes = dict(runner.plan_scopes())
    env_files = [f for f in scopes.get("other", []) if "/env/" in f]
    check("F2", "app" in scopes and "env" not in scopes and len(env_files) == 3,
          "a scope whose files are ALL protected is folded into `other` "
          "rather than given an agent — it is still READ, because it is where "
          "an agent learns what the service is, but it is not worth a plan "
          "call of its own")


def t_rows_for() -> None:
    """Each plan agent gets its own rows, not every agent's."""

    digest = "\n".join([
        "svc_a/x.php:3  [echoes request data]  echo $_GET['q'];",
        "svc_b/y.php:9  [runs a shell]  system($cmd);",
        "svc_b/vendor.js  [minified: 2 lines, longest 9000 chars]  x1",
    ])
    only_a = _rows_for(digest, "svc_a", "svc_a/x.php\nsvc_a/z.php",
                       limit=120)
    check("K9", "svc_a/x.php" in only_a and "svc_b" not in only_a,
          "one digest is walked for the whole tree and each scope is handed "
          "only its own rows — an agent reading one service used to spend its "
          "attention on another service's vendored file")
    check("K10", "vendor.js" in _rows_for(digest, "svc_b", "svc_b/vendor.js",
                                          limit=120),
          "a summarised (minified) row carries no line number and must still "
          "be matched to its scope")
    check("K11", _rows_for(digest, "", "anything", limit=120) == digest,
          "with no scope there is one agent and a TRUNCATED listing, so the "
          "digest passes through whole rather than being filtered against a "
          "partial set of paths")
    # …and the WALK's own marker is not an agent's marker. The walk now runs
    # wide so the split has something to divide; whatever it says about its own
    # limit is about the walk, and handing it on tells the agent its slice was
    # cut when it was not.
    walked = digest + "\n... (stopped at 900 hits; read the tree for the rest)"
    starved = _rows_for(walked, "nowhere", "nowhere/x.php", limit=120)
    check("K15", "filled up before reaching this part" in starved,
          "a scope the walk never reached SAYS SO. An empty section is a "
          "claim: the prompt renders the full 'grepped for you' header over "
          "it, so a starved slice and a clean one must not be the same string")
    clean = _rows_for(digest, "nowhere", "nowhere/x.php", limit=120)
    check("K16", clean == "",
          "…and a scope the walk DID reach and found nothing in stays empty, "
          "so the section is omitted rather than filled with a false alarm")

    check("K14", _rows_for(walked, "", "anything", limit=120) == digest,
          "the WALK's truncation notice never reaches an agent — it used to be "
          "copied into every scope, so a starved slice was never empty and the "
          "prompt rendered a full section header over one line saying the walk "
          "had stopped")


def t_not_overfit() -> None:
    """The module must not only work on the bundle it was written against.

    Three structural assumptions had been fitted to a single directory
    layout, and none of them would have failed a test or a job: they would
    have degraded silently on the next bundle.
    """

    from modules.live_fire_validator import _is_dependency

    layouts = {
        "fo_src/src/kweb/a.php": "kweb",
        "fo_src/src/adminx/b.php": "adminx",
        "services/api/main.go": "api",
        "services/worker/w.go": "worker",
        "backend/src/index.ts": "backend",
        "cmd/server/main.go": "server",
    }
    got = {}
    for path, want in layouts.items():
        root = _bundle_root([path, want + "/x"]) if "/" in path else ""
        got[path] = _scope_of(path, root=path.split("/")[0]
                              if path.startswith(("fo_src/", "services/"))
                              else "")
    check("X1", all(got[p] == w for p, w in layouts.items()),
          f"a service is found however the bundle lays itself out — one "
          f"container name was the only shape this knew, and on "
          f"`services/api/` every path fell to 'other' and collapsed the "
          f"fan-out back to one agent: {got}")

    rails = [_scope_of(p) for p in ("app/controllers/x.rb", "app/models/y.rb")]
    check("X2", rails == ["app", "app"],
          "…and `apps/web/` holds services while Rails' `app/models/` is ONE "
          "service's own layout; treating both as containers split a single "
          "application into a scope per directory, each with its own agent")

    vendored = ["a/vendor/x.php", "a/node_modules/y.js", "s/.venv/lib/z.py",
                "p/site-packages/q.py", "r/target/debug/a.rs", ".git/config"]
    check("X3", all(_is_dependency(v) for v in vendored)
          and not _is_dependency("fo_src/src/kweb/a.php"),
          "code nobody wrote is skipped in every ecosystem, not just one "
          "or two")

    seeds = ["x/database/01.sql", "y/sql/seed.sql", "z/initdb/01.sql",
             "a/seeds/users.yml", "b/migrations/001.sql", "c/docker/Dockerfile",
             "d/infra/compose.yml"]
    blocked = protected_paths(seeds)
    check("X4", len(blocked) == len(seeds),
          "seed data is protected under every common directory name, not "
          "just one. A scoring server may log in with seeded accounts: "
          f"a patch that rewrites them breaks every authenticated request by "
          f"construction — unprotected here: "
          f"{[s for s in seeds if s not in blocked]}")
    check("X5", not protected_paths(["app/src/x.php", "svc/api/main.go"]),
          "…while ordinary source stays patchable")


def t_plan_fan_out() -> None:
    """One plan agent per part of the bundle, at the same time.

    The plan agent was the round's longest serial step and the whole round's
    biggest single cost: 733 of round one's 1170 seconds on job f432f9d8e16d
    and 453 of round two's 894 — one model reading one tree while nothing
    else happened. The parts of a bundle are independent, so they are read at
    the same time.
    """

    ws = fresh_workspace("fanout")
    src = Path(ws.original) / BUNDLE / "src"
    for service, rel in (("kweb", "one.php"), ("adminx", "two.php"),
                         ("dryad", "three.php")):
        (src / service).mkdir(parents=True, exist_ok=True)
        for n in range(4):
            (src / service / f"{n}{rel}").write_bytes(b"<?php\n")
    # A part too small to be worth an agent of its own.
    (src / "tiny").mkdir(parents=True, exist_ok=True)
    (src / "tiny" / "a.php").write_bytes(b"<?php\n")

    scoped: list[str] = []
    # THE FAN-OUT HAS TO ACTUALLY OVERLAP. Running the agents one after
    # another would leave every other check in here passing while the change
    # bought nothing: the plan agent is the round's longest serial step and
    # running it N times in a row is worse than running it once.
    gate = threading.Barrier(4, timeout=20)
    overlap = {"broken": False}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            try:
                gate.wait()
            except threading.BrokenBarrierError:
                overlap["broken"] = True
            scoped.append(prompt)
            # Each agent answers with its OWN V1: that is the trap the merge
            # exists for.
            if "kweb" in prompt:
                return plan_reply(("V1", A_PHP))
            if "adminx" in prompt:
                return plan_reply(("V1", B_JS))
            return json.dumps({"vulnerabilities": []})
        edit(Path(cwd), A_PHP if "a.php" in prompt else B_JS, b"X\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke, slots=6)
    runner.run_round(index=1, known=4)

    names = [n for n, _ in runner.plan_scopes()]
    check("F1", {"kweb", "adminx", "dryad"} <= set(names),
          "the bundle is split by service directory, the unit a "
          "vulnerability lives inside")
    check("F2", len(scoped) == len(names),
          "…and every part gets its own agent, in one fan-out")
    check("F3", all("WHOLE BUNDLE has 4" in p for p in scoped),
          "each agent is told the count is for the WHOLE bundle: handing "
          "'there are N' to M agents is how a fan-out returns N times M "
          "leads")
    check("F4", sorted(runner.board.assignments) == ["V1", "V2"],
          "two agents both answered V1 and the board holds two distinct "
          "vulnerabilities — ids are assigned centrally, because `admit()` "
          "keys on them")

    # THE BRANCH NOTHING RAN. This line only fires when the plan agents name
    # more than the contest announced, and no check reached it — so it went
    # on reading `vulnerability.exploitability` after that field was deleted,
    # and would have raised AttributeError on the first job that found a
    # vulnerability past the announced count. Every suite was green.
    ws2 = fresh_workspace("morethanknown")
    logs: list[str] = []

    def invoke2(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        edit(Path(cwd), A_PHP if "a.php" in prompt else B_JS, b"X\n")
        return "done"

    runner2, _, _ = make_runner(ws2, invoke=invoke2)
    runner2._log = logs.append
    runner2.run_round(index=1, known=1)
    check("F9", any("2 leads against 1 announced" in line for line in logs),
          "more leads than the contest announced is worth saying — and this "
          "is the branch that went on reading a deleted field because no "
          "check ever reached it")

    # The lane for a scope whose agent returned nothing must not say it
    # replied: the invoker logs its own failure and hands back "".
    ws3 = fresh_workspace("emptyplan")
    runner3, _, _ = make_runner(
        ws3, invoke=lambda role, *a, **k: "" if role == "plan" else "done")
    runner3.agents_path = ws3.root / "agents.json"
    runner3.run_round(index=1, known=1)
    lanes = {r["key"]: r for r in
             json.loads(runner3.agents_path.read_text())["agents"]}
    check("F11", all(r["state"] == "failed"
                     for r in lanes.values() if r["role"] == "plan"),
          "a plan agent that returned nothing is a FAILED lane, not a lane "
          "that says it replied — that is a whole part of the bundle "
          "unexamined, and the grid has to say so")

    trees = sorted(p.name for p in (ws.root / "work").glob("plan-*"))
    check("F10", len(trees) == len(names) and len(set(trees)) == len(trees),
          "each plan agent gets a working directory of its own — agents write "
          "scratch files, and three of them in one tree is a collision that "
          "killed one agent in a second with zero characters")

    check("F7", not overlap["broken"],
          "…and they run at the SAME TIME. One after another would leave "
          "every other check here passing while the change bought nothing")
    check("F8", "tiny" not in names,
          "a part with one file is folded in with the loose ones: giving it "
          "an agent costs a whole model call to read a single file")

    # A bundle with no src/<service> layout at all: one scope, one agent,
    # exactly as before the fan-out existed. Splitting a tree that has no
    # seams would hand several agents the same files and pay for each.
    flat = fresh_workspace("flat")
    flat_calls: list[str] = []

    def flat_invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            flat_calls.append(prompt)
            return json.dumps({"vulnerabilities": []})
        return "done"

    flat_runner, _, _ = make_runner(flat, invoke=flat_invoke)
    flat_runner.run_round(index=1, known=1)
    check("F6", len(flat_calls) == 1
          and "ONE PART" not in flat_calls[0]
          and "this service has 1" in flat_calls[0],
          "a bundle with no service layout is one scope and one agent, told "
          "the count plainly — a tree with no seams split into parts would "
          "hand several agents the same files and pay for each")

    check("F5", all(("only one part" in p) or ("ONE PART" in p)
                    for p in scoped),
          "and each is told it is looking at one part of several, so it does "
          "not stop early believing someone else has the rest")


def t_plan_streaming() -> None:
    """A lead reaches a blueteam WHEN IT LANDS, not when the last agent stops.

    The replies were drained into a list with `as_completed` and merged in one
    batch, so three plan agents finishing at 520s, 660s and 890s had every one
    of their leads held until 890s. Measured across nine rounds of five jobs
    that was 2m54 per round in which a blueteam could have been running and
    was not.

    PROVED BY DEADLOCK, NOT BY A STOPWATCH. The slow agents do not answer
    until a blueteam has run; a stopwatch check would pass on a machine that
    happened to schedule the threads kindly, and this one cannot. If leads
    wait for the last reply there is nothing to release them, the wait times
    out, and the blueteam lands at the END of `order` instead of the middle.
    """

    ws = fresh_workspace("streaming")
    src = Path(ws.original) / BUNDLE / "src"
    for service in ("kweb", "adminx", "dryad"):
        (src / service).mkdir(parents=True, exist_ok=True)
        for n in range(4):
            (src / service / f"{n}.php").write_bytes(b"<?php\n")

    released = threading.Event()
    order: list[str] = []
    lock = threading.Lock()

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            if "kweb" in prompt:
                with lock:
                    order.append("plan:fast")
                return plan_reply(("V1", A_PHP))
            released.wait(timeout=8)
            with lock:
                order.append("plan:slow")
            return json.dumps({"vulnerabilities": []})
        with lock:
            order.append("blueteam")
        released.set()
        edit(Path(cwd), A_PHP, b"X\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke, slots=6)
    # WHEN the board reached disk, not just whether. Measured on job
    # 8bd3c68d8df6: blueteams ran from 07:17:33 and live-fire-board.json was
    # first written at 07:22:46 -- 5m13s in which the operator's grid showed
    # agents working on a vulnerability list that did not exist, and in which
    # a crash would have lost every lead, because the resume path rebuilds
    # submissions from board.assignments.
    real_publish = runner.publish_board

    def publish_board():
        with lock:
            order.append("board")
        real_publish()

    runner.publish_board = publish_board
    runner.run_round(index=1, known=4)

    check("F14", "board" in order and "plan:slow" in order
          and order.index("board") < order.index("plan:slow"),
          "the board is written when the leads are ADMITTED, while the other "
          "plan agents are still reading — the grid names an agent for V1 and "
          "the board has to be able to say what V1 IS")
    check("F15", "board" in order and "blueteam" in order
          and order.index("board") < order.index("blueteam"),
          "…and BEFORE its blueteam starts, so a crash in that window cannot "
          "lose a lead that already has an agent and a tree")

    check("F12", "blueteam" in order and "plan:slow" in order
          and order.index("blueteam") < order.index("plan:slow"),
          "the first plan agent's lead reached a blueteam while the others "
          "were still reading the tree — every lead used to wait for the "
          "slowest agent, which is the round's longest step by design")
    check("F13", sorted(runner.board.assignments) == ["V1"],
          "…and the leads the later replies did not name are not invented: "
          "one agent answered, one vulnerability is on the board")


def t_ship_during_plan() -> None:
    """A validated patch is IN THE BUNDLE while the plan agents still read.

    The streaming check above proved the PRODUCING half: a lead reaches a
    blueteam when it lands. This is the consuming half, and it was missed,
    because `_collect` shipped every patch it was handed and `_collect`
    cannot start until `identify` has returned. Job 8bd3c68d8df6: blueteams
    from 07:17:33, a patch validated at 07:19:16, the last plan agent silent
    until 07:22:46 — and live-fire-patches.json, the board and the bundle all
    first written at 07:22:46. R10 could not see it: the round had not ended,
    so shipping "before the end of the round" was satisfied by a call that
    was still three and a half minutes late.

    PROVED BY DEADLOCK, like the streaming check: the slow plan agent does
    not answer until a version exists. If shipping waits for the fan-out
    there is nothing to release it, the wait times out, and the count it
    records is zero.
    """

    ws = fresh_workspace("shipplan")
    src = Path(ws.original) / BUNDLE / "src"
    for service in ("kweb", "adminx", "dryad"):
        (src / service).mkdir(parents=True, exist_ok=True)
        for n in range(4):
            (src / service / f"{n}.php").write_bytes(b"<?php\n")

    shipped = threading.Event()
    versions_while_the_plan_was_still_reading = {"n": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            if "kweb" in prompt:
                return plan_reply(("V1", A_PHP))
            shipped.wait(timeout=8)
            versions_while_the_plan_was_still_reading["n"] = len(
                runner.repo.history)
            return json.dumps({"vulnerabilities": []})
        edit(Path(cwd), A_PHP, b"X\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke, slots=6)

    def unblock():
        # Give the blueteam room to validate and ship, then let the other
        # plan agents answer whether it did or not — a regression must FAIL
        # this check, not hang the suite.
        for _ in range(400):
            if runner.repo.history:
                break
            time.sleep(0.02)
        shipped.set()

    helper = threading.Thread(target=unblock)
    helper.start()
    runner.run_round(index=1, known=4)
    helper.join(timeout=12)

    check("R12", versions_while_the_plan_was_still_reading["n"],
          "a patch that passed is in a published bundle while the PLAN "
          "agents are still reading the tree — shipping used to belong to "
          "the collector, which cannot run until the last of them has "
          "answered, so a fix that validated at 07:19 reached the operator "
          "at 07:22")


def t_plan_cut_off() -> None:
    """A plan agent the provider KILLED must not be recorded as answering.

    Job 7a92cd679e8c: one plan agent burned
    its whole budget, was killed mid-sentence, came back with 562 characters
    of prose, and the lane said `done: replied`. So a part of the tree nobody
    had finished reading was recorded as read, the drop
    line blamed the model's JSON, and the next round had no reason to try
    harder. The adapter knew — it yields a typed stop reason after killing
    the process group — and this layer kept the prose and dropped the field.
    """

    ws = fresh_workspace("cutoff")
    src = Path(ws.original) / BUNDLE / "src"
    for service in ("kweb", "adminx", "dryad"):
        (src / service).mkdir(parents=True, exist_ok=True)
        for n in range(4):
            (src / service / f"{n}.php").write_bytes(b"<?php\n")

    class _Invoke:
        """A callable carrying the seam the real provider shim carries.

        THREAD-LOCAL like the real one. The scopes are read at the same time,
        so an instance attribute would have each agent overwrite the others'
        verdict — and a stub that models the seam wrongly tests the wrong
        thing even when it is green.
        """

        def __init__(self) -> None:
            self._tl = threading.local()

        @property
        def last_error_kind(self):
            return getattr(self._tl, "kind", None)

        def __call__(self, role, system, prompt, *, cwd=None, timeout_s=0.0):
            if role == "plan":
                if "kweb" in prompt:
                    self._tl.kind = None
                    return plan_reply(("V1", A_PHP))
                # Killed: whatever it had written, and nothing parseable.
                self._tl.kind = "timeout"
                return "I was still reading when"
            self._tl.kind = None
            edit(Path(cwd), A_PHP, b"X\n")
            return "done"

    logs: list[str] = []
    runner, _, _ = make_runner(ws, invoke=_Invoke(), slots=6)
    runner._log = logs.append
    runner.run_round(index=1, known=4)

    # DERIVED, not counted: `plan_scopes` also emits an "other" lane for the
    # loose files, and a hardcoded number would make this test a statement
    # about the splitter instead of about the lane.
    lanes = {k: v for k, v in runner._agents.items() if k.startswith("plan:")}
    cut = [k for k, v in lanes.items() if v.get("state") == "failed"]
    answered = [k for k, v in lanes.items() if v.get("state") == "done"]
    check("F16", answered == ["plan:kweb"] and len(cut) == len(lanes) - 1,
          "a killed plan agent's lane says FAILED and only the one that "
          "really answered says done — the grid may not report a turn the "
          "provider cut as a turn that answered")
    check("F17", cut and all("cut off" in (lanes[k].get("detail") or "")
                             for k in cut),
          "…and says so in words the operator can act on, rather than a "
          "parser's error about column 2")

    drops = [m for m in logs if "not used" in m]
    check("F18", bool(drops) and "cut off" in drops[0],
          "the round's own line says the agent was cut off, not that it "
          "wrote bad JSON: a killed process is not a formatting mistake")
    check("F19", bool(drops) and ("adminx" in drops[0] or "dryad" in drops[0]),
          "…and NAMES THE PART nobody finished reading — without it the "
          "operator cannot tell which half of the bundle went unread")


def t_board_survives_a_silent_round() -> None:
    """A round where every plan agent returned nothing still writes a board.

    Leads are published as they are ADMITTED now, so the write at the end of
    `identify` is redundant on every round that found something — and exactly
    because of that it is the only one left on a round that found nothing. A
    first round whose agents all die would otherwise leave no board file at
    all, and "the job has not written a board" and "the job has no leads" are
    not the same sentence to anyone reading the panel.
    """

    ws = fresh_workspace("silentround")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        return ""

    runner, _, _ = make_runner(ws, invoke=invoke)
    published = {"n": 0}
    real = runner.publish_board

    def counting():
        published["n"] += 1
        real()

    runner.publish_board = counting
    runner.run_round(index=1, known=1)
    check("P1b", published["n"] >= 1,
          "the board is written even when no plan agent answered — an absent "
          "file reads as a broken job, not as an empty board")


def t_retry_keeps_its_best() -> None:
    """The retry carries the CLOSEST attempt, and remembers every one.

    Job 7b91e6188cea, V10: 1641, 1595, 378, 47, 1595, 432, 1595, 447. It
    reached 47 unexplained on the fourth try and came back at 1595 on the
    fifth, and nothing still held the patch that had got to 47 — `own_diff`
    was overwritten on every refusal. The repeat guard could not help: it
    compared one slot against the next patch, so the same verdict three times
    at positions 2, 5 and 7 was never ADJACENT and could not fire.
    """

    ws = fresh_workspace("bestattempt")
    seen: list[bytes] = []
    # near-miss, then a regression, then the same regression again
    payloads = [b"NEAR\n", b"WIDE\n", b"WIDE\n"]
    prompts: list[str] = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        prompts.append(prompt)
        payload = payloads[min(len(seen), len(payloads) - 1)]
        seen.append(payload)
        edit(Path(cwd), A_PHP, payload)
        return "done"

    calls = {"n": 0}

    def verdict_for_bt():
        calls["n"] += 1
        # 1 unexplained, then 3 — the second attempt is strictly worse.
        n = 1 if calls["n"] == 1 else 3
        return _Verdict(False, unexplained=tuple(
            _Finding("report_page", "body-extra-line", f"line {i}")
            for i in range(n)))

    runner, _, _ = make_runner(ws, invoke=invoke,
                               verdicts={"btv1": verdict_for_bt})
    runner.run_round(index=1, known=1)

    check("Y10", len(prompts) >= 3 and "NEAR" in prompts[2],
          "the third attempt is shown the NEAR MISS it made first, not the "
          "wider patch it made second — an attempt that nearly passed is the "
          "only useful thing a refused agent has")
    check("Y11", len(prompts) >= 3 and "line 2" not in prompts[2],
          "…and the findings that travel with it are that attempt's own, "
          "because a diff paired with somebody else's findings describes a "
          "patch that never existed")
    check("Y12", runner.board.assignments["V1"].state == FAILED
          and "same patch" in (runner.board.assignments["V1"].reason or ""),
          "a patch it has ALREADY handed back stops the loop even when the "
          "repeat is not the previous one — one slot of memory could only "
          "catch a repeat that came twice in a row")


def t_agent_grid_race() -> None:
    """Two agents recording state at once must not fight over one temp file.

    Job 3d0cf9b6e883 logged this on its first fan-out: three plan agents came
    up in the same second, all three wrote the same `.tmp`, the first rename
    moved it away and the others got "No such file or directory". The lock
    covered the dict and not the file the dict produces.

    Checked by SERIALISATION rather than by racing: if the write happens
    inside the lock, a second caller cannot enter while the first is in it,
    so a barrier the two would have to meet at times out. Racing for the
    failure would pass whenever the window happened to miss.
    """

    ws = fresh_workspace("gridrace")
    runner, _, _ = make_runner(ws, invoke=lambda *a, **k: "")
    runner.agents_path = ws.root / "live-fire-agents.json"

    import modules.live_fire_v2_round as R

    gate = threading.Barrier(2, timeout=2)
    met = {"both": False}
    real = R._write_json_atomic

    def slow(path, payload):
        try:
            gate.wait()
            met["both"] = True
        except threading.BrokenBarrierError:
            pass
        real(path, payload)

    R._write_json_atomic = slow
    try:
        threads = [threading.Thread(target=runner.agent_state,
                                    args=(f"V{n}", "running", "x"))
                   for n in (1, 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
    finally:
        R._write_json_atomic = real

    check("G5", not met["both"],
          "the file write is inside the lock, so two agents recording at "
          "once serialise instead of racing for the same temp file")
    check("G6", runner.agents_path.exists()
          and len(json.loads(runner.agents_path.read_text())["agents"]) == 2,
          "…and both lanes survive: serialising is not dropping one")


def t_agent_grid() -> None:
    """The operator's grid needs a lane per agent, which run.log cannot give.

    Blueteams starting in the same second write identical
    "blueteam agent starting" lines with no vulnerability id between them.
    """

    ws = fresh_workspace("grid")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        edit(Path(cwd), A_PHP if "a.php" in prompt else B_JS, b"X\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    runner.agents_path = ws.root / "live-fire-agents.json"
    runner.run_round(index=1, known=2)

    rows = {r["key"]: r for r in
            json.loads(runner.agents_path.read_text())["agents"]}
    check("G1", {"plan", "repo", "V1", "V2"} <= set(rows),
          "every agent has a lane: the plan agent, the repo agent, and one "
          "per vulnerability")
    check("G2", rows["V1"]["role"] == "blueteam"
          and rows["plan"]["role"] == "plan"
          and rows["repo"]["role"] == "repo",
          "…each labelled with the role it plays, so the grid can group them")
    check("G3", rows["V1"]["state"] == "done"
          and rows["V1"]["detail"] and rows["V1"]["finished_at"],
          "a finished lane says so, with what it did and when it stopped")
    check("G4", rows["plan"]["started_at"] and rows["plan"]["finished_at"],
          "and a lane carries both ends, so the grid can show elapsed time")


def t_plan_reply_unusable() -> None:
    """A plan agent's bad JSON costs its turn, not the job.

    Measured on job 9b908e2b715d: round 2's plan reply had an unescaped quote
    at character 996, parse_vulnerabilities raised, and a run that already had
    three validated patches in flight died with nothing published. The runner
    has always treated a BLUETEAM failure that way — one agent's bad turn
    costs that agent's turn — and the plan agent is not a special case.
    """

    ws = fresh_workspace("badplan")
    calls = {"n": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            calls["n"] += 1
            if calls["n"] == 1:
                return plan_reply(("V1", A_PHP))
            return '{"vulnerabilities": [{"id": "V2", "path": "x" oops}]}'
        edit(Path(cwd), A_PHP, BASE_A.replace(b"echo 1;", b"echo esc(1);"))
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    first = runner.run_round(index=1)
    check("N1", first.published is not None,
          "round one publishes normally")

    # Round two's plan reply is broken. The round must still run.
    second = runner.run_round(index=2)
    check("N2", second.identified == (),
          "a reply that cannot be parsed yields no new leads")
    check("N3", runner.board.integrated() == ["V1"],
          "…and the work already in the bundle is untouched — the job does "
          "not die with three validated patches in flight")


def t_round_agent_dies() -> None:
    ws = fresh_workspace("dies")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        if "a.php" in prompt:
            raise RuntimeError("provider exploded")
        edit(Path(cwd), B_JS, b"CHANGED\n")
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    result = runner.run_round(index=1)
    by_id = {o.vulnerability_id: o for o in result.outcomes}
    check("B5", by_id["V1"].submission is None
          and "provider exploded" in by_id["V1"].reason
          and by_id["V2"].submission is not None,
          "one agent dying costs that assignment and nothing else — the "
          "others' work is still valid and the reason is kept. Caught by the "
          "fan-out's guard; patch_one deliberately has none of its own, "
          "because a second one was indistinguishable from this")


def t_validator_explodes() -> None:
    """The outer handler in the fan-out, which B5 cannot reach.

    B5's agent raises INSIDE patch_one, which catches it itself. This raises
    in the validator — past that handler — so only the fan-out's own guard
    keeps the round alive.
    """

    ws = fresh_workspace("boom")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        target = A_PHP if "a.php" in prompt else B_JS
        edit(Path(cwd), target, b"CHANGED\n")
        return "done"

    def boom():
        raise RuntimeError("docker daemon went away")

    runner, _, _ = make_runner(ws, invoke=invoke, verdicts={"btv1": boom})
    result = runner.run_round(index=1)
    by_id = {o.vulnerability_id: o for o in result.outcomes}
    check("B7", by_id["V1"].submission is None
          and "docker daemon" in by_id["V1"].reason
          and by_id["V2"].submission is not None,
          "an error RAISED PAST patch_one — the validator itself failing — "
          "still costs only that assignment, and the reason survives on the "
          "board rather than the round dying")


def t_round_no_change() -> None:
    ws = fresh_workspace("nochange")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        return "I looked and decided not to change anything"

    runner, validator, _ = make_runner(ws, invoke=invoke)
    result = runner.run_round(index=1)
    check("B6", result.outcomes[0].reason == "no change"
          and runner.board.assignments["V1"].state == FAILED
          and not validator.calls,
          "a blueteam that changed nothing is a failed attempt and NO stack "
          "is raised for it — a validation of an unchanged tree costs a whole "
          "stack to prove nothing")


# ------------------------------------------------------- nothing published


def t_no_false_integration() -> None:
    ws = fresh_workspace("nofalse")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        edit(Path(cwd), A_PHP, BASE_A.replace(b"echo 1;", b"echo esc(1);"))
        return "done"

    runner, _, _ = make_runner(
        ws, invoke=invoke,
        verdicts={"integrated": _Verdict(False, unexplained=("y",)),
                  "integratedb": _Verdict(False, unexplained=("y",))})
    result = runner.run_round(index=1)

    check("M1", result.published is None and not result.integrated_ok,
          "an integrated bundle the validator refuses publishes nothing")
    check("M2", runner.board.assignments["V1"].state != INTEGRATED,
          "and the vulnerability is NOT marked integrated — nothing reached "
          "the operator, and marking it would stop the board ever working on "
          "it again while the count still read as coverage")

    ws2 = fresh_workspace("nofalse2")
    runner2, _, _ = make_runner(ws2, invoke=invoke, zip_bytes=None)
    runner2.run_round(index=1)
    second = runner2.run_round(index=2)
    check("M3", second.published is None
          and runner2.board.integrated() == ["V1"],
          "a second round that rebuilds a byte-identical bundle cuts no "
          "version, and does not un-integrate what the first one shipped")


class _Finding:
    """A line-level finding, shaped like the real SlaFinding."""

    def __init__(self, name, kind, detail):
        self.name, self.kind, self.detail = name, kind, detail


def _rows(detail):
    return _Finding("report_page", "body-extra-line", detail)


def _one_patch_invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
    if role == "plan":
        return plan_reply(("V1", A_PHP))
    edit(Path(cwd), A_PHP, BASE_A.replace(b"echo 1;", b"echo esc(1);"))
    return "done"


def t_second_opinion() -> None:
    """A failed bundle is re-judged in a fresh stack; only what repeats counts.

    Job f432f9d8e16d discarded a round's validated patches with one refused
    bundle. Each had passed validation on the full corpus, and their bundle
    was then refused on findings, every one of them a value the database
    maintains for itself, which can differ between two freshly seeded
    instances, with `broken` empty and availability holding. That variance
    lives BETWEEN stacks, so the validator's two confirmation passes, which
    share one stack, cannot see it.
    """

    ws = fresh_workspace("secondop")
    runner, val, _ = make_runner(
        ws, invoke=_one_patch_invoke,
        verdicts={"integrated": _Verdict(False, unexplained=(_rows("value-a"),)),
                  "integratedb": _Verdict(True)})
    result = runner.run_round(index=1)
    check("O1", result.published is not None and result.integrated_ok,
          "a finding the second stack does not reproduce is the environment, "
          "not the bundle, and the round ships")
    check("O2", [c[0] for c in val.calls][-2:] == ["integrated", "integratedb"],
          "…and the second opinion is a SEPARATE compose project, not another "
          "pass against the stack that raised the finding")
    check("O3", result.integrated is not None and result.integrated.ok
          and not result.integrated.unexplained,
          "the verdict recorded for the operator is the one we acted on — "
          "recording run one would show discarded findings as real")

    # A DIFFERENT value clears it too: identity includes the line.
    ws = fresh_workspace("secondop2")
    runner, _, _ = make_runner(
        ws, invoke=_one_patch_invoke,
        verdicts={"integrated": _Verdict(False, unexplained=(_rows("value-a"),)),
                  "integratedb": _Verdict(False, unexplained=(_rows("value-b"),))})
    check("O4", runner.run_round(index=1).published is not None,
          "a second stack reporting a DIFFERENT value clears the first one "
          "just as a clean stack would — the line is part of the finding")

    # And the thing the check exists for still fails.
    ws = fresh_workspace("secondop3")
    runner, _, _ = make_runner(
        ws, invoke=_one_patch_invoke,
        verdicts={"integrated": _Verdict(False, unexplained=(_rows("value-a"),)),
                  "integratedb": _Verdict(False, unexplained=(_rows("value-a"),))})
    result = runner.run_round(index=1)
    check("O5", result.published is None and not result.integrated_ok,
          "a break that repeats on an independent stack still refuses the "
          "bundle — two patches that each pass alone can break together, and "
          "an interaction reproduces in any stack")

    # Not judged is not the same as not there.
    ws = fresh_workspace("secondop4")
    unstable = _Verdict(True)
    unstable.verdict = _Sla(ok=True, findings=(),
                            unstable=("report_page",))
    runner, _, _ = make_runner(
        ws, invoke=_one_patch_invoke,
        verdicts={"integrated": _Verdict(False, unexplained=(_rows("value-a"),)),
                  "integratedb": unstable})
    result = runner.run_round(index=1)
    check("O6", result.published is None,
          "a request the second stack could not judge yields no evidence, so "
          "the finding is KEPT — dropping it would turn \"we did not look\" "
          "into \"it was not there\"")

    # Availability is terminal on either run.
    ws = fresh_workspace("secondop5")
    runner, val, _ = make_runner(
        ws, invoke=_one_patch_invoke,
        verdicts={"integrated": _Verdict(False, unexplained=("boom",),
                                         availability=False)})
    result = runner.run_round(index=1)
    check("O7", result.published is None
          and "integratedb" not in [c[0] for c in val.calls],
          "a bundle that will not come up is not a comparison artefact, so no "
          "second stack is paid for")


def t_deferral_survives() -> None:
    ws = fresh_workspace("defer")

    rounds = {"n": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            rounds["n"] += 1
            return plan_reply(("V1", A_PHP), ("V2", A_PHP))
        # Both blueteams rewrite the SAME line of the SAME file.
        if rounds["n"] > 1:
            # The re-tasked one, writing something it did not write before.
            edit(Path(cwd), A_PHP, BASE_A.replace(b"echo 1;", b"echo REDONE;"))
            return "done"
        payload = (BASE_A.replace(b"echo 1;", b"echo esc(1);")
                   if "V1" in prompt else
                   BASE_A.replace(b"echo 1;", b"echo (int)1;"))
        edit(Path(cwd), A_PHP, payload)
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    result = runner.run_round(index=1)
    board = runner.board
    states = {vid: board.assignments[vid].state for vid in ("V1", "V2")}
    won = [v for v, st in states.items() if st == INTEGRATED]
    lost = [v for v, st in states.items() if st == DEFERRED]
    check("M4", len(won) == 1 and len(lost) == 1,
          "of two patches to one line, exactly one is integrated and the "
          "other is deferred — WHICH one is not fixed, because a patch that "
          "has already shipped keeps its path, and which shipped first "
          "depends on which blueteam validated first. That is the price of "
          "never taking back a fix the operator already has")
    check("M5", board.assignments[lost[0]].attempts == 1
          and [a.vulnerability.id for a in board.ready()] == lost,
          "the deferred one is ready again — the tree it lost to now holds "
          "the other fix, so the conflict it hit no longer exists")
    check("M6", result.published and result.published["vuln_clear"] == 1,
          "the round ships the one that merged")

    # THE ONE PATH WHERE A STALE DIFF CAN SURVIVE. A deferred vulnerability
    # already has a stored patch from the round it lost in, and it is the
    # only kind that gets patched again — an integrated one never is. A
    # `patch_one` that reused whatever was already there would leave the
    # panel showing the losing patch under a vulnerability the bundle now
    # fixes a different way.
    before = runner.patches[lost[0]]["diff"]
    runner.run_round(index=2)
    after = runner.patches[lost[0]]["diff"]
    check("M8", "REDONE" in after and after != before,
          "a re-tasked deferral's stored diff is its NEW patch, not the one "
          "the merge refused a round ago")


# ------------------------------------------------------------------ budget


def t_deferral_without_publish() -> None:
    """Two patches collide AND the bundle is refused. Both facts must stick."""

    ws = fresh_workspace("defernopub")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", A_PHP))
        payload = (BASE_A.replace(b"echo 1;", b"echo esc(1);")
                   if "V1" in prompt else
                   BASE_A.replace(b"echo 1;", b"echo (int)1;"))
        edit(Path(cwd), A_PHP, payload)
        return "done"

    runner, _, _ = make_runner(
        ws, invoke=invoke,
        verdicts={"integrated": _Verdict(False, unexplained=("z",)),
                  "integratedb": _Verdict(False, unexplained=("z",))})
    runner.run_round(index=1)
    board = runner.board
    check("M7", board.assignments["V2"].state == DEFERRED
          and "overlaps" in board.assignments["V2"].reason,
          "a DEFERRAL is true whether or not a version was cut — the merge "
          "really could not take that patch, and losing that fact leaves the "
          "plan agent with no reason to give a different direction")
    check("M8", board.assignments["V1"].state != INTEGRATED,
          "…while ACCEPTANCE is not true, because nothing reached the operator")


def t_protected_paths() -> None:
    """Compose files, Dockerfiles and seed data are refused before any stack.

    A patch that rewrites the compose file can leave a stack nothing can
    reach, and a whole validation cycle is then spent discovering the patch
    had broken the HARNESS rather than the service.

    Seed data is the other half. The corpus authenticates with the seeded
    accounts, so a patch that changes them breaks every logged-in request by
    construction, and not one of the lines that then go missing is a service
    regression. A prompt asked for this boundary; enforcement holds it.
    """

    from modules.live_fire_v2_round import protected_paths

    blocked = protected_paths([
        f"{BUNDLE}/docker-compose.yml",
        f"{BUNDLE}/env/web/Dockerfile",
        f"{BUNDLE}/env/seed/01_seed.sql",
        A_PHP, B_JS,
    ])
    check("X1", set(blocked) == {
        f"{BUNDLE}/docker-compose.yml",
        f"{BUNDLE}/env/web/Dockerfile",
        f"{BUNDLE}/env/seed/01_seed.sql"},
        "the compose file, the Dockerfile and the database seed are all out "
        "of bounds; application source is not")

    ws = fresh_workspace("prot")

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP))
        # The blueteam edits its assigned file AND the compose file.
        edit(Path(cwd), A_PHP, BASE_A.replace(b"echo 1;", b"echo esc(1);"))
        edit(Path(cwd), f"{BUNDLE}/docker-compose.yml", b"services: {} # hacked\n")
        return "done"

    runner, validator, _ = make_runner(ws, invoke=invoke)
    result = runner.run_round(index=1)
    out = result.outcomes[0]
    check("X2", out.submission is None and "protected" in out.reason,
          "a patch that touches a protected file is refused")
    check("X3", not validator.calls,
          "…BEFORE the stack is raised. Left to the validator this costs an "
          "agent turn PLUS a whole stack to discover the patch broke the "
          "harness rather than the service")
    check("X4", "docker-compose" in runner.board.assignments["V1"].reason
          and "application source" in runner.board.assignments["V1"].reason,
          "and the board says WHICH file and where the fix has to live, so "
          "the plan agent can pick a different target instead of repeating it")


def t_patch_diff() -> None:
    """What the blueteam DID, not what the plan agent said to do.

    Those diverge, and the divergence is the interesting part: on job
    2de379a0139f the first V2 and V3 attempts followed their patch_direction
    exactly, were refused for breaking the SLA, and the second attempts
    succeeded by doing something the direction had never asked for. The board
    alone shows only the direction.
    """

    from modules.live_fire_v2_round import unified_patch, MAX_DIFF_LINES

    ws = fresh_workspace("diff")
    patched = BASE_A.replace(b"echo 1;", b"echo esc(1);")
    out = unified_patch(ws.original, {A_PHP: patched})
    check("D1", out["paths"] == [A_PHP] and out["added"] == 1
          and out["removed"] == 1,
          "a one-line change reads as one line added and one removed")
    check("D2", "-  echo 1;" in out["diff"] and "+  echo esc(1);" in out["diff"],
          "…and the diff shows both sides, so the operator can see the fix "
          "rather than read a description of it")

    binary = bytes(range(256)) * 4
    (ws.original / f"{BUNDLE}/blob.bin").write_bytes(binary)
    bin_out = unified_patch(ws.original, {f"{BUNDLE}/blob.bin": binary + b"x"})
    # A DECODE FAILURE IS NOT A BINARY: a text file in a legacy single-byte
    # encoding has no NUL byte in it. Calling such a file binary would report
    # "+0/-0" for a patch to it AND put the heading
    # WHAT YOU CHANGED LAST TIME above a byte count in the retry prompt.
    latin = "café: <?php echo 1; ?>\n".encode("latin-1")
    (ws.original / f"{BUNDLE}/latin.php").write_bytes(latin)
    lat_out = unified_patch(
        ws.original,
        {f"{BUNDLE}/latin.php": latin.replace(b"echo 1;", b"echo esc(1);")})
    check("D3b", "binary file" not in lat_out["diff"] and lat_out["added"] == 1
          and "esc(1)" in lat_out["diff"],
          "a file that is text in another encoding gets a REAL diff — the "
          "operator cannot review a patch reported as a byte count, and the "
          "agent retrying it is told it has seen a diff it has not")

    check("D3", "binary file" in bin_out["diff"],
          "a file with NUL bytes in it IS described rather than decoded — a "
          "diff that tried to render one would fill the panel with noise, and "
          "the byte counts are the only honest thing left to say about it")

    big = b"\n".join(b"line %d" % i for i in range(2000))
    (ws.original / f"{BUNDLE}/big.txt").write_bytes(big)
    # Every line replaced, so the raw diff is ~4000 lines and the cap is the
    # only thing that could bring it down.
    rewritten = b"\n".join(b"LINE %d" % i for i in range(2000))
    big_out = unified_patch(ws.original, {f"{BUNDLE}/big.txt": rewritten})
    check("D4", len(big_out["diff"].splitlines()) <= MAX_DIFF_LINES + 4
          and "more diff lines" in big_out["diff"],
          "a huge rewrite is capped, because nobody reads thousands of lines "
          "in a panel")

    # End to end: a validated patch reaches the sibling file, a refused one
    # does not.
    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        target = A_PHP if "a.php" in prompt else B_JS
        payload = (patched if target == A_PHP
                   else BASE_B.replace(b"y = 2", b"y = esc(2)"))
        edit(Path(cwd), target, payload)
        return "done"

    runner, _, _ = make_runner(
        ws, invoke=invoke, verdicts={"btv2": _Verdict(False, unexplained=("x",))})
    runner.board_path = ws.root / "live-fire-board.json"
    runner.patches_path = ws.root / "live-fire-patches.json"
    runner.run_round(index=1)

    saved = json.loads((ws.root / "live-fire-patches.json").read_text())["patches"]
    check("D5", "V1" in saved and "V2" not in saved,
          "only a patch the validator PASSED gets a diff — a refused one never "
          "reached the bundle and showing its diff would suggest it had")
    board = json.loads((ws.root / "live-fire-board.json").read_text())
    check("D6", board["patch_summary"]["V1"]["added"] == 1
          and "diff" not in board["patch_summary"]["V1"],
          "the polled board carries only the SIZE of the change; the diff "
          "itself lives in the sibling file, because the board crosses the "
          "wire every couple of seconds")


def t_board_published() -> None:
    """The board reaches disk the moment it changes, not at the end.

    A blueteam turn is minutes and a round is longer. An operator watching a
    live job wants to know WHICH vulnerabilities were found when the plan
    agent names them — the same reason patch-progress.json is written per
    version. News that arrives with the final report arrives after the tick it
    was needed for.
    """

    ws = fresh_workspace("board")
    seen_states = []

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(("V1", A_PHP), ("V2", B_JS))
        # Snapshot the file as the blueteams run, so "published early" is
        # observed rather than inferred from the final state.
        try:
            d = json.loads(board_file.read_text())
            seen_states.append(sorted(
                a["vulnerability"]["id"] for a in d["assignments"]))
        except Exception:
            pass
        target = A_PHP if "a.php" in prompt else B_JS
        payload = (BASE_A.replace(b"echo 1;", b"echo esc(1);")
                   if target == A_PHP else BASE_B.replace(b"y = 2", b"y = esc(2)"))
        edit(Path(cwd), target, payload)
        return "done"

    board_file = ws.root / "live-fire-board.json"
    runner, _, _ = make_runner(ws, invoke=invoke)
    runner.board_path = board_file
    runner.run_round(index=1)

    check("P1", seen_states and seen_states[0] == ["V1", "V2"],
          "the board is on disk WHILE the blueteams are still working — "
          "written when the plan agent named them, not when the round ended")

    final = json.loads(board_file.read_text())
    by_id = {a["vulnerability"]["id"]: a for a in final["assignments"]}
    check("P2", by_id["V1"]["state"] == INTEGRATED
          and by_id["V2"]["state"] == INTEGRATED,
          "…and it ends carrying the outcome, so the panel shows what became "
          "of each one")
    check("P3", by_id["V1"]["vulnerability"]["patch_direction"]
          and by_id["V1"]["vulnerability"]["bug_class"],
          "each row carries what the operator needs to read it: the class and "
          "the direction the plan agent gave")
    check("P4", final.get("submitted") == ["V1", "V2"],
          "and which ones produced a validated patch")

    # A view must never end the round.
    ws2 = fresh_workspace("board2")
    runner2, _, _ = make_runner(ws2, invoke=invoke)
    runner2.board_path = Path("/proc/nonexistent-dir/board.json")
    # Tolerant: a regression that lets the write escape should fail THIS check
    # with its reason, not take the suite down with it.
    try:
        result = runner2.run_round(index=1)
    except Exception as exc:
        result = type("_X", (), {"published": None, "why": repr(exc)})()
    check("P5", result.published is not None,
          "an unwritable board path does not end the round — it is a view, "
          "and losing it must not lose the work")


def t_budget() -> None:
    ws = fresh_workspace("budget")
    live = {"now": 0, "peak": 0}
    lock = threading.Lock()

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply(*[(f"V{i}", A_PHP) for i in range(1, 5)])
        with lock:
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
        time.sleep(0.05)
        edit(Path(cwd), A_PHP, BASE_A + f"// {prompt[:12]}\n".encode())
        with lock:
            live["now"] -= 1
        return "done"

    runner, validator, budget = make_runner(ws, invoke=invoke, slots=2)
    runner.run_round(index=1)
    check("S5", live["peak"] <= 2,
          "concurrent AGENT calls are capped too. The stack budget cannot do "
          "it — an agent holds no slot — so without this a plan agent naming "
          "twelve vulnerabilities opens twelve provider calls at once and the "
          "operator pays for all of them before the first verdict returns")
    check("S1", budget.peak <= 2,
          "the blueteams never put more than the budget of stacks up — "
          "exhausting docker's address pool fails every OTHER job on the host")
    check("S2", max(validator.budget_at_call) <= 2
          and min(validator.budget_at_call) >= 1,
          "and a slot is held FOR the validation, which is the thing that "
          "costs a whole stack")
    check("S3", budget.in_use == 0, "every slot is given back")

    src = ROUND_PY.read_text()
    acquire_before_validate = src.index("self.budget.acquire()") < src.index(
        "verdict = self.validator.validate(")
    check("S4", acquire_before_validate and "self.budget.acquire()" not in
          src[src.index("def patch_one"):src.index("changed, added =")],
          "the budget is NOT taken around the agent call: an agent is minutes "
          "of a model and costs docker nothing, so bounding it there starves "
          "the round for no benefit")


def t_cumulative() -> None:
    """The bundle is rebuilt from EVERY validated patch, not just this round's."""

    ws = fresh_workspace("cumul")
    round_no = {"n": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            round_no["n"] += 1
            return (plan_reply(("V1", A_PHP)) if round_no["n"] == 1
                    else plan_reply(("V2", B_JS)))
        target = A_PHP if "a.php" in prompt else B_JS
        payload = (BASE_A.replace(b"echo 1;", b"echo esc(1);")
                   if target == A_PHP else BASE_B.replace(b"y = 2", b"y = esc(2)"))
        edit(Path(cwd), target, payload)
        return "done"

    runner, _, _ = make_runner(ws, invoke=invoke)
    first = runner.run_round(index=1)
    second = runner.run_round(index=2)
    check("K1", first.published["vuln_clear"] == 1
          and second.published["vuln_clear"] == 2,
          "round two's bundle carries round one's fix as well — the bundle is "
          "cumulative, and rebuilding from the full set each time is what "
          "makes a deferred patch simply re-merge with no replay path to get "
          "wrong")
    check("K2", sorted(second.published["changed_paths"]) == sorted([A_PHP, B_JS]),
          "…and both files are in it")


def run_checks() -> bool:
    _FAILED.clear()
    TMP.mkdir(parents=True, exist_ok=True)
    for fn in (t_changes, t_round_happy, t_round_refused,
               t_ship_early,
               t_retry_in_round, t_retry_out_of_time,
               t_sinks_in_plan_prompt,
        t_single_agent_listing,
        t_dependency_manifest_gate,
        t_scope_budget,
        t_scope_all_protected,
        t_rows_for, t_not_overfit,
               t_plan_fan_out, t_plan_streaming, t_ship_during_plan,
               t_plan_cut_off, t_board_survives_a_silent_round,
               t_retry_keeps_its_best,
               t_agent_grid_race, t_agent_grid,
               t_plan_reply_unusable, t_round_agent_dies,
               t_validator_explodes, t_round_no_change,
               t_no_false_integration, t_second_opinion,
               t_deferral_survives,
               t_deferral_without_publish, t_protected_paths,
               t_patch_diff,
               t_board_published,
               t_budget, t_cumulative):
        fn()
    return not _FAILED


MUTATIONS = [
    ("only one container directory name holds services", ROUND_PY,
     '_CONTAINER_DIRS = ("src", "services", "service", "apps", "packages",\n'
     '                   "cmd", "modules")',
     '_CONTAINER_DIRS = ("src",)',
     "X1"),
    ("Rails' own app/ layout is read as a container of services", ROUND_PY,
     '_CONTAINER_DIRS = ("src", "services", "service", "apps", "packages",\n'
     '                   "cmd", "modules")',
     '_CONTAINER_DIRS = ("src", "services", "service", "apps", "app",\n'
     '                   "packages", "cmd", "modules")',
     "X2"),
    ("the bundle's own top directory becomes the only scope", ROUND_PY,
     "        bundle = _bundle_root(rels)",
     '        bundle = ""',
     None),
    ("seed data is protected under only one of its names", ROUND_PY,
     '    "/database/", "/db/", "/sql/", "/initdb/", "/seeds/", "/seed/",\n'
     '    "/fixtures/", "/migrations/",',
     '    "/database/",',
     "X4"),
    ("a part with nothing patchable still gets its own agent", ROUND_PY,
     "            if len(v) < self.MIN_SCOPE_FILES or len(protected_paths(v)) == len(v)",
     "            if len(v) < self.MIN_SCOPE_FILES",
     "F2"),
    ("the board is not written until the plan phase ends", ROUND_PY,
     "                self.publish_board()\n"
     "            # OUTSIDE the gate.",
     "                pass\n"
     "            # OUTSIDE the gate.",
     "F14"),
    ("a killed plan agent is recorded as having answered", ROUND_PY,
     '        if getattr(self.invoke, "last_error_kind", None) == "timeout":',
     "        if False:",
     "F16"),
    ("the round stops saying which part went unread", ROUND_PY,
     '                        f"{tag}: the agent was cut off at "',
     '                        f"the agent was cut off at "',
     "F19"),
    ("a cut reply is blamed on the model's formatting", ROUND_PY,
     '                        if was_cut else f"{tag}: {dropped[i]}"',
     '                        if False else f"{tag}: {dropped[i]}"',
     "F18"),
    ("a file that is text in another encoding is called binary", ROUND_PY,
     '        if (b"\\x00" in old_payload[:_BINARY_SNIFF]',
     "        if True or (b\"\\x00\" in old_payload[:_BINARY_SNIFF]",
     "D3b"),
    ("the retry is handed its last attempt instead of its best", ROUND_PY,
     "            own_diff, findings = best[1], list(best[2])",
     "            own_diff, findings = self._diff_text(changed), findings",
     "Y10"),
    ("the repeat guard forgets everything but the last attempt", ROUND_PY,
     "            if digest in seen:",
     "            if digest in list(seen)[-1:]:",
     "Y12"),
    ("leads wait for the last plan agent again", ROUND_PY,
     "            if on_leads is not None:",
     "            if False:",
     "F12"),
    ("a validated patch waits for the collector again — which cannot run "
     "until the last plan agent has answered", ROUND_PY,
     "            self.ship()",
     "            pass",
     "R12"),
    ("the round reads its verdict from the last build alone", ROUND_PY,
     "        published = self._round_published",
     "        published = self._last_merge and None",
     "R11"),
    ("two patches landing at once start two builds", ROUND_PY,
     "            if self._shipping:\n                self._ship_again = True\n                return",
     "            if False:\n                self._ship_again = True\n                return",
     None),
    ("a patch landing mid-build is forgotten", ROUND_PY,
     "                    if not self._ship_again:\n                        self._shipping = False\n                        return",
     "                    if True:\n                        self._shipping = False\n                        return",
     None),
    ("the submissions dict is iterated while threads write it", ROUND_PY,
     "        with self._ship_gate:\n            # A COPY.",
     "        if True:\n            # A COPY.",
     None),
    ("an empty plan reply is reported as a reply", ROUND_PY,
     '        if not (raw or "").strip():',
     "        if False:",
     "F11"),
    ("the plan agents share one working directory again", ROUND_PY,
     "                cwd=self._plan_tree_for(scope),",
     "                cwd=None,",
     "F10"),
    ("the agent-grid write escapes its lock", ROUND_PY,
     "                if self.agents_path is not None:\n"
     "                    _write_json_atomic(self.agents_path, payload)",
     "            if self.agents_path is not None:\n"
     "                _write_json_atomic(self.agents_path, payload)",
     "G5"),
    ("more leads than announced stops being reported", ROUND_PY,
     "        if known is not None and len(self.board.assignments) > known:",
     "        if False:",
     "F9"),
    ("a tree with no seams is split anyway", ROUND_PY,
     "        if len(scopes) < 2:",
     "        if len(scopes) < 0:",
     "F6"),
    ("the bundle is not split, so one agent reads all of it", ROUND_PY,
     "        if len(scopes) < 2:",
     "        if True:",
     "F2"),
    ("every part of the bundle lands in one scope", ROUND_PY,
     '        if part.lower() in _CONTAINER_DIRS:',
     '        if False:',
     "F1"),
    ("the plan agents are run one after another", ROUND_PY,
     "            workers = min(len(scopes), max(1, self.budget.slots))",
     "            workers = 1",
     None),
    ("a scope with two files gets an agent of its own", ROUND_PY,
     "    MIN_SCOPE_FILES = 3",
     "    MIN_SCOPE_FILES = 1",
     None),
    ("the doors are dropped, leaving only the sinks", ROUND_PY,
     '                    sources=_rows_for(self._sources, scope, listing,\n'
     '                                      limit=AGENT_SOURCE_LIMIT),',
     '                    sources="",',
     "K6"),
    ("the plan agent stops being told what can reach what", ROUND_PY,
     '                    topology=self._topology or "",',
     '                    topology="",',
     "K7"),
    ("the per-agent cap is dropped, so one scope can swallow the budget",
     ROUND_PY,
     "    if len(rows) > limit:",
     "    if False:",
     "K13"),
    ("the collapsed fan-out goes back to a four-hundred path cap", ROUND_PY,
     '            whole = "\\n".join(\n'
     "                rel for _name, files in scopes for rel in files\n"
     "            ) or summarise_tree(Path(self.workspace.original))",
     "            whole = summarise_tree(Path(self.workspace.original))",
     "F5"),
    ("a dependency manifest is refused at the gate again", ROUND_PY,
     "        if (allow_dependency_manifests\n"
     "                and name in _DEPENDENCY_MANIFESTS\n"
     "                and not any(d in lowered for d in _MANIFEST_NEVER_UNDER)):",
     "        if False:",
     "F3"),
    ("a manifest inside a seed directory slips through", ROUND_PY,
     "                and not any(d in lowered for d in _MANIFEST_NEVER_UNDER)):",
     "                and True):",
     "F4"),
    ("a starved scope is silent, so it reads as clean", ROUND_PY,
     "    elif not rows and walk_stopped:",
     "    elif False:",
     "K15"),
    ("a scope inherits another scope's truncation notice", ROUND_PY,
     '    rows = [r for r in digest.splitlines() if not r.startswith("...")]',
     "    rows = digest.splitlines()",
     "K14"),
    ("every scope is handed every scope's rows again", ROUND_PY,
     '            if rel in wanted:\n                kept.append(row)',
     "            kept.append(row)",
     "K9"),
    ("the plan agent greps for its own sinks again", ROUND_PY,
     '                    sinks=_rows_for(self._sinks, scope, listing,\n'
     '                                    limit=AGENT_SINK_LIMIT),',
     '                    sinks="",',
     "K3"),
    ("the digest is recomputed every round", ROUND_PY,
     "        if self._sinks is None:",
     "        if True:",
     "K5"),
    ("a refusal ends the round for that vulnerability again", ROUND_PY,
     "            if verdict.ok:\n                break",
     "            if True:\n                break",
     "Y1"),
    ("the blueteam is told a count instead of the lines", ROUND_PY,
     "            findings = self._finding_lines(verdict)",
     "            findings = [f'{len(verdict.unexplained)} unexplained']",
     "Y2"),
    ("the retry forgets what the blueteam changed", ROUND_PY,
     "            own_diff, findings = best[1], list(best[2])",
     '            own_diff, findings = "", list(best[2])',
     "Y3"),
    ("the first attempt is handed stale findings", ROUND_PY,
     "        findings = list(assignment.findings)",
     "        findings = ['[body-extra-line] r: x']",
     "Y4"),
    ("a passing patch keeps the findings that refused it", ROUND_PY,
     '        assignment.note(SUBMITTED, f"{len(changed)} file(s) validated",\n                        findings=[])',
     '        assignment.note(SUBMITTED, f"{len(changed)} file(s) validated")',
     "Y6"),
    ("a retry is started with no time to judge it", ROUND_PY,
     "        return self.now() + RETRY_RESERVE_S > self.deadline",
     "        return False",
     "Y7"),
    ("the same patch is paid for twice", ROUND_PY,
     "            if digest in seen:",
     "            if False:",
     "Y8"),
    ("the agent grid loses its per-agent lanes", ROUND_PY,
     '                row = self._agents.setdefault(\n                    key, {"key": key, "role": "blueteam",',
     '                row = self._agents.setdefault(\n                    "all", {"key": key, "role": "blueteam",',
     "G1"),
    ("every lane claims to be a blueteam", ROUND_PY,
     "                if role:\n                    row[\"role\"] = role",
     "                if False:\n                    row[\"role\"] = role",
     "G2"),
    ("a finished lane never stops", ROUND_PY,
     '                if state in ("done", "failed"):\n                    row["finished_at"] = stamp',
     '                if False:\n                    row["finished_at"] = stamp',
     "G3"),
    ("the failed bundle is never re-judged", ROUND_PY,
     "            verdict = self._second_opinion(verdict, sorted(merge.files))",
     "            verdict = verdict",
     "O1"),
    ("the second opinion reuses the stack that raised the finding", ROUND_PY,
     '                suffix="integratedb",',
     '                suffix="integrated",',
     "O2"),
    ("run one is recorded while the intersection is acted on", ROUND_PY,
     "        self._last_integrated = verdict\n        if not verdict.ok:\n"
     "            # Name the requests.",
     "        self._last_integrated = self._first_integrated\n"
     "        if not verdict.ok:\n            # Name the requests.",
     "O3"),
    ("a finding is identified by its request alone, not its line", ROUND_PY,
     '        str(getattr(finding, "detail", finding)),',
     '        "",',
     "O4"),
    ("any second opinion clears the bundle", ROUND_PY,
     "            f for f in first.unexplained if self._reproduced(f, second)",
     "            f for f in () if self._reproduced(f, second)",
     "O5"),
    ("a request the second stack skipped counts as cleared", ROUND_PY,
     "        if name in set(second.verdict.unstable) or name in set(second.verdict.broken):\n            return True",
     "        if False:\n            return True",
     "O6"),
    ("an unavailable bundle is paid for twice", ROUND_PY,
     "        if not first.availability or first.verdict.broken:",
     "        if False:",
     "O7"),
    ("a refused patch still gets a diff", ROUND_PY,
     "            patch = unified_patch(Path(self.workspace.original), changed)",
     "            patch = self.patches.get(vid) or unified_patch(\n"
     "                Path(self.workspace.original), changed)",
     "M8"),
    ("the whole diff is shipped in the polled board", ROUND_PY,
     '                vid: {k: patch[k] for k in ("paths", "added", "removed")}',
     "                vid: patch",
     "D6"),
    ("a binary file is decoded and takes the view down", ROUND_PY,
     '        if (b"\\x00" in old_payload[:_BINARY_SNIFF]\n'
     '                or b"\\x00" in new_payload[:_BINARY_SNIFF]):',
     "        if False:",
     None),
    ("a huge rewrite is shipped whole", ROUND_PY,
     "        if len(diff) > MAX_DIFF_LINES:",
     "        if False:",
     "D4"),
    ("a patch to the compose file reaches the validator", ROUND_PY,
     "            forbidden = protected_paths(\n"
     "                changed, allow_dependency_manifests=True)",
     "            forbidden = []",
     "X2"),
    ("the boundary is checked after the stack is raised", ROUND_PY,
     "        if forbidden:",
     "        if False:",
     "X2"),
    ("the deny list forgets the infrastructure directories", ROUND_PY,
     '_PROTECTED_DIRS = (\n    "/env/", "/deploy/", "/tests/", "/test/", "/infra/", "/docker/",\n    # Seed data, under every name these bundles give it.\n    "/database/", "/db/", "/sql/", "/initdb/", "/seeds/", "/seed/",\n    "/fixtures/", "/migrations/",\n)\n',
     '_PROTECTED_DIRS = ()\n',
     "X1"),
    ("the deny list forgets the compose file itself", ROUND_PY,
     '    "docker-compose",\n    "dockerfile",',
     '    "dockerfile",',
     "X1"),
    ("the refusal stops saying which file or where the fix belongs", ROUND_PY,
     '                    f"edited files a patch may not touch ({detail}); the fix "\n'
     '                    "has to live in application source",',
     '                    "refused",',
     "X4"),
    ("the board never reaches disk at all", ROUND_PY,
     "        if self.board_path is None:\n            return",
     "        if True:\n            return",
     None),
    ("a broken board path takes the round down with it", ROUND_PY,
     "        except Exception as exc:  # noqa: BLE001 - a view must not end a round",
     "        except ZeroDivisionError as exc:",
     "P5"),
    ("a file the agent added is folded into the submission", ROUND_PY,
     "        if not source.is_file():\n            added.append(rel)\n            continue",
     "        if not source.is_file():\n            added.append(rel)",
     None),
    ("an unchanged file is collected as a change", ROUND_PY,
     "        if payload != source.read_bytes():",
     "        if True:",
     "C3"),
    ("only the integrated bundle is validated", ROUND_PY,
     "                verdict = self.validator.validate(\n"
     "                    tree, sorted(changed), suffix=f\"bt{suffix}\"\n                )",
     "                verdict = _Skip()",
     None),
    ("a refused patch is submitted anyway", ROUND_PY,
     "            if verdict.ok:\n                break",
     "            if verdict is not None:\n                break",
     "B1"),
    ("a blueteam that changed nothing still raises a stack", ROUND_PY,
     "        if not changed:",
     "        if False:",
     "B6"),
    ("a failure past patch_one ends the whole round", ROUND_PY,
     "            except Exception as exc:  # noqa: BLE001\n"
     "                # One blueteam dying must not end the round",
     "            except ZeroDivisionError as exc:\n"
     "                # One blueteam dying must not end the round",
     None),
    ("a refused integrated bundle still marks its patches integrated", ROUND_PY,
     "            if published is not None:\n                self.board.apply_merge(merge)",
     "            if True:\n                self.board.apply_merge(merge)",
     "M2"),
    ("a deferral is forgotten when nothing is published", ROUND_PY,
     "                self.board.defer(merge.deferred)",
     "                pass",
     "M7"),
    ("the bundle is rebuilt from this round's patches only", ROUND_PY,
     "        submissions = [self.submissions[k] for k in sorted(self.submissions)]\n"
     "        if not submissions:",
     "        submissions = list(self.submissions.values())[-1:]\n"
     "        if not submissions:",
     "K1"),
    ("the budget is never taken, so stacks are unbounded", ROUND_PY,
     "            self.budget.acquire()\n            try:\n                verdict = self.validator.validate(\n"
     "                    tree, sorted(changed), suffix=f\"bt{suffix}\"\n                )\n"
     "            finally:\n                self.budget.release()",
     "            verdict = self.validator.validate(\n"
     "                tree, sorted(changed), suffix=f\"bt{suffix}\"\n            )",
     "S2"),
    ("the fan-out ignores the budget when sizing its pool", ROUND_PY,
     "                max_workers=max(1, self.budget.slots)) as pool:",
     "                max_workers=None) as pool:",
     "S5"),
    ("the integrated bundle is validated without a slot", ROUND_PY,
     "        self.budget.acquire()\n        try:\n            verdict = self.validator.validate(\n"
     "                Path(self.workspace.candidate),",
     "        if True:\n            verdict = self.validator.validate(\n"
     "                Path(self.workspace.candidate),",
     None),
    ("an exhausted assignment is handed to a blueteam again", ROUND_PY,
     "        for assignment in self.board.dispatch():",
     "        for assignment in list(self.board.assignments.values()):",
     None),
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

    # Derived, for the same reason: a mutation naming another module
    # would otherwise kill the run mid-loop with a KeyError.
    originals = {path: path.read_text() for _, path, *_ in MUTATIONS}
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
