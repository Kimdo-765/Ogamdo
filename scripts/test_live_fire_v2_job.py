#!/usr/bin/env python3
"""The v2 job: ingest, bootstrap, rounds, artifacts — with no model, no docker.

v1's run_job runs a patch LOOP; this runs ROUNDS, and the difference decides
what the job is allowed to do. A round has four agents in it, produces an
INTEGRATED bundle rather than a candidate, and can end with nothing published
without that being a failure.

WHAT THIS FILE DEFENDS, and none of it is covered by the module suites.

1. THE JOB STOPS FOR A NAMED REASON. Four of them, asked in order, and each
   one prevents a different waste: starting a round that cannot finish leaves
   a whole stack per blueteam up when the job is killed; running past the
   operator's count asks for vulnerabilities nobody says exist; re-asking the
   same question of the same tree pays twice for one answer. S-family.

2. THE OPERATOR'S FEEDBACK IS ACTUALLY READ. api/routes/jobs.py writes
   {"entries": [...]}, not {"feedback": [...]}, and a guessed key would read
   nothing — silently. The plan agent would never learn that a fix is not
   holding, which is the one signal that distinguishes "keep looking" from
   "what you already shipped is broken". F-family.

3. THE MODULE ID STAYS `live-fire`. The per-version feedback endpoint
   (api/routes/jobs.py) and the patch-history panel (web-ui/app.js) both key
   on it. A v2 job with a new id would silently lose the operator's entire
   interaction loop — history to read, feedback to enter. A-family.
"""

from __future__ import annotations

import hashlib
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

JOB_PY = ROOT / "modules" / "live_fire_v2_job.py"
ORCH_PY = ROOT / "modules" / "live_fire_orchestrator.py"
ROUTE_PY = ROOT / "api" / "routes" / "live_fire_module.py"

_TMP = tempfile.mkdtemp(prefix="lf-v2job-")
os.environ.update(DATA_DIR=_TMP, JOBS_DIR=str(Path(_TMP) / "jobs"))

from modules import live_fire_v2_job as J  # noqa: E402
from modules._common import write_meta  # noqa: E402
from modules.live_fire_orchestrator import INTEGRATED, STALL_NOTICE  # noqa: E402

_FAILED: list[str] = []
JOB = "aabbccddeeff"
BUNDLE = "fo_src"
A_PHP = f"{BUNDLE}/src/a.php"
BASE_A = b"<?php\necho 1;\n"


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


def make_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{BUNDLE}/docker-compose.yml", "services: {}\n")
        zf.writestr(A_PHP, BASE_A.decode())
    return path


@dataclasses.dataclass
class _Sla:
    ok: bool = True
    checked: int = 10
    total: int = 10
    findings: tuple = ()
    unstable: tuple = ()
    broken: tuple = ()


@dataclasses.dataclass
class _V:
    ok: bool = True
    availability: bool = True
    unexplained: tuple = ()
    explained: tuple = ()
    verdict: _Sla = dataclasses.field(default_factory=_Sla)

    def as_dict(self):
        return {"ok": self.ok}


class _Validator:
    """Never raises a stack; agrees unless a suffix is on the refuse list."""

    def __init__(self, refuse=()):
        self.established = False
        self.refuse = set(refuse)

    def propose(self, invoke, **kw):
        return ([], [])

    def establish(self, requests, ready):
        self.established = True

        class _B:
            coverage = "0/0"
            dropped = ()

        return _B()

    def validate(self, tree, changed, *, suffix, **kw):
        # DATACLASSES, like the real ValidationResult and SlaVerdict. A stub
        # that is merely attribute-compatible passes every check that reads it
        # and fails the moment the round builds a modified copy of it.
        refused = suffix in self.refuse
        findings = ("x",) if refused else ()
        return _V(ok=not refused, unexplained=findings,
                  verdict=_Sla(ok=not refused, findings=findings))


def fresh_job(job_id: str, *, known=None, timeout=3600) -> Path:
    jobs = Path(os.environ["JOBS_DIR"])
    root = jobs / job_id
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    write_meta(job_id, id=job_id, module="live-fire", status="queued",
               job_timeout=timeout,
               live_fire_known_vulnerabilities=known,
               live_fire_version=2)
    return root


class _RanAway(BaseException):
    """The round loop went round far more often than any healthy run does.

    A BaseException on purpose. `_plan_once` catches Exception around the
    provider call so one dead plan agent costs its own turn and not the
    round — which is right, and which would also swallow this. An abort
    signal is not an agent failing.
    """


# How many plan calls a runaway is. A healthy job here does a handful of
# rounds; this is the backstop, not a ceiling under test.
RUNAWAY_PLANS = 60


def marching_clock(step=1000.0):
    """A clock that MOVES, because the deadline is now the only way out.

    Every one of these jobs used to end on a ceiling and could run on a real
    clock. None of them can now: with no round limit, no attempt limit and no
    "nothing changed" stop, a job runs until its timeout.
    """

    tick = {"t": 0.0}

    def now():
        tick["t"] += step
        return tick["t"]

    return now


def _guard_runaway(invoke):
    """Count plan calls, and give up if the round loop never ends.

    THE DEADLINE CHECK IS THE ONLY WAY OUT of that loop now, so the mutation
    that removes it produces a program that does not terminate — and a
    mutation has to be CAUGHT, not survived by hanging. The count is on the
    plan call rather than on the clock because the mutation deletes the
    clock's only caller: a backstop has to watch something the loop does
    unconditionally.
    """

    seen = {"plans": 0}

    def guarded(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            seen["plans"] += 1
            if seen["plans"] > RUNAWAY_PLANS:
                raise _RanAway(
                    f"{seen['plans']} plan calls; the round loop never ended"
                )
        return invoke(role, system, prompt, cwd=cwd, timeout_s=timeout_s)

    return guarded


def run(job_id, *, invoke, known=None, timeout=3600, clock=None, refuse=()):
    """Runs a whole job — on a MARCHING CLOCK unless a check supplies its own.

    Every ceiling is gone: no round limit, no attempt limit, and none of the
    three "nothing changed" stops. The deadline is one of only two ways out
    and the operator is the other, so a job on a real clock would run for its
    full timeout. The default here makes the deadline arrive in a handful of
    rounds instead.
    """

    root = fresh_job(job_id, known=known, timeout=timeout)
    archive = make_zip(root / "input.zip")
    try:
        payload = J.run_job(job_id, str(archive),
                            invoke=_guard_runaway(invoke),
                            validator=_Validator(refuse),
                            clock=clock or marching_clock())
    except _RanAway as exc:
        # A verdict, not a crash: every check that reads `stop_reason` or the
        # round list then fails on its own terms and says what went wrong.
        payload = {"stop_reason": f"the round loop ran away — {exc}", "rounds": [],
                   "integrated": [], "versions": [],
                   "board": {"assignments": [], "stalled": []}}
    return payload, root


def plan_reply(*ids):
    return json.dumps({
        "vulnerabilities": [
            {"id": vid, "bug_class": "xss", "path": A_PHP,
             "evidence": "line 2", "patch_direction": "escape it",
             "attack": "anonymous GET /?q=<script>alert(1)</script> comes back "
                       "unescaped in the page"}
            for vid in ids
        ]
    })


def fixing_invoke(*, names=("V1",), rounds_of_names=None):
    """A plan agent that names `names`, and blueteams that really edit."""

    state = {"round": 0}

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            state["round"] += 1
            if rounds_of_names is not None:
                idx = state["round"] - 1
                chosen = (rounds_of_names[idx]
                          if idx < len(rounds_of_names) else ())
            else:
                chosen = names if state["round"] == 1 else ()
            return plan_reply(*chosen)
        vid = prompt.split()[1]
        (Path(cwd) / A_PHP).write_bytes(BASE_A + f"// {vid}\n".encode())
        return "done"

    return invoke


# ------------------------------------------------------------------- stops


def t_stop_all_found() -> None:
    result, root = run("a" * 12, invoke=fixing_invoke(names=("V1",)), known=1)
    check("S1", result["stop_reason"] == "out of time"
          and len(result["rounds"]) > 1,
          "the operator's count is a STATEMENT ABOUT THE BUNDLE, NOT A "
          "BUDGET: a job that has integrated all of them keeps looking, "
          "because the plan agent finding one more is exactly the case the "
          "operator asked to be covered")
    check("S2", result["integrated"] == ["V1"] and result["versions"],
          "and a version was cut")


def t_stop_nothing_left() -> None:
    result, _ = run("b" * 12, invoke=fixing_invoke(names=()), known=None)
    check("S3", result["stop_reason"] == "out of time"
          and len(result["rounds"]) > 1 and not result["integrated"],
          "an empty board is not a reason to stop either — the tree changes "
          "under the plan agent as patches land, so asking it again is not "
          "asking the same question")


def t_stop_no_progress() -> None:
    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply("V1")
        return "I could not fix it"

    result, _ = run("c" * 12, invoke=invoke, known=4)
    check("S4", result["stop_reason"] == "out of time"
          and len(result["rounds"]) > 1,
          "and neither is a round in which every blueteam failed; the "
          "orchestrator deciding it has paid enough is the operator's call, "
          "not its own")


def t_refused_bundle_keeps_going() -> None:
    """What actually ended job f432f9d8e16d, as a check.

    A round validated several patches. Their bundle was refused on findings,
    every one of them a value that differs between fresh stacks, so nothing
    was published; the plan agent had only re-sightings, so nothing
    was identified; and the job stopped — most of its vulnerabilities open
    and that round's finished patches on the floor while the operator still
    had budget.
    """

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply("V1", "V2") if "V1" not in prompt else plan_reply()
        vid = prompt.split()[1]
        (Path(cwd) / A_PHP).write_bytes(BASE_A + f"// {vid}\n".encode())
        return "done"

    result, _ = run("e" * 12, invoke=invoke, known=4,
                    refuse=("integrated", "integratedb"))
    check("S9", result["stop_reason"] == "out of time"
          and len(result["rounds"]) > 2,
          "a bundle the validator refuses costs that round's version, not the "
          "rest of the job — the orchestrator does not get to decide it has "
          "paid enough while the operator still has budget")


def t_no_attempt_ceiling() -> None:
    """Three refusals used to end a vulnerability for the whole job."""

    def invoke(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "plan":
            return plan_reply("V1")
        return "I could not fix it"

    result, root = run("g" * 12, invoke=invoke, known=1,
                       clock=marching_clock(step=300.0))
    board = {a["vulnerability"]["id"]: a
             for a in (result.get("board") or {}).get("assignments") or []}
    check("S10", (board.get("V1") or {}).get("attempts", 0) > STALL_NOTICE,
          "a vulnerability keeps getting a blueteam however many times it has "
          "failed: the cap that used to stop at three was a ceiling, and it "
          "removed the lead from the board for the rest of the run no matter "
          "how much budget was left")
    check("S11", "V1" in ((result.get("board") or {}).get("stalled") or []),
          "…and what replaced it is a REPORT — the board says where the time "
          "is going without deciding to stop spending it")


def t_stop_deadline() -> None:
    ticks = iter([0.0] + [10_000.0] * 40)

    def clock():
        try:
            return next(ticks)
        except StopIteration:
            return 10_000.0

    result, _ = run("d" * 12, invoke=fixing_invoke(names=("V1",)),
                    known=4, timeout=600, clock=clock)
    check("S5", result["stop_reason"] == "out of time" and not result["rounds"],
          "a round that cannot finish is not started — its stacks would still "
          "be up when the job is killed, leaking a whole stack per "
          "blueteam and leaving the operator nothing for the time spent")


def t_rounds_bounded() -> None:
    check("S6", not hasattr(J, "MAX_ROUNDS") and J.ROUND_RESERVE_S > 0,
          "there is NO round ceiling — the reserve is what makes the deadline "
          "check meaningful, and the deadline is one of the only two ways out")


# ---------------------------------------------------------------- feedback


def t_feedback_key() -> None:
    root = Path(os.environ["JOBS_DIR"]) / ("e" * 12)
    root.mkdir(parents=True, exist_ok=True)
    (root / "patch-feedback.json").write_text(json.dumps({
        "entries": [
            {"attempt": 1, "blocked": 3, "note": "tick 4"},
            {"attempt": 2, "blocked": 1, "note": "tick 5"},
        ]
    }))
    check("F1", J._blocked_count(root) == 1,
          "the LATEST entry is what the plan agent is told — feedback is a "
          "running score, not a total")
    text = J._feedback_text(root)
    check("F2", "V1: 3 attacks blocked" in text and "V2: 1 attacks blocked" in text,
          "every version's score reaches the prompt, so a fix that stopped "
          "holding is visible as a trend and not just a number")

    (root / "patch-feedback.json").write_text(json.dumps({"feedback": [
        {"attempt": 1, "blocked": 3}]}))
    check("F3", J._blocked_count(root) is None,
          "the key is `entries`, which is what api/routes/jobs.py writes — a "
          "guessed key reads nothing at all, silently, and the plan agent "
          "never learns that a fix is not holding")

    (root / "patch-feedback.json").write_text("not json")
    check("F4", J._blocked_count(root) is None and J._feedback_text(root) == "",
          "a corrupt feedback file is no feedback, not a dead job")


# ----------------------------------------------------------- module wiring


def t_module_identity() -> None:
    result, root = run("f" * 12, invoke=fixing_invoke(names=("V1",)), known=1)
    check("A1", result["module"] == "live-fire" and result["live_fire_version"] == 2,
          "the module id stays `live-fire` — the per-version feedback "
          "endpoint and the history panel both key on it, and a new id would "
          "silently take the operator's whole interaction loop away")
    check("A2", (root / "result.json").is_file()
          and (root / "report.md").is_file(),
          "the terminal artifacts land where the job already looks for them")
    check("A3", (root / "patch-progress.json").is_file(),
          "…and the version history the UI renders is written as versions are "
          "cut, not at the end: the scoring tick is the submission window")

    meta = json.loads((root / "meta.json").read_text())
    check("A4", meta.get("live_fire_version") == 2
          and meta.get("live_fire_integrated") == 1
          and meta.get("ready_to_deploy") is True,
          "meta carries what the job list needs to show without opening it")


def t_failure_is_recorded() -> None:
    """A job that dies must not keep saying `running`.

    Measured on the first real v2 run (a61b0ac5ce6b): the validator agent
    returned empty text because its provider had no credentials,
    parse_corpus raised, RQ recorded the failure — and meta still read
    `running` with `error: None`. The UI showed a live job that no process
    was working on. v1's run_job has always written a failure; v2's did not.
    """

    def broken(role, system, prompt, *, cwd=None, timeout_s=0.0):
        if role == "validator":
            return ""        # exactly what an unauthenticated provider returns
        return "done"

    job_id = "9" * 12
    root = fresh_job(job_id, known=1)
    archive = make_zip(root / "input.zip")

    class _RealParse:
        """Uses the real validator so parse_corpus is what raises."""

        def propose(self, invoke, **kw):
            from modules.live_fire_validator import parse_corpus
            from modules.live_fire_stack import Entrypoint
            raw = invoke("sys", "prompt")
            return parse_corpus(raw, entrypoints=[Entrypoint("n", 80, "net")])

        def establish(self, *a, **k):
            raise AssertionError("must not be reached")

        def validate(self, *a, **k):
            raise AssertionError("must not be reached")

    raised = None
    try:
        J.run_job(job_id, str(archive), invoke=broken, validator=_RealParse())
    except Exception as exc:
        raised = exc
    meta = json.loads((root / "meta.json").read_text())
    check("E1", raised is not None,
          "the exception still propagates, so RQ records the failure too")
    check("E2", meta.get("status") == "failed" and meta.get("stage") == "failed",
          "…and meta says FAILED rather than leaving a dead job looking alive")
    check("E3", "not JSON" in str(meta.get("error") or ""),
          "with the reason attached, so the operator can see it was the "
          "agent's empty reply and not the patcher")


def t_version_stamp() -> None:
    """The job list has to be able to SEE a new bundle for the alarm to fire.

    The flag alarm works by polling /api/jobs and noticing a value that grew.
    A patch version is the same shape of news, so the count has to be in meta —
    stamped per round, because that is where a version is cut and the operator
    should hear about it on the next poll rather than at the end of a job that
    may run for another hour.
    """

    result, root = run("7" * 12, invoke=fixing_invoke(names=("V1",)), known=1)
    meta = json.loads((root / "meta.json").read_text())
    check("N1", meta.get("live_fire_versions") == 1,
          "the number of published bundles is in meta, where the jobs poll "
          "can see it")
    check("N2", meta.get("live_fire_integrated") == 1,
          "…alongside how many vulnerabilities that bundle closes, which is "
          "what the toast shows")


def t_sla_feedback() -> None:
    """SLA pass is ground truth the validator cannot produce, and it is
    tri-state: not reported is not the same as failed."""

    root = Path(os.environ["JOBS_DIR"]) / ("s" * 12)
    root.mkdir(parents=True, exist_ok=True)
    (root / "patch-feedback.json").write_text(json.dumps({"entries": [
        {"attempt": 1, "blocked": 3, "sla_pass": True, "note": "tick 4"},
        {"attempt": 2, "blocked": 5, "sla_pass": False, "note": "tick 5"},
    ]}))
    text = J._feedback_text(root)
    check("L1", "V1: 3 attacks blocked · SLA PASS" in text
          and "V2: 5 attacks blocked · SLA FAIL" in text,
          "both signals reach the agents on every version, because they mean "
          "different things: blocked is progress against the red team, SLA is "
          "whether the service still works")
    check("L2", "FAILED V2 ON SLA" in text and "corpus missed" in text,
          "a failed SLA says WHY it matters — the validator passed that "
          "bundle, so its corpus missed whatever the scoring server checks — "
          "and asks for the smallest change next time")

    (root / "patch-feedback.json").write_text(json.dumps({"entries": [
        {"attempt": 1, "blocked": 3}]}))
    quiet = J._feedback_text(root)
    check("L3", "SLA not reported" in quiet and "FAILED" not in quiet,
          "an unreported SLA is reported as unreported — reading it as a "
          "failure would make every unscored version look like a regression")


def t_resume_restores() -> None:
    """A FIX cycle continues the job; it does not start a second one."""

    result, root = run("r" * 12, invoke=fixing_invoke(names=("V1",)), known=2)
    check("Q1", result["integrated"] == ["V1"], "the first cycle integrates V1")

    board = J._restore_board(root)
    check("Q2", board is not None and board.assignments["V1"].state == INTEGRATED,
          "the board survives the job that produced it")
    check("Q3", board.assignments["V1"].attempts == 1,
          "…with its attempt count intact. A FIX cycle is more information, "
          "not a fresh budget: an agent that failed three times does not get "
          "three more because a button was pressed")

    from modules.live_fire_orchestrator import PENDING as _P
    board2 = J._restore_board(root)
    board2.assignments["V1"].state = _P
    check("Q4", [a.vulnerability.id for a in board2.ready()] == ["V1"],
          "a restored board is a working board — its assignments can be "
          "handed straight back to a blueteam")


def t_route() -> None:
    src = ROUTE_PY.read_text()
    check("R1", "live_fire_version: Optional[int] = Form(None)," in src
          and src.index("live_fire_version: Optional[int]")
          > src.index("vulnerability_count: Optional[int]"),
          "the new form field is APPENDED — inserting one mid-signature "
          "silently reassigned every positional caller after it once already")
    check("R2", '"modules.live_fire_v2_job.run_job" if version == 2' in src,
          "v2 is enqueued to its own entry point")
    # Pinned to the META dict, not merely present in the file: the response
    # body carries the same key, and a check that only asks "is this string
    # anywhere" passes while meta loses it — and meta is what the job reads
    # back to decide which engine it is.
    check("R3",
          '"live_fire_contract": contract,\n        "live_fire_version": version,'
          in src,
          "the version is written into META, which is what the job itself "
          "reads back")
    check("R4", '"module": "live-fire",' in src,
          "while the module id is unchanged")

    form = (ROOT / "web-ui" / "index.html").read_text()
    check("R5", 'name="live_fire_version"' in form,
          "the form offers the engine, because the API/UI suite requires the "
          "form fields and the route parameters to be the same set")


def run_checks() -> bool:
    _FAILED.clear()
    for fn in (t_stop_all_found, t_stop_nothing_left, t_stop_no_progress,
               t_refused_bundle_keeps_going, t_no_attempt_ceiling,
               t_stop_deadline, t_rounds_bounded, t_feedback_key,
               t_module_identity, t_failure_is_recorded,
               t_version_stamp, t_sla_feedback,
               t_resume_restores, t_route):
        fn()
    return not _FAILED


MUTATIONS = [
    ("the round ceiling comes back", JOB_PY,
     "    index = 0\n    while True:\n        index += 1",
     "    index = 0\n    for _ in range(1):\n        index += 1",
     "S1"),
    ("the operator's count becomes a budget again", JOB_PY,
     '            log("job: every known vulnerability is integrated — still looking")',
     '            break',
     "S1"),
    ("an empty board ends the job again", JOB_PY,
     '            log("job: nothing on the board is ready; the next round asks the "\n                "plan agent again")',
     "            break",
     "S3"),
    ("a refused bundle ends the job again", JOB_PY,
     "        rounds.append(result.as_dict())",
     "        rounds.append(result.as_dict())\n"
     "        if result.published is None:\n            break",
     "S9"),
    ("a round is started with no time to finish it", JOB_PY,
     "        if now() + ROUND_RESERVE_S > deadline:",
     "        if False:",
     "S5"),
    ("the reserve is dropped, so the deadline check means nothing", JOB_PY,
     "ROUND_RESERVE_S = 420.0",
     "ROUND_RESERVE_S = 0.0",
     "S6"),
    ("feedback is read from the wrong key", JOB_PY,
     '    rows = payload.get("entries")',
     '    rows = payload.get("feedback")',
     "F1"),
    ("the plan agent is told the first score instead of the latest", JOB_PY,
     "    latest = rows[-1]",
     "    latest = rows[0]",
     "F1"),
    ("a corrupt feedback file ends the job", JOB_PY,
     "    except (OSError, json.JSONDecodeError):\n        return []",
     "    except OSError:\n        return []",
     None),
    ("a dead job keeps saying it is running", JOB_PY,
     '        write_meta(job_id, status="failed", stage="failed", error=str(exc)[:2000])',
     "        pass",
     "E2"),
    ("the failure reason is dropped", JOB_PY,
     'error=str(exc)[:2000])',
     'error=None)',
     "E3"),
    ("the job swallows the exception instead of failing the RQ job", JOB_PY,
     '        write_meta(job_id, status="failed", stage="failed", error=str(exc)[:2000])\n        raise',
     '        write_meta(job_id, status="failed", stage="failed", error=str(exc)[:2000])\n        return {}',
     "E1"),
    ("the published version count never reaches meta", JOB_PY,
     "            live_fire_versions=len(repo.history),",
     "            live_fire_versions=0,",
     "N1"),
    ("an unreported SLA reads as a failure", JOB_PY,
     '        mark = ("SLA PASS" if sla is True\n'
     '                else "SLA FAIL" if sla is False else "SLA not reported")',
     '        mark = "SLA PASS" if sla is True else "SLA FAIL"',
     "L3"),
    ("a failed SLA arrives with no explanation of what it means", JOB_PY,
     "    failed = [r for r in rows if r.get(\"sla_pass\") is False]",
     "    failed = []",
     "L2"),
    ("the attempt ceiling comes back", ORCH_PY,
     "                if a.state in (PENDING, DEFERRED, FAILED)",
     "                if a.state in (PENDING, DEFERRED, FAILED)\n"
     "                and a.attempts < STALL_NOTICE",
     "S10"),
    ("a stalled vulnerability is dropped instead of reported", ORCH_PY,
     "            if a.state not in _TERMINAL and a.attempts >= STALL_NOTICE",
     "            if False",
     "S11"),
    ("a resumed board loses its attempt counts", JOB_PY,
     '            attempts=int(row.get("attempts") or 0),',
     "            attempts=0,",
     "Q3"),
    ("the job reports a different module id", JOB_PY,
     '        "module": "live-fire",\n        "live_fire_version": 2,',
     '        "module": "live-fire-v2",\n        "live_fire_version": 2,',
     "A1"),
    ("the version history is not written", JOB_PY,
     "    repo = RepoAgent(job_id=job_id, workspace=workspace, output_root=root, log=log)",
     "    repo = RepoAgent(job_id=job_id, workspace=workspace,\n"
     "                     output_root=root / 'hidden', log=log)",
     "A3"),
    ("meta stops carrying what the job list shows", JOB_PY,
     "        live_fire_integrated=len(integrated),",
     "        live_fire_integrated=0,",
     "A4"),
    ("v2 is enqueued to the v1 entry point", ROUTE_PY,
     '        "modules.live_fire_v2_job.run_job" if version == 2\n'
     '        else "modules.live_fire_job.run_job",',
     '        "modules.live_fire_job.run_job",',
     "R2"),
    ("the version never reaches meta", ROUTE_PY,
     '        "live_fire_contract": contract,\n        "live_fire_version": version,',
     '        "live_fire_contract": contract,',
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

    # Every file MUTATIONS names, not just the two this suite started
    # with: a path missing here is a KeyError halfway through the run,
    # which reads as the suite crashing rather than a mutation escaping.
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
