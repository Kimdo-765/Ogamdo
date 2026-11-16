"""The RQ entry point for live-fire v2: ingest, bootstrap, rounds, artifacts.

v1's `live_fire_job.run_job` runs a patch LOOP: one agent, one candidate tree,
attempts until a gate passes. v2 runs ROUNDS, and the difference is not
cosmetic — a round has four agents in it, produces an integrated bundle rather
than a candidate, and can end with nothing published without that being a
failure of the job.

WHAT DECIDES WHEN TO STOP — there are exactly two:

  * the deadline. A defence contest is scored on a tick and the operator's
    budget is the job timeout; a round that starts too late to finish is worse
    than no round, because its stacks are still up when the job is killed.
  * the operator, whose stop arrives from outside as RQ's STOP_JOB.

AND NOTHING ELSE. There were three more once — every known vulnerability
integrated, no work left, and a round that changed nothing — and each was the
orchestrator deciding it had paid enough while the operator still had budget.
The last of them ended job f432f9d8e16d two rounds in, with most of its
vulnerabilities open and three validated patches on the floor, because one
environmental finding refused the bundle. The count is now a log line.

THE ARTIFACTS ARE THE OPERATOR'S, NOT THE JOB'S. `patch-progress.json` is
written by the repo agent as each version is cut, so a fix that exists at
minute three is downloadable at minute three; the scoring tick is the
submission window, not the job. `report.md` and `result.json` are written at
the end. The module id stays `live-fire` on purpose — the per-version feedback
endpoint and the history panel both key on it, and v2 changing the id would
silently take away the operator's whole interaction loop.
"""

from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable

from modules._common import job_dir, read_meta, write_meta
from modules.live_fire_orchestrator import (
    AssignmentBoard,
    DEFAULT_SLOTS,
    INTEGRATED,
    LOWEST_PRIORITY,
    PENDING,
    SUBMITTED,
    SlotBudget,
)
from modules.live_fire_repo import RepoAgent
from modules.live_fire_stack import StackLimits
from modules.live_fire_v2_round import (
    BLUETEAM_TIMEOUT_S,
    PLAN_TIMEOUT_S,
    LiveFireV2Runner,
)
from modules.live_fire_validator import ValidatorAgent
from modules.live_fire_workspace import create_workspace, load_workspace

WORKSPACE_NAME = "live-fire-workspace"
RESULT_NAME = "result.json"
# The vulnerability board, at the job root so the UI can fetch it by path the
# same way it already fetches patch-progress.json.
BOARD_NAME = "live-fire-board.json"

# THERE IS NO ROUND CEILING. A round is one plan call, N blueteam calls and
# N+1 stack validations, so it is minutes; the job runs rounds until its
# timeout or until the operator stops it, and nothing else.

# Reserve for the final round's own work. Starting a round with less than this
# left means its stacks are still up when the job is killed, which leaks a
# whole stack per blueteam and leaves the operator nothing for the time spent.
ROUND_RESERVE_S = 420.0


class _ProviderInvoke:
    """Routes a v2 role to its provider and runs one turn.

    Kept as a callable rather than wired into the runner so a test can drive
    the whole job with no model in the loop — the same seam the validator and
    the round runner already use.
    """

    def __init__(self, job_id: str, *, plan_tree: Path, log=None):
        from modules.live_fire_agent import LiveFireInvoker
        from modules.live_fire_provider import AgentCall, resolve_live_fire_route

        self.job_id = job_id
        self.plan_tree = Path(plan_tree)
        self._AgentCall = AgentCall
        self._resolve = resolve_live_fire_route
        self._invoker = LiveFireInvoker(job_id, log=log)
        self._attempts: dict[str, int] = {}
        # HOW THE LAST TURN ON THIS THREAD ENDED. `run_turn` returns the text
        # and an AgentUsage that says whether the turn was cut; returning only
        # the text threw that away, and `_plan_once` then recorded a killed
        # plan agent as done/"replied". Thread-local because `identify` runs
        # one of these per scope at once through a single instance.
        self._last = threading.local()

    def __call__(
        self, role: str, system: str, prompt: str, *, cwd: Path | None = None,
        timeout_s: float = PLAN_TIMEOUT_S,
    ) -> str:
        route = self._resolve(self.job_id, role)
        self._attempts[role] = self._attempts.get(role, 0) + 1
        call = self._AgentCall(
            job_id=self.job_id,
            route=route,
            stage=role,
            attempt=self._attempts[role],
            payload=None,
        )
        # A read-only role still needs a working directory its tools can use:
        # the plan agent reads the tree, and an agent that cannot write a
        # scratch file fails for a reason that has nothing to do with the task.
        working = Path(cwd) if cwd is not None else self.plan_tree
        text, usage = self._invoker.run_turn(
            call, system, prompt,
            cwd=working, turn_timeout_s=timeout_s, tools=True,
        )
        self._last.error_kind = getattr(usage, "error_kind", None)
        return text

    @property
    def last_error_kind(self) -> str | None:
        """Why this thread's last turn ended, or None if it ended normally.

        A property rather than a return value because `invoke` is a plain
        callable everywhere it is used, including in the suites' stubs; a
        caller that does not know to ask gets exactly today's behaviour.
        """

        return getattr(self._last, "error_kind", None)


def _refresh_plan_tree(original: Path, dest: Path) -> Path:
    from modules.live_fire_v2_round import _make_writable

    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(original, dest, symlinks=True)
    _make_writable(dest)
    return dest


def _restore_board(root: Path) -> AssignmentBoard | None:
    """Rebuild the board a finished cycle left behind."""

    from modules.live_fire_orchestrator import Assignment, Vulnerability

    try:
        payload = json.loads((root / BOARD_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    board = AssignmentBoard()
    for row in payload.get("assignments") or []:
        raw = row.get("vulnerability") or {}
        if not raw.get("id"):
            continue
        board.assignments[str(raw["id"])] = Assignment(
            vulnerability=Vulnerability(
                id=str(raw["id"]),
                bug_class=str(raw.get("bug_class") or "unknown"),
                path=str(raw.get("path") or ""),
                evidence=str(raw.get("evidence") or ""),
                patch_direction=str(raw.get("patch_direction") or ""),
                # Carried, or a resumed board would sort every lead last.
                priority=int(raw.get("priority") or LOWEST_PRIORITY),
                # Carried too: a resumed blueteam would otherwise be told what
                # the code does wrong and not what the exploit sends.
                attack=str(raw.get("attack") or ""),
            ),
            state=str(row.get("state") or PENDING),
            # ATTEMPTS ARE CARRIED, NOT RESET. A FIX cycle is more information,
            # not a fresh budget: an agent that could not fix something in
            # three tries does not get three more just because the operator
            # pressed a button.
            attempts=int(row.get("attempts") or 0),
            reason=str(row.get("reason") or ""),
            history=list(row.get("history") or []),
            # The findings are carried too, so a vulnerability re-opened by a
            # FIX cycle starts with what refused it rather than a count.
            findings=[str(f) for f in (row.get("findings") or [])],
        )
    return board if board.assignments else None


def _restore_submissions(root: Path, workspace: Any) -> dict[str, Any]:
    """Rebuild what each blueteam contributed, from the trees it left on disk.

    The trees are still there — one per vulnerability, each a copy of base
    with that blueteam's edits — so the submissions can be reconstructed
    exactly rather than stored a second time. A vulnerability whose tree is
    gone simply has no submission and is re-patched.
    """

    from modules.live_fire_repo import PatchSubmission
    from modules.live_fire_v2_round import collect_changes

    board = _restore_board(root)
    out: dict[str, Any] = {}
    if board is None:
        return out
    work = root / "live-fire-v2"
    for vid, assignment in board.assignments.items():
        if assignment.state not in (SUBMITTED, INTEGRATED):
            continue
        tree = work / f"bt-{vid.lower()}"
        if not tree.is_dir():
            continue
        try:
            changed, _added = collect_changes(Path(workspace.original), tree)
        except OSError:
            continue
        if not changed:
            continue
        out[vid] = PatchSubmission(
            vulnerability_id=vid,
            bug_class=assignment.vulnerability.bug_class,
            path=assignment.vulnerability.path,
            summary=assignment.vulnerability.patch_direction,
            mitigation_class="unknown",
            files=changed,
            # A RESUMED job orders its merge by severity like any other. Left
            # off, every rebuilt submission ties at the default and the merge
            # falls back to the id -- which, since plan replies are merged as
            # they land, is the order the leads arrived in.
            priority=assignment.vulnerability.priority,
        )
    return out


def run_job(
    job_id: str,
    archive_path: str,
    *,
    invoke: Callable[..., str] | None = None,
    validator: Any = None,
    clock: Callable[[], float] | None = None,
    resume: bool = False,
) -> dict[str, Any]:
    """Ingest → bootstrap → rounds → artifacts.

    `resume=True` is the operator's FIX button: the same job, continued. The
    workspace, the board, the blueteam trees and the version history are all
    still on disk, so the cycle picks up where it stopped and the next bundle
    is V(n+1) rather than a second V1 in a different job.
    """

    now = clock or time.monotonic
    meta = read_meta(job_id) or {}
    timeout = float(meta.get("job_timeout") or 0) or 3600.0
    known = meta.get("live_fire_known_vulnerabilities")
    known = int(known) if isinstance(known, int) else None
    deadline = now() + timeout

    root = job_dir(job_id)
    logs: list[str] = []

    def log(message: str) -> None:
        logs.append(message)
        try:
            with open(root / "run.log", "a", encoding="utf-8") as handle:
                handle.write(f"{time.strftime('%H:%M:%S')} {message}\n")
        except OSError:
            pass

    write_meta(job_id, status="running", stage="safe-ingest")
    ws_root = root / WORKSPACE_NAME
    if resume and (ws_root / "original").is_dir():
        # create_workspace refuses to overwrite, and re-ingesting would throw
        # away the candidate tree the last cycle's bundle was built from.
        workspace = load_workspace(ws_root)
        log("job: resuming — workspace, board and blueteam trees reused")
    else:
        workspace = create_workspace(Path(archive_path), ws_root)
    work_dir = root / "live-fire-v2"
    work_dir.mkdir(parents=True, exist_ok=True)

    plan_tree = _refresh_plan_tree(
        Path(workspace.original), work_dir / "plan-tree"
    )
    invoke = invoke or _ProviderInvoke(job_id, plan_tree=plan_tree, log=log)

    limits = StackLimits()
    validator = validator or ValidatorAgent(
        job_id=job_id,
        base_root=Path(workspace.original),
        work_dir=work_dir / "validator",
        limits=limits,
        log=log,
    )
    repo = RepoAgent(job_id=job_id, workspace=workspace, output_root=root, log=log)
    runner = LiveFireV2Runner(
        job_id=job_id,
        workspace=workspace,
        validator=validator,
        repo=repo,
        work_dir=work_dir,
        invoke=invoke,
        board=(_restore_board(root) if resume else None) or AssignmentBoard(),
        budget=SlotBudget(DEFAULT_SLOTS),
        board_path=root / BOARD_NAME,
        log=log,
        # The retry inside a round is bounded by the SAME deadline as the
        # rounds themselves; without this the runner has no clock and a
        # blueteam could be handed the file again with no time to judge it.
        deadline=deadline,
        now=now,
    )

    if resume:
        # Restored HERE, where `resume` and `workspace` are in scope. The
        # bundle is cumulative — every round rebuilds from every patch that
        # has ever passed — so a cycle that forgot the earlier submissions
        # would publish a bundle missing fixes the operator already has.
        restored = _restore_submissions(root, workspace)
        runner.submissions.update(restored)
        log(
            f"job: restored {len(restored)} validated patch(es) "
            f"({sorted(restored)}) so the bundle stays cumulative"
        )

    try:
        return _run_rounds(
            job_id=job_id, runner=runner, repo=repo, root=root,
            work_dir=work_dir, known=known, deadline=deadline, now=now, log=log,
        )
    except Exception as exc:  # noqa: BLE001 - a dead job must not look alive
        # WITHOUT THIS the job stays `running` forever. Measured on the first
        # real v2 run: the validator agent came back empty (its provider had
        # no credentials), parse_corpus raised, RQ recorded the failure — and
        # meta still said `running` with no error, so the UI showed a live job
        # that nothing was working on. v1's run_job has always written this;
        # v2's did not.
        log(f"job: FAILED — {type(exc).__name__}: {exc}")
        write_meta(job_id, status="failed", stage="failed", error=str(exc)[:2000])
        raise


def _run_rounds(
    *, job_id: str, runner: Any, repo: Any, root: Path, work_dir: Path,
    known: int | None, deadline: float, now: Callable[[], float],
    log: Callable[[str], None],
) -> dict[str, Any]:
    write_meta(job_id, stage="baseline")
    runner.bootstrap()

    rounds: list[dict[str, Any]] = []
    # THE ONLY WAYS OUT ARE THE DEADLINE AND THE OPERATOR. There used to be
    # four more -- a round ceiling, "every known vulnerability is integrated",
    # "nothing left to work on", and "a round produced nothing new" -- and
    # every one of them was the orchestrator deciding it had paid enough while
    # the operator still had budget. Job f432f9d8e16d ended on the last of
    # them with most of its vulnerabilities open, two rounds in.
    #
    # The operator's stop arrives from outside, as RQ's STOP_JOB, so there is
    # nothing to poll for here. Nothing spins either: every iteration costs a
    # plan agent call, which is minutes.
    stop = "out of time"
    index = 0
    while True:
        index += 1
        if now() + ROUND_RESERVE_S > deadline:
            log("job: not enough time left to finish another round")
            break
        write_meta(job_id, stage=f"round-{index}")
        feedback = _feedback_text(root)
        result = runner.run_round(
            index=index,
            known=known,
            feedback=feedback,
            blocked=_blocked_count(root),
        )
        rounds.append(result.as_dict())
        _write_json(work_dir / "rounds.json", {"rounds": rounds})
        # The count the job list polls, so a new bundle can raise an alarm the
        # way a flag does. Stamped per round because that is where a version
        # is cut; the operator finds out on the next poll rather than at the
        # end of a job that may run for another hour.
        write_meta(
            job_id,
            live_fire_versions=len(repo.history),
            live_fire_integrated=len(runner.board.integrated()),
        )

        # The operator's count is a statement about the bundle, not a budget:
        # a job that has integrated all of them keeps looking, because the
        # plan agent finding one more is exactly the case the operator asked
        # to be covered.
        if result.remaining[0] == 0:
            log("job: every known vulnerability is integrated — still looking")
        if not runner.board.ready():
            log("job: nothing on the board is ready; the next round asks the "
                "plan agent again")

    log(f"job: stopping — {stop}")
    report = runner.report()
    integrated = runner.board.integrated()
    result_payload = {
        "module": "live-fire",
        "live_fire_version": 2,
        "stop_reason": stop,
        "rounds": rounds,
        "integrated": integrated,
        "board": runner.board.as_dict(),
        "versions": repo.history,
        "report": report.name,
    }
    _write_json(root / RESULT_NAME, result_payload)
    write_meta(
        job_id,
        status="done",
        stage="done",
        live_fire_version=2,
        live_fire_integrated=len(integrated),
        live_fire_stop_reason=stop,
        ready_to_deploy=bool(repo.history),
    )
    return result_payload


def _write_json(path: Path, payload: Any) -> None:
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _feedback_rows(root: Path) -> list[dict[str, Any]]:
    """What the operator typed against each published version, if anything."""

    try:
        payload = json.loads(
            (root / "patch-feedback.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return []
    # "entries", not "feedback": api/routes/jobs.py writes
    # {"entries": [{"attempt": N, "blocked": M, "note": ..., "at": ...}]} and
    # a guessed key here would read no feedback at all, silently — the plan
    # agent would never learn that a fix is not holding.
    rows = payload.get("entries")
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _blocked_count(root: Path) -> int | None:
    rows = _feedback_rows(root)
    if not rows:
        return None
    latest = rows[-1]
    value = latest.get("blocked")
    return int(value) if isinstance(value, int) else None


def _feedback_text(root: Path) -> str:
    """What the operator learned from the contest, in the agents' words.

    TWO SIGNALS, AND THEY MEAN DIFFERENT THINGS. `blocked` says how many
    attacks a bundle stopped — progress against the red team. `sla_pass` says
    whether the scoring server judged the service still working, and it is
    ground truth the validator cannot produce: its corpus is a GUESS at what
    the scoring server asks, and a failed SLA on a bundle the validator passed
    means the guess missed something.
    """

    rows = _feedback_rows(root)
    if not rows:
        return ""
    lines = []
    for row in rows:
        sla = row.get("sla_pass")
        mark = ("SLA PASS" if sla is True
                else "SLA FAIL" if sla is False else "SLA not reported")
        lines.append(
            f"  V{row.get('attempt', '?')}: "
            f"{row.get('blocked', '?')} attacks blocked · {mark}"
            + (f" · {row['note']}" if row.get("note") else "")
        )
    failed = [r for r in rows if r.get("sla_pass") is False]
    if failed:
        versions = ", ".join(f"V{r.get('attempt')}" for r in failed)
        lines.append(
            f"\nTHE SCORING SERVER FAILED {versions} ON SLA. The validator "
            "passed that bundle, so its request/response corpus missed "
            "whatever the scoring server checks. Prefer the smallest change "
            "that closes the vulnerability, and do not alter output the "
            "original produced — including whitespace, ordering and "
            "attribute form."
        )
    return "\n".join(lines)


__all__ = ["BOARD_NAME", "ROUND_RESERVE_S", "RESULT_NAME",
           "run_job"]
