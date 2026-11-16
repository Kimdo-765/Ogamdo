"""One round of live-fire v2: plan, patch, validate, integrate, publish.

`live_fire_orchestrator` holds the board and the budget; `live_fire_validator`
and `live_fire_repo` hold the oracle and the bundle. This is the loop that
drives them, and the order it runs in is the design:

    bootstrap once   validator.establish() -- two base stacks, then a third
                     capture across a minute boundary. Roughly two minutes,
                     entirely on the critical path, because every later
                     verdict is judged against that baseline. Nothing a
                     blueteam does can be believed before it finishes.

    each round       plan agent reads the tree and names vulnerabilities
                     -> the board admits the ones it has not already fixed
                     -> a blueteam agent per assignment, in parallel
                     -> each patched tree is validated ON ITS OWN
                     -> what passed is integrated
                     -> the INTEGRATED bundle is validated again
                     -> a version is cut, or nothing is

EVERY BLUETEAM GETS ITS OWN COPY OF BASE. Not a nicety: they run at the same
time, and a shared tree would mean one agent reading another's half-finished
edit. It is also what lets N validations run concurrently, since a validation
is a whole compose stack pointed at a tree.

THE SLOT BUDGET GUARDS STACKS, NOT AGENTS. An agent call is minutes of a model
thinking and costs no docker resources; a validation is a whole compose stack,
containers and bridges both. Bounding the wrong one either starves the round
or exhausts docker's address pool -- and the second failure takes out every
OTHER job on the host, not just this one.

WHAT THE RUNNER DOES NOT DO IS DECIDE. Whether a patch is good is the
validator's call, whether it fits is the merge's, and whether a vulnerability
is still open is the board's. This file only sequences them, so that when a
round produces nothing the reason is already attributable to one of the three.
"""

from __future__ import annotations

import concurrent.futures
import difflib
import hashlib
import json
import re
import shutil
import stat
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from modules.live_fire_orchestrator import (
    Assignment,
    DEFERRED,
    AssignmentBoard,
    BLUETEAM_SYSTEM,
    FAILED,
    IN_FLIGHT,
    PLAN_SYSTEM,
    SUBMITTED,
    SlotBudget,
    PROMPT_FINDINGS,
    blueteam_prompt,
    merge_plans,
    plan_prompt,
    remaining_estimate,
)
from modules.live_fire_repo import PatchSubmission, integrate
from modules.live_fire_validator import (
    CorpusRequest,
    _is_dependency,
    compose_topology,
    sink_digest,
    source_digest,
    summarise_tree,
)


# Directory names that HOLD services rather than being one. This once knew a
# single container name, and on a tree laid out as `services/api/` or
# `apps/web/` every path fell through to "other", collapsing the fan-out back
# to the single agent it replaced. Nothing failed; the whole change simply
# bought nothing.
# `apps` but not `app`: `apps/web/` holds services, while Rails' `app/models/`
# is ONE service's own layout, and treating it as a container split a single
# application into three scopes that each got their own agent.
_CONTAINER_DIRS = ("src", "services", "service", "apps", "packages",
                   "cmd", "modules")


def _rows_for(
    digest: str | None, scope: str, listing: str, *, limit: int
) -> str:
    """The rows of one digest that belong to one plan agent, capped per agent.

    ONE digest is walked for the whole tree, and every plan agent used to be
    handed all of it: on job 586ba6888920 the agent reading one service spent
    its attention on dozens of rows from another's vendored file. The walk
    already happened, so keeping only this scope's paths costs nothing.

    THE CAP BELONGS HERE, NOT ON THE WALK. Capping the walk and partitioning
    afterwards spends one budget in path-alphabetical order, so the first
    service eats it and every later one gets nothing -- measured on this
    bundle, a scope that sorted late received zero of its available rows.
    Worse, it was invisible: the global "stopped at
    N" marker was copied into every scope, so the string was never empty,
    `plan_prompt` still rendered the section header, and the agent was told the
    grep had been done for it over a single line saying the walk had stopped.
    """

    if not digest:
        return ""
    rows = [r for r in digest.splitlines() if not r.startswith("...")]
    walk_stopped = len(rows) != len(digest.splitlines())
    if scope:
        wanted = {line.strip() for line in listing.splitlines() if line.strip()}
        kept = []
        for row in rows:
            head = row.split("  ", 1)[0]
            rel = head.rsplit(":", 1)[0] if ":" in head else head
            if rel in wanted:
                kept.append(row)
        rows = kept
    if len(rows) > limit:
        rows = rows[:limit]
        rows.append(f"... (stopped at {limit} hits; read the tree for the rest)")
    elif not rows and walk_stopped:
        # AN EMPTY SECTION IS A CLAIM. Without this the starved scope and the
        # genuinely clean one are the same empty string, the prompt renders the
        # full "grepped for you" header over nothing, and the agent is told the
        # work was done for it when the walk never reached its files.
        rows = ["... (the tree-wide scan filled up before reaching this part; "
                "nothing here was scanned — grep it yourself)"]
    return "\n".join(rows)


def _scope_of(rel: str, *, root: str = "") -> str:
    """Which part of the bundle a path belongs to.

    `bundle/src/web/lib/x.php` is web, `services/api/main.go` is
    api, `backend/src/index.ts` is backend. A file with nowhere else to go is
    "other" -- it still reaches an agent, just not one of its own.

    `root` is the single top directory every path shares, if there is one:
    `bundle` is the root, not a service, and treating it as one would
    put the entire tree in a single scope.
    """

    parts = [p for p in rel.split("/") if p]
    if root and parts and parts[0] == root:
        parts = parts[1:]
    for index, part in enumerate(parts[:-1]):
        if part.lower() in _CONTAINER_DIRS:
            nxt = parts[index + 1]
            # `src/index.ts` -- the next component is the FILE, so `src`
            # itself is the service and its parent, if any, names it.
            if index + 1 < len(parts) - 1:
                return nxt
            return parts[index - 1] if index else "other"
    # No container directory at all: the first component is the service,
    # unless it is the only thing between the root and the file.
    if len(parts) > 1:
        return parts[0]
    return "other"


def _bundle_root(paths: Sequence[str]) -> str:
    """The one top directory every path shares, or "" if they differ."""

    tops = {p.split("/", 1)[0] for p in paths if "/" in p}
    return next(iter(tops)) if len(tops) == 1 else ""


# Wall-clock per agent call. The plan agent reads a whole tree; a blueteam
# edits one file. Neither is bounded by tokens in practice, only by how long
# the operator can afford to wait inside a short tick.
PLAN_TIMEOUT_S = 900.0
BLUETEAM_TIMEOUT_S = 900.0

# How much time an in-round retry needs before the job deadline. COMPUTED, not
# guessed: a retry is one blueteam call, which cannot exceed its own timeout,
# plus the stack that judges it. Reserving less would leave that stack up when
# the job is killed -- the failure ROUND_RESERVE_S exists for, one level down.
RETRY_RESERVE_S = BLUETEAM_TIMEOUT_S + 120.0

# One row per agent, polled by the operator's grid.
AGENTS_NAME = "live-fire-agents.json"

_SAFE_SUFFIX = re.compile(r"[^a-z0-9]+")

# Files a blueteam may not edit, ENFORCED rather than merely asked for.
#
# BLUETEAM_SYSTEM has always said "do not touch Dockerfiles, compose files,
# deployment scripts or tests", and a prompt alone does not hold that line.
# A patch that rewrites the compose file can leave a stack nothing can reach
# at all, and a whole validation cycle is then spent discovering that the
# patch had broken the harness rather than the service.
#
# Seed data is the other half of the same lesson. The corpus authenticates
# with the seeded accounts, so a patch that changes them breaks every
# logged-in request by construction, and not one of the lines that then go
# missing is a service regression.
#
# Refused BEFORE the stack is raised, so the attempt costs an agent turn
# instead of an agent turn plus a whole stack, and the reason reaches the
# plan agent in time to pick a different target.
_PROTECTED = (
    "docker-compose",
    "dockerfile",
    ".dockerignore",
    "docker-entrypoint",
)
# Directories whose contents a patch may not touch. The NAME-based list above
# is layout-independent; this one was not -- it once listed a single
# seed-directory name, and a bundle that seeds from any other had its
# credentials wide open to a blueteam. PLAN_SYSTEM spells out why that
# matters: the scoring server logs in with those accounts, so changing them
# breaks every authenticated request by construction and the patch is
# refused for breaking the service while the bug stays open.
# How wide the one-per-job walk goes, and how much of it any single plan agent
# is handed. The first pair must comfortably exceed the second times the number
# of scopes, or the walk starves the later ones before the split happens.
# Generous on purpose. The walk spends its budget in path-alphabetical order,
# so a cap sized for "enough rows overall" is really a cap on WHO IS SEEN: on a
# monorepo whose first service is large, every service sorting after it gets
# nothing. Rows are strings and the walk happens once per job; the cap that
# protects the PROMPT is the per-agent one below.
SCAN_SINK_LIMIT = 6000
SCAN_SOURCE_LIMIT = 4000
AGENT_SINK_LIMIT = 120
AGENT_SOURCE_LIMIT = 60


_PROTECTED_DIRS = (
    "/env/", "/deploy/", "/tests/", "/test/", "/infra/", "/docker/",
    # Seed data, under every name these bundles give it.
    "/database/", "/db/", "/sql/", "/initdb/", "/seeds/", "/seed/",
    "/fixtures/", "/migrations/",
)


# Lines of diff kept per file. A rewritten minified script is thousands of
# lines and nobody reads those in a panel; the point is to see WHAT the
# blueteam did, and the bundle itself is one click away for the rest.
# Truncation is stated in the diff, never silent.
MAX_DIFF_LINES = 400


def unified_patch(original_root: Path, files: Mapping[str, bytes]) -> dict[str, Any]:
    """What the blueteam actually changed, as a diff a human can read.

    The plan agent's `patch_direction` says what SHOULD be done; this says
    what WAS done, and those are not the same thing — on job 2de379a0139f the
    first V2 and V3 attempts followed their direction exactly and were refused
    for breaking the SLA, and the second attempts succeeded by doing something
    the direction had not asked for.

    Bytes, not text: a source file need not be valid UTF-8, and a diff
    that raises on one would take the whole view down.
    """

    original_root = Path(original_root)
    chunks: list[str] = []
    added = removed = 0
    for path in sorted(files):
        new_payload = files[path]
        try:
            old_payload = (original_root / path).read_bytes()
        except OSError:
            old_payload = b""
        # A DECODE FAILURE IS NOT EVIDENCE OF A BINARY. This asked UTF-8 and
        # called anything that refused it a binary, and a text file in a
        # legacy single-byte encoding, with not one NUL byte in it, answers
        # that description. A patch to such a file would report "+0/-0" and
        # a diff the operator could not read, and `_diff_text` would still
        # return a NON-EMPTY string, which would put the heading
        # WHAT YOU CHANGED LAST TIME above a byte count in the retry prompt.
        # An agent told it has seen its own patch, when it has not, is worse
        # off than one told nothing.
        if (b"\x00" in old_payload[:_BINARY_SNIFF]
                or b"\x00" in new_payload[:_BINARY_SNIFF]):
            chunks.append(
                f"--- a/{path}\n+++ b/{path}\n"
                f"(binary file: {len(old_payload)} -> {len(new_payload)} bytes)"
            )
            continue
        old_lines = _as_text(old_payload).splitlines()
        new_lines = _as_text(new_payload).splitlines()
        diff = list(
            difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="", n=3,
            )
        )
        for line in diff:
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
        if len(diff) > MAX_DIFF_LINES:
            kept = diff[:MAX_DIFF_LINES]
            kept.append(
                f"… {len(diff) - MAX_DIFF_LINES} more diff lines; the full "
                "change is in the bundle"
            )
            diff = kept
        chunks.append("\n".join(diff))
    return {
        "paths": sorted(files),
        "added": added,
        "removed": removed,
        "diff": "\n\n".join(chunks),
    }


# Manifests an installer READS. Nothing in this set executes: a lockfile and a
# pinned requirements list are data, and a fix for a vulnerable dependency has
# nowhere else to live. The patch gate lets these names through anywhere
# except the seed, fixture, migration, test, database and initdb directories
# listed below.
#
# DELIBERATELY NARROWER than `live_fire_patch_loop._DEPENDENCY_FILES`, which
# also lists `build.gradle`, `Gemfile`, `package.json`, `pom.xml` and
# `composer.json`. Every one of those carries a scripts or plugins section, and
# a node bundle's seed directory IS a `package.json` whose scripts decide what
# accounts get planted -- allowing it would open the thing the rule exists to
# close.
_DEPENDENCY_MANIFESTS = frozenset({
    "requirements.txt", "requirements-dev.txt", "constraints.txt",
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "go.mod", "go.sum",
    "composer.lock", "gemfile.lock", "poetry.lock", "pipfile.lock",
    "cargo.lock", "gradle.lockfile",
})

# …and not even those, inside the directories whose whole job is to decide what
# the database starts with or what the tests do.
_MANIFEST_NEVER_UNDER = ("/seed/", "/seeds/", "/fixtures/", "/migrations/",
                         "/test/", "/tests/", "/database/", "/initdb/")


def protected_paths(
    paths: Sequence[str], *, allow_dependency_manifests: bool = False
) -> list[str]:
    """Which of these a blueteam is not allowed to have edited.

    `allow_dependency_manifests` is for the PATCH GATE only, never for the
    scope fold. The fold asks "is there anything here worth a plan agent",
    and a directory of pinned versions is not; the gate asks "may this edit
    ship", and for a vulnerable pin the manifest is the only place the fix
    can go. Passing it at the fold would give a directory of pinned versions
    its own agent.
    """

    out: list[str] = []
    for path in sorted(paths):
        lowered = "/" + str(path).lower().strip("/")
        name = lowered.rsplit("/", 1)[-1]
        if (allow_dependency_manifests
                and name in _DEPENDENCY_MANIFESTS
                and not any(d in lowered for d in _MANIFEST_NEVER_UNDER)):
            continue
        if any(name.startswith(token) or token in name for token in _PROTECTED):
            out.append(path)
            continue
        if any(part in lowered for part in _PROTECTED_DIRS):
            out.append(path)
    return out


class RoundError(RuntimeError):
    """The round could not be sequenced."""


@dataclass(frozen=True)
class BlueteamOutcome:
    """What became of one blueteam's turn, and why."""

    vulnerability_id: str
    submission: PatchSubmission | None
    validation: Any = None
    reason: str = ""
    ignored_additions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "submitted": self.submission is not None,
            "reason": self.reason,
            "ignored_additions": list(self.ignored_additions),
            "validation": (
                self.validation.as_dict()
                if hasattr(self.validation, "as_dict")
                else None
            ),
        }


# How much of a file to sniff before calling it binary. A NUL byte is the
# discriminator because a text file in ANY encoding has none; a decode failure
# is not, and the difference is not academic on these bundles.
_BINARY_SNIFF = 4096


def _as_text(payload: bytes) -> str:
    """Decode a file that is text, whatever encoding it is text in.

    latin-1 cannot fail -- every byte is a code point -- so this only ever
    changes WHICH characters come back, never whether a diff is produced. It
    is the fallback rather than the default because a UTF-8 file decoded as
    latin-1 shows mojibake for every multi-byte character, and these bundles
    are full of non-ASCII text.
    """

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.decode("latin-1")


def _write_json_atomic(path: Path, payload: Any) -> None:
    """Write a view file so a reader never sees half of it."""

    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    tmp.replace(path)


def _finding_key(finding: Any) -> tuple[str, str, str]:
    """Identity of a finding: which request, what kind, which line.

    `detail` carries the line itself, so one request reporting two
    different lines is two different findings. A second stack that merely
    reports a DIFFERENT line therefore clears the first one just as a clean
    stack would.
    """

    return (
        str(getattr(finding, "name", "")),
        str(getattr(finding, "kind", "")),
        str(getattr(finding, "detail", finding)),
    )


@dataclass(frozen=True)
class RoundResult:
    index: int
    identified: tuple[str, ...]
    outcomes: tuple[BlueteamOutcome, ...]
    published: dict[str, Any] | None
    integrated_ok: bool
    remaining: tuple[int | None, str]
    board: dict[str, Any]
    # The verdict on the WHOLE bundle. Recorded because it is the one refusal
    # nobody could act on: every blueteam outcome carried its findings, but a
    # bundle that failed said only `integrated_ok: false`, so neither the
    # operator nor the plan agent could see which request broke or why.
    # Last, because a defaulted field cannot precede a required one.
    integrated: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "round": self.index,
            "identified": list(self.identified),
            "outcomes": [o.as_dict() for o in self.outcomes],
            "published": self.published,
            "integrated_ok": self.integrated_ok,
            "integrated": (
                self.integrated.as_dict()
                if hasattr(self.integrated, "as_dict") else None
            ),
            "remaining": {"count": self.remaining[0], "why": self.remaining[1]},
            "board": self.board,
        }


def _make_writable(root: Path) -> None:
    """The workspace original is read-only by design; a copy of it must not be."""

    for path in [root, *root.rglob("*")]:
        try:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                continue
            path.chmod(stat.S_IMODE(mode) | stat.S_IWUSR | stat.S_IXUSR
                       if path.is_dir() else stat.S_IMODE(mode) | stat.S_IWUSR)
        except OSError:
            continue


def collect_changes(
    original_root: Path, patched_root: Path
) -> tuple[dict[str, bytes], list[str]]:
    """What the blueteam changed, and what it added that will be ignored.

    Only files that EXIST IN THE ORIGINAL are collected. A file an agent adds
    is dropped when the ZIP is rebuilt from the input manifest, so carrying it
    into a submission would make `integrate` defer the whole thing -- losing a
    good fix because of a scratch file the agent left behind. Additions are
    returned separately so the round can say so rather than swallow it.
    """

    original_root = Path(original_root)
    patched_root = Path(patched_root)
    changed: dict[str, bytes] = {}
    added: list[str] = []
    for path in sorted(patched_root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(patched_root).as_posix()
        source = original_root / rel
        if not source.is_file():
            added.append(rel)
            continue
        payload = path.read_bytes()
        if payload != source.read_bytes():
            changed[rel] = payload
    return changed, added


class LiveFireV2Runner:
    """Sequences the four roles. Owns no policy of its own."""

    def __init__(
        self,
        *,
        job_id: str,
        workspace: Any,
        validator: Any,
        repo: Any,
        work_dir: Path,
        invoke: Callable[..., str],
        board: AssignmentBoard | None = None,
        budget: SlotBudget | None = None,
        zip_builder: Callable[[Any, Path], Any] | None = None,
        board_path: Path | None = None,
        log: Callable[[str], None] | None = None,
        deadline: float | None = None,
        now: Callable[[], float] = time.monotonic,
    ):
        self.job_id = job_id
        self.workspace = workspace
        self.validator = validator
        self.repo = repo
        self.work_dir = Path(work_dir)
        self.invoke = invoke
        self.board = board or AssignmentBoard()
        self.budget = budget or SlotBudget()
        self.zip_builder = zip_builder
        self._log = log
        self.board_path = Path(board_path) if board_path else None
        # Diffs live beside the board, not inside it: the board is polled
        # every couple of seconds and a rewritten minified script would be
        # shipped on every tick. The panel fetches these once, when a row is
        # opened.
        self.patches_path = (
            self.board_path.with_name("live-fire-patches.json")
            if board_path else None
        )
        self.patches: dict[str, dict[str, Any]] = {}
        self.corpus_path = (
            self.board_path.with_name("live-fire-corpus.json")
            if board_path else None
        )
        self.submissions: dict[str, PatchSubmission] = {}
        self.deadline = deadline
        self.now = now
        # One row per agent, for the grid the operator watches. Beside the
        # board for the same reason the diffs are: the board is polled on a
        # tick and this changes far more often than it does.
        self.agents_path = (
            self.board_path.with_name(AGENTS_NAME) if board_path else None
        )
        self._agents: dict[str, dict[str, Any]] = {}
        self._agents_lock = threading.Lock()
        # The board view and the dict that feeds half of it. `patches` is
        # written from the blueteams' own threads and read by
        # `publish_board`, and `publish_board` itself now runs from a
        # blueteam's thread as its patch ships AND from the round's thread as
        # leads are admitted. Two writers and one fixed `.tmp` name is the job
        # 3d0cf9b6e883 failure again, one file over.
        #
        # NEVER HELD ACROSS `_ship_gate`. `publish_board` takes the gate for a
        # snapshot and lets it go BEFORE taking this one; `_ship_gate` is a
        # plain Lock and a nesting in the other direction self-deadlocks.
        self._view_lock = threading.Lock()
        # Shipping runs from the blueteams' own threads as their patches
        # validate, so it needs a gate. `_ship_again` is the coalescing half:
        # a patch that lands while a bundle is being built does not start a
        # second build, it makes the running one go round once more.
        self._ship_gate = threading.Lock()
        # Guards `_cut_scopes`, which one plan agent per scope writes
        # at the same time.
        self._cut_lock = threading.Lock()
        self._shipping = False
        self._ship_again = False
        self._round_published: dict[str, Any] | None = None
        self._round_integrated_ok = False
        self._last_merge: Any = None
        self._last_integrated: Any = None
        # vulnerability id -> paths whose CURRENT merged content the next
        # attempt must start from, because that is where it lost a merge.
        self._rebase: dict[str, set[str]] = {}

    def log(self, message: str) -> None:
        if self._log:
            self._log(message)

    # -- the agent grid ---------------------------------------------------

    def agent_state(self, key: str, state: str, detail: str = "",
                    *, role: str | None = None) -> None:
        """Record what one agent is doing, for the operator's grid.

        run.log CANNOT drive that grid, which is why this exists:
        blueteams starting in the same second write identical
        "blueteam agent starting" lines with no vulnerability id between
        them. Keyed by `key` -- a vulnerability id for a blueteam, the role
        name for the plan and repo agents -- so a row is a lane, not an event.

        Called from the fan-out's threads, so it takes a lock. It also must
        never be the thing that ends a round: a grid is a view.
        """

        try:
            with self._agents_lock:
                # "blueteam" is the DEFAULT, and `role` is what overrides
                # it. Setting the role in both places read as belt and braces
                # and was neither: each covered for the other, so removing
                # either one changed nothing any check could see.
                row = self._agents.setdefault(
                    key, {"key": key, "role": "blueteam",
                          "started_at": None, "finished_at": None}
                )
                if role:
                    row["role"] = role
                row["state"] = state
                row["detail"] = detail[:200]
                stamp = time.time()
                if state in ("running", "retrying") and not row["started_at"]:
                    row["started_at"] = stamp
                if state in ("done", "failed"):
                    row["finished_at"] = stamp
                else:
                    row["finished_at"] = None
                row["updated_at"] = stamp
                payload = {"agents": [
                    self._agents[k] for k in sorted(self._agents)
                ]}
                # THE WRITE IS INSIDE THE LOCK TOO. It was not, and job
                # 3d0cf9b6e883 logged it on the first fan-out: three plan
                # agents came up in the same second, all three wrote the same
                # `.tmp`, the first rename moved it away and the others got
                # "No such file or directory". A lock that covers the state
                # but not the file it produces is not protecting the thing
                # that breaks.
                if self.agents_path is not None:
                    _write_json_atomic(self.agents_path, payload)
        except Exception as exc:  # noqa: BLE001 - a view is not a verdict
            self.log(f"round: could not record agent state ({exc})")

    def _save_corpus(
        self, requests: Sequence[CorpusRequest], ready: Sequence[str]
    ) -> None:
        """Keep the corpus so a later cycle is judged by the same questions."""

        if self.corpus_path is None:
            return
        try:
            payload = {
                "requests": [
                    {
                        "name": r.name, "service": r.service, "port": r.port,
                        "path": r.path, "method": r.method,
                        "headers": dict(r.headers), "body": r.body,
                        "session": r.session, "serves": r.serves,
                    }
                    for r in requests
                ],
                "ready": list(ready),
            }
            tmp = self.corpus_path.with_suffix(self.corpus_path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.corpus_path)
        except Exception:  # noqa: BLE001
            pass

    def publish_board(self) -> None:
        """Write the board where the UI can read it, as soon as it changes.

        AS SOON AS IT CHANGES, not at the end of the round. A blueteam turn is
        minutes and a round is longer; an operator watching a live job wants
        to know WHICH vulnerabilities were found the moment the plan agent
        names them, not after every patch has been validated. Same reason
        `patch-progress.json` is written per version rather than at the end:
        on a short tick, information that arrives with the final report
        arrives too late to act on.

        Never raises. This is a view, and losing it must not lose the round.
        """

        if self.board_path is None:
            return
        # TAKEN AND RELEASED BEFORE `_view_lock`. Blueteam threads write
        # `submissions` under this gate; holding both would make the order
        # load-bearing for every future caller, and a snapshot let go is one
        # less rule to keep.
        with self._ship_gate:
            submitted = sorted(self.submissions)
        try:
            with self._view_lock:
                payload = dict(self.board.as_dict())
                payload["submitted"] = submitted
                # A per-row summary small enough to poll; the diff itself is
                # in the sibling file.
                payload["patch_summary"] = {
                    vid: {k: patch[k] for k in ("paths", "added", "removed")}
                    for vid, patch in self.patches.items()
                }
                # BOTH FILES, ONE LOCK, ONE SNAPSHOT, AND THE WRITES INSIDE
                # IT. They were two `try` blocks each inventing its own
                # `.tmp` from a fixed name: two threads publishing at once
                # wrote the same temp path, the first rename moved it away
                # and the second got "No such file or directory" -- which is
                # job 3d0cf9b6e883 on the agent grid, and the reason
                # `agent_state` keeps its write inside its lock. Separate
                # blocks also let the two files come from two different
                # snapshots, so the panel could hold a diff for a row the
                # board did not list.
                _write_json_atomic(self.board_path, payload)
                if self.patches_path is not None and self.patches:
                    _write_json_atomic(
                        self.patches_path, {"patches": self.patches}
                    )
        except Exception as exc:  # noqa: BLE001 - a view must not end a round
            # SAID OUT LOUD. This was `pass`, and a board that had quietly
            # stopped updating looked exactly like the bug this call exists to
            # prevent: on job 8bd3c68d8df6 nobody could tell a board that had
            # nothing new to say from one whose write had been raising for
            # five minutes. `agent_state` already logs for this reason.
            self.log(f"round: could not publish the board ({exc})")

    # -- bootstrap --------------------------------------------------------

    def bootstrap(self, corpus: Any = None, *, credentials: str = "") -> Any:
        """Establish the baseline every later verdict rests on.

        `corpus` lets a caller supply a proposal instead of asking the model
        for one -- used by tests and by a re-run that already knows what the
        corpus should be. Otherwise the validator asks its own agent.
        """

        if corpus is None and self.corpus_path and self.corpus_path.is_file():
            # A FIX cycle re-establishes the baseline against the same
            # ORIGINAL tree, but it must not pay for the corpus again: asking
            # the validator agent to re-read the service costs six to twelve
            # minutes and would return a DIFFERENT corpus, so the second run's
            # verdicts would not be comparable with the first's.
            try:
                saved = json.loads(self.corpus_path.read_text(encoding="utf-8"))
                corpus = (
                    [CorpusRequest(**row) for row in saved["requests"]],
                    list(saved["ready"]),
                )
                self.log(
                    f"round: reusing the saved corpus ({len(corpus[0])} "
                    "requests) so this cycle is judged the same way the last "
                    "one was"
                )
            except Exception:  # noqa: BLE001 - a bad file just means re-ask
                corpus = None
        if corpus is None:
            requests, ready = self.validator.propose(
                lambda system, prompt: self.invoke(
                    "validator", system, prompt, cwd=None,
                    timeout_s=PLAN_TIMEOUT_S
                ),
                credentials=credentials,
            )
        else:
            requests, ready = corpus
        self._save_corpus(requests, ready)
        baseline = self.validator.establish(requests, ready)
        self.log(
            f"round: baseline established, {baseline.coverage} requests usable"
            + (f", dropped {[d.name for d in baseline.dropped]}"
               if baseline.dropped else "")
        )
        return baseline

    # -- the plan agent ---------------------------------------------------

    # Walked ONCE per job: the base tree does not change, and the plan
    # agent reads the original every round. (The duplicate declaration
    # that used to sit here was a merge artefact, not two fields.)
    _sinks: str | None = None
    _sources: str | None = None
    _topology: str | None = None

    # A part of the bundle small enough that giving it its own agent costs
    # more than it finds. Folded into "other" with the loose files.
    MIN_SCOPE_FILES = 3

    def plan_scopes(self) -> list[tuple[str, list[str]]]:
        """Split the bundle into the parts one plan agent each can hold.

        By `<container>/<service>`, because a service is the unit a
        vulnerability lives inside. Everything else lands in one "other" scope
        rather than being dropped: the Dockerfiles and the seed SQL are not
        patchable, but they are where an agent learns what the service is.

        WHAT IT ACTUALLY PRODUCES, measured rather than hoped for. This used to
        claim one scope per service, which the code has never produced on any
        bundle: a service with fewer files than `MIN_SCOPE_FILES` is folded
        into "other", so the measured split had fewer scopes than the bundle
        had services, and the run log said so all along. A docstring that
        describes an intention rather than a behaviour is how a fold nobody
        chose gets read as a fold somebody did.
        """

        root = Path(self.workspace.original)
        groups: dict[str, list[str]] = {}
        rels: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if _is_dependency(rel):
                continue
            rels.append(rel)
        bundle = _bundle_root(rels)
        for rel in rels:
            groups.setdefault(_scope_of(rel, root=bundle), []).append(rel)
        other = groups.pop("other", [])
        # Folded in: a part too small to be worth its own model call, and a
        # part with nothing a blueteam may patch. A deployment directory is the
        # second kind -- Dockerfiles and seed SQL, every one of them protected
        # -- and giving it an agent spends a plan call on files no patch may
        # touch.
        for name in [
            k for k, v in groups.items()
            if len(v) < self.MIN_SCOPE_FILES or len(protected_paths(v)) == len(v)
        ]:
            other.extend(groups.pop(name))
        scopes = sorted(groups.items())
        if other:
            scopes.append(("other", sorted(other)))
        return scopes

    def _plan_tree_for(self, scope: str) -> Path:
        """A working directory of its own for one plan agent.

        Job 3d0cf9b6e883: the fan-out's agents all ran in the single
        `plan-tree`, because `cwd=None` means "the one plan tree" — and one
        of them died in a second with a JSONDecodeError and zero
        characters. Agents write scratch files; a shared directory is a
        collision, and the blueteams have had one tree each from the start
        for exactly this reason.
        """

        suffix = _SAFE_SUFFIX.sub("-", scope.lower()) or "all"
        dest = self.work_dir / f"plan-{suffix}"
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(Path(self.workspace.original), dest, symlinks=True)
        _make_writable(dest)
        return dest

    def _seed_rebase(self, assignment: Assignment, dest: Path) -> None:
        """Show a DEFERRED blueteam the edit that beat it.

        `board.ready()` puts a deferred assignment back in the queue on the
        premise that "the tree it lost to now contains the other fix" -- but
        the tree handed out above is a copy of the ORIGINAL, so that premise
        was never true in code. The agent re-derived the same patch from the
        same bytes and lost the same merge: on job 586ba6888920 V6 was
        deferred for the same reason in four consecutive rounds.

        ONLY THE COLLIDING PATH is replaced. Copying the whole candidate would
        make every other vulnerability's fix look like this agent's work, and
        a submission that claims files it did not edit drags them down with it
        the next time it loses.
        """

        paths = self._rebase.get(assignment.vulnerability.id)
        if not paths:
            return
        candidate = Path(self.workspace.candidate)
        for rel in sorted(paths):
            try:
                payload = (candidate / rel).read_bytes()
            except OSError:
                continue
            target = dest / rel
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            except OSError:
                continue

    # Set by `_plan_once` for the scopes whose turn the provider CUT, and
    # read by `identify` so the round can say which part of the tree nobody
    # finished reading. Written under `_cut_lock` because one plan agent per
    # scope runs at the same time.
    _cut_scopes: set[str] | None = None

    def _plan_once(self, scope: str, listing: str, *, known: int | None,
                   feedback: str) -> str:
        key = f"plan:{scope}" if scope else "plan"
        self.agent_state(key, "running", f"reading {scope or 'the source'}",
                         role="plan")
        try:
            raw = self.invoke(
                "plan",
                PLAN_SYSTEM,
                plan_prompt(
                    tree_summary=listing,
                    known=known,
                    already=list(self.board.assignments.values()),
                    feedback=feedback,
                    sinks=_rows_for(self._sinks, scope, listing,
                                    limit=AGENT_SINK_LIMIT),
                    sources=_rows_for(self._sources, scope, listing,
                                      limit=AGENT_SOURCE_LIMIT),
                    topology=self._topology or "",
                    scope=scope,
                ),
                cwd=self._plan_tree_for(scope),
                timeout_s=PLAN_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001 - one scope's turn, not the
            # round. BROAD ON PURPOSE, and the cost of that is real: it
            # swallows anything a test raises through the provider seam too,
            # so a harness that needs to abort has to raise a BaseException.
            self.agent_state(key, "failed", f"{type(exc).__name__}: {exc}"[:120],
                             role="plan")
            self.log(f"round: the plan agent for {scope or 'the tree'} died ({exc})")
            return ""
        if not (raw or "").strip():
            # AN EMPTY REPLY IS NOT A REPLY. The invoker logs its own failure
            # and hands back "", so a lane that said "done: replied" here was
            # reporting a plan agent that died in a second with zero
            # characters as if it had answered — one of the plan agents on
            # job 3d0cf9b6e883.
            self.agent_state(key, "failed", "no reply", role="plan")
            self.log(
                f"round: the plan agent for {scope or 'the tree'} returned "
                "nothing"
            )
            return ""
        # A KILLED TURN IS NOT AN ANSWER, and this lane used to say it was.
        # The adapter kills the process group and yields a typed stop_reason;
        # `LiveFireInvoker` turns that into error_kind "timeout", so the grid
        # can stop reporting an agent cut mid-sentence as `done: replied`. On
        # job 7a92cd679e8c one plan agent burned its whole budget, came
        # back with 562 characters of prose, and the board said it had
        # answered — so a part of the tree nobody had finished reading was
        # recorded as read, and the next round had no
        # reason to try harder.
        #
        # THE TEXT IS STILL RETURNED. A cut agent may have finished a complete
        # list and been killed while idling, and the caller decides what is
        # usable; this only stops the LABEL from lying.
        if getattr(self.invoke, "last_error_kind", None) == "timeout":
            self.agent_state(
                key, "failed", f"cut off at {PLAN_TIMEOUT_S:.0f}s", role="plan")
            self.log(
                f"round: the plan agent for {scope or 'the tree'} was cut off "
                f"at {PLAN_TIMEOUT_S:.0f}s — that part of the tree was not "
                "finished"
            )
            with self._cut_lock:
                if self._cut_scopes is None:
                    self._cut_scopes = set()
                self._cut_scopes.add(scope)
            return raw
        self.agent_state(key, "done", "replied", role="plan")
        return raw

    def identify(self, *, known: int | None, feedback: str,
                 on_leads: Callable[[], None] | None = None) -> list[str]:
        """Ask every plan agent what is wrong, releasing leads AS THEY LAND.

        `on_leads` is called after each reply has been merged and admitted,
        and the round uses it to start blueteams. THE POINT IS THE WAITING:
        the replies were drained with `as_completed` and merged in one batch,
        so three agents that returned at 520s, 660s and 890s all had their
        leads held until 890s -- 370 seconds in which the fastest agent's
        work sat on the board with nothing reading it, every round.

        Two things are given up for that, and neither is free:

        * ACROSS-REPLY DEDUPLICATION BY EVIDENCE LENGTH. `merge_plans` used to
          see every reply at once, so when two agents named the same file and
          bug class the longer-evidenced one won. It now sees one reply at a
          time, and the second agent's sighting resolves through the board's
          ids instead: same lead, same id, and `admit` either takes the newer
          direction (if no blueteam has started) or keeps the running one. So
          the LAST reply to name a bug sets its direction where the LONGEST
          used to. Both are arbitrary between two agents that found the same
          thing; what is not arbitrary is that a running blueteam no longer
          has its direction changed underneath it.

        * IDS AS A SEVERITY RANKING. A lead's number now records when it
          arrived, not how bad it is. `ready()` was already ordered by
          priority so the dispatch order is unchanged, and `integrate` sorts
          on priority explicitly rather than relying on the id for it.
        """

        if self._sinks is None:
            # ONCE PER JOB, not per round: the base tree does not change, and
            # the plan agent reads the ORIGINAL every round.
            # Walked WIDE: the per-agent cap is applied by `_rows_for` once
            # the rows have been split by scope, so the walk must not spend the
            # budget before anybody knows whose rows they are.
            self._sinks = sink_digest(
                Path(self.workspace.original), limit=SCAN_SINK_LIMIT)
            self._sources = source_digest(
                Path(self.workspace.original), limit=SCAN_SOURCE_LIMIT)
            self._topology = compose_topology(Path(self.workspace.original))

        scopes = self.plan_scopes()

        # What this round DISCOVERED, not what it admitted. The plan agent
        # re-reads the tree each round and will name vulnerabilities it
        # already assigned; those are re-assignments — useful, because the
        # direction may be new — but they are not discoveries, and counting
        # them as such means a job that has stopped finding anything never
        # notices, because the same lead is "found" again every round.
        #
        # Taken ONCE, before the first reply is admitted, so "new" means new
        # to the round and not new to the reply.
        before = set(self.board.assignments)
        dropped: list[str] = []
        fresh: list[str] = []
        reassigned: list[str] = []
        # SETS, because a batch merge saw every reply at once and counted two
        # agents naming one bug as one lead. Merging one reply at a time
        # counts it twice unless the counting is by identity, and "plan named
        # 3" for a round that found one vulnerability is a worse answer than
        # the one this change was made to speed up.
        named: set[str] = set()
        answered = False
        # Merging reads the board to decide which ids are free and admitting
        # takes them: two calls that must not interleave, and the board's own
        # lock cannot span them. UNCONTENDED AS WRITTEN, because `take` is
        # called from the `as_completed` loop and so sees one reply at a time
        # -- the lock is here so that stays a property of this function
        # rather than something a reader has to go and verify.
        merge_gate = threading.Lock()

        def take(raw: str, scope: str = "") -> None:
            """Merge, admit and release ONE plan reply."""

            nonlocal answered
            reply = (raw or "").strip()
            if not reply:
                return
            with merge_gate:
                answered = True
                mark = len(dropped)
                found = merge_plans(
                    [reply],
                    existing=list(self.board.assignments.values()),
                    dropped=dropped,
                )
                # WHICH PART OF THE TREE, and whether anyone finished reading
                # it. "a plan reply could not be read: Expecting value: line 1
                # column 2 (char 1)" describes a model that wrote bad JSON; a
                # killed process is not that, and on job 7a92cd679e8c the two
                # were indistinguishable in the log. The operator could not
                # tell a part of the tree nobody had finished reading from a
                # reply with bad JSON.
                with self._cut_lock:
                    was_cut = scope in (self._cut_scopes or set())
                tag = scope or "the whole tree"
                for i in range(mark, len(dropped)):
                    dropped[i] = (
                        f"{tag}: the agent was cut off at "
                        f"{PLAN_TIMEOUT_S:.0f}s and left a fragment"
                        if was_cut else f"{tag}: {dropped[i]}"
                    )
                named.update(v.id for v in found)
                for assignment in self.board.admit(found):
                    vid = assignment.vulnerability.id
                    seen = reassigned if vid in before else fresh
                    if vid not in seen:
                        seen.append(vid)
                # HERE, not at the end of identify. These leads are about to
                # get a blueteam, and the board is the only record of WHAT
                # they are: the agent grid shows V4 running, and without this
                # the file that says what V4 IS does not exist for as long as
                # the slowest plan agent keeps reading. A crash in that window
                # lost every one of them, because the resume path rebuilds
                # submissions from board.assignments.
                self.publish_board()
            # OUTSIDE the gate. Starting a blueteam copies a tree and opens a
            # provider call; holding the merge lock across that would make the
            # next reply wait for exactly the thing this change exists to stop
            # waiting for.
            if on_leads is not None:
                on_leads()

        if len(scopes) < 2:
            # Nothing to split. One agent, the whole listing -- and THE WHOLE
            # listing. `summarise_tree` caps at 400 paths, which was fine when
            # this branch meant "a small bundle"; it does not mean that. Every
            # named part folding (a bundle of many small services, or one whose
            # parts are all protected) lands here too, and on a tree past the
            # cap every file beyond it was silently dropped: those files
            # reached no agent at all, and nothing said so. `plan_scopes` has
            # already walked the tree
            # and applied `_is_dependency`, so its own listing is both
            # complete and the same set the fan-out branch would have used.
            whole = "\n".join(
                rel for _name, files in scopes for rel in files
            ) or summarise_tree(Path(self.workspace.original))
            take(self._plan_once("", whole, known=known, feedback=feedback), "")
        else:
            # THE PLAN AGENT WAS THE ROUND'S LONGEST SERIAL STEP: 733 of round
            # one's 1170 seconds on job f432f9d8e16d, and 453 of round two's
            # 894, all of it one model reading one tree. The parts are
            # independent, so they are read at the same time.
            self.log(
                f"round: {len(scopes)} plan agents, one per part — "
                + ", ".join(f"{name} ({len(files)})" for name, files in scopes)
            )
            workers = min(len(scopes), max(1, self.budget.slots))
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers) as pool:
                futures = {
                    pool.submit(
                        self._plan_once, name, "\n".join(files),
                        known=known, feedback=feedback,
                    ): name
                    for name, files in scopes
                }
                for future in concurrent.futures.as_completed(futures):
                    take(future.result(), futures[future])

        # LOUD, because the alternative is indistinguishable from a clean
        # bundle: a plan agent that ignored the schema and a tree with nothing
        # attackable in it both produce an empty list.
        if dropped:
            # SAY WHAT ACTUALLY HAPPENED. Across the whole corpus not one of
            # the nine drops was a lead that stated no attack — every one was
            # a reply the reader could not use — and a header that names the
            # wrong cause sends the next reader looking in the wrong place.
            self.log(
                f"round: {len(dropped)} plan finding(s) not used — "
                + "; ".join(dropped[:6])
                + (f" (+{len(dropped) - 6} more)" if len(dropped) > 6 else "")
            )
        if not named and answered:
            self.log("round: the plan agents named nothing usable this round")
        # No "plan" lane here: each scope reported its own, and a summary
        # lane would sit in the grid next to them saying something none of
        # them said.
        #
        # Still ONE line for the whole round, after the last reply, even
        # though the leads went out one reply at a time: the operator reads
        # this to learn what the round found, and three partial lines would
        # be three answers to a question with one.
        self.log(
            f"round: plan named {len(named)}; new {fresh}"
            + (f", re-assigned {reassigned}" if reassigned else "")
        )
        # NO publish here. Leads reach the board as they are ADMITTED now,
        # and a round that admitted nothing still gets one from `ship`, so a
        # third write would only be a third chance to race the other two.
        return fresh

    # -- one blueteam -----------------------------------------------------

    def _tree_for(self, assignment: Assignment) -> Path:
        suffix = _SAFE_SUFFIX.sub("-", assignment.vulnerability.id.lower())
        dest = self.work_dir / f"bt-{suffix}"
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(Path(self.workspace.original), dest, symlinks=True)
        _make_writable(dest)
        self._seed_rebase(assignment, dest)
        return dest

    @staticmethod
    def _finding_lines(verdict: Any) -> list[str]:
        """The validator's findings as lines an agent can act on."""

        out: list[str] = []
        for f in getattr(verdict, "unexplained", ()) or ():
            kind = str(getattr(f, "kind", "") or "?")
            name = str(getattr(f, "name", "") or "?")
            detail = str(getattr(f, "detail", f))[:200]
            out.append(f"[{kind}] {name}: {detail}")
        return out

    def _diff_text(self, changed: Mapping[str, bytes]) -> str:
        try:
            return unified_patch(
                Path(self.workspace.original), changed
            ).get("diff", "")
        except Exception:  # noqa: BLE001 - a prompt must not lose a patch
            return ""

    def _out_of_time(self) -> bool:
        """Is there time to hand this back once more?

        A retry that starts too late is the failure `ROUND_RESERVE_S` already
        guards against between rounds, one level down: its stack is still up
        when the job is killed.
        """

        if self.deadline is None:
            return False
        return self.now() + RETRY_RESERVE_S > self.deadline

    def patch_one(self, assignment: Assignment) -> BlueteamOutcome:
        """Hand one vulnerability to a blueteam, and keep handing it back.

        THE RETRY IS IN HERE RATHER THAN A ROUND AWAY. A refusal used to end
        this vulnerability's round: the findings went nowhere, and the next
        attempt waited behind a plan agent that cost 733 seconds on job
        f432f9d8e16d. Handing the SAME agent the lines that differed costs one
        model call and one stack -- and the blueteams run concurrently, so the
        round pays for the slowest retry, not the sum of them.

        NOTHING COUNTS ATTEMPTS. The operator is the only brake; the two
        things that end this loop are the deadline and a blueteam that has
        stopped producing new work. The second is not a ration: an agent that
        returns byte-identical files has said everything it has to say, and
        paying another stack for the same verdict buys nothing. The next
        round's plan agent is the thing that can change strategy.
        """

        vid = assignment.vulnerability.id
        # Findings from an earlier ROUND, so a re-assigned vulnerability opens
        # with what refused it last time rather than rediscovering it.
        findings = list(assignment.findings)
        own_diff = ""
        # EVERY attempt, not the last one. This was a single slot compared
        # against the next patch, so it could only ever catch a repeat that
        # was ADJACENT: on job 7b91e6188cea V10's refusals came back
        # 1641, 1595, 378, 47, 1595, 432, 1595, 447 — the same verdict three
        # times, never twice in a row, so the guard could not fire whatever
        # the bytes were. A set is memory, not a ration: nothing here counts
        # attempts or refuses to hand the work out again.
        seen: set[str] = set()
        # The closest any attempt has come, kept as a PAIR. Handing back the
        # last attempt's diff with the last attempt's findings is coherent;
        # handing back the best diff with the last findings is not, so both
        # travel together or neither does.
        best: tuple[tuple[int, int], str, list[str]] | None = None
        last_verdict: Any = None

        while True:
            assignment.attempts += 1
            assignment.note(IN_FLIGHT, f"attempt {assignment.attempts}")
            self.agent_state(vid, "running", f"attempt {assignment.attempts}")
            tree = self._tree_for(assignment)
            target = tree / assignment.vulnerability.path
            try:
                source = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                source = "(the file named by the plan agent could not be read)"

            # No try/except around the agent call. An earlier draft had one,
            # and the mutation suite showed it could be deleted without a
            # single check noticing: the fan-out's own guard already catches
            # anything raised in here, records the same reason on the same
            # assignment, and keeps the round alive. A guard indistinguishable
            # from its neighbour is not defence in depth, it is untested code
            # that reads like a guarantee.
            self.invoke(
                "blueteam",
                BLUETEAM_SYSTEM,
                blueteam_prompt(assignment.vulnerability, source,
                                findings=findings, own_diff=own_diff),
                cwd=tree,
                timeout_s=BLUETEAM_TIMEOUT_S,
            )

            changed, added = collect_changes(
                Path(self.workspace.original), tree
            )
            if added:
                self.log(
                    f"round: {vid} added {len(added)} file(s) that the ZIP "
                    f"cannot carry; ignored: {added[:3]}"
                )
            if not changed:
                assignment.note(FAILED, "the blueteam changed nothing")
                self.agent_state(vid, "failed", "changed nothing")
                return BlueteamOutcome(vid, None, validation=last_verdict,
                                       reason="no change",
                                       ignored_additions=tuple(added))

            forbidden = protected_paths(
                changed, allow_dependency_manifests=True)
            if forbidden:
                # Before the stack, not after. A patch to the compose file
                # breaks the harness rather than the service, and discovering
                # that costs a whole stack if it is left to the validator.
                detail = ", ".join(forbidden[:3])
                assignment.note(
                    FAILED,
                    f"edited files a patch may not touch ({detail}); the fix "
                    "has to live in application source",
                )
                self.log(f"round: {vid} edited protected file(s): {detail}")
                self.agent_state(vid, "failed", f"protected: {detail}")
                return BlueteamOutcome(
                    vid, None, validation=last_verdict,
                    reason=f"edited protected file(s): {detail}",
                    ignored_additions=tuple(added),
                )

            digest = hashlib.sha256(
                b"".join(
                    path.encode("utf-8") + b"\0" + changed[path] + b"\0"
                    for path in sorted(changed)
                )
            ).hexdigest()
            if digest in seen:
                assignment.note(
                    FAILED,
                    "handed back the same patch after being told what "
                    "differed; a new direction has to come from the plan agent",
                    findings=findings,
                )
                self.log(
                    f"round: {vid} produced the same patch again — not paying "
                    "for the same verdict twice"
                )
                self.agent_state(vid, "failed", "same patch again")
                return BlueteamOutcome(
                    vid, None, validation=last_verdict,
                    reason="repeated the refused patch",
                    ignored_additions=tuple(added),
                )
            seen.add(digest)

            # THE VALIDATION IS WHAT COSTS A STACK, so the budget is taken
            # here and not around the agent call above.
            suffix = _SAFE_SUFFIX.sub("-", vid.lower())
            self.agent_state(vid, "running", "validating")
            self.budget.acquire()
            try:
                verdict = self.validator.validate(
                    tree, sorted(changed), suffix=f"bt{suffix}"
                )
            finally:
                self.budget.release()
            last_verdict = verdict

            if verdict.ok:
                break

            detail = (
                "availability" if not verdict.availability
                else f"{len(verdict.unexplained)} unexplained"
            )
            findings = self._finding_lines(verdict)
            # THE CLOSEST ONE, not the most recent. `own_diff` was overwritten
            # on every refusal, so an attempt that nearly passed was thrown
            # away by the next one that did not: job 7b91e6188cea's V10
            # reached 47 unexplained on its fourth try and came back at 1595
            # on its fifth, and nothing anywhere still held the patch that had
            # got to 47. An availability failure scores worse than any number
            # of unexplained lines, because a stack that did not come up is
            # not a near miss.
            score = (0 if verdict.availability else 1, len(verdict.unexplained))
            if best is None or score < best[0]:
                best = (score, self._diff_text(changed), list(findings))
            own_diff, findings = best[1], list(best[2])
            assignment.note(FAILED, f"validator refused it ({detail})",
                            findings=findings)
            self.log(f"round: {vid} refused by the validator ({detail})")
            for line in findings[:PROMPT_FINDINGS]:
                self.log(f"    {vid} {line[:160]}")

            if self._out_of_time():
                self.log(
                    f"round: {vid} has no time left to try again before the "
                    "job deadline"
                )
                self.agent_state(vid, "failed", f"refused: {detail}")
                return BlueteamOutcome(
                    vid, None, validation=verdict,
                    reason=f"validator refused: {detail}",
                    ignored_additions=tuple(added),
                )
            self.agent_state(
                vid, "retrying",
                f"refused ({detail}); patching again",
            )
            self.log(
                f"round: {vid} patching again with the {len(findings)} "
                "line(s) that differed"
            )

        submission = PatchSubmission(
            vulnerability_id=vid,
            bug_class=assignment.vulnerability.bug_class,
            path=assignment.vulnerability.path,
            summary=assignment.vulnerability.patch_direction,
            mitigation_class="unknown",
            files=changed,
            # So the merge can order by severity without a board to ask.
            priority=assignment.vulnerability.priority,
        )
        try:
            patch = unified_patch(Path(self.workspace.original), changed)
        except Exception:  # noqa: BLE001 - a view must not lose a good patch
            patch = {"paths": sorted(changed), "added": 0,
                     "removed": 0, "diff": ""}
        # Diffed OUTSIDE the lock and assigned inside it: the diff reads every
        # changed file and `publish_board` only needs the dict to stop moving.
        with self._view_lock:
            self.patches[vid] = patch
        assignment.note(SUBMITTED, f"{len(changed)} file(s) validated",
                        findings=[])
        self.log(f"round: {vid} validated, {len(changed)} file(s) submitted")
        self.agent_state(vid, "done", f"{len(changed)} file(s) validated")
        # ON THIS THREAD, THE MOMENT THE VALIDATOR PASSED IT. `_collect` used
        # to do this, and `_collect` cannot start until `identify` has
        # returned: on job 8bd3c68d8df6 this patch validated at 07:19:16 and
        # the last plan agent did not answer until 07:22:46, so a finished fix
        # sat 3m30s inside a worker's return value -- unrecorded, unpublished,
        # and invisible to a scoring tick that came and went in between.
        #
        # This is also the FIRST caller that makes `ship`'s coalescing do
        # anything. Called one outcome at a time from a single collecting
        # thread, the calls never overlapped, so N validated patches bought N
        # integrated validations -- N whole compose stacks -- rather than the
        # "two or three integrations, not one per vulnerability" its docstring
        # claims. From the blueteams' own threads they do overlap, and the
        # ones that arrive mid-build collapse into the build already running.
        with self._ship_gate:
            self.submissions[vid] = submission
        try:
            self.ship()
        except Exception as exc:  # noqa: BLE001
            # A BUNDLE THAT WOULD NOT BUILD IS NOT THIS PATCH'S FAULT. The
            # submission is already recorded, so `run_round`'s closing `ship`
            # will try it again and end the round there if it is real; losing
            # this outcome instead would also lose the reason.
            self.log(
                f"round: {vid} validated but the bundle did not build ({exc})"
            )
        return BlueteamOutcome(vid, submission, validation=verdict,
                               ignored_additions=tuple(added))

    # -- the round --------------------------------------------------------

    def run_round(
        self,
        *,
        index: int,
        known: int | None = None,
        feedback: str = "",
        blocked: int | None = None,
    ) -> RoundResult:
        self._round_published = None
        self._round_integrated_ok = False
        # ONE pool for the whole round, held open across `identify`, because
        # the blueteams now start while the plan agents are still reading.
        futures: dict[concurrent.futures.Future, Assignment] = {}
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, self.budget.slots)) as pool:
            try:
                identified = self.identify(
                    known=known, feedback=feedback,
                    on_leads=lambda: self._dispatch(pool, futures),
                )
                # More leads than the contest announced is worth saying,
                # because the operator's count is the only statement anyone
                # has about how many exist. It no longer decides ANYTHING --
                # nothing is rationed, so every lead gets an agent -- and this
                # used to print each one's reach label, a field that no longer
                # exists.
                if known is not None and len(self.board.assignments) > known:
                    self.log(
                        f"round: {len(self.board.assignments)} leads against "
                        f"{known} announced — all of them get an agent"
                    )
                stalled = self.board.stalled()
                if stalled:
                    self.log(
                        "round: still open after several attempts each — "
                        f"{[a.vulnerability.id for a in stalled]} "
                        "(still being worked; this is where the budget is "
                        "going)"
                    )
                # What no plan reply released: an assignment left DEFERRED or
                # FAILED by an earlier round when this round's agents named
                # nothing new, and every lead at all on the path where
                # `on_leads` never fired because every reply was blank.
                self._dispatch(pool, futures)
            finally:
                # EVEN IF `identify` RAISED. Leads are released while the plan
                # agents are still reading, so by the time anything can go
                # wrong up there a blueteam may already be running -- and
                # `dispatch` marked it IN_FLIGHT, which `ready()` does not
                # return. Letting the pool's own exit wait for it and discard
                # the result would strand that vulnerability for the whole job.
                outcomes = self._collect(futures)
        # One more, for whatever landed while the last build was running and
        # for the deferrals the merge could not take.
        self.ship()
        published = self._round_published
        integrated_ok = self._round_integrated_ok
        remaining = remaining_estimate(
            known=known,
            integrated=len(self.board.integrated()),
            blocked=blocked,
        )
        self.log(f"round {index}: {remaining[1]}")
        return RoundResult(
            index=index,
            identified=tuple(identified),
            outcomes=tuple(outcomes),
            published=published,
            integrated_ok=integrated_ok,
            remaining=remaining,
            board=self.board.as_dict(),
            integrated=self._last_integrated,
        )

    def _dispatch(
        self,
        pool: concurrent.futures.ThreadPoolExecutor,
        futures: dict[concurrent.futures.Future, Assignment],
    ) -> None:
        """Give every ready assignment a blueteam, NOW.

        Called once per plan reply rather than once per round. A lead the
        first of three plan agents found used to wait for the slowest one to
        finish reading its own part of the tree -- on this bundle's rounds
        that was between five and six minutes of a blueteam that could have
        been running.

        `board.dispatch()` marks what it hands back IN_FLIGHT while holding
        the board's lock, so a call that overlaps an earlier one cannot name
        the same assignment twice. It must not: `_tree_for` rmtree's `bt-<id>`
        on the way in, so two blueteams on one id means the second deletes the
        first one's workspace out from under it mid-read.

        Everything returned is therefore ALREADY in-flight, and dropping one
        here instead of submitting it would hide it from `ready()` for the
        rest of the job.
        """

        for assignment in self.board.dispatch():
            futures[pool.submit(self.patch_one, assignment)] = assignment

    def _collect(
        self, futures: dict[concurrent.futures.Future, Assignment],
    ) -> list[BlueteamOutcome]:
        """Wait for the blueteams and take what they returned.

        NOT WHERE SHIPPING HAPPENS ANY MORE. It was, and it cannot start
        until `identify` has returned -- so on job 8bd3c68d8df6 a patch that
        validated at 07:19:16 waited for a plan agent that answered at
        07:22:46. `patch_one` records and ships its own submission now, on
        its own thread, the moment the validator passes it.

        This is still the round's JOIN, which is why nothing else had to
        become one: a blueteam's `ship()` runs inside `patch_one`, so its
        future does not resolve until that call has returned. When this loop
        ends, every future is done and therefore no thread is inside the repo
        agent -- `_round_published` is a settled fact by the time `run_round`
        reads it, with no second thread to wait for and no stop event to get
        right.

        Agent concurrency is capped at the slot budget by the pool the caller
        owns, even though agents do not hold slots: without SOME cap a plan
        agent that names twelve vulnerabilities opens twelve provider calls at
        once, and the operator pays for all of them before the first verdict
        comes back.
        """

        if not futures:
            return []
        outcomes: list[BlueteamOutcome] = []
        for future in concurrent.futures.as_completed(futures):
            assignment = futures[future]
            try:
                outcomes.append(future.result())
            except Exception as exc:  # noqa: BLE001
                # One blueteam dying must not end the round: the others'
                # work is still valid and the board keeps the reason.
                assignment.note(FAILED, f"{type(exc).__name__}: {exc}"[:200])
                outcomes.append(
                    BlueteamOutcome(
                        assignment.vulnerability.id, None,
                        reason=f"{type(exc).__name__}: {exc}"[:200],
                    )
                )
        outcomes.sort(key=lambda o: o.vulnerability_id)
        self.publish_board()
        return outcomes

    _last_integrated: Any = None
    # Run one, kept only so a reader can see what the second stack cleared.
    _first_integrated: Any = None

    @staticmethod
    def _reproduced(finding: Any, second: Any) -> bool:
        """Did the second stack see this finding too?

        A request the second stack could not judge -- unstable there, or
        broken there -- yields NO evidence, so the finding is kept. Dropping
        it would turn "we did not look" into "it was not there", which is the
        one way a second opinion can make the gate weaker than one stack.
        """

        name = getattr(finding, "name", "")
        if name in set(second.verdict.unstable) or name in set(second.verdict.broken):
            return True
        # getattr throughout: `findings` is whatever the validator handed
        # back, and the thing that decides whether a patch ships must not be
        # the thing that raises on an unexpected shape.
        seen = {_finding_key(f) for f in second.verdict.findings}
        return _finding_key(finding) in seen

    def _second_opinion(self, first: Any, files: Sequence[str]) -> Any:
        """Re-judge a FAILED integrated bundle in a fresh, independent stack.

        This is the confirmation the validator already performs -- "a finding
        that does not reproduce is noise" -- moved to the axis where the
        variance actually lives. Its two confirmation passes share one stack,
        so anything that varies BETWEEN stacks survives them intact.

        Job f432f9d8e16d is why. Several patches each passed validation on
        the full corpus; their bundle was then refused on findings, every one
        of them a value the database maintains for itself, which can differ
        between two freshly seeded instances. `broken` was empty and
        availability held. Every patch the round had validated was discarded
        with the refused bundle.

        Paid once per round and only on failure, which is where a false
        positive is most expensive: a whole round's work, not one patch.
        A genuine interaction between two patches reproduces in any stack, so
        this does not blind the check to the thing it exists for -- two
        patches that each pass alone and break together.
        """

        if not first.availability or first.verdict.broken:
            # Terminal on either run. A bundle that will not come up, or whose
            # requests error outright, is not a comparison artefact.
            return first

        self.log(
            "round: asking a second independent stack whether those findings "
            "are the bundle or the environment"
        )
        self.budget.acquire()
        try:
            second = self.validator.validate(
                Path(self.workspace.candidate), list(files),
                suffix="integratedb",
            )
        except Exception as exc:  # noqa: BLE001 - a failed retry must not
            # end the round; without a second opinion we keep the first.
            self.log(f"round: the second stack did not answer ({exc})")
            return first
        finally:
            self.budget.release()

        if not second.availability:
            return first

        kept_findings = tuple(
            f for f in first.verdict.findings if self._reproduced(f, second)
        )
        kept_unexplained = tuple(
            f for f in first.unexplained if self._reproduced(f, second)
        )
        dropped = len(first.unexplained) - len(kept_unexplained)
        if dropped:
            self.log(
                f"round: {dropped} integrated finding(s) did not reproduce on "
                "a second stack and were discarded as environmental"
            )
        merged = replace(
            first.verdict,
            ok=not kept_findings,
            findings=kept_findings,
            # The WEAKER of the two coverages, and every request either stack
            # had to skip: a verdict must not read as better evidenced than
            # the thinner of the runs behind it.
            checked=min(first.verdict.checked, second.verdict.checked),
            unstable=tuple(sorted(
                set(first.verdict.unstable) | set(second.verdict.unstable)
            )),
        )
        return replace(
            first,
            ok=not kept_unexplained,
            verdict=merged,
            explained=tuple(
                f for f in first.explained if self._reproduced(f, second)
            ),
            unexplained=kept_unexplained,
        )

    def _ship_once(self) -> None:
        """Build the bundle, publish it, and record what shipped.

        The board bookkeeping lives HERE rather than in `run_round` because
        shipping no longer happens only at the end of a round. Left where it
        was, a mid-round publish would ship a patch and then the round's final
        integration — byte-identical to it, so `published` is None — would
        take the "nothing reached the operator" branch and never mark those
        vulnerabilities integrated.
        """

        published, ok = self._integrate_and_publish()
        merge = self._last_merge
        if merge is not None:
            # WHERE it collided, not just that it did. The next attempt starts
            # from the winner's version of that one file, which is the only
            # thing that can make the retry differ from the try.
            for deferral in merge.deferred:
                # REBOUND, not mutated in place. `_seed_rebase` runs on a
                # blueteam's thread as its tree is copied and does
                # `sorted(...)` over the set this `.get`s; `.add()` on the set
                # that thread is sorting raises "Set changed size during
                # iteration". Shipping ran on the round's own thread when this
                # was written and now runs on a blueteam's. Building a new set
                # means the one the reader is holding never changes under it,
                # and neither side needs a lock.
                self._rebase[deferral.vulnerability_id] = (
                    self._rebase.get(deferral.vulnerability_id, set())
                    | {deferral.path}
                )
            if published is not None:
                self.board.apply_merge(merge)
            else:
                # A DEFERRAL is true whether or not a version was cut -- the
                # merge really could not take that patch. ACCEPTANCE is not:
                # if the integrated bundle failed validation, or was identical
                # to the last one, nothing NEW reached the operator, and
                # marking those vulnerabilities integrated would stop the
                # board from ever working on them again while the count read
                # as coverage.
                # THROUGH THE BOARD, so it happens under the board's lock.
                # This runs on a blueteam's thread now, and `ready()` decides
                # from `state` whether an assignment gets another agent.
                self.board.defer(merge.deferred)
        if published is not None:
            self._round_published = published
        self._round_integrated_ok = ok or self._round_integrated_ok
        self.publish_board()

    def ship(self) -> None:
        """Publish what is validated so far, coalescing concurrent calls.

        AS SOON AS A PATCH VALIDATES, not when the round ends. Measured on
        job 3d0cf9b6e883: V7 passed at 01:50:20 and sat unshipped for seven
        minutes while the round waited on two blueteams still retrying; V6,
        V4 and V3 piled up behind it, and a scoring tick went by
        with four validated patches in hand and nothing submitted. The module
        already holds this principle for `patch-progress.json` -- "a fix that
        exists at minute three is downloadable at minute three" -- and the
        bundle was the one thing still waiting for the end of the round.

        Coalescing, not queueing: a patch that lands while a bundle is being
        built makes the running build go round once more rather than starting
        a second one. So a round pays for two or three integrations, not one
        per vulnerability.
        """

        with self._ship_gate:
            if self._shipping:
                self._ship_again = True
                return
            self._shipping = True
        try:
            while True:
                with self._ship_gate:
                    self._ship_again = False
                self._ship_once()
                with self._ship_gate:
                    # Cleared under the SAME lock as the check, or a patch
                    # landing in between would set a flag nobody reads.
                    if not self._ship_again:
                        self._shipping = False
                        return
        except BaseException:
            with self._ship_gate:
                self._shipping = False
            raise

    def _integrate_and_publish(self) -> tuple[dict[str, Any] | None, bool]:
        """Fold every patch that has ever passed, then check the whole thing.

        EVERY submission, not just this round's: the bundle is cumulative, and
        rebuilding it from the full set each time is what makes a deferred
        patch simply re-merge once the conflict clears, with no separate
        replay path to get wrong.
        """

        with self._ship_gate:
            # A COPY. Blueteam threads add to `submissions` as they validate,
            # and iterating a dict another thread is writing raises.
            submissions = [self.submissions[k] for k in sorted(self.submissions)]
        if not submissions:
            self._last_merge = None
            self.log("round: nothing validated, so there is nothing to integrate")
            self.agent_state("repo", "idle", "nothing validated to integrate",
                             role="repo")
            return None, False
        self.agent_state("repo", "running",
                         f"merging {len(submissions)} patch(es)", role="repo")

        base = self.repo.base_files(
            {path for s in submissions for path in s.files}
        )
        # Whatever has already reached the operator claims its paths first.
        merge = integrate(base, submissions,
                          protected=self.repo.shipped_ids())
        self._last_merge = merge
        self.repo.materialise(merge)
        if merge.deferred:
            self.log(
                "round: deferred "
                + ", ".join(
                    f"{d.vulnerability_id} ({d.reason})" for d in merge.deferred
                )
            )
        if not merge.accepted:
            return None, False

        self.budget.acquire()
        try:
            verdict = self.validator.validate(
                Path(self.workspace.candidate),
                sorted(merge.files),
                suffix="integrated",
            )
        finally:
            self.budget.release()

        self._first_integrated = verdict
        if not verdict.ok:
            verdict = self._second_opinion(verdict, sorted(merge.files))
        self._last_integrated = verdict
        if not verdict.ok:
            # Name the requests. "2 unexplained" is a number nobody can act
            # on; `report_page` and `listing` are two places to look.
            # getattr, not attribute access: `unexplained` is whatever the
            # validator handed back, and a logging line must never be the
            # thing that ends a round.
            where = ", ".join(sorted(
                {n for n in (getattr(f, "name", "") for f in verdict.unexplained) if n}
            )) or "no request named"
            self.log(
                "round: the INTEGRATED bundle failed validation "
                f"({len(verdict.unexplained)} unexplained on {where}) — two "
                "patches that each passed alone can still break together"
            )
            for finding in verdict.unexplained[:PROMPT_FINDINGS]:
                self.log(
                    f"    integrated [{getattr(finding, 'kind', '?')}] "
                    f"{getattr(finding, 'name', '?')}: "
                    f"{str(getattr(finding, 'detail', finding))[:120]}"
                )
            self.agent_state(
                "repo", "failed",
                f"bundle refused on {where}"[:120], role="repo",
            )
            return None, False

        builder = self.zip_builder
        if builder is None:
            from modules.live_fire_workspace import build_patched_zip

            builder = build_patched_zip
        entry = self.repo.publish(
            merge, validation=verdict, submissions=submissions, builder=builder
        )
        if isinstance(entry, dict):
            self.agent_state(
                "repo", "done",
                f"published {entry.get('version') or '?'} "
                f"({entry.get('vuln_clear', '?')} vuln clear)",
                role="repo",
            )
            return entry, True
        # PUBLISH DECLINED — and the grid used to say "published a version"
        # anyway, because the ternary only read `entry` when it was a dict.
        # `publish` returns None three ways: the bundle was byte-identical to
        # the last, nothing was accepted, or cutting it would have un-fixed
        # something already shipped. The operator is the only brake on this
        # engine, and a lane claiming a publish at the moment the bundle
        # stopped moving is worse than no lane at all — the contradicting
        # evidence is one line in a log the grid exists so nobody has to read.
        self.agent_state("repo", "idle", "nothing new to publish", role="repo")
        return entry, True

    def report(self) -> Path:
        submissions = [self.submissions[k] for k in sorted(self.submissions)]
        return self.repo.write_report(submissions)


__all__ = [
    "AGENTS_NAME",
    "BLUETEAM_TIMEOUT_S",
    "BlueteamOutcome",
    "LiveFireV2Runner",
    "PLAN_TIMEOUT_S",
    "RETRY_RESERVE_S",
    "RoundError",
    "RoundResult",
    "collect_changes",
    "unified_patch",
]
