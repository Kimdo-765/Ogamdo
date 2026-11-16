"""The repo agent: N independent patches in, one integrated bundle out.

THE OPERATOR'S SPEC:

    repo agent는 validator agent에게 검사받은 패치파일을 인수받아 패치 통합본
    으로 재생산 및 이력 관리, 레포트 생산, 오퍼레이터에게 패치 통합본 버전별로
    제공

WHY MERGING IS A REAL PROBLEM AND NOT BOOKKEEPING.
In v1 one agent edited one candidate tree, so "the patch" and "the tree" were
the same object.  v2 has N blueteam agents, each working on its OWN copy of
base so they cannot overwrite one another mid-flight, which means what arrives
here is N INDEPENDENT DIFFS AGAINST A COMMON BASE.  Two of them touching the
same file is not an exotic case: one source file can easily hold two
vulnerabilities.

The rule this module implements is therefore:

  * a file only one submission touched  -> take it
  * a file several touched, in regions that do not overlap -> merge both
  * a file several touched, overlapping -> take the FIRST in a deterministic
    order and DEFER the rest, saying so

DEFER, NOT DROP.  A silently discarded patch is a vulnerability the operator
believes is fixed.  A deferral is a work item: the plan agent re-tasks that
blueteam against the MERGED tree, where the conflict no longer exists because
the other fix is already in it.

AND THE INTEGRATED BUNDLE IS RE-VALIDATED.  Two individually safe patches can
break together -- one escapes a value the other now double-escapes, one
renames a helper the other calls.  The operator uploads what THIS module
produces, not what any single blueteam produced, so this output is what has to
be checked.  That is the caller's job, but it is not optional, and
`publish()` refuses to record a version as verified without a verdict.

BYTES, NOT TEXT.  A source file need not be valid UTF-8, and decoding one
raised UnicodeDecodeError in the v1 loop, which is how an unexplained change
shipped on job bf8d00c76ed8.  Every path here works on bytes and splits on
b"\\n", so a binary file merges when only one submission touched it and
conflicts honestly when several did.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

PROGRESS_NAME = "patch-progress.json"
REPORT_NAME = "report.md"


def _id_order(vid: str) -> tuple[int, str]:
    """V2 before V10. The twin of the orchestrator's helper, kept local so
    this module stays free of imports from its siblings.

    NOT COSMETIC HERE. `integrate` used to sort by the raw id, so V18 claimed
    a path before V6 and V19 before V8 -- and the loser of a merge is dropped
    whole. On job 586ba6888920 that silently un-fixed V6 (part of which
    conflicted with NOTHING) and V8, both already shipped, between the v9
    and v20 bundles."""

    match = re.search(r"(\d+)$", vid)
    return (int(match.group(1)) if match else 1_000_000, vid)


class RepoError(ValueError):
    """The integrated bundle could not be produced."""


@dataclass(frozen=True)
class PatchSubmission:
    """One blueteam's validated patch, as a set of whole files.

    Whole files rather than a diff because that is what the blueteam actually
    has -- its own copy of base with edits applied -- and because reconstructing
    a diff only to re-apply it adds a step that can fail.  The base content is
    carried alongside so the merge can be three-way: without it, two
    submissions that both "changed" a file are indistinguishable from two that
    merely both contain it.
    """

    vulnerability_id: str
    bug_class: str
    path: str
    summary: str
    mitigation_class: str
    files: Mapping[str, bytes]
    # CARRIED, not re-derived, because `integrate` orders by it and the merge
    # has no board to ask. It used to be unnecessary: ids were handed out in
    # priority order within a round, so sorting by id sorted by severity as a
    # side effect. Plan replies are merged as they land now, so V6 can be
    # worse than V2 -- the coupling is gone and the field has to be real.
    priority: int = 99

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "bug_class": self.bug_class,
            "path": self.path,
            "summary": self.summary,
            "mitigation_class": self.mitigation_class,
            "priority": self.priority,
            "files": sorted(self.files),
        }


@dataclass(frozen=True)
class Deferral:
    vulnerability_id: str
    path: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "path": self.path,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MergeResult:
    files: Mapping[str, bytes]
    accepted: tuple[str, ...]
    deferred: tuple[Deferral, ...]
    merged_paths: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": list(self.accepted),
            "deferred": [d.as_dict() for d in self.deferred],
            "changed_paths": sorted(self.files),
            "co_edited_paths": list(self.merged_paths),
        }


def _lines(payload: bytes) -> list[bytes]:
    return payload.split(b"\n")


def _changed_ranges(base: Sequence[bytes], other: Sequence[bytes]) -> list[tuple[int, int, list[bytes]]]:
    """Where `other` departs from `base`, in base coordinates."""

    matcher = difflib.SequenceMatcher(None, list(base), list(other), autojunk=False)
    out: list[tuple[int, int, list[bytes]]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        out.append((i1, i2, list(other)[j1:j2]))
    return out


def _contains(outer: Sequence[Any], inner: Sequence[Any]) -> bool:
    """Every edit in `inner` is also in `outer`, counting duplicates.

    This is how a REBASED patch is recognised, and recognising it explicitly is
    the whole point. An earlier attempt inferred agreement from two edit lists
    merely SHARING a hunk, and that is not the same statement: inside a run of
    identical lines `_changed_ranges` splits a one-line substitution into an
    insertion plus a deletion, and the deletion half lands at the same base
    range for both sides whichever occurrence each actually edited. Dropping
    that shared hunk as "agreed" deleted the very entry whose `start < cursor`
    test detected the overlap, and two genuinely conflicting patches merged
    into a file neither blueteam wrote. Containment cannot make that mistake:
    the artifact is ONE hunk out of several, and the real edit each side made
    is absent from the other's list.
    """

    remaining = [tuple((s, e, tuple(r))) for s, e, r in outer]
    for edit in inner:
        key = (edit[0], edit[1], tuple(edit[2]))
        if key not in remaining:
            return False
        remaining.remove(key)
    return True


def _merge_edits(
    left: Sequence[tuple[int, int, list[bytes]]],
    right: Sequence[tuple[int, int, list[bytes]]],
) -> list[tuple[int, int, list[bytes]]] | None:
    """Pool two edit lists in BASE coordinates, or refuse.

    NOTHING IS DEDUPED HERE. A hunk appearing in both lists is two entries, and
    the second one tripping the cursor is exactly the refusal we want -- see
    `_contains` for why "both lists hold this hunk" does not mean "both sides
    made this change".
    """

    edits = sorted(list(left) + list(right), key=lambda e: (e[0], e[1]))
    cursor = 0
    last_insert_at: int | None = None
    for start, end, _replacement in edits:
        # Regions that overlap: there is no honest way to pick between them.
        if start < cursor:
            return None
        if start == end:
            # Two INSERTIONS at the same point do not overlap by the rule
            # above -- both are zero-width -- but their order is not
            # decidable, and choosing one silently reorders somebody's code.
            if last_insert_at == start:
                return None
            last_insert_at = start
        cursor = end
    return edits


def _apply_edits(
    base: bytes, edits: Sequence[tuple[int, int, list[bytes]]]
) -> bytes:
    """Lay a sorted, non-overlapping edit list back onto the base."""

    base_lines = _lines(base)
    out: list[bytes] = []
    cursor = 0
    for start, end, replacement in edits:
        out.extend(base_lines[cursor:start])
        out.extend(replacement)
        cursor = end
    out.extend(base_lines[cursor:])
    return b"\n".join(out)


def merge_three_way(base: bytes, left: bytes, right: bytes) -> bytes | None:
    """Combine two independent edits of `base`, or refuse.

    Returns None when the two edits touch overlapping regions, because there is
    no honest way to pick: guessing here ships a file neither blueteam wrote
    and neither validator checked.  Adjacent-but-not-overlapping edits DO
    merge, which is the common case when two fixes land in different functions
    of the same file.

    One side CONTAINING the other is not a conflict, it is a rebase: the patch
    that lost a merge was handed the winner's version of the file and wrote its
    fix on top, so its edit list is the winner's plus its own.
    """

    left_edits = _changed_ranges(_lines(base), _lines(left))
    right_edits = _changed_ranges(_lines(base), _lines(right))
    if _contains(right_edits, left_edits):
        return right
    if _contains(left_edits, right_edits):
        return left
    combined = _merge_edits(left_edits, right_edits)
    if combined is None:
        return None
    return _apply_edits(base, combined)


def integrate(
    base_files: Mapping[str, bytes],
    submissions: Sequence[PatchSubmission],
    *,
    protected: Sequence[str] = (),
) -> MergeResult:
    """Fold N independent patches into one tree, deterministically.

    Order is by severity then vulnerability id, not arrival — WITH ONE
    DELIBERATE EXCEPTION named below. Two runs of the same job should produce
    the same bundle, and "whoever finished first" is not a property the
    operator can reason about or a maintainer can reproduce.

    SEVERITY IS SORTED ON EXPLICITLY because it stopped being implied. Ids
    were handed out in priority order within a round, so ordering by id put
    the worst bug first for free; once plan replies began being merged as they
    landed, an id became a record of WHEN a lead arrived and nothing else. The
    id is still in the key, and still breaks every tie, so the result is as
    reproducible as it was -- it is the first field that changed meaning.

    THE EXCEPTION, and it is a real cost paid on purpose. `protected` is a fact
    about what has ALREADY BEEN PUBLISHED, so when two patches are mutually
    exclusive -- the same line of the same file -- which one is standing when
    the first version is cut decides which one keeps the path, and that depends
    on which blueteam validated first. Two runs can therefore keep different
    (both valid) fixes for such a pair. The alternative is worse: without the
    protection a newcomer displaces a fix the operator already has, which is
    exactly how job 586ba6888920 shipped v20 without the V6 and V8 fixes
    that v9 already carried. Losing reproducibility of WHICH of two
    equivalent fixes survives costs less than taking one back.

    `protected` names the vulnerabilities that are ALREADY IN A PUBLISHED
    BUNDLE. They claim their paths first, so a newcomer can never displace a
    fix the operator has already been handed. This is the structural half of
    the guarantee; `publish` refuses the version if one goes missing anyway.

    Ordering alone is not enough and was not the whole bug: the natural order
    fixes WHO wins, protection fixes WHAT MAY BE LOST. On job 586ba6888920 the
    raw-id sort put V18 ahead of V6 and V19 ahead of V8, and both losers had
    already shipped in the v9 bundle.
    """

    shipped = set(protected)
    ordered = sorted(
        submissions,
        key=lambda s: (
            0 if s.vulnerability_id in shipped else 1,
            s.priority,
            _id_order(s.vulnerability_id),
        ),
    )
    # EDIT LISTS, NOT ACCUMULATED BYTES, and this is the load-bearing choice.
    # Re-diffing the merged file to find "what is already applied" asks
    # SequenceMatcher to describe a file it has never seen the history of, and
    # it answers with whatever alignment is cheapest: two accepted hunks a line
    # apart come back as ONE wider hunk. A third patch landing strictly inside
    # that invented span then conflicts with nothing and is deferred anyway --
    # so whether a patch is accepted depended on how many patches had already
    # been folded into its file, and one file often takes several patches.
    # Keeping each accepted edit in BASE coordinates is what
    # makes acceptance a property of the patches instead of of the fold order.
    applied: dict[str, list[tuple[int, int, list[bytes]]]] = {}
    merged: dict[str, bytes] = {}
    owner: dict[str, str] = {}
    accepted: list[str] = []
    deferred: list[Deferral] = []
    co_edited: list[str] = []

    for submission in ordered:
        # A submission is atomic: it either lands whole or it is deferred
        # whole. Applying half of a fix is worse than applying none -- the
        # validator checked the pair of edits together, not one of them.
        # The BASE each edit list was computed against travels with it.
        # Re-looking it up at commit time asks the same question twice
        # and answers it from a dict that may not hold the key.
        staged: dict[str, tuple[bytes, list[tuple[int, int, list[bytes]]]]] = {}
        blocked: Deferral | None = None
        for path, payload in sorted(submission.files.items()):
            base = base_files.get(path)
            if base is None:
                blocked = Deferral(
                    submission.vulnerability_id,
                    path,
                    "the patch adds a file that is not in the original bundle",
                )
                break
            if payload == base:
                continue
            incoming = _changed_ranges(_lines(base), _lines(payload))
            current = applied.get(path)
            if current is None:
                staged[path] = (base, incoming)
                continue
            if _contains(incoming, current):
                # A REBASE: this patch was handed the winner's version of the
                # file and wrote its fix on top, so its list already carries
                # every edit standing here. Without this the retry is
                # guaranteed to lose the same merge it lost the first time.
                staged[path] = (base, incoming)
                co_edited.append(path)
                continue
            if _contains(current, incoming):
                # Already in the bundle, by a patch that did more. Accept the
                # submission and change nothing.
                staged[path] = (base, current)
                continue
            combined = _merge_edits(current, incoming)
            if combined is None:
                blocked = Deferral(
                    submission.vulnerability_id,
                    path,
                    f"overlaps the edit already applied for "
                    f"{owner.get(path, 'an earlier patch')}",
                )
                break
            staged[path] = (base, combined)
            co_edited.append(path)
        if blocked is not None:
            deferred.append(blocked)
            continue
        for path, (source, edits) in staged.items():
            applied[path] = edits
            merged[path] = _apply_edits(source, edits)
            owner.setdefault(path, submission.vulnerability_id)
        accepted.append(submission.vulnerability_id)

    return MergeResult(
        files=merged,
        accepted=tuple(accepted),
        deferred=tuple(deferred),
        merged_paths=tuple(sorted(set(co_edited))),
    )


# --------------------------------------------------------------------------
# Versioning, history, report
# --------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


class RepoAgent:
    """Owns the integrated bundle, its version history, and the report.

    The progress file it writes is the SAME shape `live_fire_patch_loop`
    writes, on purpose: the operator's job UI already renders that history and
    accepts per-version feedback against it, and a second format would mean a
    second UI for the same question.  The one addition is that `verified` can
    finally be true, because v2 has a validator that actually checked.
    """

    def __init__(
        self,
        *,
        job_id: str,
        workspace: Any,
        output_root: Path,
        log: Any = None,
    ):
        self.job_id = job_id
        self.workspace = workspace
        self.output_root = Path(output_root)
        self._log = log
        # Durable, not in-memory. patch-progress.json IS the version history;
        # a job that dies mid-run and is resumed must not restart at V1 and
        # overwrite the bundles the operator already has.
        self.history: list[dict[str, Any]] = self._load_history()
        # Every path any version has written. `materialise` restores these
        # before writing, which is the only thing that stops a DEFERRED
        # vulnerability's earlier edit riding along in the next bundle.
        self._touched: set[str] = {
            str(path)
            for row in self.history
            for path in (row.get("changed_paths") or [])
        }

    def _load_history(self) -> list[dict[str, Any]]:
        path = self.output_root / PROGRESS_NAME
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        snapshots = payload.get("snapshots")
        return list(snapshots) if isinstance(snapshots, list) else []

    def log(self, message: str) -> None:
        if self._log:
            self._log(message)

    # -- the tree ---------------------------------------------------------

    def base_files(self, paths: Iterable[str]) -> dict[str, bytes]:
        """Read the ORIGINAL content of every path a submission touches.

        From `workspace.original`, which `create_workspace` made read-only, so
        the three-way merge is anchored to something no agent can have edited.
        """

        root = Path(self.workspace.original)
        out: dict[str, bytes] = {}
        for path in sorted(set(paths)):
            target = root / path
            try:
                out[path] = target.read_bytes()
            except OSError:
                continue
        return out

    def materialise(self, merge: MergeResult) -> list[str]:
        """Write the merged tree into the candidate, and nothing else.

        Reset first. A candidate left over from an earlier version would leak
        a deferred patch into this bundle -- present in the zip, absent from
        the history, and unexplained by any finding. Restoring from `original`
        is the only way to be sure what is in the tree is what merged.
        """

        original = Path(self.workspace.original)
        candidate = Path(self.workspace.candidate)
        # RESTORE FIRST, and this is not tidiness. V1 merges a fix to
        # admin/foo.php; V2's blueteam for that vulnerability is deferred, so
        # the path is absent from merge.files -- but the file on disk still
        # holds V1's edit, and build_patched_zip reads the CANDIDATE TREE. V2
        # would then ship a change that appears in no finding and no history
        # entry: exactly the unexplained_paths defect job bf8d00c76ed8 hit,
        # reproduced structurally instead of by accident.
        self.restore(self._touched - set(merge.files))
        written: list[str] = []
        for path in sorted(merge.files):
            target = candidate / path
            source = original / path
            target.parent.mkdir(parents=True, exist_ok=True)
            mode = source.stat().st_mode if source.exists() else None
            if target.exists():
                # The candidate carries the ORIGINAL's mode, and the original
                # tree is deliberately read-only. Writing the same path again
                # in a later round then fails for anyone who is not root --
                # invisible in production only because the worker runs as
                # root, and it would surface the day that changes. A round
                # that rebuilds a cumulative bundle touches the same paths
                # every time, so this is the normal path, not an edge.
                target.chmod(0o600)
            target.write_bytes(merge.files[path])
            if mode is not None:
                target.chmod(mode & 0o7777)
            written.append(path)
        self._touched |= set(written)
        return written

    def restore(self, paths: Iterable[str]) -> None:
        """Put named paths back to their original content."""

        original = Path(self.workspace.original)
        candidate = Path(self.workspace.candidate)
        for path in sorted(set(paths)):
            source = original / path
            if not source.exists():
                continue
            (candidate / path).write_bytes(source.read_bytes())

    # -- publication ------------------------------------------------------

    def shipped_ids(self) -> tuple[str, ...]:
        """Every vulnerability the LAST published bundle actually carried.

        Read out of the version history rather than kept in a field, so a
        resumed job sees what shipped before it restarted and cannot drift
        out of step with the zips on disk.
        """

        for row in reversed(self.history):
            findings = row.get("findings")
            if not findings:
                continue
            return tuple(
                str(f.get("vulnerability_id"))
                for f in findings
                if f.get("vulnerability_id")
            )
        return ()

    def publish(
        self,
        merge: MergeResult,
        *,
        validation: Any,
        submissions: Sequence[PatchSubmission],
        builder: Any,
    ) -> dict[str, Any] | None:
        """Cut a version, or decline to.

        `validation` is the validator's verdict on THE INTEGRATED BUNDLE, not
        on any single blueteam's patch. It is required, and a failing one
        publishes nothing: handing the operator a bundle that the validator
        refused is the one outcome worse than handing them nothing, because
        they will upload it.

        Returns the history entry, or None when nothing was published.
        """

        if validation is None:
            raise RepoError(
                "publish() requires the validator's verdict on the integrated "
                "bundle; two individually safe patches can break together"
            )
        if not getattr(validation, "ok", False):
            self.log(
                f"repo: integrated bundle REFUSED by the validator "
                f"({len(getattr(validation, 'unexplained', ()))} unexplained)"
            )
            return None
        if not merge.accepted:
            self.log("repo: nothing accepted, so there is no version to cut")
            return None

        # A BUNDLE MAY NEVER BE WORSE THAN THE ONE BEFORE IT. `integrate` is
        # told which vulnerabilities have shipped and orders them first, so
        # this should be unreachable -- which is exactly why it is here. On
        # job 586ba6888920 the v20 bundle un-fixed V6 and V8 and was published
        # anyway, with the deferral logged four times and nothing acting on it.
        accepted = set(merge.accepted)
        regressed = tuple(v for v in self.shipped_ids() if v not in accepted)
        if regressed:
            self.log(
                "repo: REFUSING to cut a version that un-fixes "
                f"{', '.join(regressed)} — shipped in v{len(self.history)} "
                "and missing from this merge"
            )
            return None

        version = len(self.history) + 1
        self.output_root.mkdir(parents=True, exist_ok=True)
        target = self.output_root / f"patched-v{version}.zip"
        staging = self.output_root / f".patched-v{version}.zip.tmp"
        builder(self.workspace, staging)
        digest = _sha256_file(staging)

        # A version identical to the last one is not a version. Job
        # d9fef25b2216 published V3, V4 and V5 all sharing V2's sha256 --
        # three more files to upload that were the same patch, and a history
        # that read as stalled progress rather than as nothing new.
        previous = next(
            (row.get("sha256") for row in reversed(self.history) if row.get("sha256")),
            None,
        )
        if digest == previous:
            # Never under the version name: a `patched-v4.zip` that appears and
            # vanishes is a file the operator may already be downloading.
            try:
                staging.unlink()
            except OSError:
                pass
            self.log("repo: integrated bundle is byte-identical to the last; "
                     "no version cut")
            return None
        staging.replace(target)

        by_id = {s.vulnerability_id: s for s in submissions}
        entry = {
            "version": version,
            "vuln_clear": len(merge.accepted),
            "attempt": version,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "zip": target.name,
            "sha256": digest,
            "provider_status": "integrated",
            "changed_paths": sorted(merge.files),
            "unexplained_paths": [],
            "co_edited_paths": list(merge.merged_paths),
            "deferred": [d.as_dict() for d in merge.deferred],
            "findings": [
                {
                    # The id rides along so the report can name the mitigation
                    # class without guessing: several vulnerabilities can live
                    # in one file, so `path` is not a key.
                    "vulnerability_id": vid,
                    "bug_class": by_id[vid].bug_class,
                    "severity": "unknown",
                    "path": by_id[vid].path,
                    "line": 0,
                    "patch_description": by_id[vid].summary,
                }
                for vid in merge.accepted
                if vid in by_id
            ],
            "verified": True,
            "validation": (
                validation.as_dict() if hasattr(validation, "as_dict") else {}
            ),
        }
        self.history.append(entry)
        try:
            _write_json_atomic(
                self.output_root / PROGRESS_NAME, {"snapshots": self.history}
            )
        except Exception:  # noqa: BLE001 - history must not end the run
            pass
        self.log(
            f"repo: V{version} — {len(merge.accepted)} vuln clear, "
            f"{len(merge.deferred)} deferred, sha {digest[:12]}"
        )
        return entry

    # -- report -----------------------------------------------------------

    def report(self, submissions: Sequence[PatchSubmission]) -> str:
        by_id = {s.vulnerability_id: s for s in submissions}
        lines = [
            f"# Live-fire v2 — integrated patch history",
            "",
            f"Job `{self.job_id}`.",
            "",
        ]
        if not self.history:
            lines.append("No version was published. Nothing reached the operator.")
            return "\n".join(lines) + "\n"
        for entry in self.history:
            lines.append(
                f"## V{entry['version']} — {entry['vuln_clear']} vuln clear"
            )
            lines.append("")
            lines.append(f"- Built: {entry['at']}")
            lines.append(f"- Bundle: `{entry['zip']}`")
            lines.append(f"- sha256: `{entry['sha256']}`")
            lines.append(f"- Validator: verified against the base corpus")
            lines.append("")
            for finding in entry["findings"]:
                submission = by_id.get(finding.get("vulnerability_id", ""))
                mitigation = (
                    submission.mitigation_class if submission else "unknown"
                )
                lines.append(
                    f"- `{finding['path']}` — {finding['bug_class']}"
                )
                lines.append(f"  - Mitigation class: `{mitigation}`")
                lines.append(f"  - {finding['patch_description']}")
            for deferral in entry.get("deferred") or []:
                lines.append(
                    f"- DEFERRED `{deferral['path']}` "
                    f"({deferral['vulnerability_id']}): {deferral['reason']}"
                )
            lines.append("")
        return "\n".join(lines) + "\n"

    def write_report(self, submissions: Sequence[PatchSubmission]) -> Path:
        path = self.output_root / REPORT_NAME
        self.output_root.mkdir(parents=True, exist_ok=True)
        path.write_text(self.report(submissions), encoding="utf-8")
        return path


__all__ = [
    "Deferral",
    "MergeResult",
    "PROGRESS_NAME",
    "PatchSubmission",
    "REPORT_NAME",
    "RepoAgent",
    "RepoError",
    "integrate",
    "merge_three_way",
]
