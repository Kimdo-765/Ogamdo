#!/usr/bin/env python3
"""The live-fire path an operator actually walks at the start of a contest.

Three changes, one situation, and the third was found by running the first two
against a REAL attack-and-defence bundle (job 6571ebbc19d2).

TWO CHANGES, ONE OPERATOR SITUATION: a contest has just opened. There is a
service ZIP and nothing else — no exploit, so no attack probe, so no
verification contract anyone could write honestly. And the defence tick is
short, so a fix that exists at minute three is worthless if the file only
appears when the job ends.

WHAT MUST NOT BREAK

`VerificationSpec` hard-requires at least one probe of EACH corpus, so there
is no degenerate contract to fall back on — unverified mode instead runs with
`PatchLoopSpec.verification = None`. That removes the oracle, and with it the
only evidence `ready_to_deploy` was ever allowed to rest on. So the property
this file exists to defend is:

    A JOB THAT SUPPLIED NO CONTRACT CAN NEVER REPORT ready_to_deploy: true.

It is defended in depth — the mode is refused BY NAME in `_machine_gate_errors`
rather than by the four gates happening to be false, because a later refactor
that defaulted a gate to True would otherwise flip a contract-less job to
deployable in silence. U3 is that check and mutation 3 is why it is there.

The second property is narrower: an interim snapshot must be the PATCHED tree
and must never appear when the policy gate restored the candidate — shipping
the pre-attempt tree labelled as a patch is worse than shipping nothing.

The third is a coverage invariant. `discover_service` is the only map of the
service the patch role ever gets, and it recognised python/node/go/rust/native
while `_SOURCE_SUFFIXES` had long permitted php, ruby, java and C# too. On
6571ebbc19d2 that left a PHP service out of the reported stacks entirely —
the component most likely to hold the bug, invisible. So:
EVERY LANGUAGE THE POLICY WILL PATCH MUST BE A STACK THE DISCOVERY CAN NAME,
and D3 derives that from `_SOURCE_SUFFIXES` rather than restating a list.

Mutations run in a subprocess against the real tree; a fresh interpreter
cannot be fooled by a package attribute still holding the pre-mutation module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PY = ROOT / "modules" / "live_fire_contract.py"
LOOP_PY = ROOT / "modules" / "live_fire_patch_loop.py"
VERIFIER_PY = ROOT / "modules" / "live_fire_verifier.py"
ROUTE_PY = ROOT / "api" / "routes" / "live_fire_module.py"
INDEX_HTML = ROOT / "web-ui" / "index.html"

_FAILED: list[str] = []


def chk(cid: str, ok: bool, label: str, got: object = "") -> None:
    if ok:
        print(f"PASS  [{cid}] {label}")
    else:
        print(f"FAIL  [{cid}] {label}" + (f"  | got={got!r}" if got != "" else ""))
        _FAILED.append(cid)


# ---------------------------------------------------------------------------
def _source_zip(path: Path) -> Path:
    entries = {
        "Dockerfile": b"FROM python:3.11-alpine\nCOPY . /srv\n",
        "app.py": b"import os\n\n\ndef read(p):\n    return open(p).read()\n",
        "public/hello.txt": b"hello\n",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 9, 10, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return path


ORIGINAL_APP = "import os\n\n\ndef read(p):\n    return open(p).read()\n"

PATCHED_BODY = (
    "import os\n\n\ndef read(p):\n"
    "    if os.path.isabs(p) or '..' in p:\n"
    "        raise ValueError('rejected')\n"
    "    return open(p).read()\n"
)


def run_checks() -> bool:
    base = Path(tempfile.mkdtemp(prefix="lf-unverified-"))
    os.environ["DATA_DIR"] = str(base)
    sys.path.insert(0, str(ROOT))

    from modules import live_fire_workspace as wsm
    from modules.live_fire_contract import (
        UNVERIFIED_MODE,
        patch_spec_from_snapshot,
        unverified_contract,
    )
    from modules import live_fire_patch_loop as loop
    from modules.live_fire_verifier import unverified_document

    JOB = "abc123abc123"

    # ---- the contract itself --------------------------------------------
    snapshot, spec = unverified_contract(job_id=JOB, job_timeout_s=1800)
    chk("C1", spec.verification is None,
        "no contract means no VerificationSpec at all")
    chk("C2", snapshot.get("verification_mode") == UNVERIFIED_MODE,
        "the snapshot records the mode so the worker can rebuild it")
    chk("C3", spec.verification_reserve_s == 0,
        "nothing is reserved for a verification that will not run")
    chk("C4", spec.packaging_reserve_s > 0
        and spec.packaging_reserve_s < spec.job_timeout_s,
        "packaging still gets a reserve — the ZIP is the deliverable")

    rebuilt = patch_spec_from_snapshot(snapshot, job_id=JOB, job_timeout_s=1800)
    chk("C5", rebuilt.verification is None
        and rebuilt.packaging_reserve_s == spec.packaging_reserve_s,
        "the RQ worker rebuilds the same spec from meta.json")

    # A timeout too short to hold the reserve must still yield a runnable job.
    _, tiny = unverified_contract(job_id=JOB, job_timeout_s=20)
    chk("C6", 0 < tiny.packaging_reserve_s < 20,
        "an absurdly short timeout is clamped, not refused",
        tiny.packaging_reserve_s)

    # ---- THE safety property --------------------------------------------
    root = base / "ws1"
    root.mkdir()
    ws = wsm.create_workspace(_source_zip(root / "input.zip"), root / "ws")
    doc = unverified_document(ws, JOB, reason="none supplied")
    chk("U1", doc.get("ready_to_deploy") is False,
        "the unverified document is born not-deployable")
    chk("U2", doc.get("verification_mode") == UNVERIFIED_MODE,
        "...and says so in a field, not only in prose")
    errors = loop._machine_gate_errors(doc)
    chk("U3", any("UNVERIFIED" in e for e in errors),
        "the machine gate refuses the MODE by name, not just the gates",
        errors)
    # Defence in depth: even with every gate forced to pass, the mode alone
    # must still be disqualifying. This is the refactor U3 is guarding against.
    forced = dict(doc)
    for gate in ("build_gate", "health_gate", "sla_gate", "security_gate"):
        forced[gate] = {"passed": True}
    chk("U4", any("UNVERIFIED" in e for e in loop._machine_gate_errors(forced)),
        "...and still refuses it when the four gates are forced to pass",
        loop._machine_gate_errors(forced))

    # ---- end to end, with a provider that genuinely patches --------------
    def _finding() -> object:
        return loop.VulnerabilityFinding(
            bug_class="path-traversal",
            severity="high",
            path="app.py",
            line=5,
            root_cause="open() takes an unbounded caller path",
            attack_impact="arbitrary file read",
            patch_description="reject absolute and dot-dot paths",
            patch_reason="the caller path is attacker controlled",
            mitigation_class="root-cause-fix",
            evidence_tier="B",
        )

    class Patcher:
        """Edits the tree every attempt, reports the SAME vulnerability.

        The trailing marker makes each attempt a genuinely different tree, so
        a version is published each time — otherwise the identical-zip guard
        collapses them and I11 has nothing to measure. The finding's identity
        never changes, which is the case that inflated the count: job
        c2c3cdb1f353 re-reported one vulnerability five times.
        """

        def __init__(self, body: str = PATCHED_BODY) -> None:
            self.body = body
            self.seen: list[int] = []

        def attempt(self, context):
            self.seen.append(context.attempt)
            marker = "  # pass %d" % context.attempt
            (context.candidate / "app.py").write_text(
                self.body.replace("('rejected')", "('rejected')" + marker),
                encoding="utf-8")
            return loop.ProviderResult(
                "success", "patched", findings=(_finding(),),
                ready_recommendation=True,
            )

    class Reviewer:
        def review(self, context):
            return loop.ReviewResult("no verification is available in this mode")

    root2 = base / "ws2"
    root2.mkdir()
    ws2 = wsm.create_workspace(_source_zip(root2 / "input.zip"), root2 / "ws")
    _, spec2 = unverified_contract(job_id=JOB, job_timeout_s=600)
    out2 = root2 / "out"
    result = loop.run_patch_loop(ws2, out2, spec2, Patcher(), Reviewer())
    document = result.verification

    chk("E1", document.get("ready_to_deploy") is False,
        "a SUCCESSFUL patch with no contract is still not deployable",
        document.get("ready_to_deploy"))
    chk("E2", document.get("changed_paths") == ["app.py"],
        "...and it really did patch the service", document.get("changed_paths"))
    chk("E3", any("UNVERIFIED" in risk for risk in document.get("residual_risks", [])),
        "the report carries the reason, not just the verdict")
    chk("E4", result.artifacts.patched_zip.is_file()
        and result.artifacts.report.is_file()
        and result.artifacts.verification.is_file(),
        "the three terminal artifacts are still produced")

    # ---- the PRODUCTION path, which is not the one above -----------------
    # E1-E4 call `run_patch_loop` with `reporter=None`, and that branch
    # handles a failing report by writing report_gate false. The branch
    # production uses — `run_routed_patch_loop`, which always supplies a
    # routed reporter — RAISES instead, because a deterministic report that
    # fails its own validation is an internal invariant violation.
    #
    # In unverified mode it failed by construction: `_finding_evidence_errors`
    # asked findings to match attack evidence that cannot exist without
    # probes. Job 5df30344f339 died there after three real patch turns,
    # holding a genuine fix. Everything above passed while it did, which
    # is why this check goes through the routed entry point.
    from modules.live_fire_provider import run_routed_patch_loop
    from modules.live_fire_patch_loop import _render_report

    class RoutedStub:
        """The shape LiveFireInvoker returns, without calling a model."""

        def __init__(self) -> None:
            self.roles: list[str] = []

        def invoke(self, call):
            from modules.live_fire_provider import (
                AgentInvocationResult, AgentUsage,
            )

            self.roles.append(call.route.role)
            if call.route.role == "main":
                (call.payload.candidate / "app.py").write_text(
                    PATCHED_BODY, encoding="utf-8")
                value = loop.ProviderResult(
                    "success", "patched", findings=(_finding(),),
                    ready_recommendation=True,
                )
            elif call.route.role == "reviewer":
                value = loop.ReviewResult("no verification available")
            else:
                value = _render_report(
                    call.payload.document, call.payload.findings,
                    call.payload.diffs,
                )
            return AgentInvocationResult(value=value, usage=AgentUsage())

    rootR = base / "wsR"
    rootR.mkdir()
    wsR = wsm.create_workspace(_source_zip(rootR / "input.zip"), rootR / "ws")
    _, specR = unverified_contract(job_id=JOB, job_timeout_s=600)
    (base / "jobs" / JOB).mkdir(parents=True, exist_ok=True)
    (base / "jobs" / JOB / "meta.json").write_text(json.dumps(
        {"id": JOB, "module": "live-fire", "status": "running"}))
    try:
        routed = run_routed_patch_loop(
            JOB, wsR, rootR / "out", specR, RoutedStub())
        raised = ""
    except Exception as exc:  # noqa: BLE001 - the point of the check
        routed = None
        raised = f"{type(exc).__name__}: {exc}"
    chk("Z1", routed is not None,
        "a contract-less job with a real finding completes instead of raising",
        raised)
    chk("Z2", routed is not None
        and routed.verification.get("ready_to_deploy") is False,
        "...and is still not deployable",
        routed and routed.verification.get("ready_to_deploy"))
    chk("Z3", routed is not None
        and (routed.verification.get("report_gate") or {}).get("passed") is True,
        "...and its report passes, because the missing evidence is reported "
        "by the machine gate, not twice",
        routed and routed.verification.get("report_gate"))
    chk("Z4", routed is not None and routed.artifacts.report.is_file()
        and "UNVERIFIED" in "".join(
            routed.verification.get("residual_risks") or []),
        "...with the reason still on the record")

    # ---- interim snapshots ----------------------------------------------
    names = sorted(p.name for p in out2.iterdir())
    interim = [n for n in names if re.fullmatch(r"patched-attempt-\d+\.zip", n)]
    chk("I1", bool(interim), "a patched ZIP exists per attempt", names)
    chk("I2", loop.PROGRESS_NAME in names,
        "an index names them so the UI does not have to guess", names)

    progress = json.loads((out2 / loop.PROGRESS_NAME).read_text())["snapshots"]
    chk("I3", progress and progress[0]["zip"] == "patched-attempt-1.zip"
        and progress[0]["changed_paths"] == ["app.py"],
        "the index records what each snapshot contains", progress[:1])
    chk("I4", progress and progress[0]["findings"]
        and progress[0]["findings"][0]["bug_class"] == "path-traversal",
        "...including the findings it carries, so the operator sees what ships")
    chk("I5", all(entry.get("verified") is False for entry in progress),
        "every entry says it is unverified — these are read one at a time")
    chk("I9", progress[0].get("version") == 1,
        "versions are numbered by EMISSION, so a fruitless attempt leaves no gap",
        progress[0].get("version"))
    chk("I10", progress[0].get("vuln_clear") == 1,
        "a version records the CUMULATIVE number of vulnerabilities it closes",
        progress[0].get("vuln_clear"))
    # The Patcher rewrites the SAME file with the SAME finding every attempt,
    # which is exactly what job c2c3cdb1f353's agent did. A version that
    # counted reported findings claimed 1, 2, 3, 4, 5 while every zip differed
    # from the original in one file.
    chk("I16", all(row.get("unexplained_paths") == [] for row in progress),
        "a version whose every change is explained says so",
        [row.get("unexplained_paths") for row in progress])

    chk("I11", [row.get("vuln_clear") for row in progress] == [1] * len(progress),
        "re-reporting the same vulnerability does not inflate `vuln clear`",
        [row.get("vuln_clear") for row in progress])

    first = out2 / "patched-attempt-1.zip"
    with zipfile.ZipFile(first) as archive:
        shipped = archive.read("app.py").decode()
    chk("I6", shipped == PATCHED_BODY.replace(
            "('rejected')", "('rejected')  # pass 1")
        and shipped != ORIGINAL_APP,
        "the snapshot holds THAT attempt's patched tree, not the original",
        shipped)
    chk("I7", "secret" not in "".join(zipfile.ZipFile(first).namelist())
        and sorted(zipfile.ZipFile(first).namelist())
        == ["Dockerfile", "app.py", "public/hello.txt"],
        "a snapshot is manifest members only, like the terminal ZIP",
        sorted(zipfile.ZipFile(first).namelist()))

    # An attempt that finds nothing still leaves the earlier fixes in the
    # tree, so its zip builds and is IDENTICAL to the previous one. Job
    # d9fef25b2216 published V3, V4 and V5 all sharing V2's sha256.
    rootQ = base / "wsQ"
    rootQ.mkdir()
    wsQ = wsm.create_workspace(_source_zip(rootQ / "input.zip"), rootQ / "ws")
    _, specQ = unverified_contract(job_id=JOB, job_timeout_s=600)
    outQ = rootQ / "out"
    loop.run_patch_loop(wsQ, outQ, specQ, Patcher(), Reviewer())
    # ^ Patcher varies the tree, so this run is the CONTROL. The idle one:
    rootI = base / "wsI"
    rootI.mkdir()
    wsI = wsm.create_workspace(_source_zip(rootI / "input.zip"), rootI / "ws")

    class IdlePatcher(Patcher):
        """Fixes one thing on attempt 1, then finds nothing — the real shape.

        Job d9fef25b2216 ended exactly here: two genuine fixes in the tree and
        a final attempt that came back empty, so `last_findings` was () and
        the document reported `vulnerabilities: 0`.
        """

        def attempt(self, context):
            if context.attempt == 1:
                (context.candidate / "app.py").write_text(
                    self.body, encoding="utf-8")
                return loop.ProviderResult(
                    "success", "patched", findings=(_finding(),),
                    ready_recommendation=True,
                )
            return loop.ProviderResult("failure", "nothing further found")

    _, specI = unverified_contract(job_id=JOB, job_timeout_s=600)
    outI = rootI / "out"
    loop.run_patch_loop(wsI, outI, specI, IdlePatcher(), Reviewer())
    idle = json.loads((outI / loop.PROGRESS_NAME).read_text())["snapshots"]
    digests = [row.get("sha256") for row in idle]
    chk("I12", len(idle) == 1,
        "an unchanged tree is not republished as a new version", digests)
    chk("I13", len(set(digests)) == len(digests),
        "...so no two versions share a sha256", digests)
    chk("I14", len([p for p in outI.iterdir()
                    if re.fullmatch(r"patched-attempt-\d+\.zip", p.name)]) == 1,
        "...and the redundant zip is not left on disk",
        sorted(p.name for p in outI.iterdir()))

    # The job's own record must survive a final attempt that found nothing.
    idle_doc = json.loads((outI / "verification.json").read_text())
    chk("I15", len(idle_doc.get("vulnerabilities") or []) == 1,
        "a job whose LAST attempt found nothing still reports what it fixed",
        idle_doc.get("vulnerabilities"))

    # A provider whose diff the source policy rejects has its candidate
    # RESTORED. Shipping that tree as a patch would be shipping the original
    # under a name that says otherwise.
    class PolicyBreaker:
        def attempt(self, context):
            (context.candidate / "Dockerfile").write_text(
                "FROM python:3.11-alpine\nCOPY . /srv\nRUN echo pwn\n",
                encoding="utf-8",
            )
            return loop.ProviderResult("success", "touched deployment",
                                       findings=(_finding(),))

    root3 = base / "ws3"
    root3.mkdir()
    ws3 = wsm.create_workspace(_source_zip(root3 / "input.zip"), root3 / "ws")
    _, spec3 = unverified_contract(job_id=JOB, job_timeout_s=600)
    out3 = root3 / "out"
    loop.run_patch_loop(ws3, out3, spec3, PolicyBreaker(), Reviewer())
    breaker_names = sorted(p.name for p in out3.iterdir())
    chk("I8", not [n for n in breaker_names
                   if re.fullmatch(r"patched-attempt-\d+\.zip", n)],
        "a policy-restored attempt publishes NO snapshot", breaker_names)

    # ---- discovery must see every language the policy will patch ---------
    root4 = base / "ws4"
    root4.mkdir()
    poly = root4 / "input.zip"
    entries = {
        "Dockerfile": b"FROM php:8-apache\n",
        "src/index.php": b"<?php echo $_GET['q'];\n",
        "src/lib.rb": b"def go; end\n",
        "src/App.java": b"class App {}\n",
        "src/Prog.cs": b"class Prog {}\n",
        "svc/main.py": b"print(1)\n",
    }
    with zipfile.ZipFile(poly, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 9, 10, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    ws4 = wsm.create_workspace(poly, root4 / "ws")
    found = loop.discover_service(ws4)
    chk("D1", "php" in found.stacks,
        "a PHP service is named as a php stack", found.stacks)
    chk("D2", {"ruby", "java", "dotnet"} <= set(found.stacks),
        "so are ruby, java and C#", found.stacks)
    chk("D4", "src/index.php" in found.entrypoints,
        "index.php is an entrypoint — a PHP service has no main()",
        found.entrypoints)

    # Derived, not restated: adding a suffix to the policy without adding it
    # to the stack table is the exact mistake that hid the PHP service, and a
    # hand-written expected list would not notice the next one.
    table_suffixes = {suffix for _stack, suffixes in loop.STACK_SUFFIXES
                      for suffix in suffixes}
    missing = sorted(set(loop._SOURCE_SUFFIXES)
                     - set(loop.NON_PROGRAM_SUFFIXES)
                     - table_suffixes)
    chk("D3", not missing,
        "every patchable program suffix maps to a discoverable stack", missing)

    # ---- the boundary the operator actually touches ----------------------
    route = ROUTE_PY.read_text()
    chk("R1", "verification: Optional[str] = Form(None)" in route,
        "the HTTP form no longer requires a contract")
    chk("R2", "unverified_contract(" in route
        and 'if (verification or "").strip():' in route,
        "a supplied contract is still parsed strictly; only blank falls back")
    html = INDEX_HTML.read_text()
    chk("R3", 'name="verification" rows="14"' in html
        and 'name="verification" rows="14" required' not in html,
        "the textarea is not marked required")
    chk("R4", "UNVERIFIED" in html and "Leave this blank" in html,
        "the form says what leaving it blank costs")

    return not _FAILED


# ---------------------------------------------------------------------------
MUTATIONS = [
    # `None` is not decoration: everything downstream branches on it. Give the
    # spec any other value and the loop hands it to `verify_workspace`, which
    # is why this one is detected as a CRASH rather than a failed assertion —
    # recorded as such rather than pretended to be a clean check failure.
    ("unverified mode builds a real VerificationSpec anyway", CONTRACT_PY,
     "        verification=None,\n        job_timeout_s=timeout,",
     "        verification=object(),\n        job_timeout_s=timeout,",
     None),
    ("the snapshot forgets the mode", CONTRACT_PY,
     '"verification_mode": UNVERIFIED_MODE,\n        "packaging_reserve_s"',
     '"packaging_reserve_s"',
     "C2"),
    # The exact regression that killed 5df30344f339: without this early
    # return the deterministic report fails its own validation and the routed
    # loop raises, losing a finished patch.
    ("unverified findings are asked for attack evidence that cannot exist", LOOP_PY,
     '    if document.get("verification_mode") == UNVERIFIED_MODE:\n        return []\n    classes =',
     "    classes =",
     "Z1"),
    # Anchored with the line after it: the same condition now appears twice in
    # this module, and a bare match would mutate whichever came first.
    ("the machine gate stops naming the mode", LOOP_PY,
     'if document.get("verification_mode") == UNVERIFIED_MODE:\n        errors.append(',
     "if False:\n        errors.append(",
     "U3"),
    ("the unverified document is born deployable", VERIFIER_PY,
     '"ready_to_deploy": False,\n        "verification_mode": UNVERIFIED_MODE,',
     '"ready_to_deploy": True,\n        "verification_mode": UNVERIFIED_MODE,',
     "U1"),
    ("snapshots are emitted after verification instead of before", LOOP_PY,
     "if diffs and not policy_errors and not inventory_errors:",
     "if False:",
     "I1"),
    ("a policy-restored attempt still publishes a snapshot", LOOP_PY,
     "            if diffs and not policy_errors and not inventory_errors:",
     "            if diffs or policy_errors or inventory_errors:",
     "I8"),
    ("versions are numbered by attempt, so a fruitless one leaves a gap", LOOP_PY,
     "    version = len(progress) + 1",
     "    version = attempt + 10",
     "I9"),
    ("a version stops reporting its cumulative count", LOOP_PY,
     "    cleared = len(seen)",
     "    cleared = 0",
     "I10"),
    ("the count goes back to counting reports, not vulnerabilities", LOOP_PY,
     '    seen |= {(f.bug_class, f.path) for f in provider_result.findings}\n'
     "    cleared = len(seen)",
     "    cleared = sum(len(row.get('findings') or []) for row in progress) \\\n"
     "        + len(provider_result.findings)",
     "I11"),
    ("an explained change is reported as unexplained", LOOP_PY,
     "    explained = {f.path for f in findings}",
     "    explained = set()",
     "I16"),
    ("an unchanged tree is republished as a new version", LOOP_PY,
     "        if digest == previous:\n            _remove_path(interim)\n            return",
     "        if False:\n            _remove_path(interim)\n            return",
     "I12"),
    ("the job forgets everything but its last attempt", LOOP_PY,
     "    if _carried or not last_findings:\n        last_findings = _carried",
     "    if False:\n        last_findings = _carried",
     "I15"),
    ("the index stops recording what a snapshot contains", LOOP_PY,
     '"changed_paths": [record.path for record in diffs],\n            "unexplained_paths"',
     '"changed_paths": [],\n            "unexplained_paths"',
     "I3"),
    ("a snapshot no longer says it is unverified", LOOP_PY,
     '            "verified": False,\n        }\n    except Exception as exc:',
     '            "verified": True,\n        }\n    except Exception as exc:',
     "I5"),
    ("php drops out of stack discovery", LOOP_PY,
     '("php", (".php",)),',
     '("php_disabled", (".nope",)),',
     "D1"),
    ("index.php stops being an entrypoint", LOOP_PY,
     '        "index.php",',
     '        "index.php.disabled",',
     "D4"),
    ("a patchable language has no stack to be discovered under", LOOP_PY,
     '("ruby", (".rb",)),',
     '("ruby_disabled", (".nope2",)),',
     "D3"),
    ("the form requires a contract again", ROUTE_PY,
     "verification: Optional[str] = Form(None),",
     "verification: Optional[str] = Form(...),",
     "R1"),
    ("the textarea is required again", INDEX_HTML,
     '<textarea name="verification" rows="14"',
     '<textarea name="verification" rows="14" required',
     "R3"),
]


def _subprocess() -> tuple[int, list[str]]:
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

    files = (CONTRACT_PY, LOOP_PY, VERIFIER_PY, ROUTE_PY, INDEX_HTML)
    originals = {p: p.read_text() for p in files}
    digests = {p: hashlib.sha256(t.encode()).hexdigest()
               for p, t in originals.items()}

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
                # "any detection". Used only where the mutation makes the
                # module unusable rather than wrong, so no named check can
                # report it — the suite dies first.
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
