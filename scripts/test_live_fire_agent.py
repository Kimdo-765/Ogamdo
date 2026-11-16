#!/usr/bin/env python3
"""LF-6: the transport that made live-fire able to do anything at all.

Before this, `run_job` defaulted to `DiagnosticInvoker` and every live-fire
job ended in under half a second with `provider transport unavailable`. Jobs
6571ebbc19d2 and e52d42f23ee0 are both that, on a real attack-and-defence
bundle the operator submitted twice.

WHAT THIS FILE DEFENDS — and it is not the transport

Running an agent is the easy half. The half that decides whether a run is
worth anything is `_finding_errors`, which rejects a finding unless its
`path` is in the diff AND its `line` is a CHANGED line in POST-PATCH
numbering. An agent asked "where was the bug" answers with the pre-patch line
and every finding fails; `report_errors` then goes non-empty and
`terminal_ready` is false for the whole attempt — a good patch thrown away
over a line number.

So `_repair_finding` re-checks every finding against the real diff and drops
what cannot be honest, using `DiffRecord.changed_lines` and
`.candidate_line_count` — THE SAME TWO FIELDS `_location_matches_diff` reads.
An earlier draft recomputed the changed set itself against attributes
`DiffRecord` does not have, so the guard silently accepted every line. F2 is
that case and mutation 2 is why it stays.

Nothing here invents evidence. An enum is accepted only when the model's own
value maps onto it, and a line only when it is genuinely in the diff —
"repairing" a bad line by picking a changed one would fabricate exactly what
the gate exists to check.

No model is called: every check drives the pure functions with real
workspaces and real diffs.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_PY = ROOT / "modules" / "live_fire_agent.py"
ROUTE_PY = ROOT / "api" / "routes" / "live_fire_module.py"
INDEX_HTML = ROOT / "web-ui" / "index.html"
JOB_PY = ROOT / "modules" / "live_fire_job.py"
JOBS_ROUTE_PY = ROOT / "api" / "routes" / "jobs.py"
CONTRACT_PY2 = ROOT / "modules" / "live_fire_contract.py"
LOOP_PY2 = ROOT / "modules" / "live_fire_patch_loop.py"

_FAILED: list[str] = []


def chk(cid: str, ok: bool, label: str, got: object = "") -> None:
    if ok:
        print(f"PASS  [{cid}] {label}")
    else:
        print(f"FAIL  [{cid}] {label}" + (f"  | got={got!r}" if got != "" else ""))
        _FAILED.append(cid)


ORIGINAL_PHP = b"<?php\n$q = $_GET['q'];\necho $q;\n?>\n"
PATCHED_PHP = "<?php\n$q = $_GET['q'];\necho htmlspecialchars($q);\n?>\n"


def _zip(path: Path) -> Path:
    entries = {
        "Dockerfile": b"FROM php:8-apache\n",
        "src/index.php": ORIGINAL_PHP,
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 9, 10, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return path


def run_checks() -> bool:
    base = Path(tempfile.mkdtemp(prefix="lf-agent-"))
    os.environ["DATA_DIR"] = str(base)
    sys.path.insert(0, str(ROOT))

    from modules import live_fire_workspace as wsm
    from modules.live_fire_patch_loop import (
        EVIDENCE_TIERS,
        MITIGATION_CLASSES,
        SEVERITIES,
        candidate_diff,
        _finding_errors,
    )
    from modules import live_fire_agent as agent

    LOOP_SRC = (ROOT / "modules" / "live_fire_patch_loop.py").read_text()

    root = base / "ws"
    root.mkdir()
    ws = wsm.create_workspace(_zip(root / "in.zip"), root / "workspace")
    (ws.candidate / "src/index.php").write_text(PATCHED_PHP, encoding="utf-8")
    diffs = candidate_diff(ws)
    record = diffs[0]
    changed = sorted(record.changed_lines)

    good = {
        "bug_class": "xss",
        "severity": "high",
        "path": "src/index.php",
        "line": changed[0],
        "root_cause": "the query parameter reached echo unescaped",
        "attack_impact": "script injection into every viewer's page",
        "patch_description": "wrapped the echo in htmlspecialchars",
        "patch_reason": "the value is now encoded before it reaches HTML",
        "mitigation_class": "root-cause-fix",
        "evidence_tier": "B",
    }

    finding, why = agent._repair_finding(good, diffs)
    chk("F1", finding is not None, "an honest finding survives", why)
    # The whole point: what survives here must satisfy the gate downstream.
    chk("F1b", finding is not None and _finding_errors((finding,), diffs) == [],
        "...and the loop's own gate accepts it",
        finding and _finding_errors((finding,), diffs))

    pre_patch, why = agent._repair_finding({**good, "line": 2}, diffs)
    chk("F2", pre_patch is None and "not a changed line" in why,
        "a PRE-PATCH line number is dropped, not passed through", why)

    chk("F3", agent._repair_finding({**good, "path": "./src/index.php"}, diffs)[0]
        is not None,
        "a `./` prefixed path still resolves")
    chk("F4", agent._repair_finding({**good, "path": "src/other.php"}, diffs)[0] is None,
        "a path that is not in the diff is dropped")
    chk("F5", agent._repair_finding({**good, "line": 999}, diffs)[0] is None,
        "a line past the end of the patched file is dropped")

    for field, bad in (("severity", "urgent"),
                       ("mitigation_class", "patch"),
                       ("evidence_tier", "C")):
        got = agent._repair_finding({**good, field: bad}, diffs)[0]
        chk(f"F6-{field}", got is None,
            f"a {field} outside the closed enum is dropped ({bad!r})")

    for field in ("bug_class", "root_cause", "attack_impact",
                  "patch_description", "patch_reason"):
        got = agent._repair_finding({**good, field: "   "}, diffs)[0]
        chk(f"F7-{field}", got is None, f"an empty {field} is dropped")

    chk("F8", agent._repair_finding({**good, "severity": "HIGH",
                                     "evidence_tier": "b"}, diffs)[0] is not None,
        "case is normalised, not rejected")

    # The prompt has to name the values the gate accepts, or the model spends
    # its answer on tokens that will be thrown away.
    chk("P1", '"evidence_tier": "A | B"' in agent.MAIN_TEMPLATE
        and "C" not in agent.MAIN_TEMPLATE.split('"evidence_tier"')[1][:20],
        "the prompt offers only the tiers EVIDENCE_TIERS allows")
    chk("P2", all(value in agent.MAIN_TEMPLATE for value in sorted(SEVERITIES)),
        "...and every severity")
    chk("P3", all(value in agent.MAIN_TEMPLATE for value in sorted(MITIGATION_CLASSES)),
        "...and every mitigation class")
    chk("P4", "IN THE FILE AS YOU LEFT IT" in agent.MAIN_TEMPLATE,
        "the prompt asks for the POST-PATCH line, which is the trap")
    # A violating diff gets the candidate RESTORED — the patch is lost, not
    # merely rejected — so the boundary is stated as a rule, not advice.
    for term in ("Dockerfile", "docker-compose", "deploy/", "DISCARDED"):
        chk(f"P5-{term}", term in agent.MAIN_SYSTEM,
            f"the system prompt names the {term} boundary")

    # ---- a revoked token is the same answer every attempt ----------------
    # Job 87ad54d6c50c spent five attempts — ten model calls, main and
    # reviewer each — on `refresh_token_invalidated`. The loop has no "give
    # up", so the invoker has to stop calling.
    chk("X1", agent._fatal_reason(
        "[Codex CLI error] Your access token could not be refreshed because "
        "your refresh token was revoked.") == "refresh token was revoked",
        "the CLI's own wording for a revoked token is recognised")
    chk("X2", agent._fatal_reason(
        "unexpected status 401 Unauthorized: You are not authorized to "
        "access this model.") != "",
        "so is a 401 on the model itself")
    chk("X3", agent._fatal_reason("I fixed the SQL injection in login.php") == "",
        "ordinary output is not mistaken for an auth failure")
    chk("X4", agent._fatal_reason("") == "",
        "silence is not an auth failure either")

    import modules.live_fire_patch_loop as _lp  # `loop` is bound later below

    calls: list[str] = []

    class _Revoked(agent.LiveFireInvoker):
        """Replaces only the provider CALL, so the real wrapper — which owns
        the short-circuit and the classification — is what runs."""

        def _invoke_provider(self, call, system_prompt, prompt, **kw):
            calls.append(call.route.role)
            return "[Codex CLI error] your refresh token was revoked."

    inv = _Revoked("abc123abc123")
    ctx = type("C", (), {
        "candidate": base, "attempt": 1,
        "attempt_deadline": __import__("time").monotonic() + 3600,
        "discovery": _lp.StaticDiscovery((), (), (), (), ()),
        "feedback": (),
    })()
    route = type("R", (), {"role": "main", "provider": "gpt", "model": "m"})()
    call = type("K", (), {"job_id": "abc123abc123", "route": route,
                          "stage": "patch", "attempt": 1, "payload": ctx})()
    first = inv.invoke(call)
    chk("X5", inv._fatal != "", "one revoked turn marks the provider unusable")
    second = inv.invoke(call)
    chk("X6", len(calls) == 1,
        "...and the next attempt does not call it again", calls)
    chk("X7", "re-authenticate" in second.value.summary,
        "...and says what the operator has to do", second.value.summary)
    chk("X8", second.usage.error_kind == "auth",
        "...and is classified as auth, not as a generic failure",
        second.usage.error_kind)

    # ---- the organizer's one hint: how many were planted -----------------
    # An attack-and-defence round announces a COUNT and nothing else, and that
    # number changes what "done" means. Without it the honest instruction is
    # "fix the worst one"; with it the agent knows it owes N.
    none_task = agent._task_sentence(None, 0)
    chk("N1", none_task == agent.TASK_UNKNOWN_COUNT and "3" not in none_task,
        "no hint keeps the fix-the-worst-one task")
    three = agent._task_sentence(3, 0)
    chk("N2", "3 planted vulnerabilities" in three,
        "the count reaches the prompt verbatim", three[:80])
    chk("N3", "vulnerability." in agent._task_sentence(1, 0)
        and "them" not in agent._task_sentence(1, 0),
        "one is singular, not 'as many of them as you can'",
        agent._task_sentence(1, 0)[:120])
    # The count is a search target, never a quota — a padded finding costs the
    # whole attempt, because one invalid entry fails `_finding_errors`.
    chk("N4", "Do NOT pad" in three and "not what to claim" in three,
        "the prompt says the number is what to look for, not what to claim")
    partial = agent._task_sentence(3, 1)
    chk("N5", "already patched 1" in partial and "about 2 should remain" in partial,
        "a later attempt is told what this job still owes", partial)
    done = agent._task_sentence(3, 3)
    chk("N6", "all the organizer announced" in done and "was missed" in done,
        "...and when the count is met it looks for a miss, not a filler",
        done)

    # last block wins: a model often shows a draft before its answer
    text = ('draft\n```json\n{"status": "failure"}\n```\n'
            'final\n```json\n{"status": "success", "findings": []}\n```')
    chk("J1", agent._extract_json(text) == {"status": "success", "findings": []},
        "the LAST fenced json block is the answer")
    chk("J2", agent._extract_json("no json at all") is None,
        "no block is None, not a crash")
    chk("J3", agent._extract_json("```json\n{bad json}\n```") is None,
        "malformed json is None, not a crash")

    # report role is deterministic BY DESIGN — validate_report demands exact
    # strings that prose cannot hit.
    src = AGENT_PY.read_text()
    chk("R1", "_render_report(context.document" in src,
        "the report role renders deterministically instead of asking a model")

    # A run that logs nothing is indistinguishable from a hung one. The first
    # version wrote a single line AFTER the turn, so a live-fire job showed
    # 75 bytes of run.log for twenty minutes of real work (5df30344f339).
    # EVERY drain loop, not "the string appears somewhere": there are two —
    # one shared by gpt/grok and one for claude — and a substring test passes
    # while either of them has silently stopped logging.
    _loops = [i for i, line in enumerate(src.splitlines())
              if line.strip().startswith("async for msg in ")]
    _lines = src.splitlines()
    _streamed = [i for i in _loops if _lines[i + 1].strip() == "_stream(msg)"]
    chk("L1", len(_loops) >= 2 and len(_streamed) == len(_loops),
        "every drain loop streams each message to the logger",
        (len(_loops), len(_streamed)))
    chk("L2", "agent_heartbeat(self.job_id, msg)" in src,
        "...and through agent_heartbeat, which is what writes last_agent_event_at")
    for helper in ("tool_use_line(block)", "tool_result_lines(msg)"):
        chk(f"L3-{helper.split('(')[0]}", helper in src,
            f"{helper.split('(')[0]} is used, so the lines match every other module")
    chk("L4", 'f"AGENT: {text[:500]}"' in src,
        "agent prose reaches run.log in the shape the viewer expects")
    chk("L5", "agent starting" in src
        and src.index("agent starting") < src.index("started = time.monotonic()"),
        "the role banner is written BEFORE the work, not after it")

    # The candidate tree is BOTH the agent's cwd and the thing the inventory
    # audits. An extra file there is not untidy — it restores the candidate and
    # destroys the patch. Job 5df30344f339 lost a real fix to
    # `.codex-turn.lock`.
    from modules.codex_turn_guard import TURN_LOCK_FILENAME, TURN_STOP_FILENAME
    from modules.live_fire_patch_loop import _candidate_inventory_errors

    (ws.candidate / TURN_LOCK_FILENAME).write_text("", encoding="utf-8")
    chk("S0", any("outside the input manifest" in e
                  for e in _candidate_inventory_errors(ws)),
        "an agent lock file really does fail the inventory (the bug)",
        _candidate_inventory_errors(ws))
    removed = agent.LiveFireInvoker._sweep_agent_scratch(ws.candidate)
    chk("S1", TURN_LOCK_FILENAME in removed
        and not (ws.candidate / TURN_LOCK_FILENAME).exists(),
        "the sweep removes it", removed)
    chk("S2", _candidate_inventory_errors(ws) == [],
        "...and the inventory is clean again",
        _candidate_inventory_errors(ws))

    # The sweep must NOT become a second inventory check with the opposite
    # sign: deleting a file the agent added in violation would hide the very
    # violation the gate reports.
    (ws.candidate / "src" / "sneaky.php").write_text("<?php\n", encoding="utf-8")
    agent.LiveFireInvoker._sweep_agent_scratch(ws.candidate)
    chk("S3", (ws.candidate / "src" / "sneaky.php").exists()
        and any("outside the input manifest" in e
                for e in _candidate_inventory_errors(ws)),
        "a file the AGENT added is left alone, so the policy still reports it")
    (ws.candidate / "src" / "sneaky.php").unlink()

    chk("S4", "from modules.codex_turn_guard import" in src
        and TURN_STOP_FILENAME not in src,
        "the names are imported from their producer, not retyped")
    chk("S5", "concurrent_child=True" in src,
        "codex is told not to write the lock into the audited tree at all")
    # The sweep is only as good as its call site — and the call site is what a
    # cleanup edit deletes first.
    _main_body = src.split("def _main(", 1)[1].split("\n    def ", 1)[0]
    chk("S6", "self._sweep_agent_scratch(context.candidate)" in _main_body,
        "the main role actually runs the sweep after its turn")

    chk("N7", "known = meta.get(\"live_fire_known_vulnerabilities\")" in src
        and "_task_sentence(known, already)" in src,
        "the main role reads the hint from meta and feeds it to the prompt")
    chk("N8", "self._patched.extend(findings)" in src,
        "accepted findings accumulate across attempts (V12 pins how they count)")

    # ---- the round's own scoreboard: attacks blocked per version ---------
    # The second number an A&D round gives back, and the only ground truth in
    # the whole prompt — everything else is the agent reading its own diff.
    fb_dir = base / "fb"
    fb_dir.mkdir()
    chk("B1", agent._round_feedback(fb_dir) == "",
        "no feedback file renders nothing, not an empty heading")

    def _write(rows):
        (fb_dir / agent.FEEDBACK_NAME).write_text(
            json.dumps({"entries": rows}), encoding="utf-8")

    _write([{"attempt": 1, "blocked": 2, "note": "tick 4"}])
    one = agent._round_feedback(fb_dir)
    chk("B2", "patch version 1: blocked 2 attack(s)" in one and "tick 4" in one,
        "one scored version renders with its note", one)
    chk("B3", "MORE" not in one and "NO MORE" not in one,
        "...and no trend is claimed from a single point", one)

    _write([{"attempt": 1, "blocked": 2}, {"attempt": 2, "blocked": 7}])
    up = agent._round_feedback(fb_dir)
    chk("B4", "observed MORE blocked attacks" in up
        and "do not treat one score delta as proof" in up,
        "a rising count remains observational rather than falsely causal", up)

    _write([{"attempt": 1, "blocked": 2}, {"attempt": 2, "blocked": 2}])
    flat = agent._round_feedback(fb_dir)
    chk("B5", "observed NO increase" in flat
        and "uploaded" in flat and "SLA" in flat
        and "does not by itself refute" in flat,
        "a flat count asks for deployment/SLA checks before inference", flat)

    _write([{"attempt": 1, "blocked": 7}, {"attempt": 2, "blocked": 2}])
    down = agent._round_feedback(fb_dir)
    chk("B6", "observed FEWER" in down and "regression signal" in down
        and "uploaded delta" in down and "SLA" in down,
        "a falling count is a regression signal, not a causal verdict", down)

    _write([{"attempt": 2, "blocked": 9}, {"attempt": 1, "blocked": 1}])
    ordered = agent._round_feedback(fb_dir)
    chk("B7", ordered.index("version 1") < ordered.index("version 2"),
        "versions render oldest-first, so a trend reads as a trend")

    (fb_dir / agent.FEEDBACK_NAME).write_text("{ not json", encoding="utf-8")
    chk("B8", agent._round_feedback(fb_dir) == "",
        "an unreadable feedback file is silence, not a crash")

    chk("B9", "round_feedback=_round_feedback(job_dir(self.job_id))" in src
        and "{round_feedback}# Your task" in src,
        "the feedback is wired into the prompt above the task")

    # Exercised, not grepped: a source check passes while the guard sits in a
    # dead branch with its message still in the file.
    import asyncio
    import types as _types

    class _Any:
        def __init__(self, *a, **k): pass
        def __getattr__(self, n): return _Any()
        def __call__(self, *a, **k): return _Any()
        @classmethod
        def from_url(cls, *a, **k): return _Any()

    for _name in ("redis", "docker", "rq"):
        _mod = _types.ModuleType(_name)
        _mod.__getattr__ = lambda _n: _Any
        sys.modules[_name] = _mod

    from fastapi import HTTPException
    import api.routes.jobs as JOBS

    class _Req:
        def __init__(self, payload): self._payload = payload
        async def json(self): return self._payload

    fb_job = hashlib.sha256(b"fbjob").hexdigest()[:12]
    fbd = base / "jobs" / fb_job
    fbd.mkdir(parents=True, exist_ok=True)
    (fbd / "meta.json").write_text(json.dumps(
        {"id": fb_job, "module": "live-fire", "status": "finished"}))
    (fbd / "patch-progress.json").write_text(json.dumps(
        {"snapshots": [{"attempt": 1, "zip": "patched-attempt-1.zip"}]}))

    def _post(payload):
        try:
            return ("ok", asyncio.run(
                JOBS.record_live_fire_feedback(fb_job, _Req(payload))))
        except HTTPException as exc:
            return ("http", exc.status_code)

    chk("B10", _post({"attempt": 1, "blocked": 3})[0] == "ok",
        "a score against a real version is accepted")
    chk("B11", _post({"attempt": 2, "blocked": 3}) == ("http", 400),
        "a version that was never produced is refused, so the number "
        "cannot attach to nothing")
    _post({"attempt": 1, "blocked": 9})
    _entries = json.loads((fbd / "patch-feedback.json").read_text())["entries"]
    chk("B12", len(_entries) == 1 and _entries[0]["blocked"] == 9,
        "re-scoring a tick overwrites rather than duplicating", _entries)
    chk("B13", _post({"attempt": 1, "blocked": -1}) == ("http", 400)
        and _post({"attempt": 1, "blocked": "many"}) == ("http", 400),
        "a nonsense count is refused")

    _other = hashlib.sha256(b"notlf").hexdigest()[:12]
    (base / "jobs" / _other).mkdir(parents=True, exist_ok=True)
    (base / "jobs" / _other / "meta.json").write_text(json.dumps(
        {"id": _other, "module": "web", "status": "finished"}))
    try:
        asyncio.run(JOBS.record_live_fire_feedback(
            _other, _Req({"attempt": 1, "blocked": 1})))
        _non_lf = "accepted"
    except HTTPException as exc:
        _non_lf = exc.status_code
    chk("B14", _non_lf == 400,
        "a non-live-fire job cannot be scored", _non_lf)

    # ---- one version per vulnerability, numbered by emission -------------
    from modules.live_fire_contract import attempts_for
    from modules import live_fire_patch_loop as loop

    chk("V1", "Fix EXACTLY ONE vulnerability" in agent.TASK_UNKNOWN_COUNT
        and "Fix EXACTLY ONE vulnerability" in agent._task_sentence(3, 0),
        "both task shapes ask for exactly one fix per attempt")
    chk("V2", attempts_for(None) == 3 and attempts_for(5) == 7
        and attempts_for(50) == 12,
        "the job gets enough attempts to reach the announced count, bounded",
        [attempts_for(n) for n in (None, 5, 50)])
    # V3/V4 (emission numbering and the cumulative count) are behaviours of
    # the loop's emitter and are exercised where the loop actually runs:
    # scripts/test_live_fire_unverified.py, checks I9/I10.

    # The count told the agent HOW MANY were done; it never said WHICH, so
    # job c2c3cdb1f353 walked back to the same vulnerability five attempts
    # running. All five zips differ from the original in exactly one file.
    chk("V8", agent._already_fixed_text([]) == "",
        "nothing fixed yet renders no section")
    _f = lambda bc, path, line: loop.VulnerabilityFinding(
        bug_class=bc, severity="high", path=path, line=line,
        root_cause="r", attack_impact="a", patch_description="bounded it",
        patch_reason="w", mitigation_class="root-cause-fix", evidence_tier="B")
    _fixed = agent._already_fixed_text([
        _f("sql-injection", "src/svc/app.py", 17),
        _f("sql-injection", "src/svc/app.py", 17),
        _f("path-traversal", "src/files/get.php", 42),
    ])
    chk("V9", _fixed.count("sql-injection at") == 1
        and "path-traversal at src/files/get.php:42" in _fixed,
        "each fixed vulnerability is named once, by identity", _fixed)
    chk("V10", "do NOT patch these again" in _fixed
        and "will look correct" in _fixed,
        "...and the agent is warned the fix is already in the file it reads")
    chk("V11", "already_fixed=_already_fixed_text(self._patched)" in src
        and "{already_fixed}" in src,
        "the list is wired into the prompt")
    chk("V12", "self._patched.extend(findings)" in src
        and "len({(f.bug_class, f.path) for f in self._patched})" in src,
        "`already` counts DISTINCT vulnerabilities, not reported findings")

    apx_js = (ROOT / "web-ui" / "app.js").read_text()
    for token in ("V${ver}", "${cleared} vuln clear", "operator feedback :",
                  "please input"):
        chk(f"V5-{token[:14]}", token in apx_js,
            f"the history row renders {token!r}")
    chk("V6", "snap.vuln_clear" in apx_js and "snap.version" in apx_js,
        "...from the index, not recomputed in the browser")
    chk("V7", "box.dataset.source" in apx_js and 'job.filename' in apx_js,
        "the bundle name comes from the job, not a second copy in the index")

    # ---- SLA: the normal response must stay byte-identical ---------------
    # The scoring server sends SLA traffic alongside the attacks on the same
    # tick and compares the answer against the ORIGINAL's, so "do not break
    # it" is not the constraint — "do not change it" is. The distinction is
    # not academic: `htmlspecialchars($q)` closes an XSS and also changes the
    # response for any benign value containing `&`.
    for phrase in ("Do NOT change what a LEGITIMATE request sees",
                   "compares", "ORIGINAL", "INVISIBLE on legitimate input",
                   "parameterised query", "LEGITIMATE BASELINE",
                   "exploit behaviour is expected to change"):
        chk(f"A1-{phrase[:12]}", phrase in agent.MAIN_SYSTEM,
            f"the system prompt states the SLA constraint: {phrase!r}")
    chk("A2", "escaping output that the original emitted raw" in agent.MAIN_SYSTEM,
        "...including the escaping case, which reads as a safe fix and is not")
    chk("A3", "rejecting a LEGITIMATE BASELINE input" in agent.MAIN_SYSTEM
        and "rejecting an input the original accepted" not in agent.MAIN_SYSTEM,
        "the SLA contract preserves benign baselines without preserving exploits")

    route_src = ROUTE_PY.read_text()
    chk("N9", "vulnerability_count: Optional[int] = Form(None)" in route_src
        and "live_fire_known_vulnerabilities" in route_src,
        "the create form accepts the count and stores it on the job")
    chk("N10", "1 <= int(vulnerability_count) <= 50" in route_src,
        "...bounded, because it reaches a prompt")
    html = INDEX_HTML.read_text()
    chk("N11", 'name="vulnerability_count"' in html and 'type="number"' in html,
        "the UI has the field")

    job_src = JOB_PY.read_text()
    # Not "the name appears somewhere": the name survives the guard being
    # disabled, and a disabled guard hands `None` to the loop.
    chk("W1", "if invoker is None:" in job_src
        and "invoker = LiveFireInvoker(" in job_src
        and "invoker or DiagnosticInvoker()" not in job_src,
        "the worker constructs the real invoker when none is injected")
    chk("W2", "candidate_diff=lambda: candidate_diff(workspace)" in job_src,
        "the loop's own differ is injected, so the invoker cannot disagree with the gate")
    return not _FAILED


MUTATIONS = [
    ("the pre-patch line guard is removed", AGENT_PY,
     "    if not (1 <= line <= record.candidate_line_count\n"
     "            and line in record.changed_lines):",
     "    if False:",
     "F2"),
    ("the changed-line check uses its own idea of a diff", AGENT_PY,
     "and line in record.changed_lines):",
     "and line in set()):" ,
     "F1"),
    ("a path not in the diff is accepted", AGENT_PY,
     '            return None, f"path {path!r} is not in the diff"',
     "            record = diffs[0]",
     "F4"),
    ("severity stops being a closed enum", AGENT_PY,
     "    if severity not in SEVERITIES:",
     "    if False:",
     "F6-severity"),
    ("evidence_tier stops being a closed enum", AGENT_PY,
     "    if tier not in EVIDENCE_TIERS:",
     "    if False:",
     "F6-evidence_tier"),
    ("the prompt offers a tier the gate rejects", AGENT_PY,
     '      "evidence_tier": "A | B"',
     '      "evidence_tier": "A | B | C"',
     "P1"),
    ("the prompt stops asking for the post-patch line", AGENT_PY,
     "IN THE FILE AS YOU LEFT IT",
     "where the bug was",
     "P4"),
    ("the SLA constraint softens to 'do not break it'", AGENT_PY,
     "* Do NOT change what a LEGITIMATE request sees.",
     "* Try not to break normal requests.",
     "A1-Do NOT chang"),
    ("output escaping stops being named as an SLA risk", AGENT_PY,
     "    - encoding or escaping output that the original emitted raw, so a benign",
     "    - (nothing here), so a benign",
     "A2"),
    ("the compose boundary leaves the system prompt", AGENT_PY,
     "* Do NOT touch a Dockerfile, docker-compose.yml/yaml, compose.yml/yaml,",
     "* Do NOT touch a Dockerfile,",
     "P5-docker-compose"),
    ("the first json block wins instead of the last", AGENT_PY,
     "    for raw in reversed(blocks):",
     "    for raw in blocks:",
     "J1"),
    ("the report role asks a model after all", AGENT_PY,
     "            value=_render_report(context.document, context.findings, context.diffs),",
     '            value="see machine evidence",',
     "R1"),
    ("the turn stops streaming and only reports at the end", AGENT_PY,
     '                _stream(msg)\n                # THE ADAPTER ALREADY SAYS HOW THE TURN ENDED',
     '                # THE ADAPTER ALREADY SAYS HOW THE TURN ENDED',
     "L1"),
    ("liveness stops being written", AGENT_PY,
     "            agent_heartbeat(self.job_id, msg)",
     "            pass",
     "L2"),
    ("tool results stop reaching run.log", AGENT_PY,
     "                for line in tool_result_lines(msg):",
     "                for line in []:",
     "L3-tool_result_lines"),
    ("the scratch sweep is never called", AGENT_PY,
     "        for name in self._sweep_agent_scratch(context.candidate):",
     "        for name in []:",
     "S6"),
    ("codex writes its lock into the audited tree again", AGENT_PY,
     "                    concurrent_child=True,",
     "                    concurrent_child=False,",
     "S5"),
    ("the sweep widens past agent tooling", AGENT_PY,
     "        for name in (TURN_LOCK_FILENAME, TURN_STOP_FILENAME):",
     '        for name in (TURN_LOCK_FILENAME, TURN_STOP_FILENAME, "src/sneaky.php"):',
     "S3"),
    ("the count never reaches the prompt", AGENT_PY,
     "        task=_task_sentence(known, already),",
     "        task=TASK_UNKNOWN_COUNT,",
     "N7"),
    ("the count becomes a quota instead of a target", AGENT_PY,
     '    "Do NOT pad the finding to reach {count}. A finding you cannot point at a "',
     '    "Report {count} findings. A finding you cannot point at a "',
     "N4"),
    ("a later attempt forgets what the job already fixed", AGENT_PY,
     "        self._patched.extend(findings)",
     "        pass",
     "N8"),
    ("the route stops bounding the count", ROUTE_PY,
     "        if not 1 <= int(vulnerability_count) <= 50:",
     "        if False:",
     "N10"),
    ("round feedback never reaches the prompt", AGENT_PY,
     "            round_feedback=_round_feedback(job_dir(self.job_id)),",
     '            round_feedback="",',
     "B9"),
    ("a flat score stops being called out", AGENT_PY,
     "        elif counts[-1] == counts[-2]:",
     "        elif False:",
     "B5"),
    ("a falling score reads as a rising one", AGENT_PY,
     "        if counts[-1] > counts[-2]:",
     "        if counts[-1] != counts[-2]:",
     "B6"),
    ("versions render newest-first", AGENT_PY,
     '    rows.sort(key=lambda e: e.get("attempt", 0))\n    lines = [',
     '    rows.sort(key=lambda e: -e.get("attempt", 0))\n    lines = [',
     "B7"),
    ("a score can attach to a version that never existed", JOBS_ROUTE_PY,
     "    if attempt not in known:",
     "    if False:",
     "B11"),
    ("re-scoring a tick duplicates instead of replacing", JOBS_ROUTE_PY,
     '    entries = [e for e in entries\n               if not (isinstance(e, dict) and e.get("attempt") == attempt)]',
     "    entries = list(entries)",
     "B12"),
    ("the agent is no longer told WHICH vulnerabilities are done", AGENT_PY,
     "            already_fixed=_already_fixed_text(self._patched),",
     '            already_fixed="",',
     "V11"),
    ("a re-reported fix counts as a new one", AGENT_PY,
     "        already = len({(f.bug_class, f.path) for f in self._patched})",
     "        already = len(self._patched)",
     "V12"),
    ("a revoked token is retried like an ordinary failure", AGENT_PY,
     "        if self._fatal:\n            return \"\", AgentUsage(model=model, error_kind=\"auth\")",
     "        if False:\n            return \"\", AgentUsage(model=model, error_kind=\"auth\")",
     "X6"),
    ("the revoked-token wording stops being recognised", AGENT_PY,
     '    "refresh token was revoked",',
     '    "some other string entirely",',
     "X1"),
    ("attempts stop being one-fix-each", AGENT_PY,
     '    "Fix EXACTLY ONE vulnerability in this attempt, and report exactly one "',
     '    "Fix what you can in this attempt, and report "',
     "V1"),
    ("the announced count no longer buys attempts", CONTRACT_PY2,
     "    return max(floor, min(_MAX_ATTEMPTS_CEILING,\n"
     "                          int(known_vulnerabilities) + _ATTEMPT_SLACK))",
     "    return floor",
     "V2"),
    ("the worker goes back to the diagnostic stub", JOB_PY,
     "        if invoker is None:",
     "        if False:",
     "W1"),
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

    files = (AGENT_PY, JOB_PY, ROUTE_PY, JOBS_ROUTE_PY, CONTRACT_PY2, LOOP_PY2)
    originals = {p: p.read_text() for p in files}
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
            if expect in failed:
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
