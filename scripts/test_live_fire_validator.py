#!/usr/bin/env python3
"""The validator agent — live-fire v2's oracle for "did the service survive".

THE PROPERTY THIS FILE EXISTS TO DEFEND is not "the SLA check works";
`test_live_fire_stack.py` owns that. It is that the validator can tell
"the patch did that" from "the patch broke that", and that it cannot be
talked out of the distinction.

WHY THE DISTINCTION IS THE WHOLE MODULE. Reason forward without it: blueteam
fixes a client-side bug by editing a static script -> the corpus replays ->
the request fetching that file differs, because the file served verbatim IS
the file deliberately rewritten -> the validator refuses -> the repo agent
never sees it. Every client-side fix dies that way, while a server-side fix
can leave the page it renders byte-identical.

So the rule, and E1-E4 are it:

    a served path inside the patch's own changed set is EXPLAINED;
    a rendered page that merely includes it must not move.

AND THE EXEMPTION MUST BE UNFORGEABLE. `serves` is an AGENT'S CLAIM that a
request returns a file byte for byte. If a rendered page could claim it, an
agent that wanted a free pass would simply claim it everywhere. S1-S4 check
that the claim is verified against the bytes on disk and discarded otherwise.

AND THE THREE NAMESPACES MUST AGREE. The tree listing the agent reads, the
`serves` it writes back, and `changed_paths` from the patch being judged are
three different vocabularies for the same file, and they fail in the SAME
DIRECTION when they disagree: the claim does not resolve, it is dropped with
a log line, and every static-asset fix is rejected again — the original bug,
reintroduced by a path prefix. N1-N3 pin all three to the workspace root,
which is the one `live_fire_patch_loop.DiffRecord.path` already speaks
(every changed path starts with the bundle directory's own name).

No Docker here. The stack layer is driven through a recording runner.
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

VALIDATOR_PY = ROOT / "modules" / "live_fire_validator.py"
VERIFIER_PY = ROOT / "modules" / "live_fire_verifier.py"
STACK_PY = ROOT / "modules" / "live_fire_stack.py"

from modules.live_fire_stack import (  # noqa: E402
    CapturedResponse,
    CorpusRequest,
    Entrypoint,
    SlaFinding,
    StackLimits,
)
from modules.live_fire_stack import StackError  # noqa: E402
from modules.live_fire_validator import (  # noqa: E402
    _availability_detail,
    attack_mark,
    compose_topology,
    sink_digest,
    source_digest,
    Baseline,
    CONFIRM_PASSES,
    CORPUS_SYSTEM,
    drop_clock_pairs,
    DroppedRequest,
    MAX_REQUESTS,
    MIN_BASELINE_COVERAGE,
    ValidatorAgent,
    ValidatorError,
    find_bundle_dir,
    parse_corpus,
    summarise_tree,
)

_FAILED: list[str] = []
TMP = Path(os.environ.get("CLAUDE_JOB_DIR", "/tmp")) / "lf-validator-test"


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


DOORS = [Entrypoint("kweb", 80, "uuuu6")]

# The path namespace: workspace-relative, with the bundle directory as the
# first segment.
ASSET = "fo_src/src/kweb/assets/js/apx.js"
PAGE = "fo_src/src/kweb/admin/sapphire_monitor.php"


def proposal(**over):
    base = {
        "requests": [
            {"name": "root", "service": "kweb", "port": 80, "path": "/"},
            {"name": "listing", "service": "kweb", "port": 80,
             "path": "/pages/list.php"},
            {"name": "apx_js", "service": "kweb", "port": 80,
             "path": "/assets/js/apx.js", "serves": ASSET},
            {"name": "sapmon", "service": "kweb", "port": 80,
             "path": "/admin/sapphire_monitor.php", "session": "admin"},
        ],
        "ready": ["listing"],
    }
    base.update(over)
    return base


def make_tree(root: Path, asset_body: str) -> Path:
    if root.exists():
        shutil.rmtree(root)
    bundle = root / "fo_src"
    (bundle / "src" / "kweb" / "assets" / "js").mkdir(parents=True)
    (bundle / "src" / "kweb" / "admin").mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n")
    (root / "fo_src" / "src" / "kweb" / "assets" / "js" / "apx.js").write_text(
        asset_body)
    (root / "fo_src" / "src" / "kweb" / "admin"
     / "sapphire_monitor.php").write_text("<?php echo 1;")
    return root


# ------------------------------------------------------------------ parse


def t_parse() -> None:
    reqs, ready, trimmed, _ = parse_corpus(proposal(), entrypoints=DOORS)
    check("P1", [r.name for r in reqs] == ["root", "listing", "apx_js", "sapmon"]
          and ready == ["listing"] and trimmed == 0,
          "a well-formed proposal parses into requests plus a readiness set")
    check("P2", reqs[2].serves == ASSET and reqs[3].session == "admin",
          "serves and session survive the parse")

    fenced = "here you go\n```json\n" + json.dumps(proposal()) + "\n```\ntrailing"
    reqs2, _, _, _ = parse_corpus(fenced, entrypoints=DOORS)
    check("P3", len(reqs2) == 4,
          "a model that wraps its JSON in prose and a fence is still read")

    # Refused HERE rather than later: a request aimed at something that does
    # not exist errors on every run, is dropped as "broken", and shrinks the
    # corpus silently. Each arm pins the message only ITS OWN guard produces,
    # so one cannot pass by standing in for the other.
    try:
        parse_corpus(proposal(requests=[
            {**proposal()["requests"][0], "service": "ghost"}]), entrypoints=DOORS)
        check("P4", False, "a service the bundle does not publish was accepted")
    except ValidatorError as exc:
        check("P4", "front door of this bundle" in str(exc)
              and "kweb" in str(exc),
              "an unknown service is refused, and the refusal names the "
              "services that do exist")
    try:
        parse_corpus(proposal(requests=[
            {**proposal()["requests"][0], "port": 8080}]), entrypoints=DOORS)
        check("P5", False, "a port the bundle does not publish was accepted")
    except ValidatorError as exc:
        check("P5", "does not publish" in str(exc),
              "a port the bundle never published is refused")

    try:
        parse_corpus(proposal(ready=[]), entrypoints=DOORS)
        check("P6", False, "a proposal with no readiness request was accepted")
    except ValidatorError as exc:
        check("P6", "seeding" in str(exc),
              "a corpus must name a readiness request: a static front page "
              "renders identically on both sides of the DB seeding transition")

    try:
        parse_corpus(proposal(ready=["nope"]), entrypoints=DOORS)
        check("P7", False, "a readiness name outside the corpus was accepted")
    except ValidatorError:
        check("P7", True, "a readiness name must exist in the corpus")

    over = MAX_REQUESTS + 10
    many = proposal(requests=[
        {"name": f"r{i}", "service": "kweb", "port": 80, "path": f"/{i}"}
        for i in range(over)], ready=["r0"])
    # Tolerant on purpose: a regression that RAISES here should fail this
    # check by name, with its reason, rather than crash the suite.
    try:
        kept, ready_many, trimmed_many, _ = parse_corpus(many, entrypoints=DOORS)
    except ValidatorError as exc:
        kept, ready_many, trimmed_many = [], [], f"raised: {exc}"
    check("P8", len(kept) == MAX_REQUESTS and trimmed_many == 10,
          "an oversized proposal is TRIMMED, not refused — job 673bf5286183 "
          "died after the agent spent 366s reading the service and proposed "
          "ten requests over a line, and six minutes of work went with it")
    check("P8b", trimmed_many > 0 and ready_many,
          "…and the trim reports its count, so a shortened corpus is never "
          "mistaken for full coverage")

    # A trim that takes the readiness request with it must not fail the job,
    # but the corpus must still name one.
    tail_ready = proposal(requests=[
        {"name": f"r{i}", "service": "kweb", "port": 80, "path": f"/{i}"}
        for i in range(over)], ready=["r0", f"r{over - 1}"])
    try:
        _, ready_tail, _, _ = parse_corpus(tail_ready, entrypoints=DOORS)
    except ValidatorError as exc:
        ready_tail = f"raised: {exc}"
    check("P8c", ready_tail == ["r0"],
          "a readiness name that fell off the end of a trim is dropped with "
          "it rather than failing the run")

    try:
        parse_corpus(proposal(requests=proposal()["requests"][:1], ready=["root"]),
                     entrypoints=DOORS)
        check("P9", False, "a one-request corpus was accepted")
    except ValidatorError:
        check("P9", True, "a corpus too small for a verdict to mean anything "
                          "is refused")

    dupes = proposal()["requests"] + [proposal()["requests"][0]]
    try:
        parse_corpus(proposal(requests=dupes), entrypoints=DOORS)
        check("P10", False, "a duplicate request name was accepted")
    except ValidatorError:
        check("P10", True,
              "names are the key the comparator joins on, so they must be unique")


# -------------------------------------------------------------- namespace


def t_namespace() -> None:
    root = make_tree(TMP / "ns", "console.log(1);\n")
    check("N1", find_bundle_dir(root).name == "fo_src",
          "the compose stack gets the BUNDLE directory, one level below the "
          "workspace root")
    check("N1b", find_bundle_dir(root / "fo_src").name == "fo_src",
          "a root that already IS the bundle resolves to itself")

    listing = summarise_tree(root)
    check("N2", ASSET in listing.splitlines(),
          "the listing the agent reads is workspace-relative, so the path it "
          "writes back is already the one changed_paths uses")

    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    body = (root / ASSET).read_text()
    kept = agent._verify_serves(
        {"apx_js": CorpusRequest("apx_js", "n", 80, "/a.js", serves=ASSET)},
        [CapturedResponse("apx_js", 200, {}, body)])
    check("N3", kept == {"apx_js": ASSET},
          "a claim written exactly as the listing shows it RESOLVES — the one "
          "thing that, if broken, silently rejects every static-asset fix")

    # The closing of the loop: the very same string, as a workspace-relative
    # changed path.
    explained, unexplained = ValidatorAgent._classify(
        [SlaFinding("apx_js", "body-missing-line", "x")],
        Baseline(requests=(), ready=(), per_request={}, dropped=(),
                 serves={"apx_js": ASSET}),
        [ASSET])
    check("N4", len(explained) == 1 and not unexplained,
          "and it MATCHES changed_paths — all three namespaces agree, pinned "
          "against a workspace-relative path whose first segment is the "
          "bundle directory")


# ------------------------------------------------------------ serves guard


def t_serves() -> None:
    root = make_tree(TMP / "sv", "console.log('real asset');\n")
    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    asset_body = (root / ASSET).read_text()

    ok = agent._verify_serves(
        {"a": CorpusRequest("a", "n", 80, "/a.js", serves=ASSET)},
        [CapturedResponse("a", 200, {}, asset_body)])
    check("S1", ok == {"a": ASSET},
          "a request whose bytes ARE the file keeps its claim")

    lying = agent._verify_serves(
        {"a": CorpusRequest("a", "n", 80, "/page", serves=ASSET)},
        [CapturedResponse("a", 200, {}, "<html>a rendered page</html>")])
    check("S2", lying == {},
          "a RENDERED page claiming to be a file loses the claim — otherwise "
          "an agent wanting a free pass would claim it on everything")

    ghost = agent._verify_serves(
        {"a": CorpusRequest("a", "n", 80, "/a.js",
                            serves="fo_src/src/nope.js")},
        [CapturedResponse("a", 200, {}, asset_body)])
    check("S3", ghost == {}, "a claim naming a file that is not in the bundle "
                             "loses the claim")

    almost = agent._verify_serves(
        {"a": CorpusRequest("a", "n", 80, "/a.js", serves=ASSET)},
        [CapturedResponse("a", 200, {}, asset_body[:-1])])
    check("S4", almost == {},
          "the check is byte-exact: one character short is not the file")

    # The body deliberately MATCHES the file here, so the byte check would
    # accept it; only the error guard can reject this one. A capture that
    # errored proves nothing about the bytes, whatever it happens to hold.
    errored = agent._verify_serves(
        {"a": CorpusRequest("a", "n", 80, "/a.js", serves=ASSET)},
        [CapturedResponse("a", -1, {}, asset_body, error="refused")])
    check("S5", errored == {},
          "a claim is not verified from a capture that errored, even when the "
          "bytes it carries would have matched")


# --------------------------------------------------------- classification


def t_classify() -> None:
    base = Baseline(requests=(), ready=(), per_request={}, dropped=(),
                    serves={"apx_js": ASSET})

    e, u = ValidatorAgent._classify(
        [SlaFinding("apx_js", "body-missing-line", "x")],
        base, [ASSET])
    check("E1", len(e) == 1 and not u,
          "the file the patch rewrote, served verbatim: EXPLAINED. Without "
          "this every client-side fix is rejected by its own validator")

    e, u = ValidatorAgent._classify(
        [SlaFinding("apx_js", "body-missing-line", "x")], base, [PAGE])
    check("E2", not e and len(u) == 1,
          "a served file that the patch did NOT change is still a break")

    e, u = ValidatorAgent._classify(
        [SlaFinding("sapmon", "body-missing-line", "x")], base, [PAGE])
    check("E3", not e and len(u) == 1,
          "a RENDERED page whose source the patch touched is still a break — "
          "the attack server's benign payload sees the rendering, so the "
          "rendering is the contract, not the file's bytes")

    e, u = ValidatorAgent._classify(
        [SlaFinding("root", "status", "200 -> 500")], base, [ASSET, PAGE])
    check("E4", not e and len(u) == 1,
          "a page with no claim at all is never explained away")


# ------------------------------------------------------------ baseline floor


class _Recorder:
    """Drives ValidatorAgent without Docker by standing in for _capture.

    Returns a LIST of passes, matching the real `_capture`. THREE base stacks
    now — A once, B twice across a minute boundary, C once — because two
    stacks can agree by luck and a value that varies BETWEEN stacks is
    invisible to any number of captures of the same two.
    """

    # "baseenv" too: `_environment_findings` re-reads the ORIGINAL tree
    # mid-validation, and a fake that served it the PATCHED capture would
    # call every real break "the environment" and pass everything.
    _BASE = ("basea", "baseb", "basec", "baseenv")

    def __init__(self, a, b, patched=None, c=None):
        self.a, self.b, self.patched, self.calls = a, b, patched, []
        # An unspecified third stack agrees with the first, which is the
        # ordinary case: most of a corpus is identical everywhere.
        self.c = c if c is not None else a

    def __call__(self, suffix, tree_root, requests, ready, *, passes=1,
                 cross_minute=False):
        self.calls.append((suffix, passes, cross_minute))
        if self.patched is not None and suffix not in self._BASE:
            # Honour `passes`: a fake that always returns both captures would
            # keep confirming even with the confirmation pass switched off.
            return list(self.patched)[:passes]
        source = (self.a if suffix == "basea"
                  else self.c if suffix == "basec" else self.b)
        return [source for _ in range(passes)]


def _reqs():
    return [CorpusRequest(f"r{i}", "n", 80, f"/{i}") for i in range(10)]


def t_floor() -> None:
    root = make_tree(TMP / "fl", "x\n")
    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    reqs = _reqs()
    good = [CapturedResponse(r.name, 200, {"server": "n"}, "body\n") for r in reqs]
    agent._capture = _Recorder(good, good)
    base = agent.establish(reqs, ["r0"])
    check("B1", len(base.per_request) == 10 and not base.dropped,
          "a stable corpus establishes whole")

    # Seven of ten wobble: under the floor, so the baseline is refused.
    wobbly = [CapturedResponse(r.name, 200 if i < 3 else 500, {}, "b\n")
              for i, r in enumerate(reqs)]
    agent2 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent2._capture = _Recorder(good, wobbly)
    try:
        agent2.establish(reqs, ["r0"])
        check("B2", False, "a baseline that lost 7 of 10 requests was accepted")
    except ValidatorError as exc:
        check("B2", "survived" in str(exc) and "too thin" in str(exc).lower()
              or "cannot support" in str(exc),
              "the floor is at ESTABLISH time too: the validate-time floor is "
              "computed against what survived, so 40 proposed and 30 dropped "
              "would demand 8 of 10 and report full coverage")

    # One of ten wobbles: above the floor, kept, and REPORTED.
    one_bad = [CapturedResponse(r.name, 500 if i == 9 else 200, {}, "b\n")
               for i, r in enumerate(reqs)]
    agent3 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent3._capture = _Recorder(good, one_bad)
    base3 = agent3.establish(reqs, ["r0"])
    check("B3", len(base3.per_request) == 9
          and [d.name for d in base3.dropped] == ["r9"],
          "a survivable drop is kept AND named — a silently thinner corpus "
          "reads as 'everything was checked'")
    check("B4", MIN_BASELINE_COVERAGE < 1.0,
          "the floor is a fraction, not all-or-nothing: one flaky endpoint "
          "must not cost the whole run")


def t_confirm() -> None:
    """A finding that does not reproduce is noise, not the patch's fault.

    NOT hypothetical. Two runs of the same validator against the same base
    and patched trees disagreed — one reported several unexplained findings
    on pages behind a login,
    the other none — while the base tree validated against its own baseline
    came back clean both times. A single base PAIR can under-estimate how
    volatile a page is, and the patch then wears the blame.
    """

    root = make_tree(TMP / "cf", "x\n")
    reqs = _reqs()
    stable = [CapturedResponse(r.name, 200, {"server": "n"}, "a\nb\n") for r in reqs]

    def patched(flaky_line):
        out = []
        for r in reqs:
            body = "a\nb\n" if r.name != "r5" else f"a\n{flaky_line}\n"
            out.append(CapturedResponse(r.name, 200, {"server": "n"}, body))
        return out

    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    # Pass 1 differs from base on r5; pass 2 agrees with base. Never confirmed.
    agent._capture = _Recorder(stable, stable, [patched("ZZZ"), stable])
    agent.establish(reqs, ["r0"])
    noisy = agent.validate(root, [], suffix="p")
    check("C1", noisy.ok and not noisy.unexplained,
          "a finding that appears in one capture and not the next is "
          "discarded — a single base pair can teach the calibrator that a "
          "varying field is fixed, and the patch then wears the blame")

    agent2 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent2._capture = _Recorder(stable, stable, [patched("ZZZ"), patched("ZZZ")])
    agent2.establish(reqs, ["r0"])
    real = agent2.validate(root, [], suffix="p")
    check("C2", not real.ok and any(f.name == "r5" for f in real.unexplained),
          "…but a difference that reproduces in EVERY capture is a real "
          "break and still fails")

    patched_calls = [c for c in agent2._capture.calls
                     if c[0] not in _Recorder._BASE]
    check("C3", patched_calls and patched_calls[-1][1] == CONFIRM_PASSES,
          "the extra pass runs against the ALREADY-RUNNING stack — one probe "
          "container, seconds after the long wait for it to become ready")


def t_clock() -> None:
    from modules.live_fire_validator import seconds_to_minute_boundary
    check("K1", seconds_to_minute_boundary(120.0) == 61.0
          and 1.0 < seconds_to_minute_boundary(155.0) <= 61.0,
          "the wait lands in the NEXT minute, plus a second — a capture that "
          "starts at :59.999 and a clock that reads minutes are the same "
          "problem over again")

    root = make_tree(TMP / "ck", "x\n")
    reqs = _reqs()
    good = [CapturedResponse(r.name, 200, {"server": "n"}, "body\n") for r in reqs]
    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    rec = _Recorder(good, good)
    agent._capture = rec
    agent.establish(reqs, ["r0"])
    by_suffix = {suffix: (passes, cross) for suffix, passes, cross in rec.calls}
    check("K2", by_suffix.get("baseb") == (2, True)
          and by_suffix.get("basea") == (1, False),
          "the baseline is built from THREE captures: stack A once, stack B "
          "twice AND across a minute boundary — without the gap the second "
          "pass lands in the same minute and teaches nothing the first did not")

    # The boundary that matters most is BETWEEN THE STACKS, not inside one.
    # A value written when the database was SEEDED does not change for the
    # life of that stack, so waiting between two captures of stack B teaches
    # nothing about it; only stacks seeded in different minutes can show it
    # move.
    src = VALIDATOR_PY.read_text()
    a_at = src.find('self._capture("basea"')
    b_at = src.find('self._capture(\n            "baseb"')
    # find, not index: a mutation that deletes the anchor must make this check
    # FAIL with its reason, not crash the whole suite with a ValueError.
    gap_at = src.find("gap = seconds_to_minute_boundary()")
    check("K3", 0 <= a_at < gap_at < b_at,
          "the wait sits BETWEEN stack A and stack B, so the two databases "
          "are seeded in different minutes — a seed-time value is invisible "
          "to any number of captures of the same stack")


def t_third_stack() -> None:
    """Two stacks can agree by luck; a third is what catches it.

    Some values vary BETWEEN stacks rather than within one, so no number of
    captures of the same two stacks can see them; calibration records them
    as fixed, and a correct patch is then refused on them with nothing else
    wrong.
    """

    root = make_tree(TMP / "third", "x\n")
    reqs = _reqs()

    def page(value):
        return [CapturedResponse(r.name, 200, {"server": "n"},
                                 f"<h1>X</h1>\n<td>rows {value}</td>\n")
                for r in reqs]

    # A and B agree; C, an independent stack, does not. The patched stack
    # then shows a THIRD value — so the only thing that can accept it is
    # having seen C disagree.
    agree, differs, patched = page("1"), page("2"), page("4")
    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    rec = _Recorder(agree, agree, [patched, patched], c=differs)
    agent._capture = rec
    agent.establish(reqs, ["r0"])
    suffixes = [c[0] for c in rec.calls]
    check("T1", suffixes == ["basea", "baseb", "basec"],
          "the baseline is built from THREE independent stacks")

    later = agent.validate(root, [], suffix="p")
    check("T2", later.ok,
          "a value that differed on the third stack is volatile, so a patched "
          "stack showing yet another value is not a regression")

    # And the same corpus with only two stacks would have refused it.
    agent2 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent2._capture = _Recorder(agree, agree, c=agree)
    agent2.establish(reqs, ["r0"])
    agent2._capture = _Recorder(agree, agree, [patched, patched], c=agree)
    refused = agent2.validate(root, [], suffix="p")
    check("T3", not refused.ok,
          "…while a value every base stack agreed on is still judged, so the "
          "third stack widens the net without blunting it")


def t_project() -> None:
    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=TMP / "ns",
                           work_dir=TMP / "w", sleep=lambda _s: None)
    name = agent._project("basea")
    check("J1", "bf8d00c76ed8" in name,
          "every compose project carries the job id — two concurrent v2 jobs "
          "sharing `lfv2basea` means one's teardown kills the other's capture")
    other = ValidatorAgent(job_id="0123456789ab", base_root=TMP / "ns",
                           work_dir=TMP / "w", sleep=lambda _s: None)
    check("J2", other._project("basea") != name,
          "…so two jobs never collide")


def t_attack_corpus() -> None:
    """An attack in the corpus turns the validator against the blueteam.

    The corpus defines "working": a patch is refused when it changes any of
    these responses. So a request that is itself an exploit pins the
    VULNERABLE behaviour, and the one patch that fixes the bug is the one
    patch that cannot pass. Worse, the failure is invisible — the refusal
    reads as "the response changed", which is true and says nothing about why.

    CORPUS_SYSTEM already forbids it, and on job 3d0cf9b6e883 the agent
    obeyed: 49 requests, none an attack. An instruction is not a guarantee.
    """

    benign = [
        ("/css/site.css", ""),
        ("/asset.php?file=main.css&v=2", ""),
        ("/item.php?id=1", ""),
        ("/login.php", "user=alice&pass=wrong"),
        # An http:// URL to an internal host is not itself an attack; only
        # file://, gopher://, dict:// and ftp:// and the metadata address are
        # marked.
        ("/form.php",
         "mode=save&link=http%3A%2F%2F"
         "backend.invalid%3A12345%2Fping"),
        ("/report.php?page=2&sort=asc", ""),
    ]
    attacks = [
        ("/s.php", "q=1' OR 1=1--"),
        ("/s.php", "q=x UNION SELECT null,null"),
        ("/p", "<script>alert(1)</script>"),
        ("/p?x=%3Cscript%3Ealert(1)%3C/script%3E", ""),
        ("/p", "c=<img src=x onerror=alert(1)>"),
        ("/p", "c={{7*7}}"),
        ("/p?f=../../../etc/passwd", ""),
        ("/p", "url=http://169.254.169.254/latest/meta-data"),
        ("/p", "url=file:///etc/passwd"),
        ("/p", "n=x;cat /etc/passwd"),
        ("/p", "<!DOCTYPE r SYSTEM \"file:///etc/passwd\">"),
    ]
    false_positives = [(a, b) for a, b in benign if attack_mark(a, b)]
    missed = [(a, b) for a, b in attacks if not attack_mark(a, b)]
    check("W1", not false_positives,
          "every benign request shape is left alone — a false positive "
          f"here silently costs coverage: {false_positives}")
    check("W2", not missed,
          f"and an exploit is named whatever shape it comes in: {missed}")

    # Dropped, not refused: `propose` asks the agent once, and that call took
    # 336 seconds on job 3d0cf9b6e883.
    poisoned = proposal()
    poisoned["requests"] = list(poisoned["requests"]) + [
        {"name": "sqli", "service": "kweb", "port": 80,
         "path": "/search.php?q=1%27%20OR%201=1--"},
    ]
    kept, ready_ok, _, refused = parse_corpus(poisoned, entrypoints=DOORS)
    check("W3", "sqli" not in {r.name for r in kept} and len(refused) == 1
          and "sql injection" in refused[0],
          "the attack is dropped and NAMED — one bad request costs one "
          "request, not the whole corpus and the job behind it")
    check("W4", len(kept) == len(proposal()["requests"]) and ready_ok,
          "…and everything else survives untouched")

    only_attacks = proposal(requests=[
        {"name": "a", "service": "kweb", "port": 80,
         "path": "/?q=%3Cscript%3E"},
        {"name": "b", "service": "kweb", "port": 80,
         "path": "/?q=../../etc/passwd"},
    ], ready=["a"])
    try:
        parse_corpus(only_attacks, entrypoints=DOORS)
        too_few = False
    except ValidatorError:
        too_few = True
    check("W5", too_few,
          "a corpus that was mostly attacks still fails, because dropping "
          "them leaves too few requests for a verdict to mean anything")


def t_availability_detail() -> None:
    """A stack that will not come up has to say WHY.

    Job 3d0cf9b6e883 refused V8 on

        compose-build failed with exit 1: Image lfv2btv8-...-kweb Building

    — the first line of a progress stream. Two truncations conspired: the
    error kept `stderr or stdout`, so a build log went in the bin whenever
    stderr held any progress at all, and the finding kept the first 400
    characters, which is the progress and not the reason. The blueteam was
    handed that as the thing to act on, and went and changed a patch nobody
    could tell was wrong.
    """

    from modules.live_fire_verifier import CommandResult, DockerCommandError

    exc = DockerCommandError("compose-build", CommandResult(
        1, stdout="step 1\n" + "build noise\n" * 200 + "ERROR: no space left",
        stderr="Image lfv2btv8-x-kweb Building"))
    check("V1", "no space left" in str(exc),
          "the reason survives the error even when stderr held only progress "
          "— `stderr or stdout` threw the build log away")
    detail = _availability_detail(exc)
    check("V2", "compose-build failed with exit 1" in detail
          and "no space left" in detail,
          "…and the finding the blueteam acts on carries BOTH ends: what "
          "failed, and why")
    short = _availability_detail(RuntimeError("tiny"))
    check("V3", short == "tiny",
          "a message that already fits is not mangled with an ellipsis")


def t_sink_digest() -> None:
    """Grep the tree once, here, instead of once per round in the agent.

    Job f432f9d8e16d: five of round 1's forty-one plan-agent turns were
    sink greps, and a turn is about thirteen seconds of MODEL time
    against one second of tool time — 70% of that round's plan call was the
    model, 6% was running the commands. Turns are the currency, so the way to
    make finding vulnerabilities faster is to hand over what a turn would
    have fetched.
    """

    root = TMP / "sinks"
    shutil.rmtree(root, ignore_errors=True)
    (root / "src" / "app").mkdir(parents=True)
    (root / "src" / "app" / "page.php").write_text(
        "<?php\n"
        "$id = $_GET['id'];\n"
        "echo \"<h1>\" . $_GET['title'] . \"</h1>\";\n"
        "$sql = \"SELECT * FROM n WHERE id = \" . $_GET['id'];\n"
        "system(\"ls \" . $_POST['dir']);\n"
        "$d = unserialize($_COOKIE['prefs']);\n"
        "include $_GET['page'];\n",
        encoding="utf-8",
    )
    (root / "src" / "app" / "widget.js").write_text(
        "const view = { template: markup };\npanel.innerHTML = html;\n",
        encoding="utf-8",
    )
    (root / "src" / "app" / "node_modules").mkdir()
    (root / "src" / "app" / "node_modules" / "lib.js").write_text(
        "eval('x')\n", encoding="utf-8")
    # A PYTHON vendor tree as well. With only the php and js conventions in
    # `_VENDOR_DIRS` this file is walked like source, and the check that was
    # supposed to prove the deny list could not tell the difference.
    (root / "src" / "app" / ".venv" / "lib" / "site-packages").mkdir(parents=True)
    (root / "src" / "app" / ".venv" / "lib" / "site-packages" / "dep.py").write_text(
        "import subprocess\nsubprocess.run(cmd)\n", encoding="utf-8")
    (root / "src" / "app" / "logo.png").write_bytes(b"\x89PNG\r\n")

    digest = sink_digest(root)
    labels = {line.split("[", 1)[1].split("]", 1)[0]
              for line in digest.splitlines() if "[" in line}
    check("D1", {"echoes request data", "builds SQL by concatenation",
                 "runs a shell", "unserialises",
                 "includes a path from request data", "writes raw HTML",
                 "compiles a template"} <= labels,
          "every place request data reaches a sink is reported, with WHICH "
          "sink it reached")
    check("D2", "node_modules" not in digest and "logo.png" not in digest
          and "site-packages" not in digest,
          "…and a dependency tree and a binary are not source the blueteam "
          "can patch, so neither is worth a line of the prompt — and the tree "
          "is vendored under every ecosystem's convention, not just the php "
          "and js ones")
    check("D3", "page.php:3" in digest and "page.php:2" not in digest,
          "a line number, so the agent opens the file at the right place — "
          "and `$id = $_GET['id']` alone is not a sink, it is an assignment")

    long_line = "echo $_GET['x'];" + "A" * 500
    (root / "src" / "app" / "long.php").write_text(
        "<?php\n" + long_line + "\n", encoding="utf-8")
    # The DEFAULT is what a job actually runs with, so check that too.
    trimmed = sink_digest(root)
    check("D4", all(len(line) < 260 for line in trimmed.splitlines())
          and all(len(line) < 120
                  for line in sink_digest(root, line_chars=40).splitlines()),
          "a line is trimmed: this rides on a prompt next to a four-hundred "
          "path listing, and a digest that makes the agent slower is the "
          "opposite of the point")
    capped = sink_digest(root, limit=2)
    check("D5", len(capped.splitlines()) == 3 and "stopped at 2" in capped,
          "…and the whole digest is capped, saying so rather than quietly "
          "handing over a short list as if it were the tree")

    # A MINIFIED VENDOR FILE. Trimmed to 150 characters its lines name
    # nothing, and there are enough of them to crowd out the files that do.
    (root / "src" / "app" / "bundle.php").write_text(
        "<?php\n" + "$x=1;" * 900 + "new PDO($dsn);$h=$_GET['h'];"
        + "$y=2;" * 900 + "\nunserialize($z);\n",
        encoding="utf-8")
    squashed = sink_digest(root)
    bundle = [l for l in squashed.splitlines() if "bundle.php" in l]
    check("D6", len(bundle) == 1 and "minified" in bundle[0]
          and "connects to a host it was told to" in bundle[0],
          "a minified file collapses to ONE row that still names the sink "
          "CLASSES it holds — collapsing the noise must not collapse the "
          "lead, or the suppression costs more than the noise did")

    (root / "src" / "app" / "safe.php").write_text(
        "<?php\necho htmlspecialchars($_GET['q']);\n", encoding="utf-8")
    labelled = [l for l in sink_digest(root).splitlines() if "safe.php" in l]
    check("D7", len(labelled) == 1 and "already escaped" in labelled[0],
          "an escaped hit is LABELLED, not dropped: it is usually fine and "
          "occasionally wrong, and dropping it would cost recall for noise "
          "that a word of context removes")

    # The summary must count what the ROWS would have counted. The per-line
    # loop breaks on the first pattern that matches; running every pattern over
    # the whole text instead counts one call once per pattern that claims it.
    (root / "src" / "app" / "shell.py").write_text(
        "x" * 2506 + "\n"
        + "subprocess.Popen(cmd); os.system(x); " * 3 + "\n"
        + "y" * 2600 + "\n", encoding="utf-8")
    shell = [l for l in sink_digest(root).splitlines() if "shell.py" in l][0]
    check("D15", "runs a shell x6" in shell,
          "the collapsed summary counts each call ONCE, the way the rows it "
          "replaced would have — a number that is silently double is worse "
          "than no number, because it is the evidence the operator reads")

    doors = source_digest(root)
    check("D8", "page.php:2" in doors and "[request parameter]" in doors,
          "the DOORS are listed too: `$id = $_GET['id']` is not a sink and is "
          "exactly where a trail whose sink is an ordinary library call has "
          "to be picked up")

    (root / "docker-compose.yml").write_text(
        "services:\n  edge:\n    ports:\n      - 8080:80\n"
        "    networks:\n      - out\n      - in\n"
        "  secret:\n    networks:\n      - in\n",
        encoding="utf-8")
    topo = compose_topology(root)
    check("D9", "edge" in topo and "REACHABLE FROM OUTSIDE" in topo
          and "secret" in topo and "internal only" in topo,
          "and which service the internet can reach: a connection to a host "
          "the request named is a feature in a service that stands nowhere "
          "special and a pivot in one that straddles an internal network")

    # ONE LONG LINE IS NOT A MINIFIED FILE. Keying on the maximum was the wrong
    # SHAPE of threshold: a single embedded base64 URI, inline SVG or long i18n
    # array would swallow a whole readable source file.
    (root / "src" / "app" / "wide.php").write_text(
        "<?php\n" + "\n".join(["echo $_GET['q'];"] * 400)
        + "\n$img = '" + "A" * 3000 + "';\n", encoding="utf-8")
    wide_rows = [l for l in sink_digest(root).splitlines() if "wide.php" in l]
    check("D10", len(wide_rows) > 1 and not any("minified" in l for l in wide_rows),
          "a readable file with ONE long line is still read line by line — the "
          "rule is that a minified file's lines are long ON AVERAGE")

    doors = source_digest(root)
    bundled = [l for l in doors.splitlines() if "bundle.php" in l]
    check("D11", len(bundled) == 1 and "minified" in bundled[0],
          "…and the two digests agree about the same file: dropping it from "
          "one with a bare `continue` made a collapsed file look like a clean "
          "one on that side")

    # Compose's OTHER spellings. Reporting nothing is safe; reporting the wrong
    # adjacency is not, because the plan prompt states this as fact.
    (root / "compose.yaml").write_text(
        "services:\n"
        "  gate:   # the edge\n"
        "    networks:\n"
        "      frontnet:\n"
        "        aliases: [gw]\n"
        "      backnet:\n"
        "    ports:\n"
        "      - target: 80\n"
        "        published: 8080\n"
        "  store:\n"
        "    ports:\n"
        "      - 127.0.0.1:5432:5432\n",
        encoding="utf-8")
    alt = compose_topology(root)
    gate = [l for l in alt.splitlines() if "gate" in l][0]
    store = [l for l in alt.splitlines() if "store" in l][0]
    check("D12", "frontnet" in gate and "backnet" in gate
          and "aliases" not in gate,
          "networks in MAPPING form are read as networks — the sequence-only "
          "parser left every service printing `(default)`, which does not read "
          "as a gap but as `they all share one network`: the inverse of the "
          "adjacency the prompt then asks the agent to reason about")
    check("D13", "8080:80" in gate,
          "…and a long-form port reports the PUBLISHED port, not the target")
    # REPORTING NOTHING IS SAFE; REPORTING THE WRONG ADJACENCY IS NOT. Each of
    # these printed a confident falsehood into every plan prompt.
    (root / "docker-compose.yaml").write_text(
        "services:\n"
        "  a:\n"
        "    networks:\n"
        "      front:\n"
        "        aliases:\n"
        "          - gw\n"
        "      back:\n"
        "  b:\n"
        "    network_mode: host\n"
        "  c:\n"
        "    ports:\n"
        "      - ${HOST_IP:-0.0.0.0}:80:80\n"
        "  d:\n"
        "    ports:\n"
        "      - \"[::]:81:81\"\n",
        encoding="utf-8")
    tricky = compose_topology(root)
    row = {l.strip().split("  ")[0]: l for l in tricky.splitlines() if l.startswith("  ")}
    check("D16", "gw" not in row["a"] and "front" in row["a"] and "back" in row["a"],
          "a network's ALIAS is a name the service answers to ON that network, "
          "not another network — counting it as one invents adjacency across "
          "the very boundary the prompt asks the agent to reason about")
    check("D17", "REACHABLE FROM OUTSIDE" in row["b"],
          "`network_mode: host` puts a service on the host's own stack: the "
          "most exposed a container gets, and it publishes no ports to say so")
    check("D18", "REACHABLE FROM OUTSIDE" in row["c"]
          and "REACHABLE FROM OUTSIDE" in row["d"],
          "an unresolved ${VAR} host and a bracketed [::] both FAIL OPEN — "
          "'internal only' is an assertion the reachability argument rests "
          "on, so it is only ever said about something actually read")

    check("D14", "internal only" in store,
          "…and a loopback-bound publish is not REACHABLE FROM OUTSIDE: it is "
          "reachable from this host and from nowhere else")


def t_source() -> None:
    src = VALIDATOR_PY.read_text()
    # COUNTED, not merely present. Two call sites now guard on this pair --
    # the availability capture and the mid-validation re-read of the original
    # -- so `in src` stays true when one of them is widened, and the check
    # that exists to stop exactly that would pass.
    check("X1", src.count("except (StackError, DockerCommandError)") == 2,
          "the availability catch is NARROW at BOTH sites: a bare `except "
          "Exception` turns our own AttributeError into 'the blueteam's patch "
          "is unavailable' and discards a correct patch invisibly")
    check("X2", "Do NOT include attacks" in CORPUS_SYSTEM,
          "the corpus defines what WORKING means; an attack that stops "
          "working is the point of the patch, not a regression")
    check("X3", "READS THE DATABASE" in CORPUS_SYSTEM,
          "the prompt demands a DB-backed readiness request, because that is "
          "the only kind that can see the seeding transition")
    check("X4", "exactly as it appears in THE BUNDLE listing" in CORPUS_SYSTEM,
          "the prompt pins the path namespace it asks for to the listing it "
          "gives — the two must not drift")



# --------------------------------------------------- the clock, and the tree

# A synthetic midnight crossing over three requests, kept as data rather than
# as a story: sixteen of these eighteen are one line's date moving across
# midnight, and the surviving two are what proves a trim alone cannot
# rescue the verdict. The three requests spell the date three ways, because
# `_CLOCKISH` accepts a dash, a slash or a dot, year-first or day-first.
_MIDNIGHT = (
    [("r1", "body-missing-line", "<td>2000-01-01</td>")] * 2
    + [("r1", "body-extra-line", "<td>2000-01-02</td>")] * 2
    + [("r1", "body-missing-line",
        "a nondeterministic slot held 1 line(s) in both base runs and 0 here")]
    + [("r2", "body-missing-line", "<td>2000/01/01</td>")] * 5
    + [("r2", "body-extra-line", "<td>2000/01/02</td>")] * 5
    + [("r3", "body-missing-line", "<td>01.01.2000</td>")]
    + [("r3", "body-extra-line", "<td>02.01.2000</td>")]
    + [("r3", "body-missing-line",
        "a nondeterministic slot held 1 line(s) in both base runs and 0 here")]
)


def t_clock_pairs() -> None:
    """`drop_clock_pairs` against a whole midnight crossing, not one pair."""

    findings = [SlaFinding(*row) for row in _MIDNIGHT]
    kept, dropped = drop_clock_pairs(findings)
    check("Y1", len(dropped) == 16 and len(kept) == 2,
          "the sixteen clock lines pair off and the two width findings stay "
          f"(got {len(dropped)} dropped, {len(kept)} kept)")
    check("Y1b", all("nondeterministic slot" in f.detail for f in kept),
          "what survives is exactly the findings that carry no clock reading "
          "— a trim cannot rescue this verdict, and must not pretend to")

    # CONSUME-ONCE. A listing can render the same date on every row, so a
    # first-match scan pairs one and leaves the rest standing — which is the
    # same refusal, arrived at more slowly.
    four = [SlaFinding("home", "body-missing-line", "<td>2000-01-01</td>")] * 4 \
        + [SlaFinding("home", "body-extra-line", "<td>2000-01-02</td>")] * 4
    kept4, dropped4 = drop_clock_pairs(four)
    check("Y2", not kept4 and len(dropped4) == 8,
          "four identical missing lines consume four identical extras")

    three_four = [SlaFinding("home", "body-missing-line", "<td>2000-01-01</td>")] * 4 \
        + [SlaFinding("home", "body-extra-line", "<td>2000-01-02</td>")] * 3
    kept34, _ = drop_clock_pairs(three_four)
    check("Y2b", len(kept34) == 1 and kept34[0].kind == "body-missing-line",
          "a missing line with no extra to pair against is a DELETION and "
          "stays — the pool is consumed, not reused")

    # NOT "any run of digits". A count moving between stacks is a real
    # finding, not a clock reading, and masking every number would hide it
    # instead of reporting it.
    counts = [SlaFinding("stats", "body-missing-line", '<td>Rows 0</td>'),
              SlaFinding("stats", "body-extra-line", '<td>Rows 9</td>')]
    _, dropped_counts = drop_clock_pairs(counts)
    check("Y3", not dropped_counts,
          "a count changing is not a clock reading and is never paired away — "
          "these two differ ONLY in a number, so masking every digit would "
          "pair them and hide a real finding")

    lone = [SlaFinding("home", "body-missing-line", "<td>2000-01-01</td>")]
    _, dropped_lone = drop_clock_pairs(lone)
    check("Y3b", not dropped_lone,
          "a dated line that simply vanished is a deletion, not a clock move")

    plain = [SlaFinding("x", "body-missing-line", "<b>hi</b>"),
             SlaFinding("x", "body-extra-line", "<b>hi</b>")]
    _, dropped_plain = drop_clock_pairs(plain)
    check("Y3c", not dropped_plain,
          "two details that mask to themselves never pair — masking must "
          "CHANGE something for the pair to be considered at all")

    split = [SlaFinding("a", "body-missing-line", "<td>2000-01-01</td>"),
             SlaFinding("b", "body-extra-line", "<td>2000-01-02</td>")]
    _, dropped_split = drop_clock_pairs(split)
    check("Y3d", not dropped_split,
          "a pair is only a pair within ONE request")

    times = [SlaFinding("m", "body-missing-line", "<td>2000-01-01 09:05</td>"),
             SlaFinding("m", "body-extra-line", "<td>2000-01-01 09:06</td>")]
    _, dropped_times = drop_clock_pairs(times)
    check("Y3e", len(dropped_times) == 2,
          "the minute axis is the same axis — e17f946's case pairs here too")


class _Drifted:
    """A tree whose ORIGINAL reading moves on its own, like a real one.

    `basea/baseb/basec` are captured before the drift; `baseenv` — the
    mid-validation re-read of the ORIGINAL tree — and the patched stack are
    captured after it. That is the shape of a baseline taken just before
    the date turns over.
    """

    _BASE = ("basea", "baseb", "basec")

    def __init__(self, before, after, env=None):
        self.before, self.after = before, after
        self.env = env if env is not None else after
        self.calls = []

    def __call__(self, suffix, tree_root, requests, ready, *, passes=1,
                 cross_minute=False):
        self.calls.append((suffix, passes, cross_minute))
        if suffix in self._BASE:
            return [self.before for _ in range(passes)]
        if suffix == "baseenv":
            return [self.env for _ in range(passes)]
        return [self.after for _ in range(passes)]


def _bodies(reqs, line, extra_on=None):
    out = []
    for r in reqs:
        body = f"head\n{line}\nfoot\n"
        if extra_on and r.name == extra_on:
            body += "PATCH-ADDED\n"
        out.append(CapturedResponse(r.name, 200, {"server": "n"}, body))
    return out


def t_environment() -> None:
    """The ORIGINAL tree, re-read NOW, is what answers for a moving world.

    DELIBERATELY NOT A DATE HERE. `drop_clock_pairs` already clears a date,
    so a dated fixture would pass with this mechanism switched off entirely
    and prove nothing about it. The drift used is a COUNT, which no pattern
    may mask and only a re-reading can answer.
    """

    root = make_tree(TMP / "env", "x\n")
    reqs = _reqs()
    before = _bodies(reqs, '<td>Rows 0</td>')
    after = _bodies(reqs, '<td>Rows 9</td>')

    agent = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                           work_dir=TMP / "w", sleep=lambda _s: None)
    agent._capture = _Drifted(before, after)
    agent.establish(reqs, ["r0"])
    verdict = agent.validate(root, [], suffix="p")
    check("Y4", verdict.ok and not verdict.unexplained,
          "a patch refused only because the world moved under the baseline is "
          "not refused: the ORIGINAL tree, read now, says the same thing")
    check("Y4b", any(f.name == "r5" for f in verdict.explained),
          "and the findings are kept as EXPLAINED, not deleted — a verdict "
          "with no record of what it cleared is undebuggable the one time "
          "the mechanism is wrong")

    # THE OTHER HALF, and the one that matters more: the re-read must not
    # become a pass for everything. The original drifts; the patch ALSO adds
    # a line the original does not have.
    broke = _bodies(reqs, '<td>Rows 9</td>', extra_on="r5")
    agent3 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent3._capture = _Drifted(before, broke, env=after)
    agent3.establish(reqs, ["r0"])
    real = agent3.validate(root, [], suffix="p")
    # A clock pair is not a refusal, but it is still evidence: a verdict whose
    # record shows nothing of what was removed is undebuggable the one time
    # the removal is wrong.
    dated_before = _bodies(reqs, "<td>2000-01-01</td>")
    dated_after = _bodies(reqs, "<td>2000-01-02</td>")
    agent_clock = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                                 work_dir=TMP / "w", sleep=lambda _s: None)
    agent_clock._capture = _Drifted(dated_before, dated_after)
    agent_clock.establish(reqs, ["r0"])
    dated = agent_clock.validate(root, [], suffix="p")
    check("Y9", dated.ok and dated.explained,
          "a clock pair passes, and is WRITTEN DOWN as explained rather than "
          "deleted — the same prescription the re-read below follows")

    check("Y5", not real.ok and any(f.name == "r5" for f in real.unexplained),
          "a break the ORIGINAL tree does NOT reproduce survives the re-read "
          "— this is the check that stops the mechanism passing everything")

    # ONE stack between concurrent failures, not one each.
    agent4 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent4._capture = _Drifted(before, broke, env=after)
    agent4.establish(reqs, ["r0"])
    agent4.validate(root, [], suffix="p1")
    agent4.validate(root, [], suffix="p2")
    envs = [c for c in agent4._capture.calls if c[0] == "baseenv"]
    check("Y6", len(envs) == 1,
          "two refusals inside the TTL share ONE re-read of the original — "
          "six blueteams failing together must not raise six stacks")
    check("Y8", envs and envs[0][1] == 1,
          "one pass is logically enough: if the unpatched tree shows it, the "
          "patch did not cause it")

    # A re-read that cannot run leaves the verdict exactly as it was.
    class _NoDocker(_Drifted):
        def __call__(self, suffix, tree_root, requests, ready, *, passes=1,
                     cross_minute=False):
            if suffix == "baseenv":
                raise StackError("compose refused")
            return super().__call__(suffix, tree_root, requests, ready,
                                    passes=passes, cross_minute=cross_minute)

    agent5 = ValidatorAgent(job_id="bf8d00c76ed8", base_root=root,
                            work_dir=TMP / "w", sleep=lambda _s: None)
    agent5._capture = _NoDocker(before, after)
    agent5.establish(reqs, ["r0"])
    stuck = agent5.validate(root, [], suffix="p")
    check("Y7", not stuck.ok,
          "no reading is not a pass — a re-read Docker refused keeps the "
          "verdict we already had")


def run_checks() -> bool:
    _FAILED.clear()
    TMP.mkdir(parents=True, exist_ok=True)
    for fn in (t_parse, t_namespace, t_serves, t_classify, t_floor,
               t_confirm, t_clock, t_third_stack,
               t_clock_pairs, t_environment,
               t_attack_corpus, t_availability_detail,
               t_sink_digest,
               t_project,
               t_source):
        fn()
    return not _FAILED


MUTATIONS = [
    ("the clock pairs are deleted instead of recorded", VALIDATOR_PY,
     "        explained = list(explained) + list(clock_paired)",
     "        explained = list(explained)",
     "Y9"),
    ("a clock pair is matched but never consumed", VALIDATOR_PY,
     "        paired.add(index)\n        paired.add(pool.pop(0))",
     "        paired.add(index)\n        paired.add(pool[0])",
     "Y1"),
    ("every run of digits counts as a clock reading", VALIDATOR_PY,
     '_CLOCKISH = re.compile(\n    r"\\d{4}[-./]\\d{1,2}[-./]\\d{1,2}"',
     '_CLOCKISH = re.compile(\n    r"\\d+"  # was: a date shape\n    r"|\\d{4}[-./]\\d{1,2}[-./]\\d{1,2}"',
     "Y3"),
    ("a detail with no clock reading may still pair", VALIDATOR_PY,
     "        masked = _clock_masked(finding.detail)\n"
     "        if masked == finding.detail:\n"
     "            return None\n"
     "        return (finding.name, masked)",
     "        masked = _clock_masked(finding.detail)\n"
     "        return (finding.name, masked)",
     "Y3c"),
    ("the pair ignores which request it came from", VALIDATOR_PY,
     "        return (finding.name, masked)",
     '        return ("", masked)',
     "Y3d"),
    ("the original tree is never re-read", VALIDATOR_PY,
     "        if unexplained:\n            try:\n"
     "                environment = self._environment_findings(usable, ready, floor)",
     "        if False:\n            try:\n"
     "                environment = self._environment_findings(usable, ready, floor)",
     "Y4"),
    ("a re-read Docker refused becomes a pass", VALIDATOR_PY,
     '                self.log(f"validator: the original tree did not answer ({exc})")\n'
     "                environment = frozenset()",
     '                self.log(f"validator: the original tree did not answer ({exc})")\n'
     "                environment = frozenset(\n"
     "                    (f.name, f.kind, f.detail) for f in unexplained\n"
     "                )",
     "Y7"),
    ("findings the original does NOT show are dropped too", VALIDATOR_PY,
     "                standing = [\n                    f for f in unexplained\n"
     "                    if (f.name, f.kind, f.detail) not in environment\n                ]",
     "                standing = []",
     "Y5"),
    ("the contemporaneous reading is cached forever", VALIDATOR_PY,
     "            if cached is not None and (time.monotonic() - cached[0]) < ENVIRONMENT_TTL_S:",
     "            if cached is not None and (time.monotonic() - cached[0]) > ENVIRONMENT_TTL_S:",
     "Y6"),
    ("only php and js vendoring is skipped", VALIDATOR_PY,
     '    "/vendor/", "/node_modules/",           # php, js\n'
     '    "/.venv/", "/venv/", "/site-packages/",  # python\n'
     '    "/target/",                              # rust, java\n'
     '    "/.git/", "/.svn/",                      # vcs metadata\n'
     '    "/bower_components/", "/.bundle/",',
     '    "/vendor/", "/node_modules/",',
     "D2"),
    ("an attack in the corpus is kept", VALIDATOR_PY,
     "        if mark is not None:",
     "        if False:",
     "W3"),
    ("the attack scan never looks at the body", VALIDATOR_PY,
     "        mark = attack_mark(path, body, *(str(v) for v in headers.values()))",
     "        mark = attack_mark(path)",
     "W2"),
    ("a percent-encoded attack slips through", VALIDATOR_PY,
     '        blob = f"{blob} {unquote_plus(blob)}"',
     "        blob = blob",
     "W2"),
    ("a dropped request still holds its name, so a later one collides", VALIDATOR_PY,
     "            seen.discard(name)",
     "            pass",
     None),
    ("a failed build's reason is thrown away with its log", VERIFIER_PY,
     "            part for part in (result.stderr.strip(), result.stdout.strip())\n"
     "            if part",
     "            part for part in (result.stderr.strip(),)\n"
     "            if part",
     "V1"),
    ("the finding keeps the progress and not the reason", VALIDATOR_PY,
     "    return f\"{text[:head]} … {text[-tail:]}\"",
     "    return text[:head + tail]",
     "V2"),
    ("the digest walks dependency trees too", VALIDATOR_PY,
     "    return any(part in padded for part in _VENDOR_DIRS)",
     "    return False",
     "D2"),
    ("a minified file is read line by line again", VALIDATOR_PY,
     "        if minified:\n            # ONE ROW, NOT ONE PER LINE.",
     "        if False:\n            # ONE ROW, NOT ONE PER LINE.",
     "D6"),
    ("the minified summary stops naming the sink classes", VALIDATOR_PY,
     '                    + ", ".join(f"{label} x{count}" for label, count in worst)',
     '                    + ""',
     "D6"),
    ("an escaped hit is no longer flagged as escaped", VALIDATOR_PY,
     '                        label = f"{label}, already escaped — check the flags"',
     "                        pass",
     "D7"),
    ("the doors stop being reported", VALIDATOR_PY,
     "    compiled = [(label, re.compile(pat)) for label, pat in SOURCES]",
     "    compiled = []",
     "D8"),
    ("the collapsed summary counts one call once per pattern", VALIDATOR_PY,
     "                    if any(a < span[1] and span[0] < b for a, b in claimed):\n"
     "                        continue",
     "                    if False:\n                        continue",
     "D15"),
    ("one long line condemns the whole file again", VALIDATOR_PY,
     "    return (longest > _MINIFIED_CHARS and mean > _MINIFIED_MEAN_CHARS,",
     "    return (longest > _MINIFIED_CHARS,",
     "D10"),
    ("a collapsed file is dropped from the doors instead of summarised",
     VALIDATOR_PY,
     "            doors = sum(len(pattern.findall(text)) for _, pattern in compiled)",
     "            doors = 0",
     "D11"),
    ("networks in mapping form stop being networks", VALIDATOR_PY,
     '            if key == "networks" and name:\n                current[1].append(name)',
     '            if False:\n                current[1].append(name)',
     "D12"),
    ("a long-form port loses the published side", VALIDATOR_PY,
     '            if published and target:\n                joined = f"{published}:{target}"',
     '            if False:\n                joined = f"{published}:{target}"',
     "D13"),
    ("a network alias is counted as a network again", VALIDATOR_PY,
     "            if child_indent is not None and indent > child_indent:",
     "            if False:",
     "D16"),
    ("network_mode stops being read, so host networking reads as internal",
     VALIDATOR_PY,
     '        if name == "network_mode" and inline:',
     "        if False:",
     "D17"),
    ("an unreadable host binding fails CLOSED again", VALIDATOR_PY,
     '                     and "$" not in host_ip',
     "                     and True",
     "D18"),
    ("a loopback publish is called internet-facing again", VALIDATOR_PY,
     "            if bound:\n                continue",
     "            if False:\n                continue",
     "D14"),
    ("a service's exposure is not reported", VALIDATOR_PY,
     '                f"  ports: {\', \'.join(ports) or \'(none)\'}  [{reach}]"',
     '                f"  ports: {\', \'.join(ports) or \'(none)\'}"',
     "D9"),
    ("a hit stops saying which sink it reached", VALIDATOR_PY,
     '                        label = f"{label}, already escaped \u2014 check the flags"\n'
     '                    rows.append(\n'
     '                        f"{rel}:{number}  [{label}]  {stripped[:line_chars]}"',
     '                        label = f"{label}, already escaped \u2014 check the flags"\n'
     '                    rows.append(\n'
     '                        f"{rel}  {stripped[:line_chars]}"',
     "D1"),
    ("a hit stops being trimmed", VALIDATOR_PY,
     "def sink_digest(root: Path, *, limit: int = 120, line_chars: int = 150) -> str:",
     "def sink_digest(root: Path, *, limit: int = 120, line_chars: int = 99999) -> str:",
     "D4"),
    ("the digest is truncated without saying so", VALIDATOR_PY,
     '    if truncated:\n        rows.append(f"... (stopped at {limit} hits; read the tree for the rest)")',
     "    if False:\n        pass",
     "D5"),
    ("a request aimed at a service the bundle lacks is accepted", VALIDATOR_PY,
     "        if service not in services:",
     "        if False:",
     "P4"),
    ("a corpus with no readiness request is accepted", VALIDATOR_PY,
     "    if not ready:\n        raise ValidatorError(",
     "    if False:\n        raise ValidatorError(",
     "P6"),
    ("the corpus size ceiling is dropped", VALIDATOR_PY,
     "    if len(items) > MAX_REQUESTS:",
     "    if False:",
     "P8"),
    ("an oversized proposal is refused again instead of trimmed", VALIDATOR_PY,
     "        trimmed = len(items) - MAX_REQUESTS\n        items = items[:MAX_REQUESTS]",
     "        raise ValidatorError('too many')",
     "P8"),
    ("the trim count is swallowed, so a short corpus reads as full", VALIDATOR_PY,
     "        trimmed = len(items) - MAX_REQUESTS",
     "        trimmed = 0",
     "P8"),
    ("a trimmed readiness name fails the run", VALIDATOR_PY,
     "    if unknown and not trimmed:",
     "    if unknown:",
     "P8c"),
    ("the bundle directory is not searched one level down", VALIDATOR_PY,
     "    for child in sorted(p for p in tree_root.iterdir() if p.is_dir()):",
     "    for child in []:",
     None),
    ("the tree listing stops being workspace-relative", VALIDATOR_PY,
     "        rel = path.relative_to(root).as_posix()\n"
     "        if _is_dependency(rel):\n            continue\n        rows.append(rel)",
     "        rel = path.name\n"
     "        if _is_dependency(rel):\n            continue\n        rows.append(rel)",
     "N2"),
    ("serves resolves against the bundle instead of the workspace", VALIDATOR_PY,
     "            target = self.base_root / claim",
     "            target = self.base_root / 'fo_src' / claim",
     "N3"),
    ("a rendered page can claim to be a file", VALIDATOR_PY,
     "            if hashlib.sha256(served).digest() != hashlib.sha256(raw).digest():",
     "            if False:",
     "S2"),
    ("a claim is kept even when the capture errored", VALIDATOR_PY,
     "            if response is None or response.error:",
     "            if False:",
     "S5"),
    ("any changed path explains any finding", VALIDATOR_PY,
     "            if served and served in changed:",
     "            if changed:",
     "E3"),
    ("nothing is ever explained, so client-side fixes all die", VALIDATOR_PY,
     "            if served and served in changed:",
     "            if False:",
     "E1"),
    ("the establish-time coverage floor is removed", VALIDATOR_PY,
     "        if len(kept) < max(MIN_REQUESTS, int(len(requests) * MIN_BASELINE_COVERAGE)):",
     "        if False:",
     "B2"),
    ("a dropped request is forgotten instead of reported", VALIDATOR_PY,
     '                    DroppedRequest(name, "status differed between the two base runs")',
     '                    DroppedRequest("", "")',
     "B3"),
    ("an unconfirmed finding is believed on the first sighting", VALIDATOR_PY,
     "    if len(verdicts) == 1:\n        return verdicts[0]",
     "    if True:\n        return verdicts[0]",
     "C1"),
    ("the confirmation pass is switched off", VALIDATOR_PY,
     "CONFIRM_PASSES = 2",
     "CONFIRM_PASSES = 1",
     "C1"),
    ("confirmation keeps the union instead of the intersection", VALIDATOR_PY,
     "    common = set.intersection(*keys) if keys else set()",
     "    common = set.union(*keys) if keys else set()",
     "C1"),
    ("a reproducing break is discarded along with the noise", VALIDATOR_PY,
     "        f for f in verdicts[0].findings if (f.name, f.kind, f.detail) in common",
     "        f for f in verdicts[0].findings if False",
     "C2"),
    ("the base is calibrated from two captures again", VALIDATOR_PY,
     '            "baseb", self.base_root, requests, ready, passes=2, cross_minute=True',
     '            "baseb", self.base_root, requests, ready, passes=2, cross_minute=False',
     "K2"),
    ("the third base stack is dropped", VALIDATOR_PY,
     '        fourth = self._capture("basec", self.base_root, requests, ready)[0]',
     "        fourth = third",
     "T1"),
    ("calibration ignores the third stack", VALIDATOR_PY,
     "        per_request = calibrate(first, second, third, fourth)",
     "        per_request = calibrate(first, second, third)",
     "T2"),
    ("the stacks are seeded in the same minute again", VALIDATOR_PY,
     "        gap = seconds_to_minute_boundary()",
     "        gap = 0.0  #",
     "K3"),
    ("stack B is captured once, so the clock never turns over", VALIDATOR_PY,
     "        second, third = self._capture(",
     "        second = third = self._capture(",
     None),
    ("compose projects stop carrying the job id", VALIDATOR_PY,
     '        return f"lfv2{suffix}-{self.job_id}".lower()',
     '        return f"lfv2{suffix}".lower()',
     "J1"),
    ("the availability catch swallows our own bugs again", VALIDATOR_PY,
     # Anchored on the line ABOVE too: `_environment_findings` is guarded by
     # the same narrow pair, so the clause alone is no longer unique and a
     # bare-clause anchor would silently mutate whichever came first.
     "            )\n        except (StackError, DockerCommandError) as exc:",
     "            )\n        except Exception as exc:",
     "X1"),
    ("the prompt stops demanding a database-backed readiness request",
     VALIDATOR_PY,
     "  * Include at least one page that READS THE DATABASE",
     "  * Include at least one page that reads something",
     "X3"),
]


def _subprocess() -> tuple[int, list[str]]:
    # `-B` and the purge together: two same-length mutations produce files of
    # identical size, and landing in the same second lets Python reuse the
    # previous .pyc — a harness reporting green for code it never ran.
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

    # EVERY file a mutation touches, derived rather than listed. A
    # hand-kept tuple went stale the moment an entry named another
    # module, and the run died with a KeyError halfway through the
    # mutation loop — after printing enough to look like a result.
    files = tuple(dict.fromkeys(path for _, path, *_ in MUTATIONS))
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
