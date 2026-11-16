#!/usr/bin/env python3
"""The compose-stack runtime live-fire v2 is built on.

WHY THIS FILE EXISTS
The old verifier builds ONE Dockerfile context and runs ONE container. A
live-fire bundle is a MULTI-service compose stack, so the question the whole
v2 design turns on — "does the patched build still answer a normal request the
way the original did" — could not be asked. `modules/live_fire_stack.py` is
that missing capability and this file is what keeps it honest.

THREE PROPERTIES, AND EACH ONE HAS A REAL FAILURE BEHIND IT.

1. THE TRANSFORM MUST STRIP EVERY FIXED NAME.
   What a resolved compose model can carry (names here are
   illustrative): a top-level `name: kweb`, a fixed `container_name` on
   any service, fixed host ports, AND fixed tags like `image: kweb:latest` on
   built services. That last one is the quiet one — two stacks building
   DIFFERENT source both tag `kweb:latest` and the second clobbers the
   first, so a validator would report on an image it did not build.

2. THE CAPS MUST BE IN THE FILE, NOT IN THE SHIM.
   `worker/docker_memguard.sh` is scoped to `run` and `create` on purpose.
   `compose up` talks to the daemon API and walks straight past it: no memory
   cap, no CPU cap, no job label. An uncapped sibling container is what took
   the WSL2 VM out of memory on 2026-08-01 (job 0ddd62708d39), and an
   unlabelled one is invisible to `reap_job_siblings`. So the caps and the
   label are injected declaratively and T6/T7 are why they stay there.

3. THE COMPARATOR MUST CALIBRATE ITSELF.
   "정상 서비스 응답은 원본과 동일하게 유지" cannot be byte equality — Date,
   cookies, CSRF tokens and autoincrement ids differ every run. Hand-picking
   fields to ignore is the other failure: the field quietly excluded is
   eventually the field that mattered. So base is captured TWICE against two
   independently built stacks and whatever differs between them is
   nondeterministic BY CONSTRUCTION. The C family defends that the empirical
   set is actually derived, and the D family that what survives calibration is
   still judged.

No Docker here. Every check drives the module through a recording runner, so
the suite is fast and deterministic; the live stack is exercised separately.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STACK_PY = ROOT / "modules" / "live_fire_stack.py"
DOCKERFILE = ROOT / "worker" / "Dockerfile"

from modules.live_fire_stack import (  # noqa: E402
    CapturedResponse,
    ComposeStack,
    CorpusRequest,
    JOB_LABEL,
    PROBE_OUTPUT_LIMIT,
    StackError,
    StackLimits,
    _PROBE_SCRIPT,
    _TCP_SCRIPT,
    _VOLATILE_HEADER_FLOOR,
    calibrate,
    compare,
    isolate_model,
    resolve_model,
)
from modules.live_fire_verifier import CommandResult  # noqa: E402

_FAILED: list[str] = []


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


# ---------------------------------------------------------------- fixtures

# An invented compose shape, not modelled on any bundle: a built service
# with a fixed image tag and a published port, a service that declares its
# own caps, two named networks and a named volume, and a pull-only service
# which must KEEP its image because nothing else names it. Every service has
# a container_name and joins both networks, so T2c can see an alias missing.
def model() -> dict:
    return {
        "name": "kweb",
        "services": {
            "kweb": {
                "build": {
                    "context": "/b",
                    "dockerfile": "Dockerfile",
                    "additional_contexts": {"xxxx5": "/b/xxxx5"},
                },
                "container_name": "kkkk6",
                "image": "kweb:latest",
                "ports": [{"mode": "ingress", "target": 80, "published": "80",
                           "protocol": "tcp"}],
                "restart": "always",
                "networks": {"uuuu6": None, "uuuu8": None},
                "volumes": [{"type": "volume", "source": "uuuu0",
                             "target": "/uuuu0", "volume": {}}],
            },
            "xxxx9": {
                "build": {"context": "/b/xxxx9"},
                "container_name": "xxxx4",
                "restart": "always",
                # A bundle may declare its own caps, and an operator-supplied
                # one is not a budget this host agreed to -- `mem_limit: 32g`
                # in somebody's ZIP would be honoured verbatim. Ours must win.
                "mem_limit": "32g",
                "cpus": 31.0,
                "networks": {"uuuu6": None, "uuuu8": None},
            },
            "cache": {
                "image": "redis:7",
                "container_name": "kkkk8",
                "restart": "always",
                "networks": {"uuuu6": None, "uuuu8": None},
            },
        },
        "networks": {
            "uuuu6": {"name": "uuuu6", "driver": "bridge"},
            "uuuu8": {"name": "uuuu8", "driver": "bridge"},
        },
        "volumes": {"uuuu0": {"name": "uuuu0"}},
    }


class FakeRunner:
    """Records argv and replays canned results, matched by a predicate."""

    def __init__(self, rules=()):
        self.calls: list[list[str]] = []
        self.rules = list(rules)

    def run(self, argv, timeout_s):  # noqa: D102
        argv = list(argv)
        self.calls.append(argv)
        for match, result in self.rules:
            if match(argv):
                return result(argv) if callable(result) else result
        return CommandResult(0, stdout="")

    def argv_with(self, token: str) -> list[str] | None:
        for call in self.calls:
            if token in call:
                return call
        return None


def payload(obj) -> str:
    """Exactly what the probe container writes: gzipped, base64, marked."""
    raw = json.dumps(obj).encode("utf-8")
    return "LFGZ:" + base64.b64encode(gzip.compress(raw, 6)).decode("ascii")


def resp(name, status=200, headers=None, body="", error=""):
    return CapturedResponse(name=name, status=status,
                            headers=headers or {}, body=body, error=error)


def stack(runner, **kw):
    kw.setdefault("limits", StackLimits(ready_interval_s=0.0, ready_timeout_s=1.0))
    return ComposeStack(
        bundle_dir=Path("/b"), job_id="bf8d00c76ed8", project="lfv2test",
        work_dir=Path(os.environ.get("LF_TMP", "/tmp")) / "lf-stack-test",
        runner=runner, **kw,
    )


# ------------------------------------------------------------------ checks


def t_transform() -> None:
    limits = StackLimits()
    source = model()
    out, eps = isolate_model(source, job_id="bf8d00c76ed8", project="lfv2test",
                             limits=limits)

    check("T1", "name" not in out,
          "the project name the bundle hard-codes is gone")
    check("T2", all("container_name" not in s for s in out["services"].values()),
          "no service keeps a fixed container name")
    # …BUT THE NAME SURVIVES AS DNS. A bundle's own code may call a sibling
    # by its container_name. Deleting the key outright would leave the stack
    # unable to resolve its own services, and because base and patched stacks
    # would fail the same way, the comparison alone could not catch it.
    aliases = out["services"]["xxxx9"]["networks"]["uuuu6"]
    check("T2b", (aliases or {}).get("aliases") == ["xxxx4"],
          "the stripped container name comes back as a NETWORK ALIAS, so "
          "intra-stack DNS still resolves it while the container itself is "
          "named by the project and two stacks never collide")
    check("T2c", all(
        (spec["networks"][net] or {}).get("aliases")
        for spec in out["services"].values()
        if spec.get("networks")
        for net in spec["networks"]),
          "…on EVERY network the service joins, because the caller does not "
          "know which one the name has to resolve on")

    built = out["services"]["kweb"]
    pulled = out["services"]["cache"]
    check("T3", "image" not in built and pulled.get("image") == "redis:7",
          "a built service loses its fixed tag; a pull-only one keeps the "
          "only name it has")

    check("T4",
          all("ports" not in s for s in out["services"].values())
          and [(e.service, e.port) for e in eps] == [("kweb", 80)],
          "the published port is stripped but recorded as the front door")

    check("T5", all(s["restart"] == "no" for s in out["services"].values()),
          "restart: always would resurrect a crashed service forever")

    caps = out["services"]["xxxx9"]
    check("T6",
          caps["mem_limit"] == limits.memory
          and caps["memswap_limit"] == limits.memory
          and caps["cpus"] == limits.cpus
          and caps["pids_limit"] == limits.pids,
          "our caps OVERRIDE the bundle's own — compose up bypasses the "
          "memguard shim, so this file is the only ceiling, and a ZIP that "
          "asks for 32g must not get it")

    check("T7",
          all((s.get("labels") or {}).get(JOB_LABEL) == "bf8d00c76ed8"
              for s in out["services"].values()),
          "every service is reapable by job label")

    check("T8",
          all("name" not in n for n in out["networks"].values())
          and all("name" not in v for v in out["volumes"].values()),
          "fixed network and volume names both go, so compose "
          "auto-names them under the project")

    check("T9",
          (out["networks"]["uuuu8"].get("labels") or {}).get(JOB_LABEL)
          == "bf8d00c76ed8"
          and (out["volumes"]["uuuu0"].get("labels") or {}).get(JOB_LABEL)
          == "bf8d00c76ed8",
          "networks and volumes carry the job label too")

    check("T12", source == model(),
          "the caller's model is not mutated in place")

    survived = out["services"]["kweb"]["build"].get("additional_contexts")
    check("T13", survived == {"xxxx5": "/b/xxxx5"},
          "additional_contexts survives — it is how patched source reaches "
          "the image, and losing it validates the base while reporting on "
          "the patch")

    bind_long = model()
    bind_long["services"]["kweb"]["volumes"] = [
        {"type": "bind", "source": "/data/jobs/x", "target": "/app"}
    ]
    try:
        isolate_model(bind_long, job_id="j", project="p", limits=limits)
        check("T10", False, "a long-form bind mount was accepted")
    except StackError as exc:
        check("T10", "bind" in str(exc), "a long-form bind mount is refused")

    bind_short = model()
    bind_short["services"]["kweb"]["volumes"] = ["./src:/app"]
    try:
        isolate_model(bind_short, job_id="j", project="p", limits=limits)
        check("T11b", False, "a short-form bind mount was accepted")
    except StackError as exc:
        check("T11b", "bind" in str(exc), "a short-form bind mount is refused")

    for bad in ("Has-Upper", "has space", "", "x" * 80):
        try:
            isolate_model(model(), job_id="j", project=bad, limits=limits)
            check("T11", False, f"project name {bad!r} was accepted")
            return
        except StackError:
            pass
    check("T11", True, "an unsafe compose project name is refused")


def t_resolve() -> None:
    bundle = ROOT / "scripts" / "_lf_stack_fixture"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "docker-compose.yml").write_text("services: {}\n")
    try:
        good = FakeRunner([(lambda a: "config" in a,
                            CommandResult(0, stdout=json.dumps(model())))])
        out = resolve_model(bundle, runner=good)
        argv = good.calls[0]
        check("R1",
              "config" in argv and "--format" in argv and "json" in argv
              and "--project-directory" in argv,
              "compose is used as its own parser, so the worker needs no PyYAML")
        check("R1b", out["name"] == "kweb", "the resolved model comes back")

        bad = FakeRunner([(lambda a: "config" in a, CommandResult(0, stdout="not json"))])
        try:
            resolve_model(bundle, runner=bad)
            check("R2", False, "non-JSON output was accepted")
        except StackError:
            check("R2", True, "non-JSON from compose config is refused")

        empty = FakeRunner([(lambda a: "config" in a,
                             CommandResult(0, stdout=json.dumps({"name": "x"})))])
        try:
            resolve_model(bundle, runner=empty)
            check("R3", False, "a model with no services was accepted")
        except StackError:
            check("R3", True, "a model with no services is refused")
    finally:
        (bundle / "docker-compose.yml").unlink(missing_ok=True)
        bundle.rmdir()


def t_probe() -> None:
    canned = payload([{"name": "root", "status": 200,
                       "headers": {"server": "nginx"}, "body": "hi", "error": ""}])
    runner = FakeRunner([(lambda a: "run" in a, CommandResult(0, stdout=canned))])
    s = stack(runner)
    reqs = [CorpusRequest(name="root", service="kweb", port=80, path="/")]
    got = s.probe(reqs, network="uuuu6")

    argv = runner.argv_with("run") or []
    check("P1", "--network" in argv
          and argv[argv.index("--network") + 1] == "uuuu6",
          "the probe joins the stack's own network instead of a published port")
    check("P2", f"{JOB_LABEL}=bf8d00c76ed8" in argv,
          "the probe container is reapable by job label")
    check("P4", len(got) == 1 and got[0].status == 200 and got[0].body == "hi",
          "responses come back parsed")

    big = [CorpusRequest(name=f"r{i}", service="s", port=80, path="/" + "a" * 900)
           for i in range(200)]
    try:
        s.probe(big, network="n")
        check("P3", False, "an oversized corpus spec was passed to execve")
    except StackError as exc:
        check("P3", "argv" in str(exc) or "budget" in str(exc),
              "an oversized spec is refused rather than truncated by execve")

    cut = FakeRunner([(lambda a: "run" in a,
                       CommandResult(0, stdout="LFGZ:abc\n[output truncated]"))])
    try:
        stack(cut).probe(reqs, network="n")
        check("P8", False, "a truncated capture was parsed as if complete")
    except StackError as exc:
        check("P8", "truncated" in str(exc),
              "a capture cut off by the output budget is REFUSED by name — it "
              "arrived as a bare JSONDecodeError on the first real run, with "
              "nothing pointing at the 256KiB cap that caused it")

    check("P9", PROBE_OUTPUT_LIMIT > 256 * 1024
          and 'gzip.compress(raw, 6)' in _PROBE_SCRIPT,
          "the budget is sized for a corpus and the bodies are gzipped in the "
          "container, so wire cost stops scaling with how chatty the pages are")

    check("P5", "redirect_request" in _PROBE_SCRIPT and "_NoRedirect" in _PROBE_SCRIPT,
          "redirects are not followed — following one hides a 302->200 change")
    check("P6", 'decode("latin-1")' in _PROBE_SCRIPT,
          "bodies round-trip as latin-1, so non-UTF-8 responses survive JSON")
    check("P7", "%s:%d" in _PROBE_SCRIPT and "http://" in _PROBE_SCRIPT,
          "the probe dials the service name, which is the DNS alias left once "
          "container_name is stripped")


def t_ready() -> None:
    def page(status=200, body=""):
        return payload([{"name": "root", "status": status, "headers": {},
                         "body": body, "error": ""}])
    bad_payload = page(502)
    err_payload = payload([{"name": "root", "status": -1, "headers": {},
                            "body": "", "error": "ConnectionRefused"}])
    reqs = [CorpusRequest(name="root", service="n", port=80, path="/")]

    # The middle two model the seeding hazard: 200 both times, but the body
    # grows because the database finished seeding between them.
    seq = [bad_payload, page(200, "a" * 300), page(200, "b" * 800),
           page(200, "c" * 800), page(200, "d" * 800), page(200, "e" * 800)]
    box = {"i": 0}

    def feed(_argv):
        out = seq[min(box["i"], len(seq) - 1)]
        box["i"] += 1
        return CommandResult(0, stdout=out)

    runner = FakeRunner([(lambda a: "run" in a, feed)])
    s = stack(runner, limits=StackLimits(ready_interval_s=0.0, ready_timeout_s=5.0,
                                         ready_streak=3))
    s.wait_ready(reqs, network="n")
    check("W1", box["i"] == 6,
          "a 200 whose body length is still moving is NOT ready: a DB-backed "
          "list page can answer 200 before seeding and 200 with a longer body "
          "after it, and two base captures taken inside the seeding window "
          "agree with each other")

    box2 = {"i": 0}

    def feed2(_argv):
        # Unbounded on purpose: a list that runs out would go STABLE at its
        # last element and the stack would be called ready after all.
        box2["i"] += 1
        return CommandResult(0, stdout=page(200, "x" * (100 + box2["i"] * 10)))

    s5 = stack(FakeRunner([(lambda a: "run" in a, feed2)]),
               limits=StackLimits(ready_interval_s=0.0, ready_timeout_s=0.4,
                                  ready_streak=3))
    try:
        s5.wait_ready(reqs, network="n")
        check("W5", False, "a front door that never stops changing was called ready")
    except StackError as exc:
        check("W5", "settled" in str(exc) or "still changing" in str(exc),
              "a stack that never settles is refused with WHICH request is "
              "still moving, not with a bare timeout")

    runner2 = FakeRunner([(lambda a: "run" in a, CommandResult(0, stdout=bad_payload))])
    s2 = stack(runner2, limits=StackLimits(ready_interval_s=0.0, ready_timeout_s=0.3))
    try:
        s2.wait_ready(reqs, network="n")
        check("W3", False, "a permanently 502 stack was called ready")
    except StackError as exc:
        check("W3", "502" in str(exc) and "never settled" in str(exc),
              "a stack that never warms up raises, naming the status it kept "
              "returning")

    runner3 = FakeRunner([(lambda a: "run" in a, CommandResult(0, stdout=err_payload))])
    s3 = stack(runner3, limits=StackLimits(ready_interval_s=0.0, ready_timeout_s=0.3))
    try:
        s3.wait_ready(reqs, network="n")
        check("W4", False, "a connection-refused capture was called ready")
    except StackError:
        check("W4", True, "a transport error never counts toward the streak")


def t_teardown() -> None:
    runner = FakeRunner()
    s = stack(runner)
    s.down()
    argv = runner.argv_with("down") or []
    check("L1", "-v" in argv and "--rmi" in argv and "local" in argv
          and "--remove-orphans" in argv,
          "teardown removes volumes and locally built images — "
          "reap_job_siblings sweeps neither")

    for bad in ("2G ", "big", "0g", ""):
        try:
            StackLimits(memory=bad)
            check("L2", False, f"memory {bad!r} was accepted")
            break
        except StackError:
            pass
    else:
        check("L2", True, "a malformed memory cap is refused up front")

    inspect = CommandResult(0, stdout="/lfv2test-kweb-1|1073741824|2000000000|512")
    runner2 = FakeRunner([
        (lambda a: "ps" in a, CommandResult(0, stdout="abc123\n")),
        (lambda a: "inspect" in a, inspect),
    ])
    caps = stack(runner2).inspect_caps()
    check("L3",
          caps.get("lfv2test-kweb-1", {}).get("memory") == 1073741824
          and caps["lfv2test-kweb-1"]["nano_cpus"] == 2000000000
          and caps["lfv2test-kweb-1"]["pids_limit"] == 512,
          "the cgroup Docker actually applied is readable, because a YAML key "
          "one believes compose honours is not evidence")


def t_calibrate() -> None:
    a = [resp("root", 200,
              {"server": "nginx", "date": "Thu, 11 Sep 2026 10:00:00 GMT",
               "x-session": "aaa"},
              "<html>\n<h1>KWEB</h1>\n<p>id 41</p>\n</html>")]
    b = [resp("root", 200,
              {"server": "nginx", "date": "Thu, 11 Sep 2026 10:00:00 GMT",
               "x-session": "bbb"},
              "<html>\n<h1>KWEB</h1>\n<p>id 42</p>\n</html>")]
    base = calibrate(a, b)
    one = base["root"]

    check("C1", "x-session" in one.volatile_headers,
          "a header that differs between two base runs is learned as volatile")
    check("C2", "date" in one.volatile_headers,
          "a floor header stays volatile even when two captures land in the "
          "same second and it happens to match")
    check("C3", "content-length" in one.volatile_headers,
          "content-length is derived from the body, so the body check owns it")
    check("C4", one.stable_status and one.status == 200,
          "a status that agrees across base runs is the reference")
    check("C5", "server" not in one.volatile_headers,
          "a header that agrees and is not on the floor stays checkable")
    check("C6",
          list(one.spine) == ["<html>", "<h1>KWEB</h1>", "</html>"],
          "the spine is what both base runs produced: the autoincrement line "
          "drops out on its own, with nobody naming it")

    wobble = calibrate(a, [resp("root", 500, {}, "")])
    check("C7", not wobble["root"].stable_status,
          "a base whose own status wobbles is marked unstable rather than "
          "becoming a reference")

    try:
        calibrate(a, [])
        check("C8", False, "a mismatched pair of base captures was accepted")
    except StackError:
        check("C8", True, "the two base captures must cover the same corpus")

    # THREE captures, and the third is the one that matters. Measured, not
    # supposed: a clock-derived field coarser than the gap between two base
    # captures reads the same in both, so calibration learns it as fixed and
    # a later patched capture is blamed for the clock.
    clock_a = [resp("page", 200, {"server": "n"}, "<h1>X</h1>\n<p>12:00</p>\n")]
    clock_b = [resp("page", 200, {"server": "n"}, "<h1>X</h1>\n<p>12:00</p>\n")]
    clock_c = [resp("page", 200, {"server": "n"}, "<h1>X</h1>\n<p>12:01</p>\n")]
    two_only = calibrate(clock_a, clock_b)
    later = compare(two_only, clock_c)
    check("C9", not later.ok,
          "TWO captures inside one minute teach the calibrator that a "
          "minute-granularity timestamp is fixed, and the next capture is "
          "blamed for the clock — this is the failure, reproduced")
    three = calibrate(clock_a, clock_b, clock_c)
    check("C10", compare(three, clock_c).ok
          and compare(three, [resp("page", 200, {"server": "n"},
                                   "<h1>X</h1>\n<p>12:02</p>\n")]).ok,
          "…and a third capture ACROSS the boundary excludes it: a field only "
          "has to vary once, in any pair, to be excluded forever")
    check("C11", compare(three, [resp("page", 200, {"server": "n"},
                                      "<h1>GONE</h1>\n<p>12:02</p>\n")]).ok
          is False,
          "…without making the rest of the page unjudgeable")

    try:
        calibrate(clock_a)
        check("C12", False, "a single capture was accepted as a baseline")
    except StackError as exc:
        check("C12", "at least two" in str(exc),
              "one capture teaches nothing about what varies")


def t_compare() -> None:
    a = [resp("root", 200, {"server": "nginx", "x-session": "aaa"},
              "<html>\n<h1>KWEB</h1>\n<p>id 41</p>\n</html>")]
    b = [resp("root", 200, {"server": "nginx", "x-session": "bbb"},
              "<html>\n<h1>KWEB</h1>\n<p>id 42</p>\n</html>")]
    base = calibrate(a, b)

    same = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "ccc"},
                               "<html>\n<h1>KWEB</h1>\n<p>id 99</p>\n</html>")])
    check("D1", same.ok and same.checked == 1,
          "a patch that changes only calibrated-volatile values passes — the "
          "autoincrement takes a THIRD value here, which a line-set check "
          "would have called an addition")

    hdr = compare(base, [resp("root", 200, {"server": "apache", "x-session": "c"},
                              "<html>\n<h1>KWEB</h1>\n<p>id 99</p>\n</html>")])
    check("D2", not hdr.ok and hdr.findings[0].kind == "header-changed",
          "a header that survived calibration is still judged")

    st = compare(base, [resp("root", 403, {"server": "nginx", "x-session": "c"},
                             "<html>\n<h1>KWEB</h1>\n<p>id 99</p>\n</html>")])
    check("D3", not st.ok and any(f.kind == "status" for f in st.findings),
          "an over-eager filter that starts rejecting a benign request is "
          "caught by the status alone")

    escaped = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                                  "<html>\n&lt;h1&gt;KWEB&lt;/h1&gt;\n<p>id 9</p>\n</html>")])
    check("D4", not escaped.ok
          and any(f.kind == "body-missing-line" and "KWEB" in f.detail
                  for f in escaped.findings),
          "escaping output that the original did not escape loses a stable "
          "line — the exact SLA break the attack server's benign payload sees")

    # Inserted where the base put NOTHING in either run, so the content
    # oracle owns it. D10 covers the harder case: inserted into a slot the
    # base itself varies in.
    banner_body = "<html>\n<!--waf-->\n<h1>KWEB</h1>\n<p>id 9</p>\n</html>"
    extra = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                                banner_body)])
    check("D5", not extra.ok
          and any(f.kind == "body-extra-line" for f in extra.findings),
          "a line added where both base runs had none is a change by default")
    loose = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                                banner_body)], strict_extras=False)
    check("D6", loose.ok, "…and is the one deviation a reviewer can opt out of")

    banner = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                                 "<html>\n<h1>KWEB</h1>\n<p>id 9</p>\n<!--waf-->\n</html>")])
    check("D10",
          any("nondeterministic slot" in f.detail for f in banner.findings),
          "a banner inserted into the slot where the autoincrement lives is "
          "still caught: the two base runs disagreed on that slot's CONTENT "
          "but agreed it held one line, and the count survives as an oracle")

    dropped = compare(base, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                                  "<html>\n<h1>KWEB</h1>\n</html>")])
    check("D11",
          any(f.kind == "body-missing-line" and "slot" in f.detail
              for f in dropped.findings),
          "a patch that stops rendering the row entirely is caught by the "
          "same width oracle, in the other direction")

    gone = compare(base, [])
    check("D7", not gone.ok and gone.findings[0].kind == "request-missing",
          "a request the patched capture never answered is a finding, not a pass")

    boom = compare(base, [resp("root", -1, {}, "", error="ConnectionRefused")])
    check("D8", not boom.ok and boom.findings[0].kind == "transport-error",
          "a patch that takes the service down fails before any diff runs")

    wobbly = calibrate(a, [resp("root", 500, {}, "")])
    skipped = compare(wobbly, [resp("root", 200, {"server": "nginx"}, "x")])
    check("D9", skipped.checked == 0 and skipped.unstable
          and not any(f.kind in ("status", "body-missing-line")
                      for f in skipped.findings),
          "an endpoint whose own base wobbles is reported as unstable and "
          "excluded, not blamed on the patch")
    check("D12", not skipped.ok
          and any(f.kind == "coverage" for f in skipped.findings),
          "…but a verdict with nothing left to compare is REFUSED, not passed: "
          "'everything wobbled, therefore the SLA held' is a green light for "
          "no evidence")

    two = calibrate(
        a + [resp("second", 200, {"server": "nginx"}, "<p>ok</p>")],
        b + [resp("second", 200, {"server": "nginx"}, "<p>ok</p>")])
    thin = compare(two, [resp("root", 200, {"server": "nginx", "x-session": "c"},
                              "<html>\n<h1>KWEB</h1>\n<p>id 9</p>\n</html>"),
                         resp("second", 200, {"server": "nginx"}, "<p>ok</p>")],
                   min_checked=5)
    check("D13", not thin.ok and any(f.kind == "coverage" for f in thin.findings),
          "a caller can demand more coverage than one request, and the floor "
          "is enforced in compare() rather than left to whoever forgets")

    dead = calibrate([resp("root", -1, {}, "", error="ConnectionRefused")],
                     [resp("root", -1, {}, "", error="ConnectionRefused")])
    setup = compare(dead, [resp("root", 200, {}, "ok")])
    check("D14",
          not setup.ok and setup.broken == ("root",)
          and any(f.kind == "corpus-broken" for f in setup.findings),
          "a base capture that never reached the service is a BROKEN corpus "
          "entry, not a nondeterministic one — tolerating it would let a "
          "corpus rot away request by request with every verdict still green")


def t_tcp_gate() -> None:
    """The gate that sees a seeding database.

    mysql:3306 and :33060 stay CLOSED for as long as the database seeds,
    because the official mysql image runs docker-entrypoint-initdb.d against
    a TEMPORARY server started with --skip-networking and only execs the
    real, listening mysqld afterwards. Over the same window a DB-backed list
    page can answer a steady 200 — an empty list renders consistently — so
    HTML stability can pass INSIDE the window, and the baseline is built
    against an empty database. Two base captures taken in there agree with
    each other, so nothing downstream ever notices.
    """

    inspect_rows = {
        "c1": "mysql|3306/tcp 33060/tcp 5000/udp ",
        "c2": "kweb|80/tcp ",
        "c3": "|443/tcp ",          # no compose service label: not ours
    }

    def inspect(argv):
        return CommandResult(0, stdout=inspect_rows[argv[-1]])

    runner = FakeRunner([
        (lambda a: "ps" in a, CommandResult(0, stdout="c1\nc2\nc3\n")),
        (lambda a: "inspect" in a, inspect),
    ])
    ports = stack(runner).exposed_ports()
    check("G1", ports == {"mysql": [3306, 33060], "kweb": [80]},
          "ports come from the image's own EXPOSE, udp is dropped, and a "
          "container with no compose service label is not ours to wait on")
    check("G1b", "mysql" in ports,
          "mysql's ports come from its image alone: a database service often "
          "publishes nothing and names no port in the compose file, which is "
          "exactly why an HTTP-only gate cannot see it")

    rounds = [
        [{"host": "mysql", "port": 3306, "ok": False, "error": "refused"}],
        [{"host": "mysql", "port": 3306, "ok": False, "error": "refused"}],
        [{"host": "mysql", "port": 3306, "ok": True, "error": ""}],
    ]
    box = {"i": 0}

    def feed(_argv):
        out = rounds[min(box["i"], len(rounds) - 1)]
        box["i"] += 1
        return CommandResult(0, stdout=payload(out))

    runner2 = FakeRunner([
        (lambda a: "ps" in a, CommandResult(0, stdout="c1\n")),
        (lambda a: "inspect" in a, CommandResult(0, stdout="mysql|3306/tcp ")),
        (lambda a: "run" in a, feed),
    ])
    s2 = stack(runner2, limits=StackLimits(ready_interval_s=0.0,
                                           ready_timeout_s=5.0))
    s2.wait_tcp(network="n")
    check("G2", box["i"] == 3,
          "the gate keeps polling while the port is refused and returns the "
          "moment it opens")

    runner3 = FakeRunner([
        (lambda a: "ps" in a, CommandResult(0, stdout="c1\n")),
        (lambda a: "inspect" in a, CommandResult(0, stdout="mysql|3306/tcp ")),
        (lambda a: "run" in a, CommandResult(0, stdout=payload(
            [{"host": "mysql", "port": 3306, "ok": False, "error": "refused"}]))),
    ])
    s3 = stack(runner3, limits=StackLimits(ready_interval_s=0.0,
                                           ready_timeout_s=0.3))
    try:
        s3.wait_tcp(network="n")
        check("G3", False, "a permanently closed port was called ready")
    except StackError as exc:
        check("G3", "mysql:3306" in str(exc),
              "a port that never opens is refused, naming which one")

    # Ordering: the TCP gate must run BEFORE any HTTP stability polling,
    # or the HTTP gate settles on the pre-seed state first and returns.
    order: list[str] = []

    def note(argv):
        order.append("tcp" if "socket" in " ".join(argv) else "http")
        if order[-1] == "tcp":
            return CommandResult(0, stdout=payload(
                [{"host": "mysql", "port": 3306, "ok": True, "error": ""}]))
        return CommandResult(0, stdout=payload(
            [{"name": "root", "status": 200, "headers": {}, "body": "x",
              "error": ""}]))

    runner4 = FakeRunner([
        (lambda a: "ps" in a, CommandResult(0, stdout="c1\n")),
        (lambda a: "inspect" in a, CommandResult(0, stdout="mysql|3306/tcp ")),
        (lambda a: "run" in a, note),
    ])
    s4 = stack(runner4, limits=StackLimits(ready_interval_s=0.0,
                                           ready_timeout_s=5.0, ready_streak=2))
    s4.wait_ready([CorpusRequest("root", "n", 80, "/")], network="n")
    check("G4", order and order[0] == "tcp",
          "wait_ready runs the TCP gate FIRST; an HTTP gate that goes first "
          "settles on the pre-seed state and returns before the DB is up")

    check("G5", "socket.create_connection" in _TCP_SCRIPT,
          "the TCP probe actually opens a connection rather than inferring "
          "liveness from something else")


def t_session() -> None:
    canned = payload([
        {"name": "login", "status": 302, "headers": {}, "body": "", "error": ""},
        {"name": "admin", "status": 200, "headers": {}, "body": "ok", "error": ""},
    ])
    runner = FakeRunner([(lambda a: "run" in a, CommandResult(0, stdout=canned))])
    s = stack(runner)
    got = s.probe([
        CorpusRequest("login", "n", 80, "/login.php", method="POST",
                      body="username=a&password=b", session="admin"),
        CorpusRequest("admin", "n", 80, "/admin/", session="admin"),
    ], network="net")
    argv = runner.argv_with("run") or []
    spec = json.loads(base64.b64decode(argv[-2]).decode())
    check("N1", [r["session"] for r in spec] == ["admin", "admin"],
          "the session name reaches the probe, so a login and the pages it "
          "unlocks share one jar")
    check("N2", len(got) == 2 and got[0].status == 302,
          "a login that answers 302 is captured rather than followed")
    check("N3", "http.cookiejar" in _PROBE_SCRIPT
          and "HTTPCookieProcessor" in _PROBE_SCRIPT,
          "the probe carries a real cookie jar, so pages behind a login "
          "can be checked too — the pages a patch touches often sit behind "
          "one")
    check("N4", "jar.extract_cookies(e, req)" in _PROBE_SCRIPT,
          "a 302 is raised by the no-redirect handler, so its Set-Cookie is "
          "extracted explicitly instead of trusting processor ordering")
    check("N5", 'if session and session in _jars:' in _PROBE_SCRIPT,
          "an unnamed request gets a fresh jar, so an anonymous page cannot "
          "inherit a login from earlier in the corpus")


def t_source() -> None:
    src = STACK_PY.read_text()
    check("S1", src.count("autojunk=False") == 2,
          "SequenceMatcher's junk heuristic would discard repeated structural "
          "lines like `</div>` — the very lines whose loss means the page broke")
    dockerfile = DOCKERFILE.read_text()
    check("S2",
          "docker-ce-cli docker-compose-plugin" in dockerfile,
          "the worker image installs the compose plugin; docker-ce-cli alone "
          "does not include it")
    # Matched on the apt INSTALL line, not anywhere in the file: the comment
    # explaining why buildx is needed contains the package name too, and a
    # bare containment check passes while the install loses it. S2 was caught
    # by exactly this once already.
    # Pinned to the INSTALL LINE, for the same reason S5 is: the comment
    # above it explains the reason and names every package, so a bare
    # containment check would pass on prose while the install lost them.
    check("S6", "\n    php-cli php-mbstring php-xml \\\n" in dockerfile,
          "the worker can lint PHP, so a blueteam does not spend turns "
          "falling back to the bundle's own image for `php -l`. mbstring and "
          "xml ride along because a great deal of PHP code assumes both")
    check("S7", "\n    patch \\\n" in dockerfile,
          "…and it can apply a diff it just wrote")
    check("S8", "\n    default-jdk-headless \\\n" in dockerfile
          and "\n    golang-go \\\n" in dockerfile,
          "a web backend that is not php can be syntax-checked too: the "
          "image had a JRE, which runs a class and cannot check one, and no "
          "Go at all. The cost is paid once at build rather than mid-job "
          "against a bundle nobody can read")
    check("S9", "npm install -g --no-fund --no-audit typescript@" in dockerfile,
          "…and TypeScript, PINNED. `node --check` parses JS, not TS, so a "
          "TypeScript service needs its own checker")
    check("S5",
          "docker-ce-cli docker-compose-plugin docker-buildx-plugin" in dockerfile,
          "…and buildx alongside it. `additional_contexts` is BuildKit-only, "
          "and without buildx compose falls back to the classic builder and "
          "fails outright")
    check("S3", "--no-build" in src,
          "up does not rebuild after an explicit build step, so a build "
          "failure is attributable to the build")
    check("S4", "date" in _VOLATILE_HEADER_FLOOR,
          "the floor covers the same-second Date flake that empirical "
          "calibration alone cannot see")


def run_checks() -> bool:
    _FAILED.clear()
    for fn in (t_transform, t_resolve, t_probe, t_ready, t_teardown,
               t_calibrate, t_compare, t_tcp_gate, t_session, t_source):
        fn()
    return not _FAILED


# ------------------------------------------------------------- mutations

MUTATIONS = [
    ("the worker keeps a JRE that cannot check a class", DOCKERFILE,
     "    default-jdk-headless \\\n",
     "",
     "S8"),
    ("typescript floats to whatever npm serves that day", DOCKERFILE,
     "typescript@5.9.3",
     "typescript",
     "S9"),
    ("the worker loses php, so no blueteam can lint its own patch", DOCKERFILE,
     "    php-cli php-mbstring php-xml \\\n",
     "",
     "S6"),
    ("php arrives without mbstring or xml, which a great deal of PHP code assumes", DOCKERFILE,
     "    php-cli php-mbstring php-xml \\\n",
     "    php-cli \\\n",
     "S6"),
    ("the agent writes a diff and cannot apply it", DOCKERFILE,
     "    patch \\\n",
     "",
     "S7"),
    ("the project name is left in the stack file", STACK_PY,
     '    out.pop("name", None)\n\n    labels',
     '    pass\n\n    labels',
     "T1"),
    ("container_name survives, so two stacks collide", STACK_PY,
     '        original_name = str(spec.pop("container_name", "") or "").strip()',
     '        original_name = str(spec.get("container_name", "") or "").strip()',
     "T2"),
    ("the stripped name is not given back as DNS", STACK_PY,
     "        if original_name:",
     "        if False:",
     "T2b"),
    ("the alias lands on only one of the service's networks", STACK_PY,
     "                for net_name, net_spec in list(nets.items()):",
     "                for net_name, net_spec in list(nets.items())[:1]:",
     "T2c"),
    ("a built service keeps its fixed image tag", STACK_PY,
     '        if spec.get("build"):\n            # Only safe',
     '        if False:\n            # Only safe',
     "T3"),
    ("the front door is stripped without being recorded", STACK_PY,
     "            entrypoints.append(\n                Entrypoint(service=name,",
     "            _ignored = (\n                Entrypoint(service=name,",
     "T4"),
    ("restart: always is left alone", STACK_PY,
     '        spec["restart"] = "no"',
     '        spec.setdefault("restart", "no")',
     "T5"),
    ("the bundle's own memory cap is left to win", STACK_PY,
     '        spec["mem_limit"] = limits.memory',
     '        spec.setdefault("mem_limit", limits.memory)',
     "T6"),
    ("services stop carrying the job label", STACK_PY,
     '        merged = dict(spec.get("labels") or {})\n        merged.update(labels)\n'
     '        spec["labels"] = merged\n\n    for section',
     '        merged = dict(spec.get("labels") or {})\n        spec["labels"] = merged\n'
     '\n    for section',
     "T7"),
    ("networks keep the eagerly resolved name", STACK_PY,
     '            spec.pop("name", None)\n            merged',
     '            spec.get("name", None)\n            merged',
     "T8"),
    ("a bind mount is passed through to the host daemon", STACK_PY,
     "            if str(mount.get(\"type\", \"volume\")).lower() == \"bind\":",
     "            if False:",
     "T10"),
    ("an unsafe compose project name is accepted", STACK_PY,
     "    if not _SAFE_PROJECT.match(project):",
     "    if False:",
     "T11"),
    ("the transform mutates the caller's model", STACK_PY,
     "    out = json.loads(json.dumps(model))  # deep copy through plain JSON types",
     "    out = model  # deep copy through plain JSON types",
     "T12"),
    ("compose config is asked for something other than json", STACK_PY,
     '        "config",\n        "--format",\n        "json",',
     '        "config",',
     "R1"),
    ("compose config output is trusted without parsing", STACK_PY,
     "    if not isinstance(model, dict) or not isinstance(model.get(\"services\"), dict):",
     "    if False:",
     "R3"),
    ("the probe stops joining the stack network", STACK_PY,
     '            "--network",\n            network,',
     '            "--label",\n            "probe=1",',
     "P1"),
    ("the probe container becomes unreapable", STACK_PY,
     '            "--label",\n            f"{JOB_LABEL}={self.job_id}",',
     '            "--label",\n            "lf=probe",',
     "P2"),
    ("a truncated capture is parsed as if complete", STACK_PY,
     "    if _TRUNCATION_MARK in text:",
     "    if False:",
     "P8"),
    ("the probe output budget drops back to the verifier's", STACK_PY,
     "PROBE_OUTPUT_LIMIT = 64 * 1024 * 1024",
     "PROBE_OUTPUT_LIMIT = 64 * 1024",
     "P9"),
    ("an oversized spec is handed to execve", STACK_PY,
     "        if len(blob) > _MAX_SPEC_BYTES:",
     "        if False:",
     "P3"),
    ("one good capture is enough to call the stack ready", STACK_PY,
     "                if streak >= self.limits.ready_streak:",
     "                if streak >= 1:",
     "W1"),
    ("a 5xx no longer resets the readiness streak", STACK_PY,
     "            bad = [r for r in seen if r.error or r.status < 200 or r.status >= 500]",
     "            bad = []",
     "W3"),
    ("a 200 is treated as ready even while the body is still growing", STACK_PY,
     "                if previous is not None and shape == previous:",
     "                if True:",
     "W1"),
    ("readiness stops looking at the body at all", STACK_PY,
     '                shape = {r.name: (r.status, len(r.body)) for r in seen}',
     '                shape = {r.name: (r.status,) for r in seen}',
     "W1"),
    ("the TCP gate stops running before HTTP readiness", STACK_PY,
     "        self.wait_tcp(network=network)\n        if not requests:",
     "        if not requests:",
     "G4"),
    ("a closed port no longer holds the gate", STACK_PY,
     "            if not closed:\n                return",
     "            if True:\n                return",
     "G2"),
    ("udp ports are waited on as if they were tcp", STACK_PY,
     '                if proto and proto != "tcp":',
     "                if False:",
     "G1"),
    ("a container with no compose service is waited on anyway", STACK_PY,
     "            if not service:\n                continue",
     "            if False:\n                continue",
     "G1"),
    ("teardown leaves volumes and images behind", STACK_PY,
     '            ("down", "-v", "--rmi", "local", "--remove-orphans", "-t", "10"),',
     '            ("down", "--remove-orphans", "-t", "10"),',
     "L1"),
    ("a malformed memory cap is accepted", STACK_PY,
     "        if not _SAFE_MEMORY.match(self.memory):",
     "        if False:",
     "L2"),
    ("calibration stops learning volatile headers at all", STACK_PY,
     "            if len(values) > 1:\n                volatile.add(key)",
     "            if False:\n                volatile.add(key)",
     "C1"),
    ("calibration stops folding the third capture in", STACK_PY,
     "        for key in keys:\n            values = {response.headers.get(key) for response in seen}",
     "        for key in keys:\n            values = {seen[0].headers.get(key)}",
     "C1"),
    ("only the first two captures decide a gap is volatile", STACK_PY,
     "            if len({gaps[i] for gaps in aligned}) > 1",
     "            if len({gaps[i] for gaps in aligned[:2]}) > 1",
     "C10"),
    ("a single capture is accepted as a baseline", STACK_PY,
     "    if len(captures) < 2:",
     "    if False:",
     "C12"),
    ("the spine is taken from the first capture alone", STACK_PY,
     "        for lines in line_sets[1:]:\n            spine = _spine(spine, lines)",
     "        for lines in []:\n            spine = _spine(spine, lines)",
     "C10"),
    ("the floor is dropped, so a same-second Date looks stable", STACK_PY,
     "        volatile = set(_VOLATILE_HEADER_FLOOR) | set(_DERIVED_HEADERS)",
     "        volatile = set()",
     "C2"),
    ("a wobbling base status becomes the reference anyway", STACK_PY,
     "            stable_status=len({r.status for r in seen}) == 1,",
     "            stable_status=True,",
     "C7"),
    ("the spine becomes the whole first capture", STACK_PY,
     "    matcher = difflib.SequenceMatcher(None, list(a), list(b), autojunk=False)\n"
     "    out: list[str] = []",
     "    matcher = difflib.SequenceMatcher(None, list(a), list(a), autojunk=False)\n"
     "    out: list[str] = []",
     "C6"),
    ("a surviving header change stops being judged", STACK_PY,
     "            if before == after:\n                continue",
     "            if True:\n                continue",
     "D2"),
    ("a status change is no longer a finding", STACK_PY,
     "        if observed.status != base.status:",
     "        if False:",
     "D3"),
    ("losing a stable body line stops failing", STACK_PY,
     "            if not present:",
     "            if False:",
     "D4"),
    ("an added body line is silently accepted", STACK_PY,
     "                    if gaps[index] != base.stable_gaps[index]:",
     "                    if False:",
     "D5"),
    ("a banner hides inside a nondeterministic slot", STACK_PY,
     "                if width >= 0 and len(gaps[index]) != width:",
     "                if False:",
     "D10"),
    ("the width oracle only looks for additions", STACK_PY,
     "                if width >= 0 and len(gaps[index]) != width:",
     "                if width >= 0 and len(gaps[index]) > width:",
     "D11"),
    ("a request the patch never answered passes", STACK_PY,
     "        if observed is None:",
     "        if False and observed is None:",
     None),
    ("a downed service is not reported", STACK_PY,
     "        if observed.error:",
     "        if False:",
     "D8"),
    ("an unstable endpoint is blamed on the patch", STACK_PY,
     "        if not base.stable_status:",
     "        if False:",
     "D9"),
    ("the junk heuristic comes back and eats structural lines", STACK_PY,
     "    matcher = difflib.SequenceMatcher(None, list(spine), list(observed), autojunk=False)\n"
     "    gaps: list[list[str]]",
     "    matcher = difflib.SequenceMatcher(None, list(spine), list(observed))\n"
     "    gaps: list[list[str]]",
     "S1"),
    ("a verdict with nothing comparable is called a pass", STACK_PY,
     "    if checked < min_checked:",
     "    if False:",
     "D12"),
    ("a broken corpus entry is filed as mere nondeterminism", STACK_PY,
     "            broken.append(name)",
     "            unstable.append(name)",
     "D14"),
    ("the session name is dropped on the way to the probe", STACK_PY,
     '            "session": self.session,',
     '            "session": "",',
     "N1"),
    ("every request gets its own jar, so a login never carries", STACK_PY,
     "    if session and session in _jars:",
     "    if False:",
     "N5"),
    ("a 302's Set-Cookie is left to processor ordering", STACK_PY,
     "                jar.extract_cookies(e, req)",
     "                pass",
     "N4"),
    ("the worker image loses the compose plugin", DOCKERFILE,
     "docker-ce-cli docker-compose-plugin docker-buildx-plugin",
     "docker-ce-cli docker-buildx-plugin",
     "S2"),
    ("the worker image loses buildx, so additional_contexts cannot build",
     DOCKERFILE,
     "docker-ce-cli docker-compose-plugin docker-buildx-plugin",
     "docker-ce-cli docker-compose-plugin",
     "S5"),
]


def _subprocess() -> tuple[int, list[str]]:
    # `-B` and the purge together, not either alone. Two mutations that replace
    # different lines of the SAME length produce files of identical size, and if
    # they land in the same second Python's mtime+size check reuses the stale
    # .pyc from the previous one — the mutation appears "caught" by the previous
    # mutation's check. That is a harness reporting green for code it never ran.
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

    files = (STACK_PY, DOCKERFILE)
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
                # "any detection": the mutation makes the module unusable
                # rather than wrong, so no named check can report it — the
                # suite dies before one could.
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
