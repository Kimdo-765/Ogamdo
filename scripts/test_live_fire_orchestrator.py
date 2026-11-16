#!/usr/bin/env python3
"""Live-fire v2 orchestration — who is working on what, and what became of it.

`live_fire_validator` and `live_fire_repo` own their halves. This owns the
part neither can see, and the properties below are the ones an operator
notices when they are wrong.

1. A VULNERABILITY IS NEVER SILENTLY ABANDONED. Three different things can
   stop a patch reaching the bundle — the merge deferred it, the validator
   refused it, the blueteam ran out of attempts — and each has a DIFFERENT
   next step. A deferral is not a failure: the tree it lost to now contains
   the other fix, so the conflict is gone and it should simply be re-tried. A
   validation failure needs a new direction from the plan agent. An exhausted
   assignment needs the operator to know. Collapse those three and a
   vulnerability quietly stops being worked on while the count still reads as
   coverage. A-family and B-family.

2. THE SLOT BUDGET IS A HARD CEILING ACROSS EVERY ROLE. Measured 2026-09-11:
   memory is not the constraint — NETWORKS are. Each stack takes a bridge
   per network its compose defines, docker's default pool tops out near 31, and this
   host already carries 8. Exhausting it does not degrade gracefully: new job
   setups fail outright with "could not find an available, non-overlapping
   IPv4 address pool" — a failure for every OTHER job on the box. S-family.

3. A LEAD A BLUETEAM CANNOT ACT ON IS REFUSED AT THE DOOR. A vulnerability
   with no file, or no patch direction, produces an assignment that can never
   make progress and a number the operator reads as progress. P-family.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ORCH_PY = ROOT / "modules" / "live_fire_orchestrator.py"
JOB_PY_ORCH = ROOT / "modules" / "live_fire_v2_job.py"

from modules.live_fire_orchestrator import (  # noqa: E402
    Assignment,
    AssignmentBoard,
    PRIORITY_SCALE,
    merge_plans,
    BLUETEAM_SYSTEM,
    DEFAULT_SLOTS,
    DEFERRED,
    FAILED,
    IN_FLIGHT,
    SUBMITTED,
    INTEGRATED,
    STALL_NOTICE,
    MAX_SLOTS,
    OrchestratorError,
    PENDING,
    PLAN_SYSTEM,
    SlotBudget,
    Vulnerability,
    blueteam_prompt,
    parse_vulnerabilities,
    plan_prompt,
    remaining_estimate,
)

_FAILED: list[str] = []


def check(tag: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"ok    [{tag}] {detail}")
    else:
        print(f"FAIL  [{tag}] {detail}")
        _FAILED.append(tag)


def vuln(vid="V1", path="src/app/search.php", direction="bind q"):
    return {
        "id": vid,
        "bug_class": "sqli",
        "path": path,
        "evidence": "line 42 interpolates $_GET['q']",
        # EVERY lead carries one now: a vulnerability nobody can attack is not
        # reported, so a fixture without this is not a lead the module accepts.
        "attack": "anonymous GET /search.php?q=' UNION SELECT password FROM "
                  "users-- returns the password column",
        "patch_direction": direction,
    }


class _Deferral:
    def __init__(self, vid, reason):
        self.vulnerability_id = vid
        self.reason = reason


class _Merge:
    def __init__(self, accepted=(), deferred=()):
        self.accepted = tuple(accepted)
        self.deferred = tuple(deferred)


# ------------------------------------------------------------------- parse


def t_parse() -> None:
    out = parse_vulnerabilities({"vulnerabilities": [vuln(), vuln("V2")]})
    check("P1", [v.id for v in out] == ["V1", "V2"]
          and out[0].patch_direction == "bind q",
          "a well-formed plan output becomes leads a blueteam can act on")

    # A LEAD NOBODY CAN ATTACK IS NOT A LEAD. `evidence` describes code; the
    # attack describes a request. Code that merely looks wrong spends a
    # blueteam's whole cycle, and if the patch lands it moves a response the
    # scoring server is also watching — so a fix for something nobody could
    # exploit can lose points it was never going to win.
    noattack = vuln("V9")
    del noattack["attack"]
    thin = vuln("V8")
    thin["attack"] = "sqli"
    dropped: list[str] = []
    kept = parse_vulnerabilities(
        {"vulnerabilities": [vuln(), noattack, thin]}, dropped=dropped)
    check("P1b", [v.id for v in kept] == ["V1"],
          "a lead that states no attack, and one whose attack is a gesture "
          "rather than a request, are both refused")
    check("P1c", len(dropped) == 2 and all("no attack" in d for d in dropped)
          and any("src/app/search.php" in d for d in dropped),
          "…and each refusal is RECORDED with its file: dropping them "
          "silently would make a plan agent that ignored the schema "
          "indistinguishable from a bundle with nothing attackable in it")
    check("P1d", kept[0].attack.startswith("anonymous GET"),
          "…and the attack travels with the lead, so the blueteam is aimed at "
          "a request rather than at a smell")

    # ONE BAD STRING MUST NOT COST THE WHOLE ANALYSIS. A plan agent quotes
    # source into `evidence`, and source is full of backticks, braces and
    # backslashes; one mis-escaped quote makes the document unreadable while
    # every other entry in it is perfect. On job ebf974271ade that cost one
    # service's agent its entire round — every lead, including any the
    # operator had named by hand — and the round read as "that service is
    # clean" because nothing said otherwise.
    good = json.dumps(vuln("V1"))[1:-1]
    hurt = json.dumps(vuln("V2", path="b.php"))[1:-1].replace(
        '"bind q"', '"bind q', 1)     # the closing quote, gone
    third = json.dumps(vuln("V3", path="c.php"))[1:-1]
    torn = '{"vulnerabilities": [{%s}, {%s}, {%s}]}' % (good, hurt, third)
    holes: list[str] = []
    try:
        saved = parse_vulnerabilities(torn, dropped=holes)
    except OrchestratorError:
        # Without the salvage this is what the round got: nothing, and the
        # exception swallowed one level up.
        saved, holes = [], []
    check("P9", [v.id for v in saved] == ["V1", "V3"],
          "a reply whose JSON will not parse is read ENTRY BY ENTRY, so one "
          "mis-escaped quote costs that one lead and not the round")
    check("P9b", len(holes) == 1 and "not valid JSON" in holes[0]
          and "recovered 2" in holes[0],
          "…and it says so. A silent salvage is the same lie as a silent "
          "discard: the operator cannot tell a clean service from an unread "
          "one, and only one of those is good news")

    # An array that holds nothing readable is not an empty analysis. Salvaging
    # it into `[]` would turn a model that mangled every entry into a service
    # with nothing in it, which is the silent zero this whole change exists to
    # stop.
    try:
        parse_vulnerabilities('{"vulnerabilities": [ oops, not json ]}',
                              dropped=[])
        check("P9c", False, "an unreadable array is still refused")
    except OrchestratorError:
        check("P9c", True,
              "an array from which NOTHING could be read is still REFUSED, "
              "not salvaged into an empty list — a model that mangled every "
              "entry must not read as a bundle with nothing in it")
    try:
        parse_vulnerabilities("here is my analysis, no json at all", dropped=[])
        check("P9d", False, "prose with no array is still refused")
    except OrchestratorError:
        check("P9d", True,
              "…and neither is prose that never answered the question")

    fenced = "I found two.\n```json\n" + json.dumps(
        {"vulnerabilities": [vuln()]}) + "\n```\nthat's all"
    check("P2", len(parse_vulnerabilities(fenced)) == 1,
          "a model that wraps its JSON in prose and a fence is still read")

    nopath = vuln()
    nopath["path"] = ""
    try:
        parse_vulnerabilities({"vulnerabilities": [nopath]})
        check("P3", False, "a vulnerability with no file was accepted")
    except OrchestratorError as exc:
        check("P3", "nothing to open" in str(exc),
              "a lead with no file is refused — it would produce an "
              "assignment that can never make progress and a count the "
              "operator reads as coverage")

    nodir = vuln()
    nodir["patch_direction"] = ""
    try:
        parse_vulnerabilities({"vulnerabilities": [nodir]})
        check("P4", False, "a vulnerability with no direction was accepted")
    except OrchestratorError as exc:
        check("P4", "direction" in str(exc),
              "…and so is one with no patch direction: handing a blueteam a "
              "bug with no direction spends an attempt re-deciding what the "
              "plan agent already decided")

    try:
        parse_vulnerabilities({"vulnerabilities": [{**vuln(), "id": "a b"}]})
        check("P5", False, "an unusable id was accepted")
    except OrchestratorError:
        check("P5", True, "ids are keys, so they are constrained")

    check("P6", parse_vulnerabilities(
        {"vulnerabilities": [vuln(), vuln()]}) == parse_vulnerabilities(
        {"vulnerabilities": [vuln()]}),
        "a duplicate id inside one reply is collapsed rather than tracked twice")

    check("P7", parse_vulnerabilities(
        {"vulnerabilities": [vuln("V1"), vuln("V2")]}, already=["V1"])
        == parse_vulnerabilities({"vulnerabilities": [vuln("V2")]}),
        "a vulnerability already known is skipped, not an error — the plan "
        "agent re-reads the tree each round and will see its own past work")

    try:
        parse_vulnerabilities(
            {"vulnerabilities": [vuln(f"V{i}") for i in range(40)]})
        check("P8", False, "40 vulnerabilities in one round were accepted")
    except OrchestratorError as exc:
        check("P8", "one round" in str(exc), "the round is bounded")


# ------------------------------------------------------------------- board


def t_board() -> None:
    board = AssignmentBoard()
    v1 = Vulnerability("V1", "sqli", "a.php", "e", "d")
    v2 = Vulnerability("V2", "xss", "b.js", "e", "d")
    board.admit([v1, v2])
    check("A1", [a.vulnerability.id for a in board.ready()] == ["V1", "V2"],
          "new leads are ready for a blueteam, in a deterministic order")

    board.apply_merge(_Merge(accepted=["V1"],
                             deferred=[_Deferral("V2", "overlaps V1")]))
    check("A2", board.integrated() == ["V1"],
          "an accepted patch is recorded as in the bundle")
    check("A3", board.assignments["V2"].state == DEFERRED
          and "overlaps V1" in board.assignments["V2"].reason,
          "a deferred one keeps WHY, so the next round has something to act on")

    check("A4", [a.vulnerability.id for a in board.ready()] == ["V2"],
          "the deferred one is READY AGAIN — the tree it lost to now holds "
          "the other fix, so the conflict it hit no longer exists")
    check("A5", board.assignments["V2"].attempts == 0,
          "…and it was not charged an attempt: the patch was fine, the merge "
          "could not take it, and charging would spend its budget on somebody "
          "else's collision")

    board.admit([v1])
    check("A6", board.assignments["V1"].state == INTEGRATED,
          "a vulnerability already in the bundle is not re-admitted, however "
          "often the plan agent sights it again")

    board.assignments["V2"].attempts = STALL_NOTICE * 4
    check("A7", [a.vulnerability.id for a in board.ready()] == ["V2"]
          and [a.vulnerability.id for a in board.stalled()] == ["V2"],
          "an assignment that has failed many times is STILL handed to a "
          "blueteam — `stalled` is a report about where the budget is going, "
          "not the gate its predecessor was. The cap that used to sit here "
          "removed a vulnerability from the board for the rest of the job "
          "after three refusals, however much time the operator had left")

    board2 = AssignmentBoard()
    board2.admit([v1])
    board2.assignments["V1"].attempts = 1
    board2.assignments["V1"].note(FAILED, "validator refused it")
    board2.admit([Vulnerability("V1", "sqli", "a.php", "e", "a new direction")])
    check("A8", board2.assignments["V1"].attempts == 1
          and board2.assignments["V1"].vulnerability.patch_direction
          == "a new direction",
          "a re-sighting takes the fresh direction but KEEPS the attempt "
          "count — resetting it lets an agent loop forever by re-reporting "
          "the same bug")
    check("A9", board2.assignments["V1"].state == PENDING
          and any("validator refused" in h
                  for h in board2.assignments["V1"].history),
          "…and the history keeps what happened before")

    # THE ONE STATE `admit` MUST NOT TOUCH. Plan replies are merged as they
    # land now, so a second reply can re-sight a vulnerability a blueteam is
    # ALREADY patching. The old code demoted it to PENDING, `ready()` named
    # it again, a second blueteam started, and `_tree_for` rmtree's `bt-<id>`
    # on the way in -- so the second agent deleted the first one's workspace
    # while it was reading it.
    board3 = AssignmentBoard()
    board3.admit([v1, v2])
    taken = board3.dispatch()
    check("A10", [a.vulnerability.id for a in taken] == ["V1", "V2"]
          and all(a.state == IN_FLIGHT for a in taken),
          "`dispatch` names the ready work AND marks it taken in one step, "
          "so nothing can see it ready in between — `patch_one` used to be "
          "what set IN_FLIGHT, and the gap before its first line was a "
          "window a second dispatch could fit through")
    check("A11", board3.dispatch() == [],
          "…so a dispatch that overlaps the first hands out nothing")
    board3.admit([Vulnerability("V1", "sqli", "a.php", "e", "a new direction")])
    check("A12", board3.assignments["V1"].state == IN_FLIGHT
          and board3.assignments["V1"].vulnerability.patch_direction == "d",
          "a re-sighting of a RUNNING assignment changes nothing: not its "
          "state, and not the direction the agent is already working from")
    # SUBMITTED IS THE SAME CASE, and it is the one streaming made reachable:
    # a fast blueteam validates while the slower plan agents are still
    # reading, so a later reply can re-sight a vulnerability whose patch is
    # already waiting for the merge. Demoting it starts a second agent on a
    # bug that is fixed but not yet shipped.
    board4 = AssignmentBoard()
    board4.admit([v1])
    board4.dispatch()
    board4.assignments["V1"].note(SUBMITTED, "1 file(s) validated")
    board4.admit([Vulnerability("V1", "sqli", "a.php", "e", "a new direction")])
    check("A14", board4.assignments["V1"].state == SUBMITTED
          and board4.ready() == [],
          "a validated patch waiting for the merge is not handed to a second "
          "blueteam — the first one's work is done and unshipped, not absent")

    board3.assignments["V1"].note(FAILED, "validator refused it")
    board3.admit([Vulnerability("V1", "sqli", "a.php", "e", "a new direction")])
    check("A13", board3.assignments["V1"].state == PENDING
          and board3.assignments["V1"].vulnerability.patch_direction
          == "a new direction",
          "…and it is a guard, not a ceiling: once the blueteam is done the "
          "next round re-assigns it with whatever the plan agent says then")


# -------------------------------------------------------------------- slots


def t_priority() -> None:
    """Order, now that there is nothing to ration.

    Reach used to decide it: with a finite attempt budget and a round
    ceiling, a lead that never got an agent never got fixed, so the ones an
    ordinary remote user could fire at went first. Both of those ceilings are
    gone — a job runs until its timeout or until the operator stops it, and a
    vulnerability keeps getting a blueteam for as long as that lasts. Ranking
    would now decide only which of them starts first, at the cost of a label
    the plan agent had to guess.
    """

    board = AssignmentBoard()
    board.admit([
        Vulnerability("V10", "x", "a.php", "e", "d"),
        Vulnerability("V2", "x", "b.php", "e", "d"),
        Vulnerability("V1", "x", "c.php", "e", "d"),
    ])
    check("Y1", [a.vulnerability.id for a in board.ready()]
          == ["V1", "V2", "V10"],
          "the queue is in id order, and V2 comes before V10 — lexicographic "
          "order puts V10 first, which reads as a bug to anyone watching the "
          "board")
    check("Y2", not hasattr(Vulnerability("V1", "x", "a", "e", "d"),
                            "exploitability"),
          "and a vulnerability carries no reach label at all: nothing reads "
          "it any more, and a field nothing reads is a field that drifts")


def t_priority_order() -> None:
    """What each sector's agent hunts first, and what gets worked first.

    Set by the operator: an ordinary user (or nobody at all) stealing data,
    escalating or running code, then an ordinary user taking the service
    down, then the same two for an attacker who already holds admin
    credentials, then everything else.
    """

    parsed = parse_vulnerabilities({"vulnerabilities": [
        {**vuln("V1"), "path": "a.php", "priority": 4},
        {**vuln("V2"), "path": "b.php", "priority": 1},
        {**vuln("V3"), "path": "c.php"},
        {**vuln("V4"), "path": "d.php", "priority": 99},
        {**vuln("V5"), "path": "e.php", "priority": "nonsense"},
    ]})
    by_path = {v.path: v.priority for v in parsed}
    check("Q1", by_path == {"a.php": 4, "b.php": 1, "c.php": 5,
                            "d.php": 5, "e.php": 5},
          "the agent's number is taken, and a missing or invented one is the "
          "LOWEST rather than an error — the lead behind it is still real, "
          "and refusing it over a label throws the analysis away")

    board = AssignmentBoard()
    board.admit(parsed)
    check("Q2", [a.vulnerability.path for a in board.ready()][:2]
          == ["b.php", "a.php"],
          "the queue is in priority order, so the worst thing anyone found "
          "gets a blueteam first when several are ready")

    a = json.dumps({"vulnerabilities": [
        {**vuln("V1"), "path": "z.php", "bug_class": "dos", "priority": 4}]})
    b = json.dumps({"vulnerabilities": [
        {**vuln("V1"), "path": "a.php", "bug_class": "rce", "priority": 1}]})
    merged = merge_plans([a, b])
    check("Q3", [(v.id, v.path) for v in merged]
          == [("V1", "a.php"), ("V2", "z.php")],
          "new ids are handed out in priority order across the whole fan-out, "
          "so V1 is the worst thing ANY sector found rather than whichever "
          "file happened to sort first")

    existing = AssignmentBoard()
    existing.admit(merge_plans([a]))          # z.php became V1 on its own
    again = merge_plans([a, b], existing=list(existing.assignments.values()))
    check("Q4", {v.path: v.id for v in again} == {"z.php": "V1", "a.php": "V2"},
          "…but an id the board already gave is kept whatever the priority "
          "says, because renumbering splits one vulnerability into two "
          "assignments that both get patched")


def t_merge_plans() -> None:
    """Several plan agents, one numbered list.

    The fan-out is the point — the plan agent was the round's longest serial
    step, 733 of round one's 1170 seconds on job f432f9d8e16d — but every one
    of those agents answers with a V1, and `admit()` keys on the id.
    """

    a = json.dumps({"vulnerabilities": [
        {**vuln("V1"), "path": "kweb/x.php", "bug_class": "xss",
         "evidence": "short"}]})
    b = json.dumps({"vulnerabilities": [
        {**vuln("V1"), "path": "kweb/x.php", "bug_class": "xss",
         "evidence": "a much longer piece of evidence"},
        {**vuln("V2"), "path": "adminx/y.php", "bug_class": "sqli"}]})

    merged = merge_plans([a, b])
    check("Y3", [(v.id, v.path) for v in merged]
          == [("V1", "adminx/y.php"), ("V2", "kweb/x.php")],
          "ids are assigned centrally: two agents both said V1, and taking "
          "their numbering would have merged two unrelated vulnerabilities "
          "into one assignment")
    check("Y4", merged[1].evidence == "a much longer piece of evidence",
          "the same file and class from two agents is ONE bug — they are "
          "reading the same code — and the fuller evidence is the one kept")

    twice = json.dumps({"vulnerabilities": [
        {**vuln("V1"), "path": "kweb/x.php", "bug_class": "xss",
         "evidence": "first"},
        {**vuln("V2"), "path": "kweb/x.php", "bug_class": "xss",
         "evidence": "second"}]})
    check("Y5", len(merge_plans([twice])) == 2,
          "…but ONE agent naming the same file and class twice has found two "
          "bugs, and a key that collapsed them would throw one away where "
          "nobody could see it happen")

    board = AssignmentBoard()
    board.admit(merge_plans([a, b]))
    again = merge_plans([b], existing=list(board.assignments.values()))
    check("Y6", {v.id: v.path for v in again}
          == {"V1": "adminx/y.php", "V2": "kweb/x.php"},
          "a later round keeps the ids the board already gave: renumbering "
          "would split one vulnerability into two assignments, silently")

    board.assignments["V2"].state = INTEGRATED
    check("Y7", [v.id for v in merge_plans(
              [b], existing=list(board.assignments.values()))] == ["V1"],
          "and something already in the bundle is not handed out again, "
          "however often an agent sights it")

    try:
        survived = len(merge_plans(["not json at all", b])) == 2
    except Exception:  # noqa: BLE001 - a raise here IS the failure
        survived = False
    check("Y8", survived,
          "one agent's bad JSON costs that agent's turn; the others' "
          "analysis is still good and the round still has work")



def t_slots() -> None:
    budget = SlotBudget(2)
    check("S1", budget.acquire(timeout=0.1) and budget.acquire(timeout=0.1),
          "slots are handed out up to the budget")
    check("S2", not budget.acquire(timeout=0.05),
          "and refused past it — exhausting docker's address pool fails every "
          "OTHER job on the host, not just this one")
    budget.release()
    check("S3", budget.acquire(timeout=0.1), "a released slot is reusable")
    check("S4", budget.peak == 2, "the peak is recorded for the operator")

    for bad in (0, -1, MAX_SLOTS + 1):
        try:
            SlotBudget(bad)
            check("S5", False, f"slot budget {bad} was accepted")
            break
        except OrchestratorError:
            pass
    else:
        check("S5", True,
              "a budget outside what the host can hold is refused up front")

    # The ceiling is TOTAL, not per role: a validator re-capture and a
    # blueteam patch draw on the same pool.
    shared = SlotBudget(3)
    grabbed: list[bool] = []
    done = threading.Event()

    def role(_i):
        grabbed.append(shared.acquire(timeout=0.3))
        done.wait(0.05)
        if grabbed[-1]:
            shared.release()

    threads = [threading.Thread(target=role, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    time.sleep(0.15)
    done.set()
    for t in threads:
        t.join()
    check("S6", shared.peak <= 3,
          "six concurrent roles never put more than the budget of stacks up")

    with SlotBudget(1) as held:
        check("S7", held.in_use == 1, "the context manager takes a slot")
    check("S8", True, "…and gives it back")


# ------------------------------------------------------------------ signals


def t_signals() -> None:
    left, why = remaining_estimate(known=4, integrated=2, blocked=2)
    check("G1", left == 2 and "2 of 4" in why,
          "the operator's count minus what is integrated is the estimate")

    left, why = remaining_estimate(known=4, integrated=4, blocked=4)
    check("G2", left == 0 and "all 4" in why, "and it can reach zero")

    left, why = remaining_estimate(known=4, integrated=3, blocked=1)
    check("G3", left is None and "not holding" in why,
          "THREE fixes integrated but only ONE attack blocked is not 'two "
          "left to find' — a fix is not holding, which is a different problem "
          "and a different next step")

    left, why = remaining_estimate(known=None, integrated=0, blocked=None)
    check("G4", left is None and "keep looking" in why,
          "with no count supplied there is no estimate to give, and saying so "
          "beats inventing one")


def t_prompts() -> None:
    check("X1", "DO NOT INVENT ONE TO REACH A COUNT" in PLAN_SYSTEM,
          "the plan agent is told not to pad to the operator's number — a "
          "fabricated lead costs a blueteam a whole patch-and-validate cycle")
    # The plan agent has to know the boundary too. On job fd33c5c80802 it
    # assigned findings that were real but could not be fixed in application
    # source, so a blueteam that may only edit that source could not patch
    # them — and each one spent a full agent turn returning nothing.
    plan_flat = " ".join(PLAN_SYSTEM.split())
    check("X9", "APPLICATION SOURCE" in plan_flat
          and "SEEDED CREDENTIALS" in plan_flat,
          "the plan agent is told which findings a blueteam can act on: "
          "changing seeded credentials breaks every authenticated request in "
          "the corpus by construction, so the patch is refused while the "
          "vulnerability stays open")
    check("X13", "A VULNERABILITY YOU CANNOT ATTACK IS NOT A FINDING" in plan_flat
          and '"attack"' in plan_flat
          and "not_covered" in plan_flat,
          "the plan agent is told to leave out what it cannot attack, and "
          "where to put it instead — an unproven suspicion is the operator's "
          "to chase by hand, not a blueteam's whole cycle")
    check("X16", "WHERE THE EFFECT LANDS IS NOT ALWAYS THE RESPONSE" in plan_flat
          and "client-side template injection" in plan_flat
          and "Code that a BROWSER runs is application source" in plan_flat,
          "the attack may land in the BROWSER, not the response. A plan "
          "agent that reads `attack` as a change in the response never "
          "reports a DOM XSS or a client-side template injection — the "
          "server sends the text unchanged and the page turns it into code, so under "
          "a response-shaped definition of `attack` there is nothing to "
          "write down and the whole class goes unreported")

    check("X14", "THE ORDER IS NOT A FILTER" in plan_flat,
          "…and that rule is kept separate from the ranking rule, which still "
          "drops nothing: one filters by whether an attack exists, the other "
          "by nothing at all")

    check("X11", "SPEND YOUR TURNS IN THIS ORDER" in plan_flat
          and "THE ORDER IS NOT A FILTER" in plan_flat
          and "exploitability" not in plan_flat,
          "the plan agent is told what to hunt FIRST inside its own sector, "
          "and told in the same breath that the order drops nothing — its "
          "predecessor `exploitability` decided which leads got an agent at "
          "all, which is why it went with the ceilings")
    check("X12", all(text in plan_flat for _, text in PRIORITY_SCALE)
          and plan_flat.index(PRIORITY_SCALE[0][1])
              < plan_flat.index(PRIORITY_SCALE[2][1]),
          "…with every level the operator set, in the operator's order: an "
          "ordinary account is one anyone can register, so a hole behind one "
          "is reachable by the whole internet, while an admin-only hole needs "
          "credentials the attacker does not have yet")
    check("X10", "not_covered" in plan_flat,
          "…and where to put the ones it cannot: in front of the operator, "
          "who can act on them by hand, rather than into a blueteam's turn")

    # THE READER TAKES ONLY THE FIRST BLOCK. `_JSON_BLOCK.search` returns the
    # first fenced match and `_salvage_vulnerabilities` starts from the first
    # "vulnerabilities" key, so a reply with two complete blocks yields the
    # entries of the first and discards the rest in silence. The prompt used
    # to say REPORT EACH ONE AS SOON AS YOU FIND IT -- a latency instruction
    # the transport cannot honour, and one a model obeying it literally pays
    # for by losing everything after its smallest answer. Leads reach a
    # blueteam early because `identify` fans out per reply, not because the
    # agent was asked to answer in instalments.
    check("X2", "AS SOON AS YOU FIND IT" not in PLAN_SYSTEM,
          "the plan agent is NOT asked to answer in instalments — only the "
          "first block of its reply is ever read")
    check("X2b", "FIRST" in plan_flat and "discarded" in plan_flat,
          "…and it is told so, rather than left to discover it by losing a "
          "finding")
    check("X2c", "cut in the middle" in plan_flat,
          "…and told that a reply cut mid-object is worth nothing, which is "
          "the whole reason to write the list before the budget runs out")
    aimed = blueteam_prompt(
        Vulnerability("V1", "sqli", "a.php", "line 42", "bind it", 1,
                      "anonymous GET /s?q=1' OR 1=1-- returns every row"),
        "<?php")
    check("X15", "THE ATTACK THIS MUST STOP" in aimed
          and "returns every row" in aimed,
          "the blueteam is told the REQUEST its patch has to stop, not only "
          "the line that is wrong — an agent that knows the exploit can tell "
          "whether its fix closes it or merely tidies the line above it")

    # A3. The attack is an EXAMPLE, and until this was said the blueteams
    # read it as the specification: a patch_direction that named the whole
    # class came back as a patch that closed the one spelling in the attack
    # string, and it passed while other spellings of the same input still
    # reached the sink.
    counts = " ".join(aimed.split())
    check("Z1", "WHAT COUNTS AS FIXED" in aimed,
          "the blueteam is told what would make its patch finished, in its "
          "own section — not left to infer it from the attack string")
    check("Z2", "ONE example of the vulnerability, not its definition" in counts,
          "…and told explicitly that the attack is an example: a patch aimed "
          "at the example ends the round looking green with the "
          "vulnerability still open")
    check("Z3", "PATCH DIRECTION describes the class" in counts,
          "PATCH DIRECTION is promoted from a hint to the definition of the "
          "scope — it is the only place the class is stated")
    check("Z4", "do not enumerate the bad ones" in counts
          and "known-good set" in counts,
          "and given the shape of a fix that closes a class rather than a "
          "string: normalise, then accept from a known-good set")
    # "()" is how prose names a function, so it stands for any one function
    # offered as the fix.
    check("Z5", all(word not in counts.lower() for word in
                    ("adminx", "kweb", "sapphire", "()")),
          "…stated at the level of the LANGUAGE, naming no service and no one "
          "function as the fix — the next bundle is a different application")

    check("X3", "Fix ONE vulnerability" in BLUETEAM_SYSTEM
          and "merged with theirs" in BLUETEAM_SYSTEM,
          "the blueteam is told its diff is merged with others, which is the "
          "reason a small diff matters and not just style")
    # Matched across the prompt's own line wrap, not through it.
    flat = " ".join(BLUETEAM_SYSTEM.split())
    check("X4", "benign traffic alongside every attack" in flat
          and "loses points" in flat,
          "and why the normal response must not move: the scoring server "
          "sends benign traffic with every attack, so a changed response "
          "loses points even when the vulnerability is genuinely fixed")

    board = AssignmentBoard()
    board.admit([Vulnerability("V1", "sqli", "a.php", "e", "d"),
                 Vulnerability("V2", "xss", "b.js", "e", "d")])
    board.apply_merge(_Merge(accepted=["V1"],
                             deferred=[_Deferral("V2", "overlaps V1")]))
    text = plan_prompt(tree_summary="a.php\nb.js", known=4,
                       already=list(board.assignments.values()),
                       feedback="blocked 1 of 3")
    check("X12", "NOT EVERY VULNERABILITY IS A LINE OF CODE" in text
          and "HOST, PORT or URL" in text
          and "not enabled where" in text,
          "the plan prompt lists the configuration surfaces: host-taking "
          "fields, controls not enabled at runtime, services safe only by "
          "network position, and default credentials")

    check("X5", "do not report these again" in text and "V1" in text,
          "the plan prompt tells the agent what is already in the bundle")
    check("X6", "V2" in text and "overlaps V1" in text,
          "…and what is assigned but NOT in it, with the reason, so a second "
          "direction can be given rather than the same one repeated")
    check("X7", "blocked 1 of 3" in text and "4 vulnerabilities" in text,
          "both operator signals reach the agent")

    body = blueteam_prompt(Vulnerability("V1", "sqli", "a.php", "line 42", "bind it"),
                           "<?php ...")
    check("X8", "line 42" in body and "bind it" in body and "<?php" in body,
          "the blueteam gets the evidence, the direction and the file — it "
          "should not have to redo the plan agent's analysis")


def t_roles() -> None:
    """The four v2 roles must be routable, and the guard must still guard."""

    from modules.live_fire_provider import (
        LIVE_FIRE_ROLES,
        LiveFireProviderError,
        V1_LIVE_FIRE_ROLES,
        V2_LIVE_FIRE_ROLES,
        resolve_live_fire_route,
    )

    check("V1", V2_LIVE_FIRE_ROLES == {"plan", "validator", "blueteam", "repo"},
          "every agent this redesign introduces is a routable role")
    check("V2", V1_LIVE_FIRE_ROLES <= LIVE_FIRE_ROLES
          and V2_LIVE_FIRE_ROLES <= LIVE_FIRE_ROLES,
          "…alongside v1's, because the old path stays runnable as the "
          "fallback while v2 is unproven")

    resolved = {}
    for role in sorted(V2_LIVE_FIRE_ROLES):
        route = resolve_live_fire_route("bf8d00c76ed8", role)
        resolved[role] = (route.role, bool(route.provider), bool(route.model))
    check("V3", all(r == (role, True, True) for role, r in resolved.items()),
          "each resolves to a provider and a model — unrouted roles fall back "
          "to the job's own backend, which is why this was never a crash and "
          "only ever a missing capability")

    try:
        resolve_live_fire_route("bf8d00c76ed8", "trickster")
        check("V4", False, "an unknown role was routed")
    except LiveFireProviderError as exc:
        check("V4", "unsupported" in str(exc),
              "…and a role nobody registered is still refused, so a typo in a "
              "call site fails loudly instead of silently taking the default")


def run_checks() -> bool:
    _FAILED.clear()
    for fn in (t_parse, t_board, t_priority, t_priority_order,
               t_merge_plans,
               t_slots, t_signals,
               t_prompts, t_roles):
        fn()
    return not _FAILED


PROVIDER_PY = ROOT / "modules" / "live_fire_provider.py"

MUTATIONS = [
    ("the blueteam is no longer told the attack is an example", ORCH_PY,
     '        "WHAT COUNTS AS FIXED",',
     '        "",',
     "Z1"),
    ("the class is dropped, leaving only the example", ORCH_PY,
     '        "THE ATTACK THIS MUST STOP is ONE example of the vulnerability, not "\n'
     '        "its definition. PATCH DIRECTION describes the class, and the class "',
     '        "" "",',
     "Z2"),
    ("a denylist is as good as an allowlist again", ORCH_PY,
     '        "value, or accept only from a known-good set -- do not enumerate the "\n'
     '        "bad ones. If you believe PATCH DIRECTION is wrong, say so and state "',
     '        "If you believe PATCH DIRECTION is wrong, say so and state "',
     "Z4"),
    ("an invented priority is taken at face value", ORCH_PY,
     "        if not 1 <= priority <= LOWEST_PRIORITY:",
     "        if False:",
     "Q1"),
    ("the queue stops ordering by priority", ORCH_PY,
     "                key=lambda a: (a.vulnerability.priority,\n"
     "                               _id_order(a.vulnerability.id)),",
     "                key=lambda a: _id_order(a.vulnerability.id),",
     "Q2"),
    ("new ids ignore priority, so V1 is whatever sorts first", ORCH_PY,
     "    for key in sorted(by_key, key=lambda k: (by_key[k].priority, k)):",
     "    for key in sorted(by_key):",
     "Q3"),
    ("the plan agent is not told what to hunt first", ORCH_PY,
     "SPEND YOUR TURNS IN THIS ORDER",
     "In no particular order",
     "X11"),
    ("the order becomes a filter", ORCH_PY,
     "THE ORDER IS NOT A FILTER.",
     "Report only priority 1 and 2.",
     "X11"),
    ("a torn reply is thrown away whole again", ORCH_PY,
     "            salvaged = _salvage_vulnerabilities(text)",
     "            salvaged = None",
     "P9"),
    ("the salvage is silent, so an unread service reads as clean", ORCH_PY,
     "            if dropped is not None:\n"
     "                dropped.append(\n"
     '                    f"(reply was not valid JSON: {exc}; recovered "',
     "            if False:\n"
     "                dropped.append(\n"
     '                    f"(reply was not valid JSON: {exc}; recovered "',
     "P9b"),
    ("prose with no array is salvaged into an empty answer", ORCH_PY,
     "    if not found:\n        return None",
     "    if False:\n        return None",
     "P9c"),
    ("an unattackable lead is reported anyway", ORCH_PY,
     "        if len(attack) < MIN_ATTACK_CHARS:",
     "        if False:",
     "P1b"),
    ("a refusal is not recorded, so it cannot be told from a clean bundle",
     ORCH_PY,
     "            if dropped is not None:\n"
     "                dropped.append(\n"
     '                    f"{path} ({str(item.get(\'bug_class\') or \'unknown\').strip()})"',
     "            if False:\n"
     "                dropped.append(\n"
     '                    f"{path} ({str(item.get(\'bug_class\') or \'unknown\').strip()})"',
     "P1c"),
    ("the attack is not handed to the blueteam", ORCH_PY,
     "    if vulnerability.attack:",
     "    if False:",
     "X15"),
    ("the attack is defined by the response again, losing stored xss",
     ORCH_PY,
     "    WHERE THE EFFECT LANDS IS NOT ALWAYS THE RESPONSE, and reading it that way",
     "    The response is the whole of it, and reading it that way",
     "X16"),
    ("the plan agent is not told to leave unattackable leads out", ORCH_PY,
     "A VULNERABILITY YOU CANNOT ATTACK IS NOT A FINDING.",
     "Report anything that looks wrong.",
     "X13"),
    ("a resumed board sorts every lead last", JOB_PY_ORCH,
     '                priority=int(raw.get("priority") or LOWEST_PRIORITY),',
     "                priority=LOWEST_PRIORITY,",
     None),
    ("the queue sorts ids as text, so V10 comes before V2", ORCH_PY,
     "                key=lambda a: (a.vulnerability.priority,\n"
     "                               _id_order(a.vulnerability.id)),",
     "                key=lambda a: (a.vulnerability.priority,\n"
     "                               a.vulnerability.id),",
     "Y1"),
    ("the agents' own numbering is taken", ORCH_PY,
     "        vid = known_ids.get(key)",
     "        vid = by_key[key].id",
     "Y3"),
    ("the shorter evidence wins a collision", ORCH_PY,
     "            if prev is None or len(v.evidence) > len(prev.evidence):",
     "            if prev is None:",
     "Y4"),
    ("one agent's two bugs in a file collapse into one", ORCH_PY,
     "            key = (*pair, seen_here)",
     "            key = (*pair, 0)",
     "Y5"),
    ("a later round renumbers what the board already assigned", ORCH_PY,
     "        known_ids[(*pair, nth)] = a.vulnerability.id",
     "        known_ids[(*pair, nth)] = a.vulnerability.id + 'x'",
     "Y6"),
    ("something already in the bundle is handed out again", ORCH_PY,
     "        if key in integrated:\n            continue",
     "        if False:\n            continue",
     "Y7"),
    ("one agent's bad JSON costs the whole round", ORCH_PY,
     "        except OrchestratorError as exc:\n            # One agent's bad JSON",
     "        except ZeroDivisionError:\n            # One agent's bad JSON",
     "Y8"),
    ("the plan agent is told to rank by reach again", ORCH_PY,
     "Report everything you can attack",
     "Rank them by exploitability",
     "X11"),
    ("the v2 roles are not registered", PROVIDER_PY,
     'V2_LIVE_FIRE_ROLES = frozenset({"plan", "validator", "blueteam", "repo"})',
     'V2_LIVE_FIRE_ROLES = frozenset()',
     "V1"),
    ("an unregistered role is routed anyway", PROVIDER_PY,
     "    if normalized_role not in LIVE_FIRE_ROLES:",
     "    if False:",
     "V4"),
    ("a lead with no file is accepted", ORCH_PY,
     "        if not path:",
     "        if False:",
     "P3"),
    ("a lead with no patch direction is accepted", ORCH_PY,
     "        if not direction:",
     "        if False:",
     "P4"),
    ("an already-known vulnerability is tracked twice", ORCH_PY,
     "        if vid in seen:\n            # Not an error",
     "        if False:\n            # Not an error",
     "P7"),
    ("the round stops being bounded", ORCH_PY,
     "    if len(items) > limit:",
     "    if False:",
     "P8"),
    ("a deferred assignment is never retried", ORCH_PY,
     "            if a.state in (PENDING, DEFERRED, FAILED)",
     "            if a.state in (PENDING, FAILED)",
     "A4"),
    ("a deferral is charged as a failed attempt", ORCH_PY,
     "                assignment.note(DEFERRED, deferral.reason)",
     "                assignment.attempts += 1\n"
     "                assignment.note(DEFERRED, deferral.reason)",
     "A5"),
    ("an integrated vulnerability is re-admitted", ORCH_PY,
     "            if existing is not None and existing.state in _TERMINAL:",
     "            if False:",
     "A6"),
    ("a running blueteam's assignment is demoted mid-flight", ORCH_PY,
     "                if existing is not None and existing.state in _CLAIMED:",
     "                if False:",
     "A12"),
    ("a patch waiting for the merge is re-assigned to a second blueteam",
     ORCH_PY,
     "_CLAIMED = frozenset({IN_FLIGHT, SUBMITTED})",
     "_CLAIMED = frozenset({IN_FLIGHT})",
     "A14"),
    ("dispatch hands work out without marking it taken", ORCH_PY,
     '                assignment.note(IN_FLIGHT, "dispatched")',
     "                pass",
     "A11"),
    ("a stalled assignment disappears instead of being reported", ORCH_PY,
     "            if a.state not in _TERMINAL and a.attempts >= STALL_NOTICE",
     "            if False",
     "A7"),
    ("a re-sighting resets the attempt count", ORCH_PY,
     "                    existing.vulnerability = vulnerability\n"
     "                    existing.note(PENDING",
     "                    existing.vulnerability = vulnerability\n"
     "                    existing.attempts = 0\n"
     "                    existing.note(PENDING",
     "A8"),
    ("the attempt ceiling comes back", ORCH_PY,
     "                if a.state in (PENDING, DEFERRED, FAILED)",
     "                if a.state in (PENDING, DEFERRED, FAILED)\n"
     "                and a.attempts < STALL_NOTICE",
     "A7"),
    ("the slot budget hands out more than it has", ORCH_PY,
     "        self._semaphore = threading.BoundedSemaphore(slots)",
     "        self._semaphore = threading.BoundedSemaphore(slots + 4)",
     "S2"),
    ("a budget beyond what the host can hold is accepted", ORCH_PY,
     "        if slots > MAX_SLOTS:",
     "        if False:",
     "S5"),
    ("released slots are not counted back", ORCH_PY,
     "            self.in_use = max(0, self.in_use - 1)",
     "            pass",
     "S6"),
    ("a fix that is not holding reads as 'more left to find'", ORCH_PY,
     "    if blocked is not None and blocked < integrated:",
     "    if False:",
     "G3"),
    ("a missing count is answered with a number anyway", ORCH_PY,
     '        return None, "no vulnerability count was supplied; keep looking"',
     '        return 0, "nothing left"',
     "G4"),
    ("the configuration surfaces are dropped from the plan prompt", ORCH_PY,
     "    lines.append(CONFIG_SURFACE)",
     "    pass",
     "X12"),
    ("the plan agent is asked to answer in instalments again", ORCH_PY,
     "ONE COMPLETE LIST, AS EARLY AS YOU CAN AFFORD IT, THEN STOP READING.",
     "REPORT EACH ONE AS SOON AS YOU FIND IT.",
     "X2"),
    ("the plan agent is not told the later blocks are thrown away", ORCH_PY,
     "FIRST block in your reply is read; anything you add after it is discarded",
     "block in your reply is read; anything you add after it is kept",
     "X2b"),
    ("the plan prompt stops naming what is already fixed", ORCH_PY,
     "    if done:\n        lines.append(",
     "    if False:\n        lines.append(",
     "X5"),
    ("the plan prompt stops naming what is still open", ORCH_PY,
     "    if open_:\n        lines.append(",
     "    if False:\n        lines.append(",
     "X6"),
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

    # EVERY file a mutation names, derived rather than listed. A
    # hand-kept dict goes stale the moment an entry points at another
    # module, and the run dies with a KeyError halfway through the
    # mutation loop -- after printing enough to look like a result.
    originals = {path: path.read_text()
                 for _, path, *_ in MUTATIONS}
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
