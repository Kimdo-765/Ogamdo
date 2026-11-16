"""Live-fire v2: the four roles, and what happens between them.

THE OPERATOR'S SHAPE, which this wires together:

    plan agent      최초 베이스 소스코드를 제공받으면 존재하는 N개의 취약점
                    식별 시작, 취약점이 식별되는대로 blueteam agent 생성 및
                    정보 인계, operator feedback에 따라 추가 취약점 식별
    blueteam agent  인수받은 정보를 받아 취약점 패치, validator에 검사 요청
    validator agent 요청/응답 쌍 + 가용성 검사, 통과하면 repo agent에게 인계
    repo agent      검사받은 패치를 인수받아 통합본 재생산, 이력 관리, 레포트

`live_fire_validator` and `live_fire_repo` own their halves. This module owns
the part neither can see: WHICH vulnerabilities are in flight, what happened
to each one, and how many stacks may be up at once.

THE SLOT BUDGET IS A REAL CEILING, NOT A TUNING KNOB.
Measured on this host 2026-09-11: memory is not the constraint. NETWORKS are
-- each stack takes one bridge per network its compose file defines, docker's
default address pool tops out near 31, and this host already carries 8. That
bounds how many stacks can be up at once, and the safe line sits well below
the bound once other jobs' challenge containers are left room. Exhausting
the pool does not degrade gracefully: new job setups fail outright with "could
not find an available, non-overlapping IPv4 address pool", which is a failure
for every OTHER job on the box, not just this one.

The budget therefore counts EVERY stack, not every blueteam: N patch
validations, plus the integrated-bundle validation, plus a base re-capture,
all draw on the same pool.

WHAT IS SEQUENTIAL, AND WHY IT CANNOT BE HELPED.
`validator.establish()` has to finish before any blueteam can submit, because
every `validate()` call is judged against that baseline -- and establish means
three base stacks, one after the other, each a full build and seed. That is on the
critical path before parallelism buys anything. Identifying vulnerabilities
can overlap it; patching cannot.

EVERY PATCH IS VALIDATED INDIVIDUALLY, AND THEN THE BUNDLE IS VALIDATED AGAIN.
The cheaper design validates only the integrated bundle: one stack cycle per
round instead of N. It was rejected because a single bad patch then fails the
whole bundle with nothing saying which one, and a round that says "something
broke" is a round nobody can act on. Individual validation is the dominant
cost of a round and it is what makes a failure attributable -- the same reason
`live_fire_repo` names what a deferral collided with.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence

from modules._prompts import LIVE_FIRE_INPUT_POLICY, ctf_category_block
from modules.private_prompts import private_prompt

# States an assignment can be in. `deferred` and `failed` are both terminal
# for the ROUND and neither is terminal for the JOB: a deferred patch is
# re-tasked against the merged tree, and a failed one goes back to the plan
# agent with what the validator said.
PENDING = "pending"
IN_FLIGHT = "in-flight"
SUBMITTED = "submitted"
INTEGRATED = "integrated"
DEFERRED = "deferred"
FAILED = "failed"

_TERMINAL = frozenset({INTEGRATED})
# A BLUETEAM HAS THIS ONE AND ITS WORK IS NOT YET RESOLVED. Not terminal --
# the next round re-assigns either of these if it comes back FAILED -- but
# not re-assignable NOW. SUBMITTED belongs here beside IN_FLIGHT because a
# fast blueteam reaches it while the slower plan agents are still reading,
# and a re-sighting that demoted it would hand a second agent a
# vulnerability whose validated patch is already waiting to ship.
_CLAIMED = frozenset({IN_FLIGHT, SUBMITTED})

# Concurrent compose stacks, across every role. See the module docstring.
DEFAULT_SLOTS = 6
MAX_SLOTS = 10

# THERE IS NO ATTEMPT CAP, and the absence is deliberate. A cap is a ceiling,
# and the operator is the only brake on this module: a job ends on its timeout
# or because the operator stopped it, not because the orchestrator decided it
# had paid enough. What used to be `MAX_PATCH_ATTEMPTS = 3` also became the
# real end of job f432f9d8e16d by another route -- `ready()` filtered on it,
# so three refusals removed a vulnerability from the board for the rest of the
# run no matter how much budget was left.
#
# What replaces it is not a smaller number. It is `patch_one` refusing to pay
# twice for the same verdict when a blueteam hands back byte-identical files,
# and this count, which is now REPORTED rather than enforced.
STALL_NOTICE = 3

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,32}$")
_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class OrchestratorError(ValueError):
    """The round could not be formed."""


# WHO CAN REACH IT, ordered by how much it costs to leave open.
#
# The operator announces a count -- five, say -- and the plan agent can find
# more than that. Blueteam slots and attempt budgets are both finite, so when
# there are more leads than the contest says exist, the ones an ORDINARY
# REMOTE USER can fire at go first: those are what the red team actually
# throws at a service. A hole that needs an admin session, or host access, is
# real and still worth fixing, but it is not what decides a tick.
#
# `unknown` sits between the two remote tiers and the rest on purpose: an
# unlabelled lead might be user-reachable, while one the agent explicitly
# marked admin-only is known not to be.
# WHAT TO HUNT FIRST, inside one sector. Set by the operator.
#
# NOT A GATE. Its predecessor, `exploitability`, decided WHICH vulnerabilities
# got an agent when slots and attempts were finite -- so the ones it ranked
# low got nothing at all, and it was removed with those ceilings. Nothing is
# rationed now: every lead a plan agent reports gets a blueteam for as long as
# the operator lets the job run. This decides only what a plan agent spends
# its own turns on first, and what gets worked first when several are ready.
#
# The axes are WHO the attacker has to be and WHAT they get, in that order: an
# ordinary account is something anyone can register, so a hole behind one is
# reachable by the whole internet, while an admin-only hole needs credentials
# the attacker does not have yet.
PRIORITY_SCALE: tuple[tuple[int, str], ...] = (
    (1, "an ORDINARY user, or nobody at all, reads data they should not, "
        "escalates privilege, or runs code"),
    (2, "an ORDINARY user, or nobody at all, takes the service down"),
    (3, "an attacker who ALREADY HAS ADMIN CREDENTIALS reads data they "
        "should not, escalates further, or runs code"),
    (4, "an attacker who ALREADY HAS ADMIN CREDENTIALS takes the service down"),
    (5, "anything else"),
)
LOWEST_PRIORITY = PRIORITY_SCALE[-1][0]


def _id_order(vid: str) -> tuple[int, str]:
    """V2 before V10. Lexicographic order puts V10 first, which reads as a
    bug to anyone watching the board."""

    match = re.search(r"(\d+)$", vid)
    return (int(match.group(1)) if match else 1_000_000, vid)


@dataclass(frozen=True)
class Vulnerability:
    """What the plan agent hands to one blueteam agent."""

    id: str
    bug_class: str
    path: str
    evidence: str
    patch_direction: str
    priority: int = LOWEST_PRIORITY
    # THE ATTACK, not the smell. `evidence` says what the code does wrong;
    # this says what an attacker actually sends and what they actually get.
    # A lead that cannot state one is not reported -- see
    # `parse_vulnerabilities`.
    attack: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "bug_class": self.bug_class,
            "path": self.path,
            "evidence": self.evidence,
            "attack": self.attack,
            "patch_direction": self.patch_direction,
            "priority": self.priority,
        }


@dataclass
class Assignment:
    """One vulnerability's whole life, kept where the operator can read it."""

    vulnerability: Vulnerability
    state: str = PENDING
    attempts: int = 0
    reason: str = ""
    history: list[str] = field(default_factory=list)
    # WHAT THE VALIDATOR ACTUALLY SAID, not how many things it said.
    #
    # `reason` used to be the whole story a later agent got: "validator
    # refused it (14 unexplained)". Measured on job f432f9d8e16d, round 2's
    # plan agent then spent 25 of its 43 tool calls -- about 213 of its 453
    # seconds -- reading rounds.json, diffing every blueteam tree and
    # grepping run.log to recover the findings this field now carries. The
    # module already knows a count is useless: `_integrate_and_publish` names
    # its requests for exactly this reason.
    findings: list[str] = field(default_factory=list)

    def note(self, state: str, reason: str = "", *,
             findings: Sequence[str] | None = None) -> None:
        self.state = state
        self.reason = reason
        if findings is not None:
            self.findings = list(findings)
        self.history.append(f"{state}: {reason}" if reason else state)

    def as_dict(self) -> dict[str, Any]:
        return {
            "vulnerability": self.vulnerability.as_dict(),
            "state": self.state,
            "attempts": self.attempts,
            "reason": self.reason,
            "history": list(self.history),
            "findings": list(self.findings),
        }


class SlotBudget:
    """A hard cap on concurrent compose stacks, shared by every role.

    A semaphore rather than a counter the callers respect: the failure it
    prevents is not this job running slowly, it is docker's address pool
    running out and every OTHER job on the host failing to start.
    """

    def __init__(self, slots: int = DEFAULT_SLOTS):
        if slots < 1:
            raise OrchestratorError("slot budget must be at least 1")
        if slots > MAX_SLOTS:
            raise OrchestratorError(
                f"slot budget {slots} exceeds the {MAX_SLOTS} this host can "
                "hold: each stack takes a bridge per network and docker's "
                "default address pool is finite"
            )
        self.slots = slots
        self._semaphore = threading.BoundedSemaphore(slots)
        self._lock = threading.Lock()
        self.in_use = 0
        self.peak = 0

    def acquire(self, timeout: float | None = None) -> bool:
        got = self._semaphore.acquire(timeout=timeout) if timeout is not None \
            else self._semaphore.acquire()
        if got:
            with self._lock:
                self.in_use += 1
                self.peak = max(self.peak, self.in_use)
        return bool(got)

    def release(self) -> None:
        with self._lock:
            self.in_use = max(0, self.in_use - 1)
        self._semaphore.release()

    def __enter__(self) -> "SlotBudget":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


# How short an `attack` may be and still be a statement rather than a gesture.
# "SQLi" is nine characters and says nothing about who sends what.
MIN_ATTACK_CHARS = 24


def _salvage_vulnerabilities(text: str) -> dict[str, Any] | None:
    """Read whatever entries survive when the document as a whole does not.

    Scans for the objects inside the `vulnerabilities` array and decodes them
    one at a time, skipping any that will not parse. Returns None when there
    is nothing to scan -- a reply with no array at all is not a damaged reply,
    it is a different kind of answer, and pretending otherwise would turn a
    model that ignored the schema into a silent zero.
    """

    start = text.find("[", text.find('"vulnerabilities"'))
    if '"vulnerabilities"' not in text or start < 0:
        return None
    decoder = json.JSONDecoder()
    found: list[Any] = []
    pos = start + 1
    while pos < len(text):
        while pos < len(text) and text[pos] in " \n\r\t,":
            pos += 1
        if pos >= len(text) or text[pos] != "{":
            break
        try:
            item, end = decoder.raw_decode(text, pos)
        except ValueError:
            # Step over the wreck to the next object and keep going.
            nxt = text.find("{", pos + 1)
            if nxt < 0:
                break
            pos = nxt
            continue
        found.append(item)
        pos = end
    if not found:
        return None
    return {"vulnerabilities": found, "not_covered": ""}


def parse_vulnerabilities(
    raw: Any,
    *,
    already: Sequence[str] = (),
    limit: int = 32,
    dropped: list[str] | None = None,
) -> list[Vulnerability]:
    """Read the plan agent's findings, refusing what cannot be acted on.

    A vulnerability with no path is not a lead the orchestrator can hand to a
    blueteam -- there is nothing to give it. Refusing here means the plan agent
    is told; accepting means an assignment that can never make progress and a
    count the operator reads as coverage.

    A vulnerability with no ATTACK is refused for the same reason, one step
    further along. `evidence` describes code; an attack describes a request.
    Code that merely looks wrong costs a blueteam a full patch-and-validate
    cycle and, if the patch lands, changes a response the scoring server is
    also watching -- so an unexploitable "fix" can lose points it was never
    going to win. `dropped` collects a line per refusal so the operator sees
    what was thrown away and why; refusing silently would make a plan agent
    that ignored the schema indistinguishable from a clean bundle.
    """

    if isinstance(raw, str):
        match = _JSON_BLOCK.search(raw)
        text = match.group(1) if match else raw
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            # ONE BAD STRING MUST NOT COST THE WHOLE ANALYSIS. A plan agent
            # quotes source into `evidence`, and source is full of backticks,
            # braces and backslashes; one mis-escaped quote makes the document
            # unreadable while every other entry in it is perfect. On job
            # ebf974271ade that cost one service's agent its ENTIRE round --
            # every lead, including any the operator had named by hand -- and
            # `merge_plans` discarded it without a word, so the round read as
            # "that service is clean".
            salvaged = _salvage_vulnerabilities(text)
            if salvaged is None:
                raise OrchestratorError(
                    f"plan output was not JSON: {exc}") from exc
            if dropped is not None:
                dropped.append(
                    f"(reply was not valid JSON: {exc}; recovered "
                    f"{len(salvaged['vulnerabilities'])} entr"
                    f"{'y' if len(salvaged['vulnerabilities']) == 1 else 'ies'}"
                    " by reading them one at a time)"
                )
            raw = salvaged
    if not isinstance(raw, Mapping):
        raise OrchestratorError("plan output must be a JSON object")
    items = raw.get("vulnerabilities")
    if not isinstance(items, list):
        raise OrchestratorError("plan output has no vulnerabilities list")
    if len(items) > limit:
        raise OrchestratorError(
            f"plan reported {len(items)} vulnerabilities, over the {limit} "
            "this orchestrator will track in one round"
        )

    seen = {str(v) for v in already}
    out: list[Vulnerability] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise OrchestratorError(f"vulnerability {index} is not an object")
        vid = str(item.get("id") or "").strip()
        if not _SAFE_ID.match(vid):
            raise OrchestratorError(
                f"vulnerability {index} has an unusable id {vid!r}"
            )
        if vid in seen:
            # Not an error: the plan agent re-reads the tree each round and
            # will see fixes it already assigned. Skipping keeps the count
            # honest without making a re-sighting a failure.
            continue
        path = str(item.get("path") or "").strip().lstrip("/")
        if not path:
            raise OrchestratorError(
                f"vulnerability {vid!r} names no file; a blueteam cannot be "
                "given a lead with nothing to open"
            )
        direction = str(item.get("patch_direction") or "").strip()
        if not direction:
            raise OrchestratorError(
                f"vulnerability {vid!r} carries no patch direction; handing a "
                "blueteam a bug with no direction is how a job spends an "
                "attempt re-deciding what the plan agent already decided"
            )
        seen.add(vid)
        try:
            priority = int(item.get("priority") or LOWEST_PRIORITY)
        except (TypeError, ValueError):
            priority = LOWEST_PRIORITY
        if not 1 <= priority <= LOWEST_PRIORITY:
            # An invented number is not an error -- the lead behind it is
            # still real, and refusing it over a label would throw the
            # analysis away. It simply goes last.
            priority = LOWEST_PRIORITY
        attack = str(item.get("attack") or "").strip()
        if len(attack) < MIN_ATTACK_CHARS:
            if dropped is not None:
                dropped.append(
                    f"{path} ({str(item.get('bug_class') or 'unknown').strip()})"
                    ": no attack stated"
                )
            continue
        out.append(
            Vulnerability(
                id=vid,
                bug_class=str(item.get("bug_class") or "unknown").strip(),
                path=path,
                evidence=str(item.get("evidence") or "").strip(),
                patch_direction=direction,
                priority=priority,
                attack=attack,
            )
        )
    return out


def remaining_estimate(
    *,
    known: int | None,
    integrated: int,
    blocked: int | None,
) -> tuple[int | None, str]:
    """How many vulnerabilities are probably still open, and why we think so.

    Two independent signals, and they disagree usefully. `known` is the hint
    the operator typed at job creation -- the contest says how many there are.
    `blocked` is the feedback the scoring server gives back: how many attacks
    the current bundle stopped. When the bundle has N fixes integrated and the
    feedback says fewer than N attacks were blocked, a fix is not holding, and
    that is a different problem from not having found them all.
    """

    if blocked is not None and blocked < integrated:
        return (
            None,
            f"{integrated} fixes are integrated but only {blocked} attacks "
            "were blocked: at least one fix is not holding, so re-examine "
            "before looking for new vulnerabilities",
        )
    if known is None:
        if blocked is not None and blocked > integrated:
            return (
                None,
                f"{blocked} attacks blocked against {integrated} integrated "
                "fixes — the count is inconsistent; treat the feedback as the "
                "authority and re-read it",
            )
        return None, "no vulnerability count was supplied; keep looking"
    left = known - integrated
    if left <= 0:
        return 0, f"all {known} known vulnerabilities are integrated"
    return left, f"{left} of {known} still to find"


# --------------------------------------------------------------------------
# Prompts
# --------------------------------------------------------------------------

PLAN_SYSTEM = LIVE_FIRE_INPUT_POLICY + ctf_category_block("live-fire") + """\
You are the PLAN agent for an attack-and-defence CTF service.

You are given the service's source. Find the vulnerabilities a red team will
exploit during the contest, and hand each one to a blueteam agent with enough
information that the blueteam does not have to re-do your analysis.

READ-ONLY ROLE: inspect source with bounded read-only commands. Do not edit or
create files, run uploaded programs, start containers, install dependencies, or
contact any network endpoint. The isolated validator owns execution.

WHAT A GOOD HANDOVER CONTAINS
  * `path` — the file. A lead with no file is not a lead anyone can open.
  * `evidence` — the specific code that is wrong, quoted, with the reason.
    Include path:line or function, the attacker-controlled source, every
    relevant validation/authorization step, the sink, and the security
    invariant that is violated. Label source-only inference as such.
  * `attack` — the REQUEST that exploits it and what that gets the attacker:
    who has to be logged in, what they send, and what happens that should not.
    "SQL injection in the search box" is not an attack; "an anonymous GET to
    /search.php?q=' UNION SELECT password FROM users-- returns the password
    column in the results table" is.

    WHERE THE EFFECT LANDS IS NOT ALWAYS THE RESPONSE, and reading it that way
    loses a whole class. A stored XSS returns the SAME BYTES it always did and
    runs in the next victim's browser. A DOM XSS or a client-side template
    injection is the same kind: the server sends the text unchanged and the
    page turns it into code, so the response shows no difference. An SSRF's
    evidence is a connection the attacker's
    own listener sees, or an error that differs by port. A DoS shows up as the
    next request timing out. Say WHERE the effect appears and what it is —
    "runs `alert(document.cookie)` in the browser of the next user who reads
    the guestbook" is a complete attack. "The response does not change" is not
    a reason to leave something out; it is what a stored XSS looks like.
  * `patch_direction` — HOW to fix it, concretely enough to act on. "Sanitise
    the input" is not a direction; "bind the id as a parameter instead of
    concatenating it into the SQL string" is. Name the invariant to
    restore and the legitimate behaviour that must remain unchanged.

Use one stable lowercase hyphenated `bug_class` slug per root cause (for
example `sql-injection`, `stored-xss`, `path-traversal`, `ssrf`, `uaf`). Do
not report spelling variants of the same root cause as separate findings.

ONE COMPLETE LIST, AS EARLY AS YOU CAN AFFORD IT, THEN STOP READING. Only the
FIRST block in your reply is read; anything you add after it is discarded
without a word, so answering in instalments loses everything after your first
and smallest one. Your turn also ends on a fixed budget, and a reply cut in
the middle of an object is worth nothing at all — a blueteam agent starts the
moment your list arrives, so decide when you have enough, write the whole list
once, and stop.

DO NOT REPORT A VULNERABILITY YOU HAVE ALREADY REPORTED. You will re-read this
tree in later rounds and see fixes you assigned earlier; those are done.

DO NOT INVENT ONE TO REACH A COUNT. If you were told there are five and you
can only evidence three, report three and say what you have not covered.
A fabricated lead costs a blueteam a full patch-and-validate cycle and teaches
the operator that a number is progress when it is not.

THE FIX MUST LIVE IN APPLICATION SOURCE. A blueteam may edit the service's own
code and nothing else — not compose files, not Dockerfiles, not deployment
scripts, not database seed data. Two kinds of finding are therefore NOT usable
here, however real they are:

  * anything whose fix is a configuration or infrastructure change
  * anything whose fix changes SEEDED CREDENTIALS. The scoring server logs in
    with those accounts, so changing them breaks every authenticated request
    by construction — the patch would be refused for breaking the service
    while the vulnerability stayed open.

Report those in `not_covered` instead, where the operator can act on them by
hand. Assigning one to a blueteam spends its whole turn and returns nothing.

SPEND YOUR TURNS IN THIS ORDER, and set `priority` to the number you used:

  1. an ORDINARY user, or nobody at all, reads data they should not, escalates privilege, or runs code
  2. an ORDINARY user, or nobody at all, takes the service down
  3. an attacker who ALREADY HAS ADMIN CREDENTIALS reads data they should not, escalates further, or runs code
  4. an attacker who ALREADY HAS ADMIN CREDENTIALS takes the service down
  5. anything else

The axes are WHO the attacker has to be and WHAT they get, in that order. An
ordinary account is something anyone can register or that the contest hands
out, so a hole behind one is reachable by the whole internet; an admin-only
hole needs credentials the attacker does not have yet. Judge by what the CODE
requires, not by what the UI suggests -- a page behind a login link that never
checks the session is reachable by nobody-at-all, which is priority 1.

A VULNERABILITY YOU CANNOT ATTACK IS NOT A FINDING. If you cannot state the
request that exploits it and what that request gets back, leave it out and put
it in `not_covered`. Code that merely looks wrong is not a vulnerability here:
it spends a blueteam's whole cycle, and if the patch lands it changes a
response the scoring server is ALSO watching -- so a fix for something nobody
could exploit can lose points it was never going to win. Reachability is part
of the attack: a sink behind a check that always fails, in a service nothing
routes to, or in a file the running app never includes, has no attack.

Say so plainly when you are unsure. "Probably exploitable" is not an attack,
and `not_covered` is where an unproven suspicion belongs -- the operator reads
it and can chase it by hand.

BUT DO NOT MISTAKE "the response is identical" FOR "there is no attack". The
scoring server watches responses, which is why a patch must not move them --
it is NOT a statement about where vulnerabilities live. Code that a BROWSER
runs is application source like any other, and a sink in it is reachable by
whoever can get their text into that page.

THE ORDER IS NOT A FILTER. Report everything you can attack, including priority
5. Nothing is dropped for ranking low: there is no attempt budget and no round
ceiling, so every vulnerability you name gets an agent for as long as the
operator lets the job run. The order decides what YOU look at first inside
your own part of the bundle, and what gets worked first when several are
ready. A priority you are unsure of is a 5, not a guess -- and a real
vulnerability reported as a 5 is worth far more than one you left out.

Reply with ONE json block and nothing else:

```json
{
  "vulnerabilities": [
    {"id": "V1", "bug_class": "sqli", "path": "src/app/search.php",
     "evidence": "line 42 interpolates $_GET['q'] into the query string",
     "attack": "anonymous GET /search.php?q=' UNION SELECT password FROM users-- returns the password column in the results table",
     "patch_direction": "use a prepared statement and bind q",
     "priority": 1}
  ],
  "not_covered": "what you could not evidence, if anything"
}
```
"""

BLUETEAM_SYSTEM = LIVE_FIRE_INPUT_POLICY + ctf_category_block("live-fire") + """\
You are a BLUETEAM agent. You have been handed ONE vulnerability and the file
it lives in. Fix that one and nothing else.

The handoff is a hypothesis backed by cited evidence, not an instruction you
must trust. Re-check its source-to-sink premise. Fix ONE root cause/security
invariant; when that invariant genuinely spans more than one existing
application file, edit only the smallest required set and explain why.

HARD BOUNDARIES
  * Edit only files that already exist in the bundle. A file you add is
    dropped when the ZIP is rebuilt from the input manifest — it will look
    like your fix vanished.
  * Do not touch Dockerfiles, compose files, deployment scripts or tests.
  * Do not rename or delete anything.
  * Fix ONE vulnerability. Another agent is already working on the others, and
    your patch is merged with theirs — the smaller your diff, the less likely
    it collides and gets deferred.

THE SERVICE MUST KEEP WORKING. The scoring server sends benign traffic
alongside every attack, and a normal response that changes loses points even
when the vulnerability is genuinely fixed. Specifically, do not:
  * escape or encode output the original did not escape
  * reject a legitimate input represented by the benign baseline. Exploit
    behaviour is expected to change; preserving the vulnerable behaviour of
    every byte sequence the original happened to accept is not the SLA goal.
  * change a status code, a header, or a field name
  * add a log line, a banner, or a comment to a response body

Do not special-case the example payload. Close the root cause across alternate
encodings, case/whitespace forms and sibling callers of the same sink. The
isolated validator owns execution; do not contact external targets or start a
second service stack yourself.

A validator will replay the benign corpus against your patched build and reject
an unexplained semantic regression. A byte-for-byte static asset served from
the exact file you changed is tracked separately so an intentional source-asset
update is not mislabelled as an unrelated SLA break. Validation happens BEFORE
your patch reaches the bundle, so a real regression costs the attempt rather
than the operator the round.
"""


# How many findings a prompt carries. Six is what `_integrate_and_publish`
# already prints, and the same reasoning applies: enough to see the shape of
# the break, not so many that the list becomes the prompt.
PROMPT_FINDINGS = 6


def blueteam_prompt(
    vulnerability: Vulnerability, source: str, *,
    findings: Sequence[str] = (), own_diff: str = "",
) -> str:
    """What one blueteam is told.

    IT USED TO BE TOLD NOTHING ABOUT ITS LAST REFUSAL. On job f432f9d8e16d
    round 2 passed more patches than round 1 -- not because the blueteams
    learned anything, but because the plan agent dug the validator's
    findings off disk and rewrote `patch_direction` with them. A
    900-second plan call was the only channel through which "your patch
    changed this response line" reached the agent holding the file. Now
    it arrives directly.
    """

    lines = [
        f"VULNERABILITY {vulnerability.id} ({vulnerability.bug_class})",
        f"File: {vulnerability.path}",
        "",
        f"EVIDENCE\n{vulnerability.evidence}",
    ]
    if vulnerability.attack:
        # THE ATTACK, so the fix is aimed at a request rather than at a smell.
        # A blueteam that knows what the exploit sends can tell whether its
        # patch closes that request or merely tidies the line above it.
        lines += [
            "",
            f"THE ATTACK THIS MUST STOP\n{vulnerability.attack}",
        ]
    lines += [
        "",
        f"PATCH DIRECTION\n{vulnerability.patch_direction}",
        "",
        # THE ATTACK IS AN EXAMPLE, NOT THE SPECIFICATION, and until this was
        # said the blueteams read it as the specification: handed one input
        # that slipped past a check, a blueteam closed that one spelling and
        # left the other spellings of the same input open, even when the
        # patch direction named the whole class. A patch aimed at the example
        # ends the round looking green with the vulnerability still open.
        "WHAT COUNTS AS FIXED",
        "THE ATTACK THIS MUST STOP is ONE example of the vulnerability, not "
        "its definition. PATCH DIRECTION describes the class, and the class "
        "is what you must close. A patch that rejects the exact bytes of the "
        "example and nothing else is not a patch: whitespace, letter case, "
        "URL- or unicode-encoding, a trailing dot or slash, an alternative "
        "spelling of the same target, or a second route into the same sink "
        "all reach it again. Normalise the input and decide on the normalised "
        "value, or accept only from a known-good set -- do not enumerate the "
        "bad ones. If you believe PATCH DIRECTION is wrong, say so and state "
        "what you did instead; do not silently do less than it asks.",
    ]
    if findings:
        shown = list(findings)[:PROMPT_FINDINGS]
        more = len(findings) - len(shown)
        tail = f"\n  ... and {more} more" if more > 0 else ""
        lines += [
            "",
            "YOUR LAST PATCH WAS REFUSED. The service must answer every "
            "request byte for byte as the ORIGINAL did; these are the lines "
            "that differed. Fix the vulnerability WITHOUT changing them:\n"
            + "\n".join(f"  {f}" for f in shown) + tail,
        ]
    if own_diff:
        lines += ["", f"WHAT YOU CHANGED LAST TIME\n{own_diff}"]
    lines += ["", f"THE FILE\n{source}", ""]
    return "\n".join(lines)


def _open_line(a: Assignment) -> str:
    """One unfinished vulnerability, with the reason it is unfinished."""

    head = f"  - {a.vulnerability.id} @ {a.vulnerability.path} ({a.state}: {a.reason})"
    if not a.findings:
        return head
    shown = list(a.findings)[:PROMPT_FINDINGS]
    more = len(a.findings) - len(shown)
    tail = f"\n      ... and {more} more" if more > 0 else ""
    return (head + "\n      the patch changed these response lines:\n"
            + "\n".join(f"      {f}" for f in shown) + tail)


CONFIG_SURFACE = ("""NOT EVERY VULNERABILITY IS A LINE OF CODE. Some are the \
shape of the configuration, and no grep will show them:
  - a form field, header or parameter that takes a HOST, PORT or URL, where
    the service that acts on it can reach something the caller cannot
  - a security control that ships in the source but is not enabled where
    the service actually runs""" + (private_prompt("live_fire_config_note_1") or "") + """
  - a service with no authentication that is only safe because of where it
    sits on the network
  - credentials that come from a default, an environment variable, or the
    compose file
Check these deliberately.""" + (private_prompt("live_fire_config_note_2") or ""))


def plan_prompt(
    *,
    tree_summary: str,
    known: int | None,
    already: Sequence[Assignment],
    feedback: str = "",
    sinks: str = "",
    sources: str = "",
    topology: str = "",
    scope: str = "",
) -> str:
    lines = []
    if scope:
        lines.append(
            f"YOU ARE LOOKING AT ONE PART OF THE BUNDLE: {scope}. Other "
            "agents have the rest. Report what you can evidence HERE."
        )
    if known is not None:
        if scope:
            # THE COUNT IS FOR THE WHOLE BUNDLE. Handing "there are N" to
            # each of M agents is how a fan-out returns N times M leads.
            lines.append(
                f"The contest says the WHOLE BUNDLE has {known} "
                "vulnerabilities, across every part. That is not a target for "
                "your part — do not pad to a number, and do not stop early "
                "because you think someone else has the rest."
            )
        else:
            lines.append(
                f"The contest says this service has {known} vulnerabilities."
            )
    done = [a for a in already if a.state == INTEGRATED]
    open_ = [a for a in already if a.state in (DEFERRED, FAILED)]
    if done:
        lines.append(
            "ALREADY FIXED AND IN THE BUNDLE (do not report these again):\n"
            + "\n".join(
                f"  - {a.vulnerability.id} {a.vulnerability.bug_class} "
                f"@ {a.vulnerability.path}"
                for a in done
            )
        )
    if open_:
        lines.append(
            "ASSIGNED BUT NOT IN THE BUNDLE — say whether each is still real, "
            "and give a different patch direction if your first one failed:\n"
            + "\n".join(_open_line(a) for a in open_)
        )
    if feedback:
        lines.append(f"OPERATOR FEEDBACK\n{feedback}")
    if sinks:
        lines.append(
            "WHERE REQUEST DATA REACHES A SINK — grepped for you, so you do "
            "not spend turns on it. Noisy on purpose: a hit is a place to "
            "look, not a finding.\n" + sinks
        )
    if sources:
        lines.append(
            "WHERE REQUEST DATA ENTERS — the other end of the same trail. A "
            "sink that is an ordinary library call is invisible from the sink "
            "side and plain from this one.\n" + sources
        )
    if topology:
        lines.append(
            "WHAT CAN REACH WHAT — read off the compose file.\n" + topology
            + "\n\nA request that arrives at a service marked REACHABLE FROM "
            "OUTSIDE and makes that service CONNECT to one marked internal "
            "only is a finding in itself, even when the call that does it is "
            "a perfectly ordinary client library. Reachability is what the "
            "priority scale measures: 1 and 2 are what somebody with no "
            "credentials can do."
        )
    lines.append(CONFIG_SURFACE)
    lines.append(f"THE SOURCE\n{tree_summary}")
    return "\n\n".join(lines)


def _vuln_key(v: Vulnerability) -> tuple[str, str]:
    return (v.path.strip().lstrip("/").lower(), v.bug_class.strip().lower())


def merge_plans(
    replies: Sequence[str], *, existing: Sequence[Assignment] = (),
    dropped: list[str] | None = None,
) -> list[Vulnerability]:
    """Fold several plan agents' replies into ONE numbered list.

    IDS ARE ASSIGNED HERE, NOT BY THE AGENTS. Every agent answers with a
    V1, and `admit()` keys on the id -- so taking their numbering would merge
    unrelated vulnerabilities into one assignment, and renumbering
    between rounds would split one vulnerability into two. A lead therefore
    keeps whatever id the board already gave the same (path, bug_class), and
    only genuinely new ones take the next free number.

    Deduplication is by that same pair, keeping the longer evidence. Not by
    similarity: two real bugs in one file are two bugs, and a merge that
    decided otherwise would silently drop one.
    """

    by_key: dict[tuple[str, str, int], Vulnerability] = {}
    for raw in replies:
        try:
            found = parse_vulnerabilities(raw, dropped=dropped)
        except OrchestratorError as exc:
            # One agent's bad JSON costs that agent's turn. The others'
            # analysis is still good, and the round still has work -- but
            # SAYING SO is the difference between "that service is clean" and
            # "nobody read that service". This used to `continue` in silence.
            if dropped is not None:
                dropped.append(f"(a plan reply could not be read: {exc})")
            continue
        # ACROSS replies, not within one. Two agents naming the same file and
        # class are looking at the same code and have found the same bug. ONE
        # agent naming it twice has found two, and a key of (path, class)
        # alone would quietly throw the second away -- which is the failure
        # mode of every clever deduplication: it is invisible.
        ordinal: dict[tuple[str, str], int] = {}
        for v in found:
            pair = _vuln_key(v)
            seen_here = ordinal.get(pair, 0)
            ordinal[pair] = seen_here + 1
            key = (*pair, seen_here)
            prev = by_key.get(key)
            if prev is None or len(v.evidence) > len(prev.evidence):
                by_key[key] = v

    # The board's own ordinals, so a re-sighting matches the assignment it
    # belongs to rather than the first one that shares its file and class.
    board_ordinal: dict[tuple[str, str], int] = {}
    known_ids: dict[tuple[str, str, int], str] = {}
    integrated: set[tuple[str, str, int]] = set()
    for a in sorted(existing, key=lambda a: _id_order(a.vulnerability.id)):
        pair = _vuln_key(a.vulnerability)
        nth = board_ordinal.get(pair, 0)
        board_ordinal[pair] = nth + 1
        known_ids[(*pair, nth)] = a.vulnerability.id
        if a.state == INTEGRATED:
            integrated.add((*pair, nth))
    used = {a.vulnerability.id for a in existing}
    out: list[Vulnerability] = []
    # NEW ids are handed out in priority order, so V1 is the worst thing any
    # agent found rather than whichever file sorts first. An id the board
    # already gave is kept regardless -- renumbering splits one vulnerability
    # into two assignments.
    for key in sorted(by_key, key=lambda k: (by_key[k].priority, k)):
        if key in integrated:
            continue
        vid = known_ids.get(key)
        if vid is None:
            number = 1
            while f"V{number}" in used:
                number += 1
            vid = f"V{number}"
            used.add(vid)
        out.append(replace(by_key[key], id=vid))
    return sorted(out, key=lambda v: (v.priority, _id_order(v.id)))


# --------------------------------------------------------------------------
# The board
# --------------------------------------------------------------------------


class AssignmentBoard:
    """Who is working on what, and what became of it.

    Kept separate from the agents because the question "is this vulnerability
    still open" has to survive an agent dying, a patch being deferred by the
    merge, and the operator's feedback arriving three rounds later.
    """

    def __init__(self) -> None:
        self.assignments: dict[str, Assignment] = {}
        # The round used to admit every lead, and only then hand any of them
        # out: nothing could read the board between the two. Plan replies are
        # merged as they land now, so `admit` runs while blueteams started by
        # an earlier reply are already going. Reentrant because `dispatch`
        # calls `ready` and both want it.
        self._lock = threading.RLock()

    def admit(self, vulnerabilities: Sequence[Vulnerability]) -> list[Assignment]:
        """Take on new leads, silently ignoring ones already integrated."""

        fresh: list[Assignment] = []
        with self._lock:
            for vulnerability in vulnerabilities:
                existing = self.assignments.get(vulnerability.id)
                if existing is not None and existing.state in _TERMINAL:
                    continue
                if existing is not None and existing.state in _CLAIMED:
                    # A BLUETEAM IS ALREADY ON IT, and this demoted it to
                    # PENDING. `ready()` then named the same vulnerability
                    # again, a second blueteam started on it, and `_tree_for`
                    # rmtree'd the first one's workspace while it was reading
                    # it. Two agents, one tree, and whichever finished second
                    # wrote over the other.
                    #
                    # A re-sighting is not worth that. The running agent has
                    # the direction it started with; if it fails, the next
                    # round re-assigns it with whatever the plan agent says
                    # then -- by which time this branch is reachable again
                    # because the state is no longer IN_FLIGHT.
                    continue
                if existing is not None:
                    # A re-sighting with new information: keep the attempt
                    # count, take the fresh direction. Resetting attempts here
                    # would let an agent loop forever by re-reporting the same
                    # bug.
                    existing.vulnerability = vulnerability
                    existing.note(PENDING, "re-assigned with new information")
                    fresh.append(existing)
                    continue
                created = Assignment(vulnerability=vulnerability)
                self.assignments[vulnerability.id] = created
                fresh.append(created)
        return fresh

    def ready(self) -> list[Assignment]:
        """Assignments a blueteam should be given, in a deterministic order.

        A FAILED one is included: it failed validation, and the plan agent has
        since had a chance to change its direction. A DEFERRED one is included
        too -- it lost a merge, and the runner seeds its next tree with the
        CANDIDATE's version of the path it collided on, so the conflict it hit
        is already resolved in the bytes it is handed.

        That last clause used to be an assumption rather than a mechanism:
        `_tree_for` copied the original tree unconditionally, so a deferred
        agent saw the same bytes as the first time and produced the same
        losing patch. See `LiveFireV2Runner._seed_rebase`.
        """

        # Ordered by WHO CAN REACH IT first, then by id so two runs of the
        # same job hand the same work to the same agents. The id alone was
        # deterministic but arbitrary: with more leads than slots it decided
        # which vulnerabilities got an agent by what the plan agent happened
        # to name them.
        with self._lock:
            return sorted(
                (
                    a
                    for a in self.assignments.values()
                    if a.state in (PENDING, DEFERRED, FAILED)
                ),
                key=lambda a: (a.vulnerability.priority,
                               _id_order(a.vulnerability.id)),
            )

    def dispatch(self) -> list[Assignment]:
        """Name everything `ready()` names AND mark it in-flight, at once.

        Two steps that must not be separable. `patch_one` was the thing that
        set IN_FLIGHT, which was safe while the round admitted every lead
        before handing out any -- nothing looked at the board in between.
        Plan replies are merged as they arrive now, so the gap between
        "ready() named it" and "the worker thread got to its first line" is a
        window, and a dispatch inside that window sees the assignment ready a
        second time and starts a second blueteam on the one tree.

        Returned already IN_FLIGHT, so the caller MUST submit every one of
        them: an assignment marked here and then dropped is invisible to
        `ready()` for the rest of the job.
        """

        with self._lock:
            taken = self.ready()
            for assignment in taken:
                assignment.note(IN_FLIGHT, "dispatched")
            return taken

    def defer(self, deferrals: Sequence[Any]) -> None:
        """Record a merge's deferrals when NOTHING was published.

        Separate from `apply_merge` because a DEFERRAL is true whether or not
        a version was cut and an ACCEPTANCE is not; the runner has always made
        that distinction, and it used to make it by reaching into
        `assignments` and calling `note` itself. That was safe while shipping
        ran on the round's own thread. It ships from a blueteam's thread now,
        so the write has to be where the lock is.
        """

        with self._lock:
            self._defer(deferrals)

    def _defer(self, deferrals: Sequence[Any]) -> None:
        for deferral in deferrals:
            assignment = self.assignments.get(deferral.vulnerability_id)
            if assignment is not None:
                # NOT an attempt. The patch was fine; the merge could not take
                # it this round. Charging an attempt would spend a blueteam's
                # budget on somebody else's collision.
                assignment.note(DEFERRED, deferral.reason)

    def stalled(self) -> list[Assignment]:
        """Open vulnerabilities that have cost a lot and produced nothing.

        A REPORT, NOT A GATE. Its predecessor, `exhausted()`, named the same
        assignments and `ready()` then refused to hand them out again -- so
        three refusals ended a vulnerability for the rest of the job while the
        operator still had budget for it. These are still handed to a blueteam
        every round; the list exists so the log and the board can say where
        the time is going.
        """

        with self._lock:
            return [
                a
                for _, a in sorted(self.assignments.items(),
                                   key=lambda kv: _id_order(kv[0]))
                if a.state not in _TERMINAL and a.attempts >= STALL_NOTICE
            ]

    def integrated(self) -> list[str]:
        with self._lock:
            return sorted(
                (vid for vid, a in self.assignments.items()
                 if a.state == INTEGRATED),
                key=_id_order,
            )

    def apply_merge(self, merge: Any) -> None:
        """Record what the repo agent did with each submitted patch.

        UNDER THE LOCK, because this no longer runs on the round's own
        thread. A blueteam ships as its patch validates, so these writes land
        while `admit` is taking a lead from a plan reply that is still
        arriving -- and what they write is `state`, which is the field
        `ready()` reads to decide who gets another agent.
        """

        with self._lock:
            for vid in getattr(merge, "accepted", ()):  # noqa: B007
                assignment = self.assignments.get(vid)
                if assignment is not None:
                    assignment.note(INTEGRATED, "in the bundle")
            self._defer(getattr(merge, "deferred", ()))

    def as_dict(self) -> dict[str, Any]:
        # ALL FOUR FIELDS UNDER THE LOCK. `assignments` was iterated while
        # `admit` inserted into it -- "dictionary changed size during
        # iteration", raised inside `publish_board`, whose `except` said
        # nothing -- while `open` came from `ready()`, which DID take the
        # lock. So the board could name an id under `open` that had no row,
        # and the half that was protected made the half that was not look
        # deliberate. Reentrant, so the three calls below still take it.
        with self._lock:
            return {
            "assignments": [
                # NATURAL ORDER, not lexicographic. This list IS what the
                # operator reads in the UI, and sorting the ids as text put
                # V10 between V1 and V2 -- which reads as a bug in the
                # numbering rather than in the sort. (`open` below is ordered
                # by PRIORITY instead: it is the work queue, not the list.)
                a.as_dict() for _, a in sorted(
                    self.assignments.items(),
                    key=lambda kv: _id_order(kv[0]),
                )
            ],
            "integrated": self.integrated(),
            "open": [a.vulnerability.id for a in self.ready()],
            "stalled": [a.vulnerability.id for a in self.stalled()],
        }


__all__ = [
    "Assignment",
    "AssignmentBoard",
    "BLUETEAM_SYSTEM",
    "DEFAULT_SLOTS",
    "DEFERRED",
    "FAILED",
    "INTEGRATED",
    "IN_FLIGHT",
    "LOWEST_PRIORITY",
    "PRIORITY_SCALE",
    "STALL_NOTICE",
    "MAX_SLOTS",
    "OrchestratorError",
    "PENDING",
    "PLAN_SYSTEM",
    "SUBMITTED",
    "SlotBudget",
    "Vulnerability",
    "blueteam_prompt",
    "merge_plans",
    "parse_vulnerabilities",
    "plan_prompt",
    "remaining_estimate",
]
