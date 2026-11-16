"""LF-6: the live-fire provider transport.

Everything around this file was finished long ago — `resolve_live_fire_route`
picks the provider and model from the job snapshot, `_record_call_usage`
writes the ledger row, `run_patch_loop` owns the gates. The one thing missing
was an `AgentInvoker` that actually runs an agent, so `run_job` defaulted to
`DiagnosticInvoker` and every live-fire job ended in under half a second with
`provider transport unavailable`. Jobs 6571ebbc19d2 and e52d42f23ee0 are both
that, on a real attack-and-defence bundle.

THREE ROLES, AND ONLY TWO OF THEM ARE A MODEL

`main` and `reviewer` are model calls. `report` is NOT, and that is a finding
rather than a shortcut: `validate_report` requires the literal string
``Final ready_to_deploy: **false**``, requires the ``path:line`` matches in
the report to equal the structured findings *in order*, and requires a
``- Mitigation class: `x` `` line per finding. Prose cannot hit that
reliably, and one stray `file.py:12` anywhere in the text breaks the ordering
check. `_render_report` already emits exactly that document from the same
inputs, so the report role returns it. The loop's fail-closed handling of a
bad report is left alone — routing around it would let READY survive a broken
report role, which is the opposite of what that handling is for.

THE HARD PART IS THE FINDING, NOT THE TRANSPORT

`_finding_errors` rejects a finding unless its `path` is in the diff AND its
`line` is one of the CHANGED lines, in post-patch numbering. An agent asked
where the bug was reports the pre-patch line and every finding fails, which
makes `report_errors` non-empty and kills `terminal_ready` for the whole run.
So the prompt asks for the patched line, and `_repair_finding` re-checks each
one against the real diff and drops what cannot be honest — one bad entry
would otherwise cost the entire attempt.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from pathlib import Path
from typing import Any

from modules._prompts import LIVE_FIRE_INPUT_POLICY, ctf_category_block
from modules.live_fire_patch_loop import (
    EVIDENCE_TIERS,
    MITIGATION_CLASSES,
    SEVERITIES,
    DiffRecord,
    ProviderResult,
    ReportContext,
    ReviewContext,
    ReviewResult,
    VulnerabilityFinding,
    _render_report,
)
from modules.live_fire_provider import AgentCall, AgentInvocationResult, AgentUsage
from modules._sdk_buffer import AGENT_MAX_BUFFER_BYTES


# A model that thinks for the whole job leaves nothing for packaging. The loop
# already reserves that time; this is the floor below which a call is not worth
# starting at all.
MIN_TURN_S = 60.0
REVIEW_TURN_S = 300.0

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

# Failures no further attempt can fix. A revoked OAuth token is the same
# answer every time, and the loop has no "give up" — it runs its whole attempt
# budget. Job 87ad54d6c50c spent five attempts, each calling main AND
# reviewer, on `refresh_token_invalidated`; with a working model those ten
# calls would have been the operator's entire contest tick.
#
# Matched on the provider's own words rather than on an exit code, because
# the CLI reports this as ordinary turn output.
_FATAL_MARKERS = (
    "refresh_token_invalidated",
    "refresh token has been invalidated",
    "refresh token was revoked",
    "not authorized to access this model",
    "401 unauthorized",
)


def _fatal_reason(text: str) -> str:
    low = (text or "").lower()
    for marker in _FATAL_MARKERS:
        if marker in low:
            return marker
    return ""


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------
MAIN_SYSTEM = LIVE_FIRE_INPUT_POLICY + ctf_category_block("live-fire") + """\
You are patching a live attack-and-defence CTF service. You are not attacking
it and you are not writing an exploit.

Your working directory IS the service source. Edit it in place.

HARD BOUNDARIES — a diff that breaks any of these is DISCARDED and your whole
attempt is thrown away, patch included:

* Do NOT touch a Dockerfile, docker-compose.yml/yaml, compose.yml/yaml,
  nginx.conf or haproxy.cfg.
* Do NOT touch anything under deploy/, deployment/, k8s/, helm/ or .github/.
* Do NOT touch any path with a `test`, `tests`, `spec` or `specs` component,
  and no file whose name starts with `test_` or `spec_`.
* Do NOT add, delete, rename or move files. Edit existing ones only.
* Do NOT change what a LEGITIMATE request sees. Every tick, the scoring server
  sends SLA traffic at the same time as the attacks, and the SLA check compares
  your service's answer against the ORIGINAL's. A patch that changes a normal
  response fails the round even when it closed the bug.

  "Changes a normal response" is stricter than "breaks it". All of these fail:

    - encoding or escaping output that the original emitted raw, so a benign
      value containing `&`, `<` or a quote now comes back different;
    - adding, removing or reformatting any field, whitespace, header, status
      code or redirect on a request the original accepted;
    - rejecting a LEGITIMATE BASELINE input the validator recorded, including
      one that merely looks unusual — exploit behaviour is expected to change,
      but the supplied benign/SLA behaviour is not;
    - new log lines, warnings or notices that reach the response body;
    - changing timing enough to miss the SLA deadline.

  So prefer a fix that is INVISIBLE on legitimate input: a parameterised query
  instead of escaping the string, a bound check that only rejects what is
  genuinely out of range, an allow-list that preserves the recorded legitimate
  baseline while rejecting the invalid attack class, or authorisation applied
  where it was missing. When the
  only fix you can see would alter a normal response, say so in
  `patch_reason` and choose the narrowest form of it you can.

WHAT A GOOD PATCH IS

Fix the ROOT CAUSE where you can — parameterise the query, bound the buffer,
check the authorisation — and say so. A targeted input filter is acceptable
when the root cause cannot be reached safely in the time available, but it
must be declared as one; claiming a filter is a root-cause fix is the single
most damaging thing you can write here.

Prefer one real fix over three speculative ones.
"""

MAIN_TEMPLATE = """\
# Service

{discovery}

{already_fixed}{round_feedback}# Your task, attempt {attempt} of this job

{task}
{feedback}

# Answer format — read this before you start editing

When you are done, end your final message with ONE fenced json block, and
nothing after it:

```json
{{
  "status": "success",
  "summary": "one sentence on what you changed",
  "findings": [
    {{
      "bug_class": "sqli | command-injection | path-traversal | ssrf | uaf | ...",
      "severity": "critical | high | medium | low",
      "path": "relative/path/as/it/appears/in/the/tree.php",
      "line": 42,
      "root_cause": "why the service was wrong",
      "attack_impact": "what an attacker got",
      "patch_description": "what you changed",
      "patch_reason": "why that closes it",
      "mitigation_class": "root-cause-fix | input-filter | mixed",
      "evidence_tier": "A | B"
    }}
  ]
}}
```

`evidence_tier` is A or B — nothing else is accepted. It is the tier of the
attack probe that demonstrates this bug: A when the run reproduced it and saw
it stop after your patch, B when the evidence is a read of the source. If the
job carries no verification contract there is no probe to cite, so use B.

`line` MUST be a line number IN THE FILE AS YOU LEFT IT — a line you actually
changed or added. Not the line the bug used to be on. A finding whose line is
not part of your diff is discarded, and a discarded finding costs the attempt.

Use `"status": "failure"` with an empty `findings` list if you could not
safely fix anything. That is a real answer and it is better than a guess.
"""

# The task sentence is not decoration — it is the difference between one fix
# and a round's worth of them. An attack-and-defence organizer usually
# announces HOW MANY vulnerabilities were planted and nothing else, and that
# single number changes what "done" means: without it the honest instruction
# is "fix the worst one you can actually fix", with it the agent knows it owes
# the operator N and can stop guessing whether to keep looking.
# ONE VULNERABILITY PER ATTEMPT, DELIBERATELY.
#
# A defence round submits on a tick, and the loop publishes a patch version
# the moment an attempt lands. If an attempt fixed three bugs at once the
# operator would get one version carrying all three and no way to tell which
# of them earned the change in blocked-attack count. Fixing one per attempt
# makes every version a single, attributable change — V1 = one bug closed,
# V2 = two closed — which is exactly the shape the round's feedback comes back
# in.
_ONE_PER_ATTEMPT = (
    "Fix EXACTLY ONE vulnerability in this attempt, and report exactly one "
    "finding for it. Not two, not the whole list. Each attempt becomes a patch "
    "version the operator uploads on its own, and a version carrying two fixes "
    "cannot be told apart by the round's score."
)

TASK_UNKNOWN_COUNT = (
    "Find the most serious vulnerability you can actually fix, and fix it in "
    "place.\n\n" + _ONE_PER_ATTEMPT
)

TASK_KNOWN_COUNT = (
    "The organizer announced that this service contains {count} planted "
    "{noun}.\n\n"
    "{progress}" + _ONE_PER_ATTEMPT + "\n\n"
    "Do NOT pad the finding to reach {count}. A finding you cannot point at a "
    "line you changed is discarded, and a wrong one costs the whole attempt — "
    "{count} is what the job is looking for across its attempts, not what to "
    "claim in this one."
)


FEEDBACK_NAME = "patch-feedback.json"


def _round_feedback(job_dir: Path) -> str:
    """Render observational scoreboard feedback: attacks blocked per version.

    The count is real round evidence, but a delta alone does not identify which
    request, patch, upload, availability change, or SLA effect caused it. The
    generated wording asks the next attempt to confirm deployment and
    validation state before drawing a causal conclusion.

    Rendered oldest-first so the trend is readable as a trend.
    """
    try:
        entries = json.loads((job_dir / FEEDBACK_NAME).read_text()).get("entries")
    except (OSError, ValueError):
        return ""
    rows = [e for e in (entries or []) if isinstance(e, dict)]
    if not rows:
        return ""
    rows.sort(key=lambda e: e.get("attempt", 0))
    lines = ["# Round feedback on the patches you already shipped", ""]
    for row in rows:
        note = str(row.get("note") or "").strip()
        lines.append(
            f"- patch version {row.get('attempt')}: blocked "
            f"{row.get('blocked')} attack(s)" + (f" — {note}" if note else "")
        )
    counts = [int(r.get("blocked", 0)) for r in rows
              if isinstance(r.get("blocked"), int)]
    if len(counts) >= 2:
        if counts[-1] > counts[-2]:
            lines.append("")
            lines.append(
                "The latest scoring window observed MORE blocked attacks than "
                "the prior one. Keep the validated fix while looking for the "
                "next surface, but do not treat one score delta as proof of "
                "which exact request caused it."
            )
        elif counts[-1] == counts[-2]:
            lines.append("")
            lines.append(
                "The latest scoring window observed NO increase. First confirm "
                "the intended bundle was uploaded and benign SLA still passed; "
                "then prefer a different attack surface. This observation does "
                "not by itself refute a locally validated vulnerability."
            )
        else:
            lines.append("")
            lines.append(
                "The latest scoring window observed FEWER blocked attacks. "
                "Treat that as a regression signal: verify the uploaded delta "
                "and SLA, then re-read the last diff before adding anything."
            )
    lines.append("")
    return "\n".join(lines)


def _already_fixed_text(patched: "list[VulnerabilityFinding]") -> str:
    """The vulnerabilities this job has ALREADY closed, by identity.

    The candidate tree the agent opens already contains these fixes, and a
    count alone does not stop it walking back to the same one — job
    c2c3cdb1f353 re-patched a single vulnerability across five attempts
    while being told each time only how many were done.
    """
    if not patched:
        return ""
    lines = ["# Already fixed in this job — do NOT patch these again", ""]
    seen: set[tuple[str, str]] = set()
    for finding in patched:
        key = (finding.bug_class, finding.path)
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"- {finding.bug_class} at {finding.path}:{finding.line} — "
            f"{finding.patch_description[:120]}"
        )
    lines.append("")
    lines.append(
        "The fix is already in the files you are about to read, so it will "
        "look correct. Find a DIFFERENT vulnerability, in different code. If "
        "you believe one of the above is still exploitable, say so in "
        "`summary` and fix the remaining hole rather than restating it."
    )
    lines.append("")
    return "\n".join(lines)


def _task_sentence(known: int | None, already: int) -> str:
    """What `done` means for this job, given the organizer's hint."""
    if not known:
        return TASK_UNKNOWN_COUNT
    remaining = max(0, known - already)
    if already and remaining:
        progress = (f"This job has already patched {already} of them, so about "
                    f"{remaining} should remain — find one of those.\n\n")
    elif already:
        progress = (f"This job has already patched {already}, which is all the "
                    "organizer announced. Look for one that was missed rather "
                    "than assuming the count is complete.\n\n")
    else:
        progress = ""
    return TASK_KNOWN_COUNT.format(
        count=known,
        noun="vulnerability" if known == 1 else "vulnerabilities",
        progress=progress,
    )


REVIEW_SYSTEM = LIVE_FIRE_INPUT_POLICY + """\
You are reviewing one failed attempt at patching a live CTF service. Answer
with at most six lines of plain text. Classify the failure as SOURCE_POLICY,
BUILD_AVAILABILITY, SLA_REGRESSION, SECURITY_PROBE, or FINDING_SCHEMA, then
give one concrete correction for the next attempt. Never recommend weakening
a gate, editing a protected path, or ignoring validator evidence. No code, no
preamble, no restating the errors back.
"""

REVIEW_TEMPLATE = """\
Attempt {attempt} did not pass.

Provider said: {summary}

Machine evidence — this is authoritative, the patch prose is not:
{errors}

Diff that was attempted:
{diff}
"""


# ---------------------------------------------------------------------------
def _discovery_text(discovery: Any) -> str:
    info = discovery.as_dict() if hasattr(discovery, "as_dict") else dict(discovery)
    lines = []
    for key in ("stacks", "entrypoints", "build_files", "health_hints"):
        values = info.get(key) or []
        if values:
            shown = ", ".join(str(v) for v in values[:12])
            more = f" (+{len(values) - 12} more)" if len(values) > 12 else ""
            lines.append(f"- {key}: {shown}{more}")
    return "\n".join(lines) or "- (static discovery found nothing to report)"


def _extract_json(text: str) -> dict[str, Any] | None:
    """Last fenced json block wins — a model often shows a draft first."""
    blocks = _JSON_BLOCK.findall(text or "")
    for raw in reversed(blocks):
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _repair_finding(
    raw: Any, diffs: tuple[DiffRecord, ...]
) -> tuple[VulnerabilityFinding | None, str]:
    """Return a finding the loop will accept, or None and why it was dropped.

    `_finding_errors` is all-or-nothing for the ATTEMPT, not for the finding:
    one invalid entry makes `report_errors` non-empty and `terminal_ready`
    false even when the patch itself was good. So a finding that cannot be
    made honest is dropped here rather than passed through to fail the run.

    Nothing is invented. An enum is only accepted when the model's own value
    maps onto it, and the line is only accepted when it is genuinely part of
    the diff — repairing that by picking a changed line at random would be
    fabricating the evidence the gate exists to check.
    """
    if not isinstance(raw, dict):
        return None, "finding is not an object"

    def _text(key: str) -> str:
        return str(raw.get(key) or "").strip()

    path = _text("path").lstrip("./")
    record = next((r for r in diffs if r.path == path), None)
    if record is None:
        # A model often reports the path with the archive prefix, or without
        # a directory it was told about. Try a unique suffix match before
        # giving up; ambiguity is a drop, not a guess.
        matches = [r for r in diffs if r.path.endswith("/" + path) or path.endswith("/" + r.path)]
        if len(matches) == 1:
            record = matches[0]
        else:
            return None, f"path {path!r} is not in the diff"

    try:
        line = int(raw.get("line"))
    except (TypeError, ValueError):
        return None, f"{record.path}: line is not an integer"
    # The SAME two fields `_location_matches_diff` reads. Recomputing the
    # changed set here would be a second implementation of "a changed line",
    # free to drift from the gate this has to satisfy — and an earlier draft
    # of this function did exactly that against attributes DiffRecord does not
    # have, which silently made every line acceptable.
    if not (1 <= line <= record.candidate_line_count
            and line in record.changed_lines):
        return None, (
            f"{record.path}:{line} is not a changed line "
            f"(changed: {sorted(record.changed_lines)[:8]})"
        )

    severity = _text("severity").lower()
    mitigation = _text("mitigation_class").lower()
    tier = _text("evidence_tier").upper()
    if severity not in SEVERITIES:
        return None, f"{record.path}: severity {severity!r} is not one of {sorted(SEVERITIES)}"
    if mitigation not in MITIGATION_CLASSES:
        return None, (
            f"{record.path}: mitigation_class {mitigation!r} is not one of "
            f"{sorted(MITIGATION_CLASSES)}"
        )
    if tier not in EVIDENCE_TIERS:
        return None, f"{record.path}: evidence_tier {tier!r} is not one of {sorted(EVIDENCE_TIERS)}"
    for key in ("bug_class", "root_cause", "attack_impact",
                "patch_description", "patch_reason"):
        if not _text(key):
            return None, f"{record.path}: {key} is empty"
    return VulnerabilityFinding(
        bug_class=_text("bug_class"),
        severity=severity,
        path=record.path,
        line=line,
        root_cause=_text("root_cause"),
        attack_impact=_text("attack_impact"),
        patch_description=_text("patch_description"),
        patch_reason=_text("patch_reason"),
        mitigation_class=mitigation,
        evidence_tier=tier,
    ), ""


# ---------------------------------------------------------------------------
class LiveFireInvoker:
    """Runs the routed agent for `main` and `reviewer`; renders `report`."""

    def __init__(self, job_id: str, *, log=None, candidate_diff=None) -> None:
        self.job_id = str(job_id)
        self._log = log or (lambda _m: None)
        # Injected so the patch loop's own differ is the single source of what
        # "a changed line" means; a second implementation here would drift from
        # the gate it has to satisfy.
        self._candidate_diff = candidate_diff
        # HOW A TURN ENDED, kept where `_run_agent` can read it back.
        # `_drain` walked past `ResultMessage` and kept only `TextBlock`s, so
        # a turn the adapter had KILLED came back as an ordinary string and
        # every caller recorded it as an answer. Thread-local because the
        # live-fire round runs one plan agent per scope at the same time
        # through a single invoker.
        self._turn = threading.local()
        # Findings accepted across attempts in THIS job. The loop keeps only
        # the last attempt's, and the prompt needs all of them — by IDENTITY,
        # not just by count. Job c2c3cdb1f353 was told only how many it had
        # patched, four times running, and went back to the same vulnerability
        # every time: a number cannot say WHICH one is already done.
        self._patched: list[VulnerabilityFinding] = []
        # Set once a provider failure that cannot be retried is seen. Every
        # later role returns immediately instead of spending another call on
        # the same answer.
        self._fatal: str = ""

    # -- transport ---------------------------------------------------------
    def run_turn(
        self, call: AgentCall, system_prompt: str, prompt: str,
        *, cwd: Path, turn_timeout_s: float, tools: bool,
    ) -> tuple[str, AgentUsage]:
        """One agent turn, for callers outside this module's own role map.

        v1's three roles are dispatched by `invoke`; v2 has four of its own and
        needs the same transport without that dispatch. This is a public name
        for the seam `_run_agent` already was, so live_fire_v2_job does not
        have to reach into a private one and quietly break when it is renamed.
        """

        return self._run_agent(
            call, system_prompt, prompt,
            cwd=cwd, turn_timeout_s=turn_timeout_s, tools=tools,
        )

    def _run_agent(
        self, call: AgentCall, system_prompt: str, prompt: str,
        *, cwd: Path, turn_timeout_s: float, tools: bool,
    ) -> tuple[str, AgentUsage]:
        """Short-circuit, run, classify. The provider call itself is
        `_invoke_provider`, kept separate so a test can drive this wrapper —
        which owns the only logic here — without a model."""
        provider = call.route.provider
        model = call.route.model
        if self._fatal:
            return "", AgentUsage(model=model, error_kind="auth")
        self._log(
            f"LIVE_FIRE {call.route.role} agent starting "
            f"({provider}/{model}, budget {turn_timeout_s:.0f}s"
            + (", tools on)" if tools else ", read-only)")
        )
        started = time.monotonic()
        # Cleared before the call, not after: this thread may have run an
        # earlier turn and a stale reason would libel the next agent.
        self._turn.stop_reason = None
        try:
            text = self._invoke_provider(
                call, system_prompt, prompt,
                cwd=cwd, turn_timeout_s=turn_timeout_s, tools=tools,
            )
            error_kind = None
        except Exception as exc:  # noqa: BLE001 - the loop must see a status
            self._log(f"LIVE_FIRE {call.route.role} agent failed: "
                      f"{type(exc).__name__}: {exc}")
            text = ""
            error_kind = type(exc).__name__
        # A CUT TURN IS NOT AN ANSWER. Read off the adapter's typed field
        # rather than its prose: matching "[Codex CLI turn timed out after
        # 900s]" would break on the first upstream reword, and would miss
        # grok's "turn_budget" entirely. The TEXT IS STILL RETURNED -- an
        # agent that finished a complete answer and was then cut while idling
        # has work worth parsing, and discarding it here would throw away the
        # thing a shorter-answer prompt exists to produce.
        if error_kind is None and getattr(self._turn, "stop_reason", None) in (
                "timeout", "turn_budget"):
            error_kind = "timeout"
        marker = _fatal_reason(text)
        if marker:
            self._fatal = marker
            error_kind = "auth"
            self._log(
                f"LIVE_FIRE provider is unusable ({marker}); remaining "
                "attempts will not call it again — re-authenticate and re-run"
            )
        self._log(
            f"LIVE_FIRE {call.route.role} via {provider}/{model} "
            f"in {time.monotonic() - started:.0f}s, {len(text)} chars"
        )
        return text, AgentUsage(model=model, error_kind=error_kind)

    def _invoke_provider(
        self, call: AgentCall, system_prompt: str, prompt: str,
        *, cwd: Path, turn_timeout_s: float, tools: bool,
    ) -> str:
        provider = call.route.provider
        model = call.route.model
        from modules._common import (
            agent_heartbeat,
            capture_session_id,
            read_meta,
            resolve_effort,
            tool_result_lines,
            tool_use_line,
        )
        effort = resolve_effort((read_meta(self.job_id) or {}).get("effort"))
        env = {"JOB_ID": self.job_id}

        # Stream, do not collect-then-summarise. The first version of this
        # wrote ONE line, after the turn ended: a live-fire job showed 75 bytes
        # of run.log for twenty minutes of a codex process working hard, and
        # from the dashboard it was indistinguishable from a hung job. Every
        # other module in this repo logs AGENT/TOOL/TOOL_RESULT as it goes, and
        # so does this now — the same three helpers, so the lines look the same
        # in the same viewer.
        #
        # `agent_heartbeat` is not decoration either: it is what writes
        # `last_agent_event_at`, `last_event_kind` and the token/cost totals
        # the usage chip reads. Without it meta says the agent has never
        # emitted anything.
        def _stream(msg) -> None:
            capture_session_id(msg, self.job_id)
            agent_heartbeat(self.job_id, msg)
            kind = type(msg).__name__
            if kind == "UserMessage":
                # Tool RESULTS. Job 7d409c40249e logged 41 commands and zero
                # outputs before misc grew this branch; the same client is
                # under this one.
                for line in tool_result_lines(msg):
                    self._log(line)
                return
            for block in (getattr(msg, "content", None) or []):
                name = type(block).__name__
                if name == "TextBlock":
                    text = getattr(block, "text", "") or ""
                    if text.strip():
                        self._log(f"AGENT: {text[:500]}")
                elif name == "ToolUseBlock":
                    self._log(tool_use_line(block))

        async def _drain(client) -> str:
            await client.query(prompt)
            chunks: list[str] = []
            async for msg in client.receive_response():
                _stream(msg)
                # THE ADAPTER ALREADY SAYS HOW THE TURN ENDED and this loop
                # used to walk past it: codex yields
                # ResultMessage(is_error=True, stop_reason="timeout") after
                # killing the process group, grok yields "turn_budget" after
                # flushing what it had. Keeping only the text made a killed
                # agent and a finished one indistinguishable to the caller.
                reason = getattr(msg, "stop_reason", None)
                if reason:
                    self._turn.stop_reason = str(reason)
                for block in (getattr(msg, "content", None) or []):
                    if type(block).__name__ == "TextBlock":
                        chunks.append(getattr(block, "text", "") or "")
            return "\n".join(chunks)

        if provider == "gpt":
            from modules.gpt_agent import GptAgentClient, GptSessionOptions

            async def _go() -> str:
                opts = GptSessionOptions(
                    system_prompt=system_prompt, model=model, cwd=str(cwd),
                    effort=effort, env=env, enable_tools=tools,
                    enable_subagents=False, turn_timeout_s=turn_timeout_s,
                    # THE CWD IS THE TREE BEING AUDITED, and that makes agent
                    # tooling dangerous in a way it is nowhere else:
                    # `acquire_turn_guard` opens `<cwd>/.codex-turn.lock`,
                    # `_candidate_inventory_errors` rejects any path not in the
                    # input manifest, and a rejected inventory RESTORES the
                    # candidate — so the lock file silently threw away the
                    # patch. Job 5df30344f339 lost a real fix that way.
                    #
                    # `concurrent_child` skips the guard, which is exactly
                    # right here rather than merely convenient: it also implies
                    # `--ephemeral`, and live-fire never resumes a session. The
                    # operator's stop fence still applies (`check_turn_stop`
                    # only reads). One live-fire agent runs at a time, so there
                    # is no concurrency the lock was protecting.
                    concurrent_child=True,
                )
                async with GptAgentClient(opts) as client:
                    return await _drain(client)
        elif provider == "grok":
            from modules.grok_acp import GrokACPClient, GrokSessionOptions
            from modules._prompts import adapt_system_prompt_for_grok

            async def _go() -> str:
                opts = GrokSessionOptions(
                    system_prompt=adapt_system_prompt_for_grok(system_prompt),
                    model=model, cwd=str(cwd), effort=effort, env=env,
                    turn_timeout_s=turn_timeout_s,
                )
                async with GrokACPClient(opts) as client:
                    return await _drain(client)
        else:
            from claude_agent_sdk import ClaudeAgentOptions, query

            async def _go() -> str:
                options = ClaudeAgentOptions(
                    max_buffer_size=AGENT_MAX_BUFFER_BYTES,
                    system_prompt=system_prompt, model=model, cwd=str(cwd),
                    allowed_tools=(["Read", "Bash", "Glob", "Grep", "Edit", "Write"]
                                   if tools else ["Read", "Glob", "Grep"]),
                    permission_mode="bypassPermissions", env=env,
                )
                chunks: list[str] = []
                async for msg in query(prompt=prompt, options=options):
                    _stream(msg)
                    for block in (getattr(msg, "content", None) or []):
                        if type(block).__name__ == "TextBlock":
                            chunks.append(getattr(block, "text", "") or "")
                return "\n".join(chunks)

        return asyncio.run(_go())

    @staticmethod
    def _sweep_agent_scratch(candidate: Path) -> list[str]:
        """Remove agent TOOLING files from the audited tree. Nothing else.

        `concurrent_child` stops codex writing its lock, but every agent
        runtime drops something in its working directory sooner or later, and
        in this one directory an extra file is not untidy — it fails the
        inventory, which restores the candidate and destroys the patch.

        The names are IMPORTED from the module that creates them, never
        retyped, and the sweep is limited to that exact set at the tree root.
        Widening it to "any file the manifest does not know" would be the same
        function as the inventory check, with the opposite sign: it would
        quietly delete a file the agent added in violation of the policy and
        hide the violation the check exists to report.
        """
        from modules.codex_turn_guard import TURN_LOCK_FILENAME, TURN_STOP_FILENAME

        removed: list[str] = []
        for name in (TURN_LOCK_FILENAME, TURN_STOP_FILENAME):
            path = candidate / name
            try:
                if path.is_file():
                    path.unlink()
                    removed.append(name)
            except OSError:
                pass
        return removed

    # -- roles -------------------------------------------------------------
    def _main(self, call: AgentCall) -> AgentInvocationResult:
        context = call.payload
        remaining = context.attempt_deadline - time.monotonic()
        if remaining < MIN_TURN_S:
            return AgentInvocationResult(
                value=ProviderResult(
                    "timeout",
                    f"only {remaining:.0f}s left before the reserved deadline",
                ),
                usage=AgentUsage(model=call.route.model, error_kind="no_budget"),
            )
        feedback = ""
        if context.feedback:
            feedback = ("\nPrevious attempts were rejected. Reviewer notes:\n"
                        + "\n".join(f"- {hint}" for hint in context.feedback))
        from modules._common import read_meta

        meta = read_meta(self.job_id) or {}
        known = meta.get("live_fire_known_vulnerabilities")
        known = int(known) if isinstance(known, int) and known > 0 else None
        # What this job has ALREADY fixed, so a second attempt is told what it
        # still owes rather than being asked for N again from scratch.
        already = len({(f.bug_class, f.path) for f in self._patched})
        from modules._common import job_dir

        prompt = MAIN_TEMPLATE.format(
            discovery=_discovery_text(context.discovery),
            attempt=context.attempt,
            task=_task_sentence(known, already),
            already_fixed=_already_fixed_text(self._patched),
            round_feedback=_round_feedback(job_dir(self.job_id)),
            feedback=feedback,
        )
        text, usage = self._run_agent(
            call, MAIN_SYSTEM, prompt,
            cwd=context.candidate, turn_timeout_s=remaining, tools=True,
        )
        for name in self._sweep_agent_scratch(context.candidate):
            self._log(f"LIVE_FIRE removed agent scratch from the candidate: {name}")
        if self._fatal:
            return AgentInvocationResult(
                value=ProviderResult(
                    "failure",
                    f"provider unusable: {self._fatal} — re-authenticate and "
                    "re-run; no further attempt was spent on it",
                ),
                usage=usage,
            )
        if not text:
            return AgentInvocationResult(
                value=ProviderResult("failure", "patch agent produced no answer"),
                usage=usage,
            )

        # The DIFF is the fact. Whatever the model claimed, the findings are
        # checked against what actually changed on disk.
        diffs = self._candidate_diff() if self._candidate_diff else ()
        payload = _extract_json(text) or {}
        raw_findings = payload.get("findings")
        findings: list[VulnerabilityFinding] = []
        dropped: list[str] = []
        for item in (raw_findings if isinstance(raw_findings, list) else []):
            finding, why = _repair_finding(item, diffs)
            if finding is not None:
                findings.append(finding)
            else:
                dropped.append(why)
        for why in dropped:
            self._log(f"LIVE_FIRE dropped finding: {why}")

        if len(findings) > 1:
            # The prompt asks for one. A model that returns several has still
            # made one diff, and rejecting the attempt over it would throw away
            # a real patch — but the version must stay attributable, so only
            # the most severe survives and the rest are said out loud.
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            findings.sort(key=lambda f: order.get(f.severity, 9))
            dropped.append(
                "attempt reported "
                + str(len(findings))
                + " findings; kept the most severe so the patch version stays "
                  "one attributable change"
            )
            findings = findings[:1]
        self._patched.extend(findings)
        status = str(payload.get("status") or "").strip().lower()
        if status not in {"success", "failure", "timeout"}:
            status = "success" if findings else "failure"
        if status == "success" and not findings:
            # The loop rejects this combination anyway ("successful provider
            # result has no vulnerability finding"); saying why here is what
            # the reviewer sees next attempt.
            status = "failure"
        summary = str(payload.get("summary") or "").strip()
        if dropped:
            summary = (summary + " | dropped findings: "
                       + "; ".join(dropped[:3]))[:600]
        if not summary:
            summary = "patch agent returned no summary"
        return AgentInvocationResult(
            value=ProviderResult(
                status, summary, findings=tuple(findings),
                ready_recommendation=bool(findings),
            ),
            usage=usage,
        )

    def _reviewer(self, call: AgentCall) -> AgentInvocationResult:
        context: ReviewContext = call.payload
        errors = list(context.policy_errors) + list(context.machine_errors) \
            + list(context.report_errors)
        prompt = REVIEW_TEMPLATE.format(
            attempt=context.attempt,
            summary=context.provider.summary or "(none)",
            errors="\n".join(f"- {e}" for e in errors[:20]) or "- (none recorded)",
            diff=(context.diff or "(empty)")[:8000],
        )
        text, usage = self._run_agent(
            call, REVIEW_SYSTEM, prompt,
            cwd=Path.cwd(), turn_timeout_s=REVIEW_TURN_S, tools=False,
        )
        if self._fatal:
            return AgentInvocationResult(
                value=ReviewResult(
                    f"provider unusable: {self._fatal}; no review was requested"
                ),
                usage=usage,
            )
        hint = (text or "").strip()
        if not hint:
            hint = "reviewer produced no hint; use the machine evidence directly"
        return AgentInvocationResult(value=ReviewResult(hint[:2000]), usage=usage)

    def _report(self, call: AgentCall) -> AgentInvocationResult:
        # Deterministic on purpose — see the module docstring. No model call,
        # so the ledger row records a zero-cost deterministic render rather
        # than pretending a provider was used.
        context: ReportContext = call.payload
        return AgentInvocationResult(
            value=_render_report(context.document, context.findings, context.diffs),
            usage=AgentUsage(model=None, cost_basis="none", runtime="deterministic"),
        )

    def invoke(self, call: AgentCall) -> AgentInvocationResult:
        if call.route.role == "main":
            return self._main(call)
        if call.route.role == "reviewer":
            return self._reviewer(call)
        return self._report(call)


__all__ = ["LiveFireInvoker", "MAIN_SYSTEM", "MAIN_TEMPLATE"]
