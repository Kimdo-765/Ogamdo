"""Flag harvester — a model that reads what the regex could not.

WHY THIS EXISTS

`_accumulate_flag_candidates` (modules/_common.py) already scans every streamed
SDK message and fills `meta.flag_candidates` in real time, bypassing the
heartbeat throttle so a hit reaches the UI immediately. Latency is not the
problem. JUDGEMENT is: its only filter is `FLAG_RE`, a fixed alphabet of ~20
known prefixes (DH, picoCTF, HTB, ...), plus a lexical placeholder blocklist.

A flag whose prefix is not on that list is invisible to it. Job 29f1d8f14268
captured `REVERSSEUM{...}`; job fed8eedff33d captured `pokactf2024{...}`.
Neither prefix is in FLAG_RE. Both were recovered only because the solver
happened to print the `FLAG_CANDIDATE:` marker — the operator's point exactly:
"정규식 매칭이 가끔 flag를 못찾을 경우가 있어서."

So this role adjudicates. It is ADVISORY ONLY and writes exactly one artifact,
`<jobdir>/flag_grain.txt`. It cannot write `meta.flags`, cannot set a status,
and cannot end a job.

THAT RESTRICTION IS NOT TIDINESS — IT IS THE WHOLE SAFETY ARGUMENT.

run.log was deliberately REMOVED from `_NARRATIVE_FLAG_SOURCES` on 2026-07-23
(modules/_common.py) because it is the raw interleaved firehose, and three jobs
paid for it: dc981a8c4741 false-finished on a flag scraped out of a recon
WebSearch summary; 44dd25365173 shipped four fabricated `DH{<sha256>}` values;
f52f0219803f produced four fake entries when judge subagents `Read` exploit.py
and echoed its literal `print("FLAG_CANDIDATE: ...")` SOURCE.

Reading run.log for flags re-enters that class by construction. Every one of
those failures was "a fake flag ended the job". A harvester that can only
append to a text file cannot reproduce any of them. The defences below reduce
noise; the write restriction is what makes the noise harmless.

INPUT — appended bytes only, never a re-read

Both sources are append-only, so the loop stores a byte offset per file in
`.harvester.state`, seeks there, and reads to EOF. The offset survives an API
restart.

One correctness detail that the monitor does NOT get right, and that matters
far more here than there: a poll can land mid-write. `splitlines()` would then
hand back a truncated tail as if it were a line, and the offset would advance
past it — so a flag's head and its tail arrive as two
fragments and NEITHER contains a flag. The monitor summarises prose, so it
survives that; this module's entire job is the exact string. Hence
`_consume_whole_lines`: the trailing partial line is not consumed and the
offset stops at the last newline, so the fragment is re-read complete on the
next pass. Costs up to one poll interval; never splits a flag.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from modules._sdk_buffer import AGENT_MAX_BUFFER_BYTES

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/data/jobs"))

# Absolute kill switch, mirroring MONITOR_ENABLED. The Settings toggle
# (settings_io.flag_harvester_enabled) is the operator-facing one.
HARVESTER_ENABLED = os.environ.get("HARVESTER_ENABLED", "1") != "0"
HARVESTER_MODEL = os.environ.get("HARVESTER_MODEL", "claude-sonnet-4-6")

# 2.0s, not the monitor's 4.0s: the stated goal is submitting before another
# team. The runner already lands its stdout in run.log within 2.0s
# (_runner.py:_POLL_INTERVAL_S), so this keeps the two hops matched.
POLL_S = 2.0
BATCH_MAX = 8            # adjudicate once this many candidate lines are pending
BATCH_MAX_S = 6.0        # ...or once this long has elapsed with >= 1 pending
# Operator decision, 2026-09-08: 60 -> 150 s, on measurement rather than on a
# failure count. Job d94336686a22's own batches, replayed through _adjudicate:
#
#   batch 0  12,532 chars   at 60 s: 61.6 s FAIL   at 300 s: 76.6 s ok, 8 finds
#   batch 3   2,218 chars   at 60 s: 61.4 s FAIL   at 300 s: 53.6 s ok, 2 finds
#   batch 1     675 chars   at 60 s: 34.2 s ok
#
# So the model was never hanging — judging a decoy-rich forensic batch (this
# challenge plants 64 candidates against a normal job's 8) simply takes 50-80 s,
# and every one of the 3 retries died on the same deadline for the same reason.
# That is why the counts reproduced exactly across two runs of the same image
# (failed=12, dropped=3 both times) and why batch 3, which straddles the line,
# passed once and failed once. The 8 findings in batch 0 were real and thrown
# away.
#
# 150 is ~2x the observed maximum, which covers the run-to-run variance that
# put batch 3 on both sides of 60. It is not free: a genuinely stuck call now
# holds a batch for 150 x ADJUDICATE_TRIES = 7.5 min instead of 3. That is
# affordable because the drain runs until `pending` empties rather than on a
# clock, so it delays no job, and because the harvester is advisory —
# scan_job_for_flags carries the flag path on its own.
#
# An earlier note here said not to raise this off a failure count. That still
# holds; what changed is that this is not a failure count, it is a measurement.
ADJUDICATE_TIMEOUT_S = 150.0
ADJUDICATE_TRIES = 3     # a failed adjudication is retried, never silently dropped
DRAIN_QUIET_POLLS = 10   # consecutive polls with no new bytes before giving up.
# DRAIN_MAX_S is NOT an absolute cap on how long the harvester outlives the
# job. The drain branch is guarded by `terminal and not pending`, so a run with
# a standing backlog never enters it, never sets `term_at`, and never consults
# this number. Job d94336686a22 was still accepting candidates seven minutes
# after its status flipped — correct behaviour (finish judging what was already
# read) but not what "absolute cap" promised, and the wrong word cost a wrong
# prediction about when its tally would land.
                         # 10 x POLL_S = 20 s, sized against the measured gap on
                         # 19cf9578a0fc: `finished` at 10:41:03, winning flag line
                         # at 10:41:16. A shorter window is blind to that job.
DRAIN_MAX_S = 180.0      # cap on the QUIET drain — see note below
BODY_MAX = 2000          # per-line clip before the model ever sees it
CONTEXT_LINES = 2        # neighbours kept with a hit, so the model can see
                         # whether it is output or source code
SUPERVISOR_S = 8.0
OUT_NAME = "flag_grain.txt"
STATE_NAME = ".harvester.state"

# The gate is deliberately LOOSER than FLAG_RE — that is the entire point.
# FLAG_RE demands a known prefix; this accepts ANY short token followed by a
# braced body, which is what `REVERSSEUM{...}` and `pokactf2024{...}` are.
#
# The body charset is the narrowing that keeps "looser" from meaning "useless".
# Measured on job 48fadce3dde7, whose agent curled 2.4 MB of blog write-ups:
# the old `[^\s{}]` body admitted `html{box-sizing:border-box}`,
# `to{transform:rotate(360deg)}`, `root{--ds-gray-900:#666;...}`,
# `try{console.log(x,eval(x))}` and `delay.{cc,h}` — CSS rules, JS blocks and
# shell brace expansion, all shaped exactly like `token{body}`.
#
# Every real flag this platform has captured is [A-Za-z0-9_-] inside the
# braces: REVERSSEUM{…}, pokactf2024{…}, INCOGNITO{…},
# DH{…}. Excluding `:;(),{}#$` and quotes drops every one of those noise
# shapes and keeps all five known captures. It is a charset rule, not a
# keyword blocklist, so a new CTF's prefix still passes.
_BRACE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,30}\{[A-Za-z0-9_!@^*+=/.\-]{6,200}\}")
_MARKER_RE = re.compile(r"FLAG[_-]?CANDIDATE\s*[:=]", re.IGNORECASE)
# Our OWN scaffolding. _prompts.py instructs the agent to plant local test
# flags in a deliberately non-real shape, `LOCAL{...}`, exactly so they cannot
# be mistaken for the real thing; job_flag_format_re already drops them. The
# harvester was the one net that did not.
_LOCAL_PLANT_RE = re.compile(r"\bLOCAL\{[^}]{0,200}\}")
_TS_RE = re.compile(r"^\[(\d\d:\d\d:\d\d)\]\s*(.*)$")

# Lines that are code, not output. f52f0219803f is the whole reason: judge
# subagents Read exploit.py and echoed its own print() statement, and four
# fabricated flags followed. A brace-shape sitting inside quotes next to a
# print/format call is a literal in a program, not something a program emitted.
_SOURCE_HINT_RE = re.compile(
    r"""(?x)
    (?: \bprint\s*\(            # print("FLAG_CANDIDATE: " ...)
      | \bf" | \bf'             # f-string
      | %s | \{\}               # format placeholders
      | \bre\.(?:search|match|findall|compile)\b
      | \bFLAG_RE\b
      | ^\s*\#                  # a comment
      | ^\s*(?:\d+\s*[|:]\s)    # `93| ` / `93: ` numbered source listing
      | ^\s*\d+\t                # `16<TAB>const FLAG = ...` — the TAB form,
                                  # which the pattern above missed and which is
                                  # what `sed -n`/Read output actually emits.
    )"""
)

# Lines carrying escaped markup are a page the agent FETCHED, not output the
# run produced. Job 48fadce3dde7's only harvester false positive came in as
#   &lt;p style=&quot;...&quot; data-ke-size=&quot;size16&quot;&gt;flag : codegate2025{...}
# — a Tistory write-up about a DIFFERENT CTF, which the model then accepted at
# 0.82 because nothing told it the line was quoted markup.
#
# NOT a rejection: a web challenge's real flag can legitimately arrive inside
# an HTML response, and dropping those would break the module this feature was
# just extended to. The line is passed to the model with its source ANNOTATED
# instead, so the judgement is made with the fact rather than without it.
_HTML_ESCAPED_RE = re.compile(r"&(?:lt|gt|quot|amp|nbsp|#\d{2,5});")


def looks_fetched(line: str) -> bool:
    """True when the line is escaped markup from a page, not run output."""
    return bool(_HTML_ESCAPED_RE.search(line or ""))

_TASKS: dict[str, asyncio.Task] = {}
# `hold` joins these for the same reason as in _monitor: a held run grows no
# log, so the watcher would idle forever holding its slot. Draining on the
# way out is the point, not a side effect — a run can be held *after* a
# candidate was already seen, and that candidate deserves adjudication now
# rather than whenever the operator gets around to a new target.
_TERMINAL = {"finished", "failed", "stopped", "error", "no_flag",
             "flag_ready", "hold"}


def harvester_enabled() -> bool:
    """Both switches must agree before any per-job task is created.

    Resolved per call so the Settings toggle takes effect without an API
    restart — a module constant would freeze the operator's choice.
    """
    if not HARVESTER_ENABLED:
        return False
    try:
        from modules.settings_io import flag_harvester_enabled
    except Exception:
        return False
    try:
        return bool(flag_harvester_enabled())
    except Exception:
        return False


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _consume_whole_lines(path: Path, off: int) -> tuple[list[str], int]:
    """Read appended bytes and return (complete lines, new offset).

    Stops at the last newline. A trailing partial line is left unconsumed and
    the offset does not advance past it, so the next pass sees it whole. This
    is the difference between reading a flag and reading half of one.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return [], off
    if off > size:
        # Truncated or replaced under us — start over rather than seek past EOF.
        off = 0
    if size <= off:
        return [], off
    try:
        with path.open("rb") as fp:
            fp.seek(off)
            data = fp.read()
    except OSError:
        return [], off
    if not data:
        return [], off
    cut = data.rfind(b"\n") + 1
    if cut <= 0:
        # A very long line still being written: consume nothing, wait for it.
        return [], off
    chunk = data[:cut]
    return chunk.decode("utf-8", "replace").splitlines(), off + cut


def _looks_like_source(line: str) -> bool:
    return bool(_SOURCE_HINT_RE.search(line))


def _interesting(line: str) -> bool:
    """Structural prefilter — what reaches the model at all.

    No cost ceiling is applied anywhere in this module (the operator is the
    only brake, by design). The model is kept cheap structurally instead: it
    adjudicates candidate lines, it never reads the firehose.
    """
    if not line:
        return False
    if _looks_like_source(line):
        return False
    # On 19cf9578a0fc the harvester reported `LOCAL{0123456789abcdef...}` at
    # 0.86 while the real flag (value withheld) went unreported. The line
    # that convinced it was the LOCAL container echoing the planted value back
    # over HTTP — which reads exactly like output the run produced, and no
    # prompt rule survives that. So the value is excluded structurally, before
    # the model is ever asked. Scrubbed for the DECISION only: a line carrying
    # both a plant and a real candidate still passes, whole and unedited.
    probe = _LOCAL_PLANT_RE.sub("", line)
    if _BRACE_RE.search(probe):
        return True
    if _LOCAL_PLANT_RE.search(line):
        return False          # the only braced value on the line is ours
    return bool(_MARKER_RE.search(probe))


def _body_of(raw: str) -> str:
    m = _TS_RE.match(raw)
    body = m.group(2) if m else raw
    return body[:BODY_MAX]


def _role_of_event(d: dict) -> str:
    return str(d.get("role") or "?")


def _scan_events(lines: list[str]) -> list[tuple[str, str]]:
    """Pull candidate text out of gpt-events.jsonl lines.

    This source carries the emitting ROLE, which run.log's flat text does not.
    dc981a8c4741 false-finished on a flag lifted from a recon WebSearch
    summary; knowing a hit came from `recon` rather than the sandbox is
    exactly the discriminator that failure needed.
    """
    out: list[tuple[str, str]] = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            d = json.loads(raw)
        except Exception:
            continue
        parts = [d.get("summary") or "", d.get("detail") or ""]
        for text in parts:
            if not isinstance(text, str) or not text:
                continue
            for seg in text.splitlines():
                seg = seg.strip()
                if _interesting(seg):
                    src = f"{_role_of_event(d)}/{d.get('tool') or d.get('kind') or 'msg'}"
                    if looks_fetched(seg):
                        src += ":fetched-page"
                    out.append((src, seg[:BODY_MAX]))
    return out


_SYS_PROMPT = """You adjudicate CTF flag candidates.

You are shown lines harvested from a running CTF solve. Some contain a
brace-shaped string. Decide, for each DISTINCT braced string, whether it is a
REAL flag the run captured, or not.

Reject, with reason:
- a placeholder or example (fake, example, test, dummy, XXXX, redacted, ...)
- a string that appears inside SOURCE CODE (a print() argument, a regex, an
  f-string, a numbered source listing) rather than in program OUTPUT
- a string the line itself presents as quoted from documentation, a
  write-up, or a search result
- ANY string on a line whose source is tagged `:fetched-page`. That tag means
  the line is escaped markup from a page the run downloaded, not output the
  run produced. A flag inside someone else's write-up is not this run's flag —
  reject it unless the line also shows the target responding. Job
  48fadce3dde7 fetched a blog about a different CTF and its flag was accepted;
  that is the mistake this tag exists to prevent.
- a flag whose prefix belongs to a different competition than the one being
  solved (e.g. a codegate flag while the target is a dreamhack host)
- a locally-planted test flag, when the line says so
- a format specifier or template such as FLAG{...} used as a shape

Accept only when the line reads as OUTPUT the run actually produced.

You have NO TOOLS and MUST NOT try to use any. Do not search the web, read
files, or run commands — the harness is text-only and a tool attempt discards
your whole answer. Judge ONLY from the lines given. When they are not enough
to be sure, still answer: give your best verdict with a lower confidence.
Never reply with anything but the JSON object.

Reply with STRICT JSON, no prose, no code fence:
{"findings":[{"flag":"<exact string>","verdict":"real"|"rejected",
  "confidence":0.0-1.0,"why":"<one short clause>"}]}
Return {"findings":[]} if nothing qualifies."""


def _parse_findings(acc: str) -> list[dict]:
    acc = (acc or "").strip()
    if not acc:
        return []
    if acc.startswith("```"):
        acc = acc.split("\n", 1)[1] if "\n" in acc else acc[3:]
        if acc.endswith("```"):
            acc = acc[:-3]
        acc = acc.strip()
    if "{" in acc and "}" in acc:
        acc = acc[acc.find("{"): acc.rfind("}") + 1]
    try:
        d = json.loads(acc)
    except Exception:
        return []
    if not isinstance(d, dict):
        return []
    items = d.get("findings")
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        flag = str(it.get("flag") or "").strip()
        if not flag:
            continue
        try:
            conf = float(it.get("confidence") or 0.0)
        except Exception:
            conf = 0.0
        out.append({
            "flag": flag,
            "verdict": "real" if str(it.get("verdict")) == "real" else "rejected",
            "confidence": max(0.0, min(1.0, conf)),
            "why": str(it.get("why") or "")[:200],
        })
    return out


_LAST_ERROR: dict[str, str] = {}


def note_error(job_id: str, detail: str) -> bool:
    """Record an adjudication failure in flag_grain.txt, once per distinct one.

    Job 8e12a5fb1475 is why this exists. A grok-routed harvester consumed the
    line `FLAG_CANDIDATE: INCOGNITO{...}`, passed it through the gate, called
    the model — and wrote nothing, because the model tried a `Web search:` the
    text-only helper refuses:

        tool_use_in_text_only_role: grok attempted `Web search:` in a helper
        that is text-only on the Claude path

    From the outside that was indistinguishable from "the model looked and
    found nothing", which is the exact failure this module's docstring warned
    about and then shipped anyway. An advisory component that cannot report
    its own silence is not advisory, it is decorative.
    """
    if not detail or _LAST_ERROR.get(job_id) == detail:
        return False
    _LAST_ERROR[job_id] = detail
    out = _outfile(job_id)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as fp:
            fp.write(f"error\tat={time.strftime('%H:%M:%S')}\tdetail={detail[:300]}\n")
    except Exception:
        return False
    return True


def note_tally(job_id: str, ok: int, accepted: int, fail: int, drop: int) -> bool:
    """Write the run's adjudication counts once, when the harvester drains.

    `note_error` says an advisory component that cannot report its own silence
    is decorative. A FAILED adjudication reports itself; a SUCCESSFUL one that
    judged nothing does not, and from outside the two are the same absence.
    That gap made job 5c4a18e68834 unreadable: flag_grain.txt held twelve
    `TimeoutError` lines and no accepted candidate, and nothing in the file
    could say whether that was twelve failures out of twelve attempts or
    twelve failures among a hundred quiet successes. Those are different
    diagnoses — the first is a broken harvester, the second is a harvester
    working on a job with no candidates in it — and picking between them cost
    an investigation that measured grok at 20.7 s on a full-size batch and
    still could not close the question.

    One line at the end settles it for the next occurrence. It is written on
    the drain path only; a cancelled harvester leaves no tally, which is
    itself distinguishable from a tally of zeros.

    `accepted` is what `append_grain` actually WROTE, not what `_adjudicate`
    returned. The first version of this counted returned batches and called
    them `with_findings`, which job 4aa002418ca0 immediately made a lie:
    `with_findings=3` printed above a file holding no candidate at all,
    because `append_grain` keeps only `verdict == "real"` and drops repeats.
    Counting the write means the number cross-checks the file it sits in —
    `accepted` equals the `flag=` lines that run added.
    """

    out = _outfile(job_id)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as fp:
            fp.write(
                f"tally\tat={time.strftime('%H:%M:%S')}\tadjudicated={ok}"
                f"\taccepted={accepted}\tfailed={fail}\tdropped={drop}\n")
    except Exception:
        return False
    return True


def _format_context(job_id: str | None) -> str:
    """The operator's declared shape, handed over as EVIDENCE — never a gate.

    This module exists because `job_flag_format_re` sometimes misses. Making a
    format match REQUIRED would punch the same hole in both nets: one operator
    typo, or a real flag the declared regex does not quite describe, and the
    sweep misses it and the harvester now refuses it too. Finding what the
    automatic matcher could not is the entire feature. So the shape raises or
    lowers confidence and never decides alone.
    """
    if not job_id:
        return ""
    fmt = (_read_json(JOBS_DIR / Path(job_id).name / "meta.json")
           .get("flag_format") or "").strip()
    if not fmt:
        return ""
    return (
        "\n\nThe operator declared this challenge's flag shape as:\n"
        f"    {fmt}\n"
        "Treat it as EVIDENCE, not as a filter. A string matching it is very "
        "likely the real flag. A string NOT matching it needs the line itself "
        "to carry the weight — a value the target actually returned — and "
        "should be reported with lower confidence. Never reject a string for "
        "its shape alone: the declared format can be wrong or incomplete, and "
        "catching what the automatic matcher missed is your whole purpose."
    )


async def _adjudicate(batch: list[tuple[str, str]], model: str, provider: str | None,
                      job_id: str | None = None) -> list[dict] | None:
    """Returns findings, or None when the adjudication FAILED.

    The distinction is load-bearing: `[]` means the model judged and found
    nothing, `None` means it never answered. Collapsing the two is how job
    19cf9578a0fc lost an entire batch to one TimeoutError.
    """
    prompt = "HARVESTED LINES:\n" + "\n".join(f"[{src}] {txt}" for src, txt in batch)
    sysp = _SYS_PROMPT + _format_context(job_id)
    try:
        if provider == "gpt":
            from modules.gpt_agent import query_gpt_once
            r = await query_gpt_once(
                prompt=prompt, cwd="/tmp", system_prompt=sysp,
                model=model, effort="low",
                timeout_s=ADJUDICATE_TIMEOUT_S, enable_tools=False,
            )
            if r.get("error"):
                if job_id:
                    note_error(job_id, str(r.get("error")))
                return None
            return _parse_findings(r.get("text") or "")
        if provider == "grok":
            # Grok is a first-class adjudicator, not a fallthrough. Without
            # this branch a grok-routed harvester would drop into the Claude
            # SDK below holding a grok-* model id and fail every batch
            # silently — the worst shape for an advisory component, because
            # "found nothing" and "never ran" look identical in flag_grain.txt.
            from modules.grok_acp import query_grok_once
            r = await query_grok_once(
                prompt=prompt, cwd="/tmp", system_prompt=sysp,
                model=model, timeout_s=ADJUDICATE_TIMEOUT_S,
                allow_tools=False,
            )
            if isinstance(r, dict):
                if r.get("error"):
                    if job_id:
                        note_error(job_id, str(r.get("error")))
                    return None
                return _parse_findings(r.get("text") or "")
            return _parse_findings(str(r or ""))
    except Exception as e:
        if job_id:
            note_error(job_id, f"{type(e).__name__}: {e}")
        return None
    # Claude / anything else: one text-only turn through the same
    # helper the monitor uses for provider-correct auth.
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        acc = ""
        opts = ClaudeAgentOptions(
            max_buffer_size=AGENT_MAX_BUFFER_BYTES,
            system_prompt=sysp, model=model, allowed_tools=[],
            permission_mode="bypassPermissions",
        )
        async for msg in query(prompt=prompt, options=opts):
            for block in (getattr(msg, "content", None) or []):
                if type(block).__name__ == "TextBlock":
                    acc += getattr(block, "text", "") or ""
        return _parse_findings(acc)
    except Exception as e:
        if job_id:
            note_error(job_id, f"{type(e).__name__}: {e}")
        return None


def _outfile(job_id: str) -> Path:
    return JOBS_DIR / Path(job_id).name / OUT_NAME


def _statefile(job_id: str) -> Path:
    return JOBS_DIR / Path(job_id).name / STATE_NAME


def grain_flag_values(job_id: str) -> list[str]:
    """Every `flag=` value this job's grain file holds, in file order.

    The ONE permitted source for a manual promotion. This file is advisory by
    construction — the module docstring above spends thirty lines on why the
    harvester may not write `meta.flags` — and a "promote from the grain"
    button is the first thing that could quietly undo that. It stays undone
    only while the promoting endpoint checks exact membership here, so this
    function is what makes that check possible.

    Parsed the way the UI parses it (`_grainRow`, web-ui/app.js): tab
    separated fields, split on the FIRST `=` only, last field of a repeated
    key winning. Both halves matter. A flag body may itself contain `=`
    (base64 padding is routine), so splitting on all of them truncates the
    value the operator is looking at; and if the server resolved a duplicate
    key differently from the UI, the operator would confirm one string and
    promote another.

    `tally` and `error` rows are skipped by key, not by position — an error
    detail is free text and could contain a tab.
    """
    out: list[str] = []
    seen: set[str] = set()
    try:
        text = _outfile(job_id).read_text(errors="replace")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        fields: dict[str, str] = {}
        for chunk in line.split("\t"):
            key, sep, value = chunk.partition("=")
            fields[key if sep else chunk] = value if sep else ""
        if "error" in fields or "tally" in fields:
            continue
        value = fields.get("flag", "").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def append_grain(job_id: str, findings: list[dict], sources: list[str]) -> int:
    """Append accepted findings to flag_grain.txt. Returns how many were new.

    Append-only and deduplicated by flag string. The file is the deliverable:
    it outlives the run, an operator can `cat` it, and nothing downstream reads
    it as authority.
    """
    out = _outfile(job_id)
    seen: set[str] = set()
    try:
        for line in out.read_text(errors="replace").splitlines():
            if line.startswith("flag="):
                seen.add(line.split("\t", 1)[0][5:])
    except Exception:
        pass
    fresh = [f for f in findings if f["verdict"] == "real" and f["flag"] not in seen]
    if not fresh:
        return 0
    stamp = time.strftime("%H:%M:%S")
    lines = []
    for f in fresh:
        lines.append(
            f"flag={f['flag']}\tconfidence={f['confidence']:.2f}\tat={stamp}\t"
            f"why={f['why']}\tsources={','.join(sorted(set(sources))[:4])}"
        )
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as fp:
            fp.write("\n".join(lines) + "\n")
    except Exception:
        return 0
    return len(fresh)


# Modules whose runs have no flag, so there is nothing here to harvest.
#
# Live-fire PATCHES a service. Its deliverable is a diff and a rebuilt ZIP;
# no flag is captured, none exists, and `meta.flags` is never read for it —
# the verdict is `ready_to_deploy`. Attaching a harvester to one was pure
# cost with a false-positive edge: it tails the run log for the whole job
# (143 KB and climbing on 5df30344f339), writes a `flag_grain.txt` and a
# grain box into a UI that can never act on them, and the service source it
# is reading is full of brace-shaped tokens — minified code is dense with
# short name{...} runs that fit the pattern — any of which, echoed into the log
# by the patch agent, buys a model call to adjudicate a flag that does not
# exist. Some attack-and-defence bundles literally ship a `flag` file.
#
# Measured before the change: every live-fire job on this host carried a
# `.harvester.state` and a `flag_grain.txt`, all reading `adjudicated=0`.
# The model cost was zero; the reason to stop is that a zero is the best case
# and the worst case is a fabricated flag on a job that has none.
_NO_FLAG_MODULES = frozenset({"live-fire"})


def module_has_flags(job_id: str) -> bool:
    """False for a module whose runs cannot contain a flag."""
    module = str(_read_json(JOBS_DIR / Path(job_id).name / "meta.json")
                 .get("module") or "").strip().lower()
    return module not in _NO_FLAG_MODULES


def _is_terminal(job_id: str) -> bool:
    return _read_json(JOBS_DIR / Path(job_id).name / "meta.json").get("status") in _TERMINAL


async def run_harvester(job_id: str, model: str | None = None) -> None:
    safe = Path(job_id).name
    job_dir = JOBS_DIR / safe
    logp = job_dir / "run.log"
    evp = job_dir / "gpt-events.jsonl"
    statep = _statefile(job_id)

    try:
        from modules.settings_io import apply_to_env
        apply_to_env()
    except Exception:
        pass

    provider = None
    try:
        # provider_for_ROLE, not provider_for_job: the operator may pin the
        # harvester to Grok or Claude in Settings > Agent & routing while the
        # job itself runs on GPT. With no route configured this returns
        # exactly provider_for_job, so the unrouted case is unchanged.
        from modules.agent_provider import provider_for_role
        provider = provider_for_role(job_id, "harvester")
    except Exception:
        try:
            from modules.agent_provider import provider_for_job
            provider = provider_for_job(job_id)
        except Exception:
            pass
    if model is None:
        try:
            # role_model_for coerces into the ROUTED provider's family and
            # honours that provider's own active preset — resolve_role_model
            # alone would hand a claude-* id to a grok-routed harvester.
            from modules.agent_provider import role_model_for
            model = role_model_for("harvester", provider, None)
        except Exception:
            try:
                from modules.model_presets import resolve_role_model
                model = resolve_role_model("harvester", HARVESTER_MODEL, provider)
            except Exception:
                model = HARVESTER_MODEL
    model = model or HARVESTER_MODEL

    st = _read_json(statep)
    off_log = st.get("log") if isinstance(st.get("log"), int) else 0
    off_ev = st.get("ev") if isinstance(st.get("ev"), int) else 0

    pending: list[tuple[str, str]] = []
    last_flush = time.monotonic()
    adjudicated: set[str] = set()
    tries: dict[str, int] = {}
    # Counted for note_tally: a quiet success is invisible without them.
    # n_written counts what reached the file, not what the model returned —
    # append_grain keeps only `verdict == "real"` and drops repeats.
    n_ok = n_written = n_fail = n_drop = 0
    quiet, quiet_at, term_at = 0, (-1, -1), None

    while True:
        lines, off_log = _consume_whole_lines(logp, off_log)
        for raw in lines:
            body = _body_of(raw)
            if _interesting(body):
                # Tell the model WHERE this came from. An unannotated line of
                # escaped blog markup reads as run output, which is how
                # codegate2025{...} was accepted at 0.82 on job 48fadce3dde7.
                pending.append(
                    ("run.log:fetched-page" if looks_fetched(body) else "run.log", body))

        ev_lines, off_ev = _consume_whole_lines(evp, off_ev)
        if ev_lines:
            pending.extend(_scan_events(ev_lines))

        try:
            statep.write_text(json.dumps({"log": off_log, "ev": off_ev}))
        except Exception:
            pass

        now = time.monotonic()
        terminal = _is_terminal(job_id)
        if pending and (len(pending) >= BATCH_MAX
                        or now - last_flush >= BATCH_MAX_S
                        or terminal):
            batch, pending = pending[:BATCH_MAX], pending[BATCH_MAX:]
            last_flush = now
            key = "\n".join(t for _, t in batch)
            if key not in adjudicated:
                findings = await _adjudicate(batch, model, provider, job_id)
                if findings is None:
                    # FAILED, not empty. The key used to be marked spent
                    # BEFORE this await, so job 19cf9578a0fc's TimeoutError at
                    # 10:25:47 discarded a whole batch that no later pass could
                    # ever reach again — losing candidates is the one failure
                    # this feature exists to prevent. Put the batch back.
                    # Budgeted per batch CONTENT, so it is a floor rather
                    # than a hard cap: a partial batch re-formed after the log
                    # grew is a different key and gets a fresh budget. That is
                    # the wanted behaviour — the new lines deserve a look — and
                    # it still terminates, because a static batch cannot renew.
                    n_fail += 1
                    tries[key] = tries.get(key, 0) + 1
                    if tries[key] < ADJUDICATE_TRIES:
                        pending = batch + pending
                    else:
                        n_drop += 1
                        adjudicated.add(key)
                        note_error(job_id, "batch dropped after "
                                   f"{ADJUDICATE_TRIES} failed adjudications")
                else:
                    n_ok += 1
                    adjudicated.add(key)
                    if findings:
                        n_written += append_grain(
                            job_id, findings, [s for s, _ in batch])

        if terminal and not pending:
            # Exit when the OUTPUT stops, not when the STATUS flips. The flag
            # is written last. On 19cf9578a0fc the job went `finished` at
            # 10:41:03 and the winning FLAG_CANDIDATE line
            # landed at 10:41:16 — 13 s later. Returning on the status change
            # left 17 KB of run.log and 21 KB of gpt-events.jsonl unread with
            # the only real flag inside, so the harvester's single report that
            # run was a false positive it had picked up earlier. Any exit
            # keyed on status is structurally blind to the winning line.
            if term_at is None:
                term_at = now
            if (off_log, off_ev) == quiet_at:
                quiet += 1
                if quiet >= DRAIN_QUIET_POLLS or now - term_at >= DRAIN_MAX_S:
                    note_tally(job_id, n_ok, n_written, n_fail, n_drop)
                    return
            else:
                quiet, quiet_at = 0, (off_log, off_ev)
        await asyncio.sleep(POLL_S)


def ensure_harvester(job_id: str) -> None:
    """Start a harvester task for job_id if none is alive. Idempotent."""
    if not harvester_enabled() or not job_id:
        return
    t = _TASKS.get(job_id)
    if t is not None and not t.done():
        return
    if _is_terminal(job_id):
        return
    # Checked HERE rather than in `_scan_running`, which is today's only
    # caller: the rule belongs with the thing it protects, so a second
    # caller cannot reintroduce it by not knowing about it.
    if not module_has_flags(job_id):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _TASKS[job_id] = loop.create_task(_guarded(job_id))


async def _guarded(job_id: str) -> None:
    try:
        await run_harvester(job_id)
    except Exception:
        pass
    finally:
        _TASKS.pop(job_id, None)


def _scan_running() -> list[str]:
    out: list[str] = []
    try:
        for d in JOBS_DIR.iterdir():
            if not d.is_dir():
                continue
            status = _read_json(d / "meta.json").get("status")
            if status and status not in _TERMINAL and (d / "run.log").exists():
                out.append(d.name)
    except Exception:
        return out
    return out


async def _supervisor() -> None:
    while True:
        try:
            # Re-checked every sweep, not captured: flipping the Settings
            # toggle on must start harvesting jobs already in flight.
            if harvester_enabled():
                for jid in _scan_running():
                    ensure_harvester(jid)
        except Exception:
            pass
        await asyncio.sleep(SUPERVISOR_S)


def start_supervisor() -> None:
    """Launch the always-on supervisor. Call once from api.main startup.

    Deliberately NOT gated on harvester_enabled() here: the supervisor is a
    sleeping loop that costs nothing, and gating it at startup would mean
    turning the Settings toggle on did nothing until the next API restart.
    """
    if not HARVESTER_ENABLED:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_supervisor())
