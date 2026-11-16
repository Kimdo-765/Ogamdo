#!/usr/bin/env python3
"""The same work, rendered as something a person can read.

WHY THIS EXISTS

GPT jobs have had a structured timeline since gpt-events.jsonl existed. Claude
and grok jobs got a `<pre>` of run.log — the identical work, shown as a wall of
`[main] TOOL Bash: {"command": "...` that the operator parses by eye. The data
was never missing: sdk.jsonl already carried the agent's prose, its tool calls
and their results, tagged by which agent produced them.

So the stream is normalised into the SAME event vocabulary the GPT endpoint
emits and the existing renderer draws both. One renderer, two sources. A second
renderer would drift from the first, which two placement policies already
taught this repo.

WHAT THIS SUITE PROTECTS

  * ABSENT IS NOT ZERO, and this feature got it wrong first. sdk.jsonl had no
    timestamps, so every tool row rendered a confident `0ms` — `Number(null)`
    is 0 and `_fmtDuration` measured before it checked. The key is omitted
    when there is nothing to subtract, AND the formatter refuses null before
    it coerces.
  * A RESULT WITH NO CALL IS EVIDENCE. An orphan tool_result means the stream
    is incomplete; dropping it hides that, so it becomes a visible warning.
  * PAIRING IS PER AGENT. main and its subagents interleave through one file,
    so a subagent's result must not close main's open call.
  * THE TOOL LABEL IS THE AGENT'S OWN. The prompts ask for a `description` and
    it is what a human would have written; the fallbacks are the most
    identifying field the tool has, never a truncated blob of JSON.
  * TOOLS ARE VISIBLE WHERE THEY ARE THE POINT. GPT hides tool cards by
    default for a measured reason — 3,899 on one job. A claude job has six,
    and hiding those leaves the prose with no record of what was done.

Run from the repository root::

    python3 scripts/test_claude_timeline.py
    python3 scripts/test_claude_timeline.py --mutate zero-for-unknown-duration
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "zero-for-unknown-duration",
    "drop-orphan-result",
    "pair-across-agents",
    "label-from-raw-input",
    "hide-tools-everywhere",
    "composer-claims-delivery",
    "cache-hit-zero-when-unknown",
    "composer-dies-on-poll",
    "agent-card-without-model",
    "model-only-from-meta",
    "always-completed",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="timeline-test-"))
os.environ["DATA_DIR"] = str(tmp)
(tmp / "jobs").mkdir()

import modules._timeline as TL  # noqa: E402
from modules.storage import JOBS_DIR  # noqa: E402

if args.mutate == "zero-for-unknown-duration":
    _real_ms = TL._ms_between
    TL._ms_between = lambda a, b: (_real_ms(a, b) or 0)
elif args.mutate == "drop-orphan-result":
    _real_build = TL._build
    def _quiet(job_id, tail):
        got = _real_build(job_id, tail)
        got["events"] = [e for e in got["events"] if e.get("kind") != "warning"]
        return got
    TL._build = _quiet
elif args.mutate == "pair-across-agents":
    _real_b2 = TL._build
    def _crossed(job_id, tail):
        # One shared slot instead of one per tag.
        import modules._timeline as M
        src = M._read(M._job_dir(job_id) / "sdk.jsonl")
        for r in src:
            r["tag"] = "main"
        M._read = lambda p: src
        try:
            return _real_b2(job_id, tail)
        finally:
            M._read = _read_real
    _read_real = TL._read
    TL._build = _crossed
elif args.mutate == "label-from-raw-input":
    TL._tool_label = lambda name, payload: json.dumps(payload)[:160]
elif args.mutate == "agent-card-without-model":
    # What this path shipped as: the card gets a name and nothing to render.
    TL._agent_identity = lambda job_id, meta: (lambda tag: {})
elif args.mutate == "model-only-from-meta":
    # `meta.model` is written when the job ENDS, so this reads blank for
    # exactly the jobs an operator is watching.
    def _meta_only(job_id, meta):
        def resolve(tag):
            m = meta.get("model")
            return {"model": m} if m and tag == "main" else {}
        return resolve
    TL._agent_identity = _meta_only
elif args.mutate == "always-completed":
    _real_b3 = TL._build
    def _all_done(job_id, tail):
        got = _real_b3(job_id, tail)
        for a in got.get("agents") or []:
            a["status"] = "completed"
        return got
    TL._build = _all_done


def make(job, records, meta=None):
    d = JOBS_DIR / job
    d.mkdir(parents=True, exist_ok=True)
    (d / "sdk.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
        encoding="utf-8")
    if meta is not None:
        (d / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return d


print("\n1. the vocabulary the existing renderer already knows")
make("basic", [
    {"kind": "text", "tag": "main", "text": "배포 환경부터 확인하겠습니다."},
    {"kind": "tool_use", "tag": "main", "name": "Bash",
     "input": {"command": "ls -la", "description": "List work directory"}},
    {"kind": "tool_result", "tag": "main", "is_error": False,
     "preview": "TOOL_RESULT: total 148"},
])
t = TL.build_timeline("basic")
check("prose and a tool call become two events",
      [e["kind"] for e in t["events"]], ["message", "tool"])
check("...and every kind is one the renderer has an icon for",
      [e["kind"] for e in t["events"] if e["kind"] not in TL._KINDS], [])
check("a call and its result are ONE row, not two",
      len([e for e in t["events"] if e["kind"] == "tool"]), 1)
tool = [e for e in t["events"] if e["kind"] == "tool"][0]
check("...carrying the result as detail", tool["detail"], "TOOL_RESULT: total 148")
check("...and the outcome as status", tool["status"], "completed")
check("an error result is reported as failed",
      TL.build_timeline("err")["events"] if False else
      (lambda: (make("err", [
          {"kind": "tool_use", "tag": "main", "name": "Bash", "input": {"command": "x"}},
          {"kind": "tool_result", "tag": "main", "is_error": True, "preview": "boom"},
      ]), TL.build_timeline("err")["events"][0]["status"])[1])(), "failed")

print("\n2. absent is not zero — the bug this shipped with")
# sdk.jsonl had no `ts`, so every tool row rendered "0ms": Number(null) is 0
# and _fmtDuration measured before it checked.
check("no timestamps means NO duration key, not a zero one",
      "duration_ms" in tool, False)
check("...and the payload says the timing is missing",
      "timing not recorded" in t["source"], True)
make("timed", [
    {"kind": "tool_use", "tag": "main", "name": "Bash", "input": {"command": "x"},
     "ts": "2026-09-19T00:00:00+00:00"},
    {"kind": "tool_result", "tag": "main", "is_error": False, "preview": "ok",
     "ts": "2026-09-19T00:00:02.500000+00:00"},
])
t2 = TL.build_timeline("timed")
check("with timestamps the real duration is reported",
      t2["events"][0].get("duration_ms"), 2500)
check("...and the payload stops apologising",
      "timing not recorded" in t2["source"], False)
# The formatter is the other half: it coerced before it checked.
js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
_fmt = js[js.index("function _fmtDuration"):]
_fmt = _fmt[:_fmt.index("\n}")]
check("_fmtDuration rejects null BEFORE Number() turns it into 0",
      _fmt.index("ms === null") < _fmt.index("Number(ms)"), True)


print("\n3. a result with no call is evidence, not noise")
make("orphan", [
    {"kind": "tool_result", "tag": "main", "is_error": False, "preview": "stray"},
])
t3 = TL.build_timeline("orphan")
check("an orphan result is surfaced as a warning",
      [(e["kind"], e["status"]) for e in t3["events"]], [("warning", "warning")])
check("...keeping what it actually said", t3["events"][0]["summary"], "stray")

print("\n4. pairing is per agent — main and a subagent share one file")
make("agents", [
    {"kind": "tool_use", "tag": "main", "name": "Bash", "input": {"command": "outer"}},
    {"kind": "tool_use", "tag": "recon", "name": "Grep", "input": {"pattern": "flag"}},
    {"kind": "tool_result", "tag": "recon", "is_error": False, "preview": "recon done"},
    {"kind": "tool_result", "tag": "main", "is_error": False, "preview": "main done"},
])
t4 = TL.build_timeline("agents")
pairs = {(e["role"], e.get("detail")) for e in t4["events"] if e["kind"] == "tool"}
check("each agent's result closes ITS own call",
      pairs, {("main", "main done"), ("recon", "recon done")})
check("...and both agents are listed",
      sorted(a["name"] for a in t4["agents"]), ["main", "recon"])

print("\n5. the one-line label is the agent's own words")
check("a description wins when the agent wrote one",
      TL._tool_label("Bash", {"command": "ls -la", "description": "List work directory"}),
      "List work directory")
check("...otherwise the most identifying field the tool has",
      TL._tool_label("Bash", {"command": "cat /etc/passwd"}), "cat /etc/passwd")
check("...a file path for an edit", TL._tool_label("Edit", {"file_path": "FINDINGS.md"}),
      "FINDINGS.md")
check("...and never a blob of JSON",
      TL._tool_label("Bash", {"command": "x"}).startswith("{"), False)
check("a multi-line command collapses to one line",
      "\n" in TL._tool_label("Bash", {"command": "a\nb\nc"}), False)

print("\n6. empty blocks are not cards")
make("empty", [
    {"kind": "thinking", "tag": "main", "thinking": ""},
    {"kind": "text", "tag": "main", "text": "   "},
    {"kind": "thinking", "tag": "main", "thinking": "real reasoning"},
])
t5 = TL.build_timeline("empty")
# An empty thinking block reports that extended thinking RAN, not that it
# thought nothing; a card saying nothing is worse than no card.
check("blank prose and blank thinking produce no cards", len(t5["events"]), 1)
check("...and real thinking still does", t5["events"][0]["summary"], "real reasoning")
make("none", [])
check("a job with no stream is not enabled, and says why",
      (TL.build_timeline("none")["enabled"], TL.build_timeline("none")["source"]),
      (False, "no sdk.jsonl"))

print("\n7. every SDK record is timestamped from here on")
import inspect  # noqa: E402
from modules._common import publish_sdk  # noqa: E402
_src = inspect.getsource(publish_sdk)
check("publish_sdk stamps ts at the one point every record passes",
      'setdefault("ts"' in _src, True)
check("...without overwriting one a caller already set",
      "setdefault" in _src and '["ts"] =' not in _src, True)

print("\n8. the view, and where tools are visible")
if args.mutate == "hide-tools-everywhere":
    js = js.replace("gptTimelineToolsPref === null ? !isGpt : gptTimelineToolsPref",
                    "gptTimelineToolsPref === null ? false : gptTimelineToolsPref", 1)
check("one endpoint serves every provider",
      '/timeline?tail=' in js, True)
check("...and claude/grok default to the timeline, not the raw log",
      'let claudeLogView' in js and '"timeline"' in js, True)
# GPT hides tool cards for a measured reason: 3,899 on 48fadce3dde7, 43.6% of
# the cards. A claude job has six, and hiding those leaves the prose alone.
check("tool visibility resolves per provider when unset",
      "gptTimelineToolsPref === null ? !isGpt : gptTimelineToolsPref" in js, True)
check("...and a toggle makes the choice explicit for both",
      "gptTimelineToolsPref = !gptTimelineTools" in js, True)
check("the tools toggle is no longer GPT-only",
      'isGptJob ? `<button class="gpt-tools-toggle"' in js, False)
api = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
check("the endpoint delegates GPT to its own richer path",
      "get_gpt_timeline(job_id, tail)" in api, True)
check("...and both paths get the stats, since it happens after the branch",
      api.index("get_gpt_timeline(job_id, tail)") < api.index('payload["stats"]'), True)
check("...and normalises everything else",
      "from modules._timeline import build_timeline" in api, True)


print("\n9. the composer — under the flow, and honest about what it did")
if args.mutate == "composer-claims-delivery":
    js = js.replace("대기열에 넣었습니다", "전달했습니다", 1)
if args.mutate == "composer-dies-on-poll":
    js = js.replace(".steer-form, .tl-composer-typing", ".steer-form", 1)
check("there is a composer at all", 'class="tl-composer"' in js, True)
check("...in the STATIC markup, so the 2s repaint of the feed cannot eat a draft",
      js.index('class="tl-composer"') < js.index('put("div.gpt-timeline-feed"')
      or 'class="tl-composer"' in js, True)
# The poll skips a panel with an unsent draft, the same way it already does for
# the retry and stop-resume forms.
check("a half-typed message suspends the poll",
      ".steer-form, .tl-composer-typing" in js, True)
check("...and the class is actually applied while typing",
      'classList.toggle(\n      "tl-composer-typing"' in js
      or 'toggle(\n      "tl-composer-typing"' in js
      or '"tl-composer-typing", (ta.value' in js, True)
# QUEUED, not delivered. Whether it lands depends on the job reaching another
# turn boundary; telling an operator they redirected something they did not is
# the one thing this feature must never do.
check("the result says QUEUED, never delivered",
      "대기열에 넣었습니다" in js and "전달했습니다" not in js, True)
check("it posts to the steer endpoint that already exists",
      "/steer`" in js, True)
# Enter makes newlines; a steer is usually more than one clause.
check("Ctrl/Cmd+Enter sends, a bare Enter does not",
      '(ev.metaKey || ev.ctrlKey) && ev.key === "Enter"' in js, True)
check("it is disabled when there is no live session to read it",
      'job.status === "running" ? "" : "disabled"' in js, True)
check("...and says WHY rather than just greying out",
      "아직 큐 대기 중입니다" in js and "읽을 세션이 없습니다" in js, True)

print("\n10. the stats bar, and the file links")
if args.mutate == "cache-hit-zero-when-unknown":
    api = api.replace('if seen else None', 'if seen else 0', 1)
check("every figure comes from the same build_trace the 궤적 view uses",
      "from modules._trace import build_trace" in api, True)
# None means no context was READ, which has no hit rate; 0% reads as a cache
# that is failing.
check("an unmeasurable cache rate is omitted, not reported as 0%",
      "if seen else None" in api, True)
check("...and the renderer skips a null rather than printing it",
      "if (st.cache_hit_pct != null)" in js, True)
check("the bar reports turns, steps, the time split and tokens",
      all(w in js for w in ("turns`", "steps`", "agent ${_traceDur",
                            "tool ${_traceDur", "judge ${_traceDur")), True)
# A tool that touched a file opens it through the file browser's OWN modal —
# one viewer, not a second one that drifts from it.
check("a file-touching tool carries only the basename",
      "_tool_file" in (ROOT / "modules" / "_timeline.py").read_text(encoding="utf-8"), True)
check("...and links through the existing preview handler",
      'class="file-preview-link tl-file"' in js, True)
check("...to the endpoint that resolves it against <job>/ and <job>/work/",
      "/file/${encodeURIComponent(event.file)}" in js, True)
_tl = (ROOT / "modules" / "_timeline.py").read_text(encoding="utf-8")
check("a tool with no file gets no link",
      "if got_file:" in _tl, True)

print("\n11. the agent card is the same contract, not just the same events")
# The renderer reads `agent.role` and `agent.model`. This path emitted `name`
# and no model at all, so every claude and grok job drew `agent` /
# "model 미확인" beside a GPT job showing the real one. Anchor the checks on
# the renderer's OWN fallback literals: if those are renamed, these must fail
# rather than keep passing against a string nobody renders any more.
check("the renderer still falls back on role, so the key must be emitted",
      'agent.role || "agent"' in js, True)
check("...and on model, which is the text the operator reported",
      'agent.model || "model 미확인"' in js, True)

_RUNNING = [
    {"kind": "text", "tag": "main", "text": "확인하겠습니다.",
     "ts": "2026-09-19T00:39:09.573625+00:00"},
    {"kind": "tool_use", "tag": "main", "name": "Bash",
     "input": {"command": "ls", "description": "List"},
     "ts": "2026-09-19T00:39:11.146654+00:00"},
    {"kind": "tool_result", "tag": "main", "is_error": False,
     "preview": "ok", "ts": "2026-09-19T00:39:11.246654+00:00"},
]
# meta.model is null here ON PURPOSE: that is what meta holds for the whole
# time a job runs, and it is the case the card got wrong.
make("live", _RUNNING, meta={"status": "running", "model": None,
                             "agent_provider": "claude"})
live = TL.build_timeline("live")
agent = (live.get("agents") or [{}])[0]
check("the card carries a role", agent.get("role"), "main")
check("...and a provider", agent.get("provider"), "claude")
check("a null meta.model does not become an unknown model",
      bool(agent.get("model")), True)
check("...and the model resolved is a claude one, not another family's default",
      str(agent.get("model", "")).startswith("claude"), True)
check("a running job's active agent reads running, not completed",
      agent.get("status"), "running")
check("the newest record is what marks it live",
      agent.get("last_at"), "2026-09-19T00:39:11.246654+00:00")

# A finished job routinely ends holding a tool call that never got its result
# — e760e68c3533 did. That must not read as a live agent.
make("done", _RUNNING + [
    {"kind": "tool_use", "tag": "main", "name": "Bash",
     "input": {"command": "sleep", "description": "Re-verify"},
     "ts": "2026-09-19T00:40:00.000000+00:00"},
], meta={"status": "finished", "model": "claude-opus-5",
         "agent_provider": "claude"})
done = (TL.build_timeline("done").get("agents") or [{}])[0]
check("a finished job's leftover open call is not a running agent",
      done.get("status"), "completed")
check("...and its explicit meta.model is honoured",
      done.get("model"), "claude-opus-5")

# A subagent that stopped emitting while main keeps going is finished, even
# though the JOB is still running.
make("two", [
    {"kind": "text", "tag": "recon", "text": "정적 분석 끝.",
     "ts": "2026-09-19T00:39:00.000000+00:00"},
    {"kind": "text", "tag": "main", "text": "이어서 진행합니다.",
     "ts": "2026-09-19T00:39:30.000000+00:00"},
], meta={"status": "running", "agent_provider": "claude"})
two = {a["role"]: a for a in TL.build_timeline("two").get("agents") or []}
check("two tags produce two cards", sorted(two), ["main", "recon"])
check("the tag holding the newest record is the running one",
      two.get("main", {}).get("status"), "running")
check("...and a subagent that went quiet is not claimed to be live",
      two.get("recon", {}).get("status"), "completed")

# The GPT path already emits these keys; drifting apart is the failure this
# module exists to prevent.
check("both paths name the same keys",
      all(k in agent for k in ("role", "model", "status")), True)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
