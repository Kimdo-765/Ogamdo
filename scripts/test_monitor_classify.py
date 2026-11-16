#!/usr/bin/env python3
"""Regression suite for the MONITOR feed's signal classifier.

Run from the repo root:   python3 scripts/test_monitor_classify.py

WHY THESE CASES
Every one is taken from a real pwn run, where 5 of 7 `kind=error` entries
were false. The error regex ran against the raw line with no notion of WHO
wrote it, so it fired on:

    "Exception:"  inside a Python heredoc the agent was composing
    "SIGSEGV"     inside a tool `description` ("Trigger SIGSEGV with …")
    "SIGSEGV"     inside a subagent prompt the agent was drafting
    "SIGSEGV"     in prose stating there is NO SIGSEGV handler — the opposite
    "SIGSEGV"     in a findings report — a success

An err badge that is wrong 5 times in 7 is worse than no badge at all: the two
REAL errors in that run were unfindable among the noise. Meanwhile two genuine
failures ("TOOL_ERROR: Exit code 1" in pre-recon) were filed as phase/info and
never surfaced.

The invariant these tests protect is small and precise:
  * a FAILURE is something the agent RECEIVED, never something it WROTE;
  * a CRASH is the goal in pwn/rev, so it is its own kind at info severity —
    but it still must appear in the feed, because "about to segfault the
    target" is exactly what an operator wants to see.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# _monitor.py imports modules._sdk_buffer at module scope; loading it by
# file path still needs the repo root importable, like every other suite.
sys.path.insert(0, str(ROOT))

_results: list[tuple[bool, str]] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append((bool(cond), label))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 58 - len(name)))


def _load():
    spec = importlib.util.spec_from_file_location("_mon", ROOT / "modules" / "_monitor.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main() -> int:
    m = _load()

    # ---------------------------------------------------------------- errors
    section("a failure is what the agent RECEIVED")
    chk("TOOL_ERROR from the orchestrator is an error",
        m.classify("[pre-recon] TOOL_ERROR: Exit code 1", "pwn") == ("error", "err"),
        m.classify("[pre-recon] TOOL_ERROR: Exit code 1", "pwn"))
    chk("a traceback in tool OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: Traceback (most recent call last):", "pwn")
        == ("error", "err"))
    chk("a python exception class in OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: BrokenPipeError: [Errno 32] Broken pipe", "pwn")
        == ("error", "err"))
    chk("connection refused in OUTPUT is an error",
        m.classify("[main] TOOL_RESULT: Connection refused", "pwn") == ("error", "err"))

    section("...never what the agent WROTE")
    chk("'Exception:' inside a heredoc the agent is composing",
        m.classify('[main] TOOL Bash:   "command": "cat > p.py <<PY\\nraise Exception: x"',
                   "pwn") is None,
        m.classify('[main] TOOL Bash:   "command": "raise Exception: x"', "pwn"))
    chk("an error word in the agent's own prose is not an event",
        m.classify("[main] AGENT: the parser raises ValueError: on bad input, so we avoid it",
                   "pwn") == ("agent", "info"),
        m.classify("[main] AGENT: raises ValueError: on bad input", "pwn"))

    # ---------------------------------------------------------------- crash
    section("a crash is the GOAL in pwn/rev")
    seg = '[main] TOOL Bash:   "description": "Trigger SIGSEGV with the PoC input"'
    chk("pwn: segfault -> crash/info", m.classify(seg, "pwn") == ("crash", "info"),
        m.classify(seg, "pwn"))
    chk("rev: segfault -> crash/info", m.classify(seg, "rev") == ("crash", "info"))
    chk("a subagent prompt mentioning SIGSEGV is crash/info, not an error",
        m.classify('[main] TOOL mcp__team__spawn_subagent:   "prompt": "find SIGSEGV paths"',
                   "pwn") == ("crash", "info"))
    chk("prose saying there is NO SIGSEGV handler is not an error",
        m.classify("[main] AGENT: the target installs no SIGSEGV handler",
                   "pwn") == ("crash", "info"))
    section("...but a fault elsewhere still is")
    chk("web: a segfault the runner REPORTS is an error",
        m.classify("[runner] child died with SIGSEGV", "web") == ("error", "err"),
        m.classify("[runner] child died with SIGSEGV", "web"))
    chk("web: a segfault the agent merely mentions is not",
        m.classify(seg, "web") is None, m.classify(seg, "web"))

    # ------------------------------------------------------- file content
    section("file content the agent READ is data, not an event")
    chk("a Read line with 'except OSError:' is not an error",
        m.classify("[main] TOOL_RESULT: 93\t            except OSError:", "pwn") is None,
        m.classify("[main] TOOL_RESULT: 93\t            except OSError:", "pwn"))
    chk("...nor at line 110", 
        m.classify("[main] TOOL_RESULT: 110\t        except OSError:", "pwn") is None)
    chk("a Read line mentioning SIGSEGV is not a crash event either",
        m.classify("[main] TOOL_RESULT: 24\t# a short read here ends in SIGSEGV",
                   "pwn") is None,
        m.classify("[main] TOOL_RESULT: 24\t# a short read here ends in SIGSEGV", "pwn"))
    chk("grep-shaped output is data too",
        m.classify("[main] TOOL_RESULT: exploit.py:93:        except OSError:", "pwn") is None)
    chk("but a REAL failure in TOOL_RESULT is still an error",
        m.classify("[main] TOOL_RESULT: BrokenPipeError: [Errno 32] Broken pipe", "pwn")
        == ("error", "err"))
    chk("and a real traceback is still an error",
        m.classify("[main] TOOL_RESULT: Traceback (most recent call last):", "pwn")
        == ("error", "err"))

    # ---------------------------------------------------------------- noise
    section("bookkeeping is not narratable")
    chk("'attempt 0/' is a turn boundary, not a retry",
        m.classify("Main session turn (attempt 0/∞)", "pwn") is None,
        m.classify("Main session turn (attempt 0/∞)", "pwn"))
    chk("'attempt 2/' IS a retry",
        m.classify("[orchestrator] Main session turn (attempt 2/5)", "pwn")
        == ("retry", "warn"))

    # ---------------------------------------------------------------- dedup
    section("near-duplicate narrations")
    chk("identical text is suppressed", m._too_similar("도구 출력 확인 완료", "도구 출력 확인 완료"))
    chk("a rephrasing is suppressed",
        m._too_similar("에이전트가 바이너리 문자열 추출을 시작",
                       "에이전트가 바이너리 문자열 추출 시작"))
    chk("genuinely different lines are kept",
        not m._too_similar("빌드 캐시 정리 완료",
                           "도구 연결 거부됨 errno 111"))
    # A related pair, distinct enough to keep BOTH.
    chk("related-but-distinct narrations are NOT over-suppressed",
        not m._too_similar(
            "설정 경로 오류 수정 후 재시작 간 응답 시간 측정 진행.",
            "에이전트가 설정 경로 수정 및 로그 회전 경로 조사; "
            "캐시 크기가 고정값이 아닌 환경 변수임을 발견"))
    chk("too-short strings are never suppressed", not m._too_similar("ok", "ok2"))
    chk("empty is never suppressed", not m._too_similar("", "anything"))

    # ------------------------------------------------------------ unchanged
    section("signals that must keep working")
    chk("a flag candidate is still good",
        m.classify('[main] TOOL_RESULT: FLAG_CANDIDATE: DH{abc}', "pwn") == ("flag", "good"))
    chk("agent prose is still agent/info",
        m.classify("[main] AGENT: starting string extraction", "pwn")
        == ("agent", "info"))
    chk("an exploit write is still an artifact",
        m.classify("[main] TOOL Write: exploit.py", "pwn") == ("artifact", "info"))
    chk("plain tool echo is still dropped",
        m.classify('[main] TOOL Read:   "file_path": "/x"', "pwn") is None)

    # ------------------------------------------------------ provider boundary
    section("every provider is monitored — the narrator is not Claude-only")
    old_jobs_dir = m.JOBS_DIR
    with tempfile.TemporaryDirectory(prefix="monitor-provider-") as tmp:
        try:
            m.JOBS_DIR = Path(tmp)

            def job(job_id: str, provider: str | None, **extra) -> None:
                d = m.JOBS_DIR / job_id
                d.mkdir()
                meta = {"status": "running", **extra}
                if provider is not None:
                    meta["agent_provider"] = provider
                (d / "meta.json").write_text(json.dumps(meta))
                (d / "run.log").write_text("[00:00:00] started\n")

            job("111111111111", "gpt")
            job("222222222222", "claude")
            job("333333333333", "grok")
            job("444444444444", None)
            job("555555555555", None, retry_of="111111111111")

            # The supervisor used to drop GPT jobs on the grounds that the
            # deterministic Timeline stood in for the narrator. They answer
            # different questions, `_narrate_gpt` was written and complete,
            # and the operator could not select the role at all — so the
            # choice was being made for them three layers down. Now the only
            # switch is the `monitor_agent` toggle.
            running = m._scan_running()
            chk("the supervisor watches EVERY provider, GPT included",
                set(running) == {"111111111111", "222222222222", "333333333333",
                                 "444444444444", "555555555555"},
                running)
            chk("...and no provider predicate survives to re-introduce the split",
                not hasattr(m, "_monitor_enabled_for_job"))
            src = (Path(__file__).resolve().parents[1]
                   / "modules" / "_monitor.py").read_text(encoding="utf-8")
            chk("the GPT narrator it can now reach is real, not a stub",
                "async def _narrate_gpt" in src and "MONITOR_GPT_MODEL" in src)
            # The Settings copy described the exclusion in detail, by function
            # name. A toggle whose own help text says the feature will decline
            # to start is worse than no help text, and it is the same drift
            # this repo keeps finding: prose promising what the code does not
            # do. Assert the claim cannot come back without the code.
            idx = (Path(__file__).resolve().parents[1]
                   / "web-ui" / "index.html").read_text(encoding="utf-8")
            chk("the Settings copy no longer names a provider gate",
                "_monitor_enabled_for_job" not in idx
                and "provider=gpt" not in idx)
            chk("...and the role stays selectable for every provider",
                'role !== "monitor"' not in
                (Path(__file__).resolve().parents[1]
                 / "web-ui" / "app.js").read_text(encoding="utf-8"))
        finally:
            m.JOBS_DIR = old_jobs_dir

    # ------------------------------------------------------- findings lane
    section("the monitor pulls findings out of the call it already makes")
    import json as _json
    src = (Path(__file__).resolve().parents[1]
           / "modules" / "_monitor.py").read_text(encoding="utf-8")
    appjs = (Path(__file__).resolve().parents[1]
             / "web-ui" / "app.js").read_text(encoding="utf-8")

    chk("the narration prompt asks for an OPTIONAL vuln object",
        '"vuln" key' in src or 'OPTIONAL \\"vuln\\" key' in src
        or "VULN — include this key ONLY" in src)
    chk("...and tells it to omit rather than invent",
        "do not send null, do not invent one" in src)
    chk("...and rules out the agent's own tooling as a finding",
        "never a problem with" in src)

    got = m._parse_narration_json(_json.dumps({
        "ko": "가", "en": "a",
        "vuln": {"title": "T", "severity": "high", "where": "f.py:1", "why": "w"}}))
    chk("a well-formed finding survives the parser",
        got.get("vuln", {}).get("title") == "T", got)
    chk("a titleless one does not",
        "vuln" not in m._parse_narration_json(
            _json.dumps({"ko": "가", "en": "a", "vuln": {"severity": "high"}})))
    chk("a finding with NO prose is not a narration",
        m._parse_narration_json(
            _json.dumps({"ko": "", "en": "", "vuln": {"title": "T"}})) == {})

    # THE SEAM THAT ACTUALLY BROKE. `_narrate` rebuilds its return value from
    # MONITOR_LANGS alone, which dropped the finding between a parser that
    # produced it and an emitter that consumed it — both of those had guards
    # and the join between them did not, so the feature looked wired and
    # emitted nothing while the model was returning `vuln` every time.
    import asyncio as _aio

    # `known` is positional at the call site — a two-parameter stub raises,
    # `_narrate` swallows it, and the test silently exercises the REAL
    # narrator instead of the projection it means to check.
    async def _fake_narrate(lines, model=None, known=()):
        return {"ko": "가", "en": "a",
                "vuln": {"title": "T", "severity": "high", "where": "f:1", "why": "w"}}

    _real = m._narrate_claude
    try:
        m._narrate_claude = _fake_narrate
        _got = _aio.run(m._narrate(["x"], "claude-haiku-4-5"))
        chk("_narrate carries the finding through its language projection",
            (_got.get("vuln") or {}).get("title") == "T", _got)
        chk("...and still guarantees every language key",
            all(l in _got for l in m.MONITOR_LANGS), _got)
    finally:
        m._narrate_claude = _real

    # The subtle one. `_flush_batch` RETURNS when a narration merely restates
    # the previous one; a finding must be taken out before that, or a repeated
    # claim is silently dropped along with the repeated prose.
    body = src.split("async def _flush_batch", 1)[1]
    # Eight rows, one finding. The exact-key dedup never fires on a
    # rephrasing, and this file's own 0.80 bigram floor caught NONE of the
    # eight measured on job 7dc1be932b26 — lowering it would collapse real
    # findings instead. So the narrator is shown what it has already reported
    # and asked not to repeat itself, in the call it is already making.
    chk("the narrator is told what it has already reported",
        "def _known_vuln_titles(" in src and "ALREADY REPORTED" in src)
    chk("...and that a reworded one is the same finding",
        "said differently" in src and "Same underlying weakness" in src)
    # Counted per NARRATOR, not pinned to a total: a fourth backend (local)
    # was added and both of these broke on the arithmetic rather than on the
    # property. Every narrator that builds the system prompt must build it
    # WITH the known list — that is the claim.
    _narrators = re.findall(r"async def (_narrate_\w+)\(", src)
    _builds = src.count("_narrate_sys_prompt(known)")
    chk(f"every narrator is given what was already reported ({len(_narrators)})",
        _builds == len(_narrators) and _builds >= 3, (_builds, _narrators))
    chk("...and the flush supplies it from the job",
        "_known_vuln_titles(job_id)" in src
        and "_narrate(bodies, model, _known_vuln_titles(job_id)" in src)
    chk("the prompt stays quiet when there is nothing to repeat",
        "ALREADY REPORTED" not in m._narrate_sys_prompt())

    chk("the finding is extracted BEFORE the near-duplicate gate",
        body.index("_emit_vuln(") < body.index("_too_similar("))

    with tempfile.TemporaryDirectory(prefix="monitor-vuln-") as tmp2:
        old_dir = m.JOBS_DIR
        try:
            m.JOBS_DIR = Path(tmp2); (m.JOBS_DIR / "v1").mkdir()
            v = {"title": "IDOR", "severity": "high", "where": "r.py:1", "why": "w"}
            m._emit_vuln("v1", dict(v), ["b"])
            m._emit_vuln("v1", {**v, "title": "  idor "}, ["b"])   # same, normalised
            m._emit_vuln("v1", {**v, "title": "CSRF"}, ["b"])      # different
            rows = (m.JOBS_DIR / "v1" / "monitor.jsonl").read_text().splitlines()
            chk("a restated finding does not become a second row",
                len(rows) == 2, rows)
            m._VULN_SEEN.clear()                                   # api restart
            m._emit_vuln("v1", dict(v), ["b"])
            chk("...and a restart does not re-announce it",
                len((m.JOBS_DIR / "v1" / "monitor.jsonl")
                    .read_text().splitlines()) == 2)
        finally:
            m.JOBS_DIR = old_dir

    # "no findings yet" and "this feature is broken" rendered identically —
    # both drew nothing — and that is exactly how the first version shipped
    # inert without anyone being able to tell. The panel now states the empty
    # case, but only once the monitor has proved it is producing at all.
    chk("an empty findings list still says so, rather than vanishing",
        "vuln-none" in appjs and "아직 없음" in appjs)
    chk("...but promises nothing when the monitor is not producing",
        "if (!all.length) return \"\";" in appjs)

    chk("the panel is scoped to its OWN view, in every state",
        appjs.split("function renderVulnPanel", 1)[1][:500]
             .count('view !== "vuln"') == 1)
    chk("...which is a real tab between Monitor and Raw log",
        appjs.index('data-action="view-monitor"')
        < appjs.index('data-action="view-vuln"')
        < appjs.index('data-action="view-log"'))
    chk("...accepted as a view value, or the tab would bounce to timeline",
        '["timeline", "monitor", "vuln", "log"]' in appjs)
    # Anchored on the ARGUMENTS THAT MATTER, not the whole call: this check
    # broke twice today when a parameter was appended, which is how a guard
    # ends up pinning a signature instead of a property.
    _live_call = re.search(r"renderVulnPanel\(\[payload\][^)]*\)", appjs)
    chk("...and a live finding arriving on another tab is not painted there",
        bool(_live_call) and "claudeLogView" in _live_call.group(0))
    _panel_call = re.search(r"renderVulnPanel\(\s*\n?\s*monitorEntries[^)]*\)", appjs)
    chk("...and the call site passes the current view",
        bool(_panel_call) and "activityView" in _panel_call.group(0))

    chk("the UI renders the panel from the SAME entries, not a new channel",
        "renderVulnPanel" in appjs and 'e.kind === "vuln"' in appjs)
    chk("a finding is clickable only while the job can still receive a steer",
        bool(_panel_call) and 'job.status === "running"' in _panel_call.group(0))
    # This repo's escapeHtml covers & < > and NOT quotes — the job tag is
    # pinned to never reach an HTML attribute for exactly that reason. The
    # finding payload is model-written text read out of challenge source, so
    # it goes in percent-encoded or not at all.
    chk("the finding payload is percent-encoded, never escapeHtml'd, in the attribute",
        "encodeURIComponent(JSON.stringify(" in appjs
        and "escapeHtml(JSON.stringify(" not in appjs)
    chk("...and is decoded symmetrically on read",
        "JSON.parse(decodeURIComponent(row.dataset.vuln" in appjs)

    # A click SELECTS; a separate button sends. One finding is frequently not
    # an exploit — the chain is — and the single-click version also meant
    # clicking a row to read it fired an instruction at the agent.
    chk("a click selects rather than steering",
        'data-action="vuln-pick"' in appjs and 'data-action="vuln-dig"' not in appjs)
    chk("...and a separate send queues the STEER, no new rail",
        'data-action="vuln-send"' in appjs and "/steer`" in appjs)
    chk("...with a way back out of a selection",
        'data-action="vuln-clear"' in appjs)
    chk("several findings are sent as ONE chain instruction",
        "may only be exploitable" in appjs and "TOGETHER" in appjs)
    chk("...which names refutation as a real answer, not a failure",
        "that\n            // is a result, not a failure" in appjs
        or "is a result, not a failure" in appjs)
    chk("one finding still asks for a verdict on itself",
        "Investigate this finding to a verdict" in appjs)
    chk("the selection survives the repaint a new finding causes",
        "const _vulnPicks = Object.create(null);" in appjs
        and "_lastMonitorEntries[id] = _lastMonitorEntries[id] || []" in appjs)
    chk("...and resolves against what is actually on the panel",
        "function _vulnPickedList(" in appjs)
    chk("...and asks for a verdict instead of asserting the claim is true",
        "confirm it end" in appjs and "or refute it" in appjs)

    failed = [r for r in _results if not r[0]]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
