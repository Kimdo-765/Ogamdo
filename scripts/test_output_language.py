#!/usr/bin/env python3
"""Executable contract for global/per-job agent output language."""

from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TMP = tempfile.TemporaryDirectory(prefix="output-language-")
DATA = Path(TMP.name)
JOBS = DATA / "jobs"
JOBS.mkdir()
os.environ.update(
    DATA_DIR=str(DATA),
    JOBS_DIR=str(JOBS),
    SETTINGS_PATH=str(DATA / "settings.json"),
    AGENT_PROVIDER="claude",
)
os.environ.pop("AGENT_OUTPUT_LANGUAGE", None)

from modules import settings_io  # noqa: E402
from modules.agent_provider import enrich_job_meta  # noqa: E402
from modules.output_language import (  # noqa: E402
    instruction_for_job,
    normalize_output_language,
    output_language_for_job,
    output_language_instruction,
    with_output_language,
)
from modules import codex_cli, gpt_responses  # noqa: E402


PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
    else:
        FAILED += 1
        print(f"FAIL  {label}\n        got  = {got!r}\n        want = {want!r}")


check("Korean alias normalizes", normalize_output_language("한국어"), "ko")
check("English alias normalizes", normalize_output_language("English"), "en")
check("unknown language is safe auto", normalize_output_language("xx"), "auto")
check("Codex adapter forwards ultra effort", codex_cli._normalize_effort("ultra"), "ultra")
check("Responses adapter forwards ultra effort", gpt_responses._normalize_effort("ultra"), "ultra")
role_configs = codex_cli._write_codex_agent_configs(
    DATA,
    "gpt-5.6-sol",
    "ultra",
    output_language_instruction("ko"),
)
check(
    "Codex native role config includes language and ultra",
    all(
        "developer_instructions = " in path.read_text(encoding="utf-8")
        and 'model_reasoning_effort = "ultra"' in path.read_text(encoding="utf-8")
        for path in role_configs.values()
    ),
    True,
)
resume_options = gpt_responses.GptSessionOptions(
    system_prompt="BASE",
    model="gpt-5.6-sol",
    cwd=str(DATA),
    env={"AGENT_OUTPUT_LANGUAGE": "ko"},
)
resume_client = codex_cli.CodexCLIClient(resume_options)
# INVERTED on 2026-09-20. The setting no longer steers a solving prompt: the
# agents solve best in English, and pointing their working language elsewhere
# cost accuracy for output the operator does not read — `report.md`,
# `findings.json` and the flag are technical either way. A resumed turn must
# therefore carry no language policy at all.
check(
    "a resumed Codex turn carries NO language policy",
    "Korean (한국어)" in resume_client._instructions("continue", resuming=True),
    False,
)
check("default setting preserves old behavior", settings_io.get_setting("agent_output_language"), "auto")

settings_io.update_settings({"agent_output_language": "ko"})
check("global Korean setting saves", settings_io.get_setting("agent_output_language"), "ko")
check(
    "public Settings view exposes normalized language",
    settings_io.get_settings_view().get("agent_output_language"),
    "ko",
)

global_meta: dict = {}
enrich_job_meta(global_meta)
check("blank job override snapshots global Korean", global_meta.get("output_language"), "ko")

override_meta: dict = {}
enrich_job_meta(override_meta, output_language="en")
check("per-job English overrides global Korean", override_meta.get("output_language"), "en")

auto_meta: dict = {}
enrich_job_meta(auto_meta, output_language="auto")
check("explicit auto keeps legacy metadata compact", "output_language" in auto_meta, False)

job_id = "language-job"
job_dir = JOBS / job_id
job_dir.mkdir()
(job_dir / "meta.json").write_text(json.dumps(global_meta), encoding="utf-8")
check("worker reads job snapshot", output_language_for_job(job_id), "ko")

instruction = instruction_for_job(job_id)
check("Korean instruction names target language", "Korean (한국어)" in instruction, True)
for protected in ("code", "shell commands", "paths", "error messages", "flags"):
    check(f"instruction protects {protected}", protected in instruction, True)
check("auto emits no extra prompt", output_language_instruction("auto"), "")
wrapped = with_output_language("BASE", job_id)
check("language block is appended", wrapped.startswith("BASE\n\n## OUTPUT LANGUAGE"), True)
check("language block is idempotent", with_output_language(wrapped, job_id), wrapped)

# A Settings edit after create must not half-switch a running job.
settings_io.update_settings({"agent_output_language": "en"})
check("job snapshot ignores later Settings edit", output_language_for_job(job_id), "ko")
settings_io.update_settings({"agent_output_language": None})
check("null clears global override", settings_io.get_setting("agent_output_language"), "auto")

try:
    settings_io.update_settings({"agent_output_language": "esperanto"})
except ValueError:
    invalid_rejected = True
else:
    invalid_rejected = False
check("invalid global language is rejected", invalid_rejected, True)

# Every public create route must accept the form field and pass it to the
# common snapshot helper. AST keeps this check independent of FastAPI/Redis.
route_files = [
    "web_module.py", "pwn_module.py", "forensic_module.py", "misc_module.py",
    "crypto_module.py", "web3_module.py", "rev_module.py",
    "live_fire_module.py",
]
for filename in route_files:
    source = (ROOT / "api" / "routes" / filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    analyze = next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and "output_language" in [arg.arg for arg in node.args.args]
    )
    check(
        f"{filename} accepts output_language",
        "output_language" in [arg.arg for arg in analyze.args.args],
        True,
    )
    enrich_calls = [
        node for node in ast.walk(analyze)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "enrich_job_meta"
    ]
    check(
        f"{filename} snapshots output_language",
        any(
            kw.arg == "output_language"
            and isinstance(kw.value, ast.Name)
            and kw.value.id == "output_language"
            for call in enrich_calls for kw in call.keywords
        ),
        True,
    )

html = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
# Two job forms now, not nine: the eight module tabs merged into one Jeopardy
# form whose module the operator agent picks. The language override has to
# survive that merge — it is one of the few things the OPERATOR still answers.
for form_id in ("jeopardy", "live-fire"):
    start = html.index(f'id="{form_id}-form"')
    form = html[start:html.index("</form>", start)]
    check(f"{form_id} UI has one language override", form.count('name="output_language"'), 1)
check("Settings UI has global language", 'name="agent_output_language"' in html, True)

common = (ROOT / "modules" / "_common.py").read_text(encoding="utf-8")
judge = (ROOT / "modules" / "_judge.py").read_text(encoding="utf-8")
reviewer = (ROOT / "modules" / "reviewer.py").read_text(encoding="utf-8")
codex = (ROOT / "modules" / "codex_cli.py").read_text(encoding="utf-8")
responses = (ROOT / "modules" / "gpt_responses.py").read_text(encoding="utf-8")
retry = (ROOT / "api" / "routes" / "retry.py").read_text(encoding="utf-8")
monitor = (ROOT / "modules" / "_monitor.py").read_text(encoding="utf-8")
# The SOLVING path must carry none of it. Each of these was a wire until
# 2026-09-20; together they are the guard against quietly re-adding one.
check("main/recon/subagents/report carry no language policy",
      common.count("with_output_language("), 0)
check("...and no language env reaches the agent process",
      'env["AGENT_OUTPUT_LANGUAGE"]' in common, False)
check("judge carries none", "instruction_for_job(job_id)" in judge, False)
check("reviewer carries none", "instruction_for_job(job_id)" in reviewer, False)
check("the Codex resume carries none",
      "output_language_instruction(" in codex, False)
check("Responses subagents carry none",
      "output_language_instruction(" in responses, False)
# ...and the setting is not dead: it picks the language of the feed the
# operator actually reads, resolved per call so the toggle takes effect now.
check("the MONITOR feed is what the setting steers now",
      "def _monitor_langs(" in monitor
      and "resolve_output_language" in monitor, True)
check("...resolved per call, not frozen at import",
      monitor.count("langs = MONITOR_LANGS"), 0)
check("...and the findings it extracts follow that language too",
      'The vuln object\'s' in monitor, True)
check("retry preserves parent snapshot", 'prev_meta.get("output_language", "auto")' in retry, True)

print(f"== summary: {PASSED} passed, {FAILED} failed ==")
TMP.cleanup()
raise SystemExit(1 if FAILED else 0)
