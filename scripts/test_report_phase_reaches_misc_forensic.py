#!/usr/bin/env python3
"""misc and forensic must produce a REPORT-PHASE findings document too.

Run on the host:

    python3 scripts/test_report_phase_reaches_misc_forensic.py [--mutate NAME]

THE GAP, MEASURED IN THE OPERATOR'S OWN LIBRARY

`api/routes/exploits.py::_harvest_findings` indexes a saved exploit by reading
the report phase's findings document — that is where `technique_name` and
`bug_classes` come from, and those are two of the seven columns the library
hint renders into a future job's prompt. Across the 246 saved entries:

    pwn      65/67  (97%)        crypto   16/17  (94%)
    web      54/66  (82%)        rev      68/94  (72%)
    misc      0/2   ( 0%)

misc is zero because misc never ran the phase. The five analyzer-shaped
modules call `run_report_phase`; the two orchestrator-shaped ones never did.
(n=2 makes the percentage weak evidence on its own — the mechanism is the
strong part: a key absent from the schema cannot be harvested.)

WHY misc CANNOT JUST WRITE `findings.json`

For an analyzer, `work_dir` is `<job>/work`. For misc and forensic it is the
JOB ROOT — and misc's pre-analysis SWEEP already writes `<job>/findings.json`
there. That file is a live interface in two directions: the misc system prompt
says "Read findings.json FIRST", and misc/orchestrator.py exposes
`strings.flag_candidates` + `embedded_flag_hits` as leads for the analyst.
Only an explicit verified marker in report.md may finish the job, but
overwriting the sweep would still destroy the evidence used to reach it.

So `run_report_phase` grew an `out_name`, misc passes
`report_findings.json`, and forensic takes the default — forensic names its
sweep artifacts `summary.json` and `log_findings.json`, so `findings.json` was
free there all along.

WHAT WAS DELIBERATELY *NOT* CHANGED

The new schemas reuse `solver_strategy.technique_name` and
`key_facts[].fact_class`, which `_harvest_findings` already resolves for rev.
Inventing fresh key names would have bought a fourth fallback and nothing
else. Section D checks the harvester consumes the new shape unmodified.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Before ANY import that reads it: api/storage.py -> modules/storage.py binds
# DATA_DIR at import time, and section F writes a real job tree.
import os  # noqa: E402
_DATA = tempfile.mkdtemp(prefix="reportphase-")
os.environ["DATA_DIR"] = _DATA

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "misc-overwrites-sweep",      # out_name dropped -> report clobbers the sweep
    "out-name-not-defaulted",     # analyzers would have to be edited
    "misc-not-wired",             # the phase is never called
    "forensic-not-wired",
    "harvest-prefers-sweep",      # name order reversed
    "schema-reuses-approach",     # the rev collapse, reproduced
    "phase-in-provider-branch",   # the shape that lost output_language
    "write-hardcodes-findings",   # out_name accepted but ignored
    "hint-is-the-upload-uuid",    # the library's only human column gets a hash
    "rev-hints-the-binary-name",  # `main` x18 returns to the name column
), default="none")
args = parser.parse_args()

passed = failed = 0


def check(label, got, want=True):
    global passed, failed
    ok = got == want
    if ok:
        passed += 1
        print("PASS  " + label)
    else:
        failed += 1
        print("FAIL  " + label + f"\n      got  = {got!r}\n      want = {want!r}")


COMMON = (ROOT / "modules" / "_common.py").read_text()
MISC = (ROOT / "modules" / "misc" / "orchestrator.py").read_text()
FOR = (ROOT / "modules" / "forensic" / "orchestrator.py").read_text()
STORAGE = (ROOT / "api" / "storage.py").read_text()
EXPLOITS = (ROOT / "api" / "routes" / "exploits.py").read_text()

# Mutations that touch a file this suite reads straight off disk register the
# mutated text here; the reader below prefers it.
_MUTATED_FILES: dict[str, str] = {}


def _read(rel: str) -> str:
    return _MUTATED_FILES.get(rel, (ROOT / rel).read_text())

# Snapshotted so "did the mutation apply?" is a question this file can answer.
# `schema-reuses-approach` anchored on the exact `technique_name` wording and
# went silently MISSED the day that string gained an "ASCII English identifier"
# clause — a stale anchor reads as a passing suite, which is the one outcome a
# mutation must never produce.
_SNAP = (COMMON, MISC, FOR, STORAGE, EXPLOITS)
_SOURCE_MUTATIONS = {
    "misc-overwrites-sweep", "out-name-not-defaulted", "misc-not-wired",
    "forensic-not-wired", "harvest-prefers-sweep", "schema-reuses-approach",
    "phase-in-provider-branch", "hint-is-the-upload-uuid",
}

if args.mutate == "misc-overwrites-sweep":
    MISC = MISC.replace('        out_name="report_findings.json",\n', "")
elif args.mutate == "out-name-not-defaulted":
    COMMON = COMMON.replace('    out_name: str = "findings.json",',
                            "    out_name: str,")
elif args.mutate == "misc-not-wired":
    MISC = MISC.replace("            anyio.run(_run_report_phase, job_id)\n", "")
elif args.mutate == "forensic-not-wired":
    FOR = FOR.replace("            anyio.run(_run_report_phase, job_id)\n", "")
elif args.mutate == "harvest-prefers-sweep":
    STORAGE = STORAGE.replace(
        '_REPORT_FINDINGS_NAMES = ("report_findings.json", "findings.json")',
        '_REPORT_FINDINGS_NAMES = ("findings.json", "report_findings.json")')
elif args.mutate == "hint-is-the-upload-uuid":
    MISC = MISC.replace(
        "        schema_text=REPORT_SCHEMA_MISC,",
        '        chal_name_hint=(read_meta(job_id) or {}).get("filename") or "",\n'
        "        schema_text=REPORT_SCHEMA_MISC,")
    FOR = FOR.replace(
        "        schema_text=REPORT_SCHEMA_FORENSIC,",
        '        chal_name_hint=(read_meta(job_id) or {}).get("filename") or "",\n'
        "        schema_text=REPORT_SCHEMA_FORENSIC,")
elif args.mutate == "rev-hints-the-binary-name":
    _rp = ROOT / "modules" / "rev" / "analyzer.py"
    _rs = _rp.read_text().replace(
        "                schema_text=REPORT_SCHEMA_REV,",
        '                chal_name_hint=(binary_name or ""),\n'
        "                schema_text=REPORT_SCHEMA_REV,")
    if _rs == _rp.read_text():
        raise SystemExit("MUTATION 'rev-hints-the-binary-name' CHANGED NOTHING "
                         "— its anchor is stale. Fix the anchor.")
    _MUTATED_FILES["modules/rev/analyzer.py"] = _rs
elif args.mutate == "schema-reuses-approach":
    # Anchored on the sentence alone, not on the punctuation after it: the
    # previous anchor carried `>",\n    "tools"` and died the moment the field
    # description grew a clause.
    COMMON = COMMON.replace(
        "do NOT reuse an `approach` value here", "reuse the approach value")
elif args.mutate == "write-hardcodes-findings":
    # The parameter exists and callers pass it, but the write ignores it —
    # source-level checks alone would miss this entirely.
    import modules._common as _C
    _orig_rrp = _C.run_report_phase
elif args.mutate == "phase-in-provider-branch":
    MISC = MISC.replace("            anyio.run(_run_report_phase, job_id)\n", "")
    MISC = MISC.replace('    summary["agent_provider"] = "claude"\n',
                        '    summary["agent_provider"] = "claude"\n'
                        '    await run_report_phase(job_id=job_id, work_dir=_job_dir(job_id),\n'
                        '                           log_fn=lambda s: _log(job_id, s))\n')

if args.mutate in _SOURCE_MUTATIONS and (COMMON, MISC, FOR, STORAGE, EXPLOITS) == _SNAP:
    raise SystemExit(
        f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor is stale. "
        "Fix the anchor; do not delete the mutation.")

# ---------------------------------------------------------------- ① out_name
print("\n--- A. out_name: additive, so the five analyzers are untouched ---")

check("run_report_phase takes an out_name",
      "out_name: str" in COMMON)
check("...defaulted to findings.json, so no analyzer call site needed an edit",
      'out_name: str = "findings.json",' in COMMON)
for mod in ("web", "pwn", "crypto", "web3", "rev"):
    src = (ROOT / "modules" / mod / "analyzer.py").read_text()
    check(f"{mod}: still calls run_report_phase without out_name",
          "run_report_phase(" in src and "out_name" not in src)
check("the write actually honours it",
      "out = work_dir / out_name" in COMMON)

# ---------------------------------------------------------- ② the collision
print("\n--- B. misc's sweep survives; forensic takes the free default ---")

check("misc passes a DIFFERENT name than the sweep's",
      'out_name="report_findings.json"' in MISC)
# The two live readers of the sweep. Either one breaking is a silent
# correctness bug: the first changes what the agent is told, the second
# changes which raw flag leads the job preserves for review.
check("...because the misc prompt still points the agent at findings.json",
      "Read findings.json FIRST" in
      (ROOT / "modules" / "misc" / "prompts.py").read_text())
check("...and the orchestrator still parses the sweep out of findings.json",
      '_job_dir(job_id) / "findings.json"' in MISC)
check("forensic uses the default (its sweep is summary/log_findings)",
      "out_name" not in FOR
      and '"log_findings.json"' in FOR)
check("forensic writes no findings.json of its own to collide with",
      '"findings.json"' not in FOR)

# ------------------------------------------------------------- ③ the wiring
print("\n--- C. called once, from run_job, not per provider branch ---")

for label, src in (("misc", MISC), ("forensic", FOR)):
    tree = ast.parse(src)
    helper = next((n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and n.name == "_run_report_phase"), None)
    check(f"{label}: a _run_report_phase helper exists", helper is not None)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None)
                  or getattr(n.func, "attr", None)) == "run_report_phase"]
    # Exactly one, and inside the helper. _claude_summary branches three ways
    # (gpt / grok / claude); putting the phase in the branches is the shape
    # that let the output-language directive go missing from all three.
    check(f"{label}: run_report_phase is called exactly once", len(calls) == 1)
    if helper is not None and len(calls) == 1:
        check(f"{label}: ...from the helper, not a provider branch",
              helper.lineno <= calls[0].lineno <= (helper.end_lineno or 0))
    summary_fn = next((n for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and n.name == "_claude_summary"), None)
    if summary_fn is not None:
        check(f"{label}: ...and NOT inside _claude_summary",
              "run_report_phase" not in ast.unparse(summary_fn))
    check(f"{label}: run_job drives it", "anyio.run(_run_report_phase, job_id)" in src)

# ------------------------------------------------ ③b the name it reports as
# `chal_name` is the library's ONLY human-readable column and
# `build_exploit_library_hint` renders it into a future job's prompt. Any
# `chal_name_hint` reaches the model as "Chal name hint: X" and it answers with
# X, so the hint decides that column. Measured over 251 stored entries:
#
#   no hint  (web, crypto, web3) : 57 distinct of 68; 17 of 17
#   binary   (rev, pwn)          : rev `main` x18 `prob` x5 `chall` x5
#   filename (misc, forensic)    : 0 of 4 usable — every one an upload UUID
#
# So misc and forensic pass NOTHING and let the model read report.md, which is
# what the modules with real names already do. Deriving a hint from the
# operator's description was tried and is the same mistake one step removed:
# job 3868bac2ec4b's description opens "Tested with Python 3.8 and 3.11.".
print("\n--- C2. the name it reports under ---")
# Now true of EVERY module, not just these two. rev and pwn passed their
# binary name and paid for it: of 95 rev entries the column reads `main` 18
# times, `prob` 5 and `chall` 5; pwn reads `prob` 9, `d8` 3, `vm` 3. Given no
# anchor the model names the challenge from the artifacts instead — web has 57
# distinct names across 68 entries, crypto 17 of 17.
for _name in ("misc", "forensic", "web", "web3", "crypto", "rev", "pwn"):
    _rel = (f"modules/{_name}/orchestrator.py" if _name in ("misc", "forensic")
            else f"modules/{_name}/analyzer.py")
    _src = _read(_rel) if _name not in ("misc", "forensic") else (
        MISC if _name == "misc" else FOR)
    check(f"{_name} passes NO chal_name_hint", "chal_name_hint" in _src, False)
check("...and the parameter still defaults to empty, so omitting it is legal",
      'chal_name_hint: str = ""' in COMMON)
check("the prompt line only appears when a hint was actually given",
      'chal_hint = f"\\nChal name hint: {chal_name_hint}\\n" if chal_name_hint else ""'
      in COMMON)
check("the description-derived helper is gone, not merely unused",
      "report_chal_name_hint" in COMMON, False)
check("...and the measurement that retired it is recorded",
      "There is no hint better than no hint" in COMMON)

# The other half of the same defect: a UUID that already reached chal_name
# must not render. Guarding only the fallback let it in the front door.
check("the display guard covers chal_name, not just chal_filename",
      "if name and not _UUIDISH.match(name):" in COMMON)


# --------------------------------------------------------- ④ the harvester
print("\n--- D. the new shape indexes with NO harvester change ---")

# Executed, not grepped: this is the whole point of reusing rev's key names.
# ONE dict for globals and locals. Passing two makes module-level names land
# in `locals` while the functions defined there close over `globals` — so
# report_findings_path() would raise NameError on its own constant.
_ns: dict = {"__name__": "api.storage_undertest"}
exec(compile(STORAGE, "api/storage.py", "exec"), _ns)
resolve = _ns["report_findings_path"]

# `import api.routes.exploits` pulls in the whole FastAPI router, which needs
# python-multipart the host does not have. Lift the two functions under test
# out of the source instead — the same trick the other UI/route suites use, and
# it keeps this runnable without the api container's dependency tree.
_ex_tree = ast.parse(EXPLOITS)
_ex_ns: dict = {"json": json, "Path": Path,
                "report_findings_path": resolve}
for _n in ast.walk(_ex_tree):
    if isinstance(_n, ast.FunctionDef) and _n.name in ("_read_json", "_harvest_findings"):
        exec(compile(ast.Module(body=[_n], type_ignores=[]),
                     "api/routes/exploits.py", "exec"), _ex_ns)
_harvest_findings = _ex_ns["_harvest_findings"]
# The function imports the resolver itself; make that import a no-op hit on the
# namespace above rather than a real one.
_harvest_findings.__globals__["report_findings_path"] = resolve


tmp = Path(tempfile.mkdtemp())
SWEEP = {"archive": {}, "binwalk": [], "exif": [], "strings": {}}
REPORT = {
    "schema_version": 1, "chal_name": "chal-misc-synthetic",
    "solver_strategy": {"technique_name": "synthetic-misc-technique"},
    "key_facts": [{"fact_class": "osint"}, {"fact_class": "stego-ruled-out"}],
}
(tmp / "findings.json").write_text(json.dumps(SWEEP))
check("a job with only the sweep resolves to the sweep",
      resolve(tmp).name, "findings.json")
# Not a regression (it is today's behaviour) but it must stay CLEAN: an
# all-None result, never keys invented out of `archive` / `binwalk`.
h = _harvest_findings(tmp)
check("...and harvests to a clean empty result, not garbage",
      h["technique_name"] is None and h["bug_classes"] == [] and h["chal_name"] is None)

(tmp / "report_findings.json").write_text(json.dumps(REPORT))
check("the report document WINS over a sweep of the same job",
      resolve(tmp).name, "report_findings.json")
h = _harvest_findings(tmp)
check("...and the misc shape harvests a technique",
      h["technique_name"], "synthetic-misc-technique")
check("...and bug classes, via rev's key_facts fallback",
      h["bug_classes"], ["osint", "stego-ruled-out"])
check("...and the challenge name", h["chal_name"], "chal-misc-synthetic")
check("a job with neither resolves to None",
      resolve(Path(tempfile.mkdtemp())), None)

check("the library harvester goes through the resolver",
      "report_findings_path" in EXPLOITS)
check("...and so does the retry lineage's technique carry",
      "report_findings_path" in (ROOT / "api" / "routes" / "retry.py").read_text())

# ------------------------------------------------------------- ⑤ the schema
print("\n--- E. the schemas ask for a mechanism, not a solver method ---")

for name in ("REPORT_SCHEMA_MISC", "REPORT_SCHEMA_FORENSIC"):
    check(f"{name} exists", f"{name} = " in COMMON)
    block = COMMON.split(f"{name} = ")[1].split('"""')[1]
    parsed_keys = ("solver_strategy", "technique_name", "key_facts", "fact_class",
                   "chal_name")
    for k in parsed_keys:
        check(f"  {name}: reuses `{k}` (what _harvest_findings already reads)",
              k in block)
    # The measured trap: rev's 61 techniques collapse onto 10 values because
    # `approach` enumerates solver methods. A schema that invites the same
    # answer produces "steganography" three hundred times.
    check(f"  {name}: forbids answering with the `approach` value",
          "do NOT reuse an `approach` value here" in block)
    check(f"  {name}: asks WHAT the challenge is, not how it was solved",
          "not how you solved it" in block)
    check(f"  {name}: is valid-ish JSON scaffolding (balanced braces)",
          block.count("{") == block.count("}"))

check("misc uses the misc schema", "REPORT_SCHEMA_MISC" in MISC)
check("forensic uses the forensic schema", "REPORT_SCHEMA_FORENSIC" in FOR)

# --------------------------------------------------- ⑥ the write, for real
print("\n--- F. runtime: the sweep survives a report phase beside it ---")

# Everything above reads source. This runs the real `run_report_phase` with a
# stubbed model call, because "the sweep is not clobbered" is a property of
# what lands on disk, not of a string in a file.
import types  # noqa: E402
import anyio  # noqa: E402

CANNED = {
    "schema_version": 1, "chal_name": "chal-misc-synthetic",
    "solver_strategy": {"technique_name": "synthetic-misc-technique"},
    "key_facts": [{"fact_class": "osint"}],
}

_fake_gpt = types.ModuleType("modules.gpt_agent")


async def _fake_query_gpt_once(**kw):
    _fake_gpt.seen = kw
    return {"text": json.dumps(CANNED)}


_fake_gpt.query_gpt_once = _fake_query_gpt_once
sys.modules["modules.gpt_agent"] = _fake_gpt

from modules._common import run_report_phase  # noqa: E402

jd = Path(_DATA) / "jobs" / "reportjob0001"
jd.mkdir(parents=True, exist_ok=True)
(jd / "meta.json").write_text(json.dumps({
    "id": "reportjob0001", "module": "misc", "agent_provider": "gpt",
}))
# The two files that share this directory for a misc job.
SWEEP_BYTES = json.dumps(SWEEP, indent=2)
(jd / "findings.json").write_text(SWEEP_BYTES)
# Flag-SHAPED, not a real flag: the body is invented, not taken from any job.
(jd / "report.md").write_text(
    "LOCAL{q7z_k3w9_mx2v_synth}\n\n# Identification\nA public source matched the "
    "artifact.\n\n# Tools tried\n"
    "- zsteg: nothing.\n")

if args.mutate == "write-hardcodes-findings":
    import modules._common as _Cmod
    _src = (ROOT / "modules" / "_common.py").read_text().replace(
        "out = work_dir / out_name", 'out = work_dir / "findings.json"')
    _mns = {"__name__": "modules._common_mutated"}
    exec(compile(_src, "modules/_common.py", "exec"), _mns)
    run_report_phase = _mns["run_report_phase"]

_logged: list[str] = []
ok = anyio.run(lambda: run_report_phase(
    job_id="reportjob0001",
    work_dir=jd,
    log_fn=_logged.append,
    schema_text="{}",
    out_name="report_findings.json",
))

check("the phase reports success", ok)
check("it wrote report_findings.json", (jd / "report_findings.json").is_file())
if (jd / "report_findings.json").is_file():
    check("...with the model's document",
          json.loads((jd / "report_findings.json").read_text())["solver_strategy"]
          ["technique_name"], "synthetic-misc-technique")
# THE load-bearing assertion of this whole change.
check("REGRESSION: the sweep's findings.json is byte-identical afterwards",
      (jd / "findings.json").read_text(), SWEEP_BYTES)
check("...and the log names the file it actually wrote",
      any("report_findings.json written" in m for m in _logged), True)

# And the default still lands on findings.json, which is what keeps the five
# analyzer call sites correct without an edit.
jd2 = Path(_DATA) / "jobs" / "reportjob0002"
jd2.mkdir(parents=True, exist_ok=True)
(jd2 / "meta.json").write_text(json.dumps({"id": "reportjob0002", "agent_provider": "gpt"}))
(jd2 / "report.md").write_text("# r\nsomething\n")
anyio.run(lambda: run_report_phase(
    job_id="reportjob0002", work_dir=jd2, log_fn=lambda _s: None, schema_text="{}"))
check("the DEFAULT out_name still writes findings.json",
      (jd2 / "findings.json").is_file())
check("...and does not invent report_findings.json",
      (jd2 / "report_findings.json").is_file(), False)

# No report.md at all -> the phase must no-op, not write an empty document.
jd3 = Path(_DATA) / "jobs" / "reportjob0003"
jd3.mkdir(parents=True, exist_ok=True)
(jd3 / "meta.json").write_text(json.dumps({"id": "reportjob0003", "agent_provider": "gpt"}))
ok3 = anyio.run(lambda: run_report_phase(
    job_id="reportjob0003", work_dir=jd3, log_fn=lambda _s: None, schema_text="{}",
    out_name="report_findings.json"))
check("a job with no report.md is a clean no-op", ok3, False)
check("...writing nothing", (jd3 / "report_findings.json").is_file(), False)

print(f"\n== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
