#!/usr/bin/env python3
"""The library's index keys must stay English even when the report is Korean.

Run on the host:

    python3 scripts/test_library_index_keys_stay_english.py [--mutate NAME]

WHAT BROKE

`modules/output_language.py` already tells the agent "do not translate or
rewrite code, shell commands, paths, filenames, identifiers, ..." and
`run_report_phase` already appends that policy to the report system prompt.
It was still not enough. Job 5c4a18e68834 (rev, output_language=ko) returned

    solver_strategy.technique_name = '<a Korean technique description — value withheld>'

`api/routes/exploits.py::_harvest_findings` lifts that value straight into the
exploit library as the entry's search key. A Korean key is not "indexed in
Korean" — it is a key that no future job's library hint will ever match, so
the entry is stored and never retrieved. The same is true of the bug-class
filter.

The failure was one of PROXIMITY, not of policy: a general sentence in the
system prompt lost to the concrete schema block sitting in the user turn.  So
the exemption lives on the fields, right where the model picks the value, and
adding another sentence to the policy would only have repeated the loss.

WHAT THIS TEST GUARDS THAT A GREP WOULD NOT

Section A discovers the schemas instead of listing them. A seventh schema
added next year is covered the day it is written, and `REPORT_SCHEMA_WEB3`
proves the point — an earlier hand-written scan of these constants missed it
because its name ends in a digit.

Section B derives the key list from `_harvest_findings` itself rather than
hard-coding four names: it collects the `.get("...")` literals that feed the
`technique` and `bug_classes` assignments. Add a fifth fallback to the
harvester and this test fails until that key is marked too — which is the
whole failure mode, since the harvester is what turns a schema field into an
index column.

Section C is the counter-check. `flag_path`, `ruled_out`, `steps` and
`caveats` are operator prose; Korean there is the setting working correctly,
and `ruled_out` in Korean is an artifact the operator specifically valued.
Marking them would be this fix over-applied.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=(
    "none",
    "technique-unmarked-rev",     # the exact field that came back Korean
    "technique-unmarked-crypto",  # the other free-text one
    "fact-class-unmarked",        # bug-class filter fragments instead
    "approach-unmarked",          # the fallback search key
    "new-schema-unmarked",        # a future schema must not slip past
    "approach-outranks-technique",  # marked English but promoted to co-equal key
    "clause-on-prose",            # over-application: flag_path marked too
    "harvester-gains-a-key",      # a 5th index key nobody marked
    "policy-drops-identifiers",   # the two halves must not contradict
    "chal-name-accepts-upload",   # the name column answers with a UUID again
    "chal-name-allows-invention", # UUID ruled out, a made-up name is not
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
EXPLOITS = (ROOT / "api" / "routes" / "exploits.py").read_text()
POLICY = (ROOT / "modules" / "output_language.py").read_text()

CLAUSE = "ASCII English identifier"
PROSE_KEYS = ("flag_path", "ruled_out", "steps", "caveats")

if args.mutate == "technique-unmarked-rev":
    COMMON = COMMON.replace(
        "'custom-vm-bytecode'. Free text, be specific; do NOT reuse an `approach` "
        "value here. ASCII English identifier, lowercase-hyphenated — never "
        "translated, this is the exploit-library search key>",
        "'custom-vm-bytecode'. Free text, be specific; do NOT reuse an `approach` "
        "value here>")
elif args.mutate == "technique-unmarked-crypto":
    COMMON = COMMON.replace(
        "'CCA2 padding oracle'. ASCII English identifier, lowercase-hyphenated — "
        "never translated, this is the exploit-library search key>",
        "'CCA2 padding oracle'>")
elif args.mutate == "fact-class-unmarked":
    COMMON = COMMON.replace(
        "constant | algorithm | check-routine | obfuscation | side-channel | … — "
        "ASCII English identifier, never translated (exploit-library index key)",
        "constant | algorithm | check-routine | obfuscation | side-channel | …")
elif args.mutate == "approach-unmarked":
    COMMON = COMMON.replace(
        "| osint-research | manual-inspection | … — ASCII English identifier, never "
        "translated. Indexed only as a FALLBACK when technique_name is missing; it "
        "is NOT the search key, so answering here does not excuse a vague "
        "technique_name",
        "| osint-research | manual-inspection | …")
elif args.mutate == "approach-outranks-technique":
    # English, but promoted to a co-equal index key — the wording that would
    # re-open the 61-techniques-to-10-values collapse.
    COMMON = COMMON.replace(
        "ASCII English identifier, never translated. Indexed only as a FALLBACK "
        "when technique_name is missing; it is NOT the search key, so answering "
        "here does not excuse a vague technique_name",
        "ASCII English identifier, never translated (exploit-library index key)")
elif args.mutate == "new-schema-unmarked":
    COMMON += (
        '\n\nREPORT_SCHEMA_KERNEL = """\\\n{\n'
        '  "schema_version": 1,\n'
        '  "solver_strategy": {\n'
        '    "approach": "rop | ret2usr | …",\n'
        '    "technique_name": "<the specific mechanism>"\n'
        '  }\n}"""\n')
elif args.mutate == "clause-on-prose":
    COMMON = COMMON.replace(
        '"flag_path": "<one paragraph: where the flag actually WAS and how it was '
        'encoded',
        '"flag_path": "<ASCII English identifier. one paragraph: where the flag '
        'actually WAS and how it was encoded')
elif args.mutate == "harvester-gains-a-key":
    EXPLOITS = EXPLOITS.replace(
        '        technique = _solver.get("approach") or None',
        '        technique = _solver.get("approach") or None\n'
        '    if not technique:\n'
        '        technique = _solver.get("attack_family") or None')
elif args.mutate == "chal-name-allows-invention":
    COMMON = COMMON.replace(
        ". Never invent an identifier-looking name that appears nowhere in the "
        "artifacts>", ">")
elif args.mutate == "chal-name-accepts-upload":
    COMMON = COMMON.replace(
        "<short name for THIS challenge — from the description when it names one, "
        "else the name the artifacts themselves use, else a short phrase saying "
        "what it IS. Never a random-UUID upload filename: it names nothing a "
        "future solver could match. Never invent an identifier-looking name that "
        "appears nowhere in the artifacts>",
        "<from description or filename>")
elif args.mutate == "policy-drops-identifiers":
    POLICY = POLICY.replace(
        'commands, paths, filenames, identifiers, protocol literals, JSON or "',
        'commands, paths, filenames, protocol literals, JSON or "')

# --------------------------------------------------------------------------
# A. Discover the report schemas rather than listing them.
# --------------------------------------------------------------------------
print("== A. schema discovery ==")

tree = ast.parse(COMMON)
schemas: dict[str, str] = {}
for node in tree.body:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        continue
    t = node.targets[0]
    if not isinstance(t, ast.Name) or "SCHEMA" not in t.id:
        continue
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        continue
    # A report schema is one the report phase fills in — identified by the
    # field the library indexes, not by a name pattern (REPORT_SCHEMA_WEB3
    # would have been missed by `[A-Z_]*`, and PRE_RECON_CACHE_SCHEMA="v7"
    # would have been wrongly included).
    if '"technique_name"' in node.value.value:
        schemas[t.id] = node.value.value

check("every module's report schema is discovered", len(schemas) >= 7)
for name in ("_FINDINGS_SCHEMA_FOR_REPORT_PROMPT", "REPORT_SCHEMA_WEB",
             "REPORT_SCHEMA_WEB3", "REPORT_SCHEMA_CRYPTO", "REPORT_SCHEMA_REV",
             "REPORT_SCHEMA_MISC", "REPORT_SCHEMA_FORENSIC"):
    check(f"  {name} is one of them", name in schemas)
check("the cache-version constant is NOT mistaken for a schema",
      "PRE_RECON_CACHE_SCHEMA" in schemas, False)

# Every schema must actually reach run_report_phase, or marking it is theatre.
for name in schemas:
    if name.startswith("_"):
        continue  # the pwn default, passed by falling through to it
    check(f"  {name} is passed as a schema_text somewhere",
          any(f"schema_text={name}" in (ROOT / p).read_text()
              for p in ("modules/web/analyzer.py", "modules/web3/analyzer.py",
                        "modules/crypto/analyzer.py", "modules/rev/analyzer.py",
                        "modules/misc/orchestrator.py",
                        "modules/forensic/orchestrator.py")))

# --------------------------------------------------------------------------
# B. Derive the index keys from the harvester, then require the clause.
# --------------------------------------------------------------------------
print("\n== B. index keys carry the clause ==")

fn = next(n for n in ast.walk(ast.parse(EXPLOITS))
          if isinstance(n, ast.FunctionDef) and n.name == "_harvest_findings")

# The two library columns a future job's hint is narrowed by. Anything that
# feeds them is an index key and must survive translation.
INDEX_TARGETS = {"technique", "bug_classes"}


def _get_keys(node) -> set[str]:
    """Every `.get("literal")` under `node`, minus the container lookups.

    `bug_classes = sorted({k.get("fact_class") for k in (f.get("key_facts") or [])})`
    reads two keys and only one of them is an index key. `key_facts` names the
    LIST; `fact_class` names the value that lands in the library column. The
    difference is structural — a container lookup sits in a comprehension's
    `iter` — so exclude those subtrees rather than blacklisting the name, which
    would have to be re-blacklisted for every future schema. (`vulns` escapes
    on its own only because it happens to be bound to a local first; relying on
    that would be luck.)
    """
    skip = {id(g.iter) for c in ast.walk(node)
            if isinstance(c, (ast.SetComp, ast.ListComp, ast.DictComp, ast.GeneratorExp))
            for g in c.generators}
    seen: set[str] = set()

    def walk(n):
        if id(n) in skip:
            return
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get" and n.args
                and isinstance(n.args[0], ast.Constant)
                and isinstance(n.args[0].value, str)):
            seen.add(n.args[0].value)
        for ch in ast.iter_child_nodes(n):
            walk(ch)

    walk(node)
    return seen


index_keys: set[str] = set()
for node in ast.walk(fn):
    if not isinstance(node, ast.Assign):
        continue
    names = {t.id for t in node.targets if isinstance(t, ast.Name)}
    if not (names & INDEX_TARGETS):
        continue
    index_keys |= _get_keys(node.value)

# `attack_class` joined this set when crypto's empty filter was fixed, and the
# test failing on the old four-name literal is exactly the intended behaviour:
# a key the harvester newly indexes must be marked before it ships.
check("the harvester's index keys are derived, not assumed",
      index_keys,
      {"technique_name", "approach", "bug_class", "attack_class", "fact_class"})

for sname, body in sorted(schemas.items()):
    for key in sorted(index_keys):
        # `"key": "value"` — the clause has to be inside THIS key's value,
        # not merely somewhere in the schema.
        for m in re.finditer(r'"' + re.escape(key) + r'": "((?:[^"\\]|\\.)*)"', body):
            check(f"  {sname}.{key} is marked English", CLAUSE in m.group(1))

# The four keys are not equals and the wording must not say they are.
# `_harvest_findings` reaches `approach` ONLY when `technique_name` is absent,
# and the rev schema carries an explicit "do NOT reuse an `approach` value here"
# because treating them as synonyms is what collapsed 61 rev techniques onto 10
# values. Marking `approach` with the same "index key" phrase as `bug_class`
# would quietly argue the opposite of that warning.
print("\n== B2. approach is marked as the fallback, not a second search key ==")

for sname, body in sorted(schemas.items()):
    for m in re.finditer(r'"approach": "((?:[^"\\]|\\.)*)"', body):
        check(f"  {sname}.approach is named a fallback", "FALLBACK" in m.group(1))
        check(f"  {sname}.approach does not claim the search key",
              "is NOT the search key" in m.group(1))
    for m in re.finditer(r'"technique_name": "((?:[^"\\]|\\.)*)"', body):
        if "approach" in m.group(1):
            check(f"  {sname}.technique_name still forbids reusing approach",
                  "do NOT reuse" in m.group(1))

# --------------------------------------------------------------------------
# C. The counter-check: prose must stay translatable.
# --------------------------------------------------------------------------
print("\n== C. operator prose is NOT marked ==")

for sname, body in sorted(schemas.items()):
    for key in PROSE_KEYS:
        for m in re.finditer(r'"' + re.escape(key) + r'": (?:"((?:[^"\\]|\\.)*)"|\[")', body):
            val = m.group(1) or ""
            check(f"  {sname}.{key} stays translatable", CLAUSE in val, False)

# --------------------------------------------------------------------------
# C2. chal_name is an index key too, and a UUID is not a name.
# --------------------------------------------------------------------------
# It lives in this suite because the fix is the same shape as the English one
# and needs the same discovery set: a rule that is not ON the field loses to
# the field's own instruction. `chal_name` used to read "<from description or
# filename>", so job 38652a3bb086 — whose description is only the platform's
# FLAG FORMAT notice and whose report.md mentions the upload once — answered
# its upload UUID (`<uuid>.zip`). Removing the caller's name hint
# did not help; the model found the filename in the artifacts and the schema
# told it that was a valid answer.
print("\n== C2. chal_name refuses the upload UUID ==")

for sname, body in sorted(schemas.items()):
    for m in re.finditer(r'"chal_name": "((?:[^"\\]|\\.)*)"', body):
        val = m.group(1)
        check(f"  {sname}.chal_name rules out a random-UUID upload name",
              "random-UUID upload filename" in val)
        # A prohibition with no alternative just leaves the model stuck.
        check(f"  {sname}.chal_name says what to answer instead",
              "the name the artifacts themselves use" in val
              and "a short phrase saying what it IS" in val)
        # Job 7880296073ba answered with a name-shaped string that appears
        # nowhere in its artifacts, once the field pushed it off
        # the (base32) filename. Ruling the UUID out without ruling invention
        # out just trades an opaque true name for a readable false one.
        check(f"  {sname}.chal_name forbids inventing one",
              "Never invent an identifier-looking name" in val)

check("the render guard still backstops entries already stored",
      "if name and not _UUIDISH.match(name):" in COMMON)


# --------------------------------------------------------------------------
# D. The field clause and the global policy must agree.
# --------------------------------------------------------------------------
print("\n== D. policy and fields do not contradict ==")

check("the language policy still exempts identifiers",
      "identifiers" in POLICY)
check("run_report_phase still applies the policy at all",
      "sys_prompt = with_output_language(sys_prompt, job_id)" in COMMON)
check("the clause explains WHY (search key), not just WHAT",
      "exploit-library" in COMMON)
check("the reason is recorded with the job that proved it",
      "5c4a18e68834" in COMMON)

print(f"\n== summary: {passed} passed, {failed} failed; mutation={args.mutate} ==")
raise SystemExit(1 if failed else 0)
