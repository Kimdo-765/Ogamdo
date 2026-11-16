#!/usr/bin/env python3
"""The harvester must see flags FLAG_RE cannot, without re-importing its poison.

WHY THIS EXISTS

`FLAG_RE` (modules/_common.py) is a fixed alphabet: DH, picoCTF, HTB, CTF,
dreamhack, ~20 prefixes. Two flags this platform actually captured are not on
it (the bodies here are invented; real flags never enter the tree):

    job 29f1d8f14268  REVERSSEUM{z96v_8q2km_smwg_prg4_x7p6x_4gns}
    job fed8eedff33d  pokactf2024{EXAMPLEXXFLAGXXVALUEXXNOTXXREALXXXXXXXXXX...}

Both were recovered only because the solver happened to print the
`FLAG_CANDIDATE:` marker. Without that habit each run would have finished with
the flag sitting in its own log, unrecognised — the operator's report:
"정규식 매칭이 가끔 flag를 못찾을 경우가 있어서."

So the harvester's prefilter is deliberately LOOSER than FLAG_RE, and the first
section below is the reason the whole component exists: a gate that only
accepts known prefixes finds nothing new.

THE COUNTERWEIGHT

Looser means it also catches the things that made run.log a banned flag source
on 2026-07-23 (`_NARRATIVE_FLAG_SOURCES`, modules/_common.py). Three jobs paid:
dc981a8c4741 false-finished on a flag scraped from a recon WebSearch summary;
44dd25365173 shipped four fabricated `DH{<sha256>}`; f52f0219803f produced four
fakes when judge subagents `Read` exploit.py and echoed its literal
`print("FLAG_CANDIDATE: ...")` SOURCE.

Two things keep that from repeating, and both are tested here: the source-code
guard, and — the load-bearing one — the harvester writes ONE text file and can
never touch `meta.flags` or a status. Every incident above was a fake flag
ENDING a job. A component that only appends to a file cannot do that.

THE CORRECTNESS DETAIL THAT IS EASY TO GET WRONG

Polling an append-only file can land mid-write. Consume the partial tail and
the offset advances past it, so a flag arrives as two fragments and NEITHER
matches. The monitor has this bug and survives it because it summarises prose.
Here the exact string IS the deliverable, so `_consume_whole_lines` stops at
the last newline. Section P proves a flag split across two polls is still read
whole.

Run:
    python3 scripts/test_flag_harvester.py
    python3 scripts/test_flag_harvester.py --mutate gate-uses-flag-re
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HARV = ROOT / "modules" / "_harvester.py"
PRESETS = ROOT / "modules" / "model_presets.py"
APPJS = ROOT / "web-ui" / "app.js"
INDEX = ROOT / "web-ui" / "index.html"
SETTINGS = ROOT / "modules" / "settings_io.py"
PROVIDER = ROOT / "modules" / "agent_provider.py"

H = HARV.read_text()
M = PRESETS.read_text()
J = APPJS.read_text()
X = INDEX.read_text()
S = SETTINGS.read_text()
A = PROVIDER.read_text()

MUTATIONS = (
    "gate-uses-flag-re",      # prefilter demands a known prefix — finds nothing new
    "no-source-guard",        # exploit.py's own print() becomes a flag again
    "consume-partial-lines",  # offset advances past a half-written line
    "offset-never-resets",    # a truncated file seeks past EOF forever
    "grain-not-deduped",      # the same flag is appended on every batch
    "grain-writes-rejected",  # rejected verdicts land in flag_grain.txt
    "role-unregistered",      # harvester missing from CONFIGURABLE_ROLES
    "harvester-hidden-gpt",   # filtered out for GPT like the monitor
    "toggle-unwired",         # the Settings checkbox never posts
    "not-routable",           # harvester missing from ROLE_OVERRIDABLE
    "js-role-drift",          # the JS mirror forgets harvester — select is inert
    "grok-not-a-target",      # Grok dropped from the routing set
    "failover-widened",       # automatic failover learns to fall onto Grok
    "no-grok-adjudicator",    # a grok-routed harvester silently finds nothing
    "prompt-invites-tools",   # the model reaches for a tool it does not have
    "errors-stay-silent",     # a failed adjudication is indistinguishable from an empty one
    "body-charset-loose",     # CSS/JS blocks are candidates again
    "fetched-not-tagged",     # scraped markup reaches the model unlabelled
    "tab-listing-passes",     # `16<TAB>const FLAG = ...` is a candidate again
    "harvests-live-fire",     # a patching job is harvested for a flag it cannot have
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_H0, _M0, _J0, _X0, _S0, _A0 = H, M, J, X, S, A

if args.mutate == "gate-uses-flag-re":
    # Anchor on the STRUCTURE, not on the exact charset — the body class is
    # tuned against measured noise and will change again.
    # A lambda replacement, because re.sub processes backslashes in a string
    # replacement and this pattern is nothing but backslashes.
    _NARROW = '_BRACE_RE = re.compile(r"(?:FLAG|CTF|DH|HTB|picoCTF)' + chr(92) + '{[^' + chr(92) + 's{}]{4,200}' + chr(92) + '}")'
    H = re.sub(r'_BRACE_RE = re\.compile\([^\n]*\)', lambda m: _NARROW, H, count=1)
elif args.mutate == "harvests-live-fire":
    H = H.replace("    if not module_has_flags(job_id):\n        return\n", "", 1)
elif args.mutate == "no-source-guard":
    H = H.replace("    if _looks_like_source(line):\n        return False\n", "", 1)
elif args.mutate == "consume-partial-lines":
    H = H.replace('    cut = data.rfind(b"\\n") + 1', "    cut = len(data)", 1)
elif args.mutate == "offset-never-resets":
    H = H.replace("    if off > size:\n        # Truncated or replaced under us — start over rather than seek past EOF.\n        off = 0\n", "", 1)
elif args.mutate == "grain-not-deduped":
    H = H.replace('f["flag"] not in seen', "True", 1)
elif args.mutate == "grain-writes-rejected":
    H = H.replace('f["verdict"] == "real" and ', "", 1)
elif args.mutate == "role-unregistered":
    M = M.replace('"monitor", "harvester",', '"monitor",', 1)
elif args.mutate == "harvester-hidden-gpt":
    # presetRoles no longer filters anything (the monitor split is gone), so
    # the mutation reintroduces a filter rather than widening one.
    J = J.replace("  return roles;\n}",
                  '  return provider === "gpt" ? roles.filter((role) => role !== "harvester") : roles;\n}', 1)
elif args.mutate == "not-routable":
    A = A.replace('"monitor", "harvester",', '"monitor",', 1)
elif args.mutate == "js-role-drift":
    J = J.replace('"monitor", "harvester", "manager"]',
                  '"monitor", "manager"]', 1)
elif args.mutate == "grok-not-a-target":
    A = A.replace('"claude", "gpt", "grok", "local"', '"claude", "gpt", "local"', 1)
elif args.mutate == "failover-widened":
    A = A.replace('ROLE_FAILOVER_PROVIDERS: frozenset[str] = frozenset({"claude", "gpt"})',
                  'ROLE_FAILOVER_PROVIDERS: frozenset[str] = frozenset({"claude", "gpt", "grok"})', 1)
elif args.mutate == "body-charset-loose":
    H = H.replace(r'\{[A-Za-z0-9_!@^*+=/.\-]{6,200}\}', r"\{[^\s{}]{4,200}\}", 1)
elif args.mutate == "fetched-not-tagged":
    H = H.replace('return bool(_HTML_ESCAPED_RE.search(line or ""))', "return False", 1)
elif args.mutate == "tab-listing-passes":
    H = H.replace("      | ^\\s*\\d+\\t                # `16<TAB>const FLAG = ...` — the TAB form,\n", "", 1)
elif args.mutate == "prompt-invites-tools":
    H = H.replace("You have NO TOOLS and MUST NOT try to use any.", "You may investigate.", 1)
elif args.mutate == "errors-stay-silent":
    # Keep the function DEFINED and make it record nothing. Deleting it makes
    # the suite raise AttributeError, which is a crash, not a bite — and a
    # mutation that kills the harness proves nothing about what it detects.
    H = H.replace("    if not detail or _LAST_ERROR.get(job_id) == detail:\n        return False",
                  "    return False", 1)
elif args.mutate == "no-grok-adjudicator":
    H = H.replace('        if provider == "grok":', '        if False:', 1)
elif args.mutate == "toggle-unwired":
    J = J.replace('''  payload.flag_harvester =
    !!e.target.querySelector("[name=flag_harvester]").checked;\n''', "", 1)

if args.mutate and (H, M, J, X, S, A) == (_H0, _M0, _J0, _X0, _S0, _A0):
    raise SystemExit(
        f"MUTATION {args.mutate!r} CHANGED NOTHING — its anchor no longer matches."
    )

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


def load_harvester():
    """Exec the MUTATED source. Importing modules._harvester would load the
    real file and quietly ignore every mutation above."""
    mod = types.ModuleType("harvester_under_test")
    exec(compile(H, str(HARV), "exec"), mod.__dict__)
    return mod


mod = load_harvester()

# The two captures' prefixes, with invented bodies: real flags never enter the tree.
REVERSSEUM = "REVERSSEUM{z96v_8q2km_smwg_prg4_x7p6x_4gns}"
POKACTF = "pokactf2024{EXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAGxxyy}"


def _flag_re():
    """The PRODUCTION FLAG_RE, imported rather than re-parsed.

    This is the baseline the harvester is measured against, not something the
    mutations touch, so the real object is the right one — and a hand-rolled
    extraction of a multi-line `re.compile(...)` is exactly the kind of
    almost-right parsing that makes a suite quietly measure the wrong thing.
    """
    from modules._common import FLAG_RE
    return FLAG_RE


def _gap_checks():
    print("\nG — the gap the harvester exists to close")
    fre = _flag_re()
    check("G0 FLAG_RE was located in _common.py", fre is not None)
    if fre:
        # The premise. If FLAG_RE already matched these, the feature is moot.
        check("G1 FLAG_RE does NOT match REVERSSEUM{...}", bool(fre.search(REVERSSEUM)), False)
        check("G1 FLAG_RE does NOT match pokactf2024{...}", bool(fre.search(POKACTF)), False)
    check("G2 the harvester DOES see REVERSSEUM{...}", mod._interesting(f"TOOL_RESULT: {REVERSSEUM}"))
    check("G2 ...and pokactf2024{...}", mod._interesting(f"AGENT: {POKACTF}"))
    check("G3 a known prefix still passes", mod._interesting("TOOL_RESULT: DH{EXAMPLEFLAGVALUENOTR}"))
    check("G4 ordinary prose does not", mod._interesting("judge: no flag here at all"), False)


def _poison_checks():
    print("\nS — the source-code echo that faked four flags (f52f0219803f)")
    check("S1 a print() of the marker is not a flag",
          mod._interesting('93|     print("FLAG_CANDIDATE: " + flag)'), False)
    check("S2 ...nor an f-string template",
          mod._interesting('    msg = f"FLAG_CANDIDATE: {flag}"'), False)
    check("S3 ...nor a regex definition",
          mod._interesting('FLAG_RE = re.compile(r"DH\\{[^}]+\\}")'), False)
    check("S4 ...nor a comment",
          mod._interesting('  # emit DH{example_value_here} when solved'), False)
    check("S5 but real output still passes",
          mod._interesting(f"[runner:stdout] FLAG_CANDIDATE: {POKACTF}"))


def _partial_line_checks(tmp):
    print("\nP — a flag split across two polls must still be read whole")
    p = Path(tmp) / "run.log"
    head, tail = REVERSSEUM[:20], REVERSSEUM[20:]
    p.write_bytes(f"[13:00:00] [main] TOOL_RESULT: {head}".encode())

    lines, off = mod._consume_whole_lines(p, 0)
    # No newline yet: nothing may be consumed, or the flag is torn in half.
    check("P1 an unterminated line is not consumed", lines, [])
    check("P1 ...and the offset does not advance", off, 0)

    with p.open("ab") as fp:
        fp.write(f"{tail}\n".encode())
    lines, off = mod._consume_whole_lines(p, off)
    check("P2 once the newline lands, one whole line arrives", len(lines), 1)
    joined = lines[0] if lines else ""
    check("P2 ...containing the COMPLETE flag", REVERSSEUM in joined)
    check("P2 ...and the offset advanced to EOF", off, p.stat().st_size)

    # Append-only: a second poll with no new bytes returns nothing.
    lines2, off2 = mod._consume_whole_lines(p, off)
    check("P3 a poll with no new bytes reads nothing", lines2, [])
    check("P3 ...and does not move the offset", off2, off)

    # Only the NEW bytes, never a re-read of what was already seen.
    with p.open("ab") as fp:
        fp.write(b"[13:00:01] [main] second line\n")
    lines3, _ = mod._consume_whole_lines(p, off)
    check("P4 only the appended line is returned", len(lines3), 1)
    check("P4 ...and it is the new one", "second line" in (lines3[0] if lines3 else ""))

    # Truncation/replacement must reset rather than seek past EOF forever.
    p.write_bytes(b"[13:00:02] [main] fresh short file\n")
    lines4, off4 = mod._consume_whole_lines(p, 10_000)
    check("P5 a truncated file is re-read from the start", len(lines4), 1)
    check("P5 ...and the offset is sane", off4, p.stat().st_size)


def _grain_checks(tmp):
    print("\nF — flag_grain.txt is the deliverable")
    jobs = Path(tmp) / "jobs"
    (jobs / "J").mkdir(parents=True, exist_ok=True)
    mod.JOBS_DIR = jobs
    out = jobs / "J" / "flag_grain.txt"

    real = {"flag": REVERSSEUM, "verdict": "real", "confidence": 0.9, "why": "solver stdout"}
    fake = {"flag": "DH{fake_flag}", "verdict": "rejected", "confidence": 0.1, "why": "placeholder"}

    n = mod.append_grain("J", [real, fake], ["run.log"])
    check("F1 an accepted finding is written", n, 1)
    body = out.read_text()
    check("F1 ...and the flag string is in the file", REVERSSEUM in body)
    check("F2 a REJECTED finding is not written", "DH{fake_flag}" in body, False)

    n2 = mod.append_grain("J", [real], ["run.log"])
    check("F3 the same flag is not appended twice", n2, 0)
    check("F3 ...so the file still holds exactly one line",
          len([l for l in out.read_text().splitlines() if l.strip()]), 1)

    other = {"flag": POKACTF, "verdict": "real", "confidence": 0.8, "why": "remote stdout"}
    mod.append_grain("J", [other], ["gpt-events.jsonl"])
    lines = [l for l in out.read_text().splitlines() if l.strip()]
    check("F4 a different flag appends rather than replaces", len(lines), 2)
    check("F4 ...and the first is still there", any(REVERSSEUM in l for l in lines))


def _code_only(src: str) -> str:
    """The module's EXECUTABLE code, with comments and docstrings removed.

    A plain grep over the file counts the docstring, which necessarily
    discusses `meta.flag_candidates` to explain what this component is not.
    "The prose mentions it" and "the code writes it" are opposite findings;
    a check that cannot tell them apart proves nothing.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(getattr(first, "value", None), ast.Constant)
                    and isinstance(first.value.value, str)):
                body.pop(0)
    return ast.unparse(tree)


def _advisory_checks():
    print("\nA — advisory only: it cannot end a job")
    # The entire safety argument. Every incident that got run.log banned as a
    # flag source was a fake flag FINISHING a run, so the property to hold is
    # not "it is careful" but "it has no way to do that at all".
    code = _code_only(H)
    for forbidden, why in (
        ("write_meta", "the only writer of meta.json"),
        ("flag_candidates", "the field the worker owns"),
        ("flag_trusted_tier", "the promotion tier"),
        ("scan_job_for_flags", "the promoting sweep"),
    ):
        check(f"A1 the executable code never calls {forbidden} ({why})",
              forbidden in code, False)
    # Reading meta.status is fine and necessary; WRITING one is not.
    check("A1 ...and never assigns a status",
          bool(re.search(r'status\s*=\s*["\']', code)), False)

    check("A2 it does write files (the grain + its own state)",
          any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr in ("write_text", "open")
              for n in ast.walk(ast.parse(H))))
    check("A3 the only job artifact it names is flag_grain.txt",
          'OUT_NAME = "flag_grain.txt"' in H)
    # Belt and braces: the docstring must still SAY so, because the next
    # person to extend this module reads the prose, not this suite.
    check("A4 the docstring records the restriction",
          "cannot write" in H and "flag_grain.txt" in H)


def _plumbing_checks():
    print("\nW — the role reaches the operator's Settings UI")
    check("W1 registered in CONFIGURABLE_ROLES", '"harvester",' in M)
    check("W2 in the UI's DEFAULT_PRESET_ROLES", '"harvester"]' in J or '"harvester",' in J)
    check("W3 has an (inherit) label so the row is not blank", "  harvester:" in J)
    # The monitor is hidden for GPT because the Timeline replaces it. Nothing
    # replaces the harvester, and GPT is what this deployment runs — hiding it
    # would make the role unreachable in practice.
    m = re.search(r"function presetRoles\([^)]*\)\s*\{(.*?)\n\}", J, re.S)
    body = m.group(1) if m else ""
    check("W4 it is NOT filtered out for GPT", "harvester" in body and "!==" in body
          and 'role !== "harvester"' in body, False)
    check("W5 the settings checkbox exists", 'name="flag_harvester"' in X)
    for frag, why in (
        ('f.querySelector("[name=flag_harvester]").checked', "loads"),
        ('if (k === "flag_harvester") continue;', "skips the raw form entry"),
        ('payload.flag_harvester =', "posts"),
    ):
        check(f"W6 the toggle {why}", frag in J)
    check("W7 the setting is declared", '("flag_harvester", "FLAG_HARVESTER", bool, True),' in S)
    check("W8 ...with an accessor", "def flag_harvester_enabled()" in S)


def _routing_checks():
    """The operator may pin the harvester to Grok or Claude independently of
    the job's own backend — Settings > Agent & routing.

    The failure mode this guards is not "wrong provider" but SILENCE: a role
    whose <select> renders while one of the three role lists omits it stores
    nothing, and an advisory component that never ran looks exactly like one
    that found nothing.
    """
    print("\nR — per-role provider routing")
    # Parsed, not spelled. This check used to match the literal
    # '"monitor", "harvester"}' — which broke the day a later commit added
    # "manager" to ROLE_OVERRIDABLE and pushed the closing brace one role
    # along. The set was right and the guard was red, which is the worst way
    # for a guard to fail: it trains you to ignore it.
    py_roles = set(re.findall(r'"(\w+)"', A[A.index("ROLE_OVERRIDABLE"): A.index("# Providers a role may be ROUTED")]))
    check("R1 harvester is routable", "harvester" in py_roles)
    # Parsed like R1, and for the same reason: this spelled the whole literal
    # and broke the day a fourth target was added and the line reflowed. The
    # claim is membership, not formatting.
    _targets = set(re.findall(r'"(\w+)"',
                   A[A.index("ROLE_TARGET_PROVIDERS"):
                     A.index("ROLE_TARGET_PROVIDERS") + 300].split("frozenset(", 1)[1]))
    check("R2 Grok is a routing target", "grok" in _targets)
    # Routing is a human choice; failover is a machine one. Widening the first
    # must not widen the second, or judge/reviewer/report/monitor start
    # falling onto a backend nobody selected.
    check("R3 automatic failover stays claude <-> gpt",
          'ROLE_FAILOVER_PROVIDERS: frozenset[str] = frozenset({"claude", "gpt"})' in A)
    check("R4 failover_target uses the NARROW set",
          "for candidate in sorted(ROLE_FAILOVER_PROVIDERS):" in A)

    js_roles = set(json.loads(re.search(r"const ROLE_OVERRIDABLE = (\[[^\]]*\]);", J).group(1)))
    js_targets = set(json.loads(re.search(r"const ROLE_TARGETS = (\[[^\]]*\]);", J).group(1)))
    html_roles = set(re.findall(r'name="role_provider_(\w+)"', X))
    check("R5 the JS role mirror matches Python", js_roles, py_roles)
    check("R6 every routable role has a <select>", html_roles, py_roles)
    check("R7 the JS target mirror includes grok", "grok" in js_targets)
    check("R8 every <select> offers Grok",
          X.count('<option value="grok">Grok</option>'), len(html_roles))

    # A grok-routed harvester must actually adjudicate on Grok. Without this
    # branch it drops into the Claude SDK holding a grok-* model id and fails
    # every batch quietly.
    check("R9 the harvester has a real Grok adjudicator",
          'if provider == "grok":' in H and "query_grok_once" in H)
    check("R10 it resolves the ROUTED provider, not just the job's",
          'provider_for_role(job_id, "harvester")' in H)


# Every prefix below appeared in a REAL job this session. The bodies are
# invented, because real flags never enter the tree, but each stays inside the
# charset real captures use ([A-Za-z0-9_-], see the comment above `_BRACE_RE`):
# the gate takes any short prefix and narrows on the body's charset and length.
CAPTURED = [
    "REVERSSEUM{z96v_8q2km_smwg_prg4_x7p6x_4gns}",   # 29f1d8f14268
    "pokactf2024{EXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAGxxyy}",
    "INCOGNITO{INCOGNITOEXAMPLEVALUENOTREALzzxx}",                   # cb6792a839fb
    "INCOGNITO{INCOGNITOEXAMPLEVALUETWONOTREALz}",                   # 8e12a5fb1475
    "DH{EXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAGVALUENOTREALzzEXAMPLEFLAG}",
]
# What the old gate let through on 48fadce3dde7, whose agent curled 2.4 MB of
# blog write-ups. All of it is shaped exactly like `token{body}`.
SCRAPED_NOISE = [
    "html{box-sizing:border-box}",
    "before{box-sizing:inherit}",
    "to{transform:rotate(360deg)}",
    "root{--ds-gray-900:#666;--ds-gray-alpha-1000:#000000e8}",
    "try{console.log(x,eval(x))}",
    "try{console.log(x,require(x+'/package.json').version)}",
    "delay.{cc,h}",
]


def _corpus_checks():
    """The gate is measured against real captures and real noise, not examples."""
    print("\nC — the measured corpus")
    kept = [f for f in CAPTURED if mod._BRACE_RE.search(f)]
    check(f"C1 every flag this platform captured still passes ({len(kept)}/{len(CAPTURED)})",
          len(kept), len(CAPTURED))
    for f in CAPTURED:
        if not mod._BRACE_RE.search(f):
            check(f"C1 ...lost: {f[:40]}", False)
    passed = [n for n in SCRAPED_NOISE if mod._BRACE_RE.search(n)]
    check("C2 CSS/JS/shell noise no longer reaches the model", passed, [])

    # The false positive itself, in the exact shape it arrived.
    poison = ('&lt;p style=&quot;text-align: center;&quot; data-ke-size=&quot;size16&quot;&gt;'
              'flag : codegate2025{abcdefEXAMPLEFLAGVALUENOTR456789abcdefEXAMPLEFLAGVALUENOTR456789}&lt;/p&gt;')
    check("C3 escaped page markup is recognised as fetched", mod.looks_fetched(poison))
    check("C3 ...while real run output is not",
          mod.looks_fetched("[runner:stdout] FLAG_CANDIDATE: DH{abc123def}"), False)
    check("C4 the prompt tells the model what the tag means", ":fetched-page" in H)
    check("C5 a TAB-delimited source listing is not a candidate",
          mod._interesting("16\tconst FLAG = 'DH{testtest}';"), False)


def _silence_checks(tmp):
    """A failed adjudication must not look like an empty one.

    Job 8e12a5fb1475, observed live: a grok-routed harvester consumed
    `FLAG_CANDIDATE: INCOGNITO{...}`, passed it through the gate, called the
    model, and wrote nothing. The cause was not the flag and not the gate —
    the SYSTEM PROMPT listed "quoted from a write-up or a web search result"
    as a rejection reason, so the model tried an actual `Web search:` in a
    text-only helper and the whole turn was discarded:

        tool_use_in_text_only_role: grok attempted `Web search:` ...

    Two defects, both fixed, both pinned here: the prompt invited a tool the
    harness forbids, and the failure was swallowed so "never ran" and "found
    nothing" produced identical output.
    """
    print("\nE — a failure must be visible")
    check("E1 the prompt forbids tools outright",
          "You have NO TOOLS and MUST NOT try to use any." in H)
    check("E2 ...and tells the model to answer anyway when unsure",
          "give your best verdict with a lower confidence" in H)
    check("E3 the rejection criterion no longer invites a lookup",
          "the line itself presents as quoted from documentation" in H)

    jobs = Path(tmp) / "ejobs"
    (jobs / "J").mkdir(parents=True, exist_ok=True)
    mod.JOBS_DIR = jobs
    out = jobs / "J" / "flag_grain.txt"
    check("E4 an adjudication error is recorded",
          mod.note_error("J", "tool_use_in_text_only_role: grok attempted `Web search:`"), True)
    # Read defensively: when note_error records nothing the file never exists,
    # and a suite that raises there reports a crash instead of the failure it
    # was written to catch.
    def _grain_text():
        try:
            return out.read_text()
        except Exception:
            return ""
    check("E4 ...where the operator will see it",
          "tool_use_in_text_only_role" in _grain_text())
    check("E5 the same error is not repeated on every batch",
          mod.note_error("J", "tool_use_in_text_only_role: grok attempted `Web search:`"), False)
    check("E6 a DIFFERENT error still gets through",
          mod.note_error("J", "TimeoutError: adjudication exceeded 60s"), True)
    check("E7 _adjudicate can report which job failed",
          "job_id: str | None = None" in H and "_adjudicate(batch, model, provider, job_id)" in H)


def _no_flag_module_checks(tmp):
    """A module whose runs cannot hold a flag must not be harvested.

    Live-fire PATCHES a service. There is no flag in the run, `meta.flags` is
    never read for it, and the verdict is `ready_to_deploy`. Before this, every
    live-fire job on the host carried a `.harvester.state` and a
    `flag_grain.txt` — all `adjudicated=0`, so the model cost was zero, but a
    zero is the BEST case: the source being read is full of brace-shaped
    tokens (minified code is dense with short name{...} runs that fit the
    pattern) and some
    attack-and-defence bundles ship a literal `flag` file. Either one, echoed
    into the run log by the patch agent, buys an adjudication for a flag that
    does not exist.
    """
    print("\n-- a module with no flags is not harvested -------------------")
    root = pathlib.Path(tmp) / "nfjobs"
    root.mkdir(parents=True, exist_ok=True)

    def _job(name, meta):
        d = root / name
        d.mkdir(exist_ok=True)
        (d / "meta.json").write_text(json.dumps(meta))
        return name

    saved = mod.JOBS_DIR
    mod.JOBS_DIR = root
    try:
        _job("aaaaaaaaaaa1", {"module": "live-fire", "status": "running"})
        _job("aaaaaaaaaaa2", {"module": "rev", "status": "running"})
        _job("aaaaaaaaaaa3", {"module": "LIVE-FIRE", "status": "running"})
        _job("aaaaaaaaaaa4", {"status": "running"})
        check("live-fire is excluded", mod.module_has_flags("aaaaaaaaaaa1"), False)
        check("a solving module is not", mod.module_has_flags("aaaaaaaaaaa2"), True)
        check("the match is case-insensitive",
              mod.module_has_flags("aaaaaaaaaaa3"), False)
        # Fail OPEN. A meta we cannot read is not evidence that the job has no
        # flag, and missing a real one costs more than a wasted scan.
        check("a job with no module recorded is still harvested",
              mod.module_has_flags("aaaaaaaaaaa4"), True)
        check("a job with no meta at all is still harvested",
              mod.module_has_flags("xxxxxxxxxxx9"), True)
    finally:
        mod.JOBS_DIR = saved

    # The predicate is worthless unless the entry point consults it, and the
    # entry point is where a future caller would bypass it.
    src = H[H.index("def ensure_harvester("):]
    src = src[:src.index("\nasync def _guarded")]
    wired = "module_has_flags(job_id)" in src
    check("ensure_harvester consults it", wired)
    # Ordering, not just presence — a guard placed after the task is created
    # has already spent what it exists to save. Guarded so a missing anchor
    # reports a FAIL rather than a traceback.
    check("...and returns before creating the task",
          wired and src.index("module_has_flags(job_id)") < src.index("create_task"))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        _gap_checks()
        _poison_checks()
        _partial_line_checks(tmp)
        _grain_checks(tmp)
        _advisory_checks()
        _plumbing_checks()
        _routing_checks()
        _silence_checks(tmp)
        _corpus_checks()
        _no_flag_module_checks(tmp)
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
