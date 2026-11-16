#!/usr/bin/env python3
"""`local` is a ROLE TARGET, never a job backend — and only where it works.

WHY THIS EXISTS

Ollama on this box is free to run and, measured against grok-4.5 on this
repository's own monitor batches, matched it 4/4 on judgement — progress,
confirmed finding, restatement, unverified hypothesis — at comparable latency
(20.4 s vs 18.8 s). That makes it worth having for the monitor.

It is NOT worth pretending it can do more. There is no session, no tool loop
and no resume behind it; `main` is not routable in any case; and a role the
operator can select which then silently does nothing is the defect this
repository keeps paying to find.

WHAT THIS SUITE PROTECTS

  * IT CANNOT DRIVE A JOB. `local` stays out of AGENT_PROVIDERS, out of
    ROLE_FAILOVER_PROVIDERS, and `normalize_provider` never returns it — so
    nothing answering "which backend runs this job" can answer `local`.
  * A PIN WITHOUT AN ADAPTER IS IGNORED, not honoured into a crash. Routed to
    a role with no local implementation, the resolution falls through the
    `gpt`/`grok` branches into the Claude one and would hand an Ollama tag to
    the Claude SDK.
  * THE UI AND THE BACKEND AGREE. Both restrict the offer to the same roles.
    Guarding one side only is how a withheld promise survives.
  * NO OUTPUT CAP. gemma4-heretic is a thinking model: measured here, the
    default budget and even 400 tokens returned `done_reason: length` with a
    ZERO-length body — a narrator that looks wired and emits nothing.

Run from the repository root::

    python3 scripts/test_local_provider.py
    python3 scripts/test_local_provider.py --mutate local-as-job-backend
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("local-as-job-backend", "pin-honoured-without-adapter",
             "ui-offers-every-role", "output-capped", "model-guessed-by-id",
             "unconfigured-pin-is-silent", "discovery-saves-silently",
             "narrator-auto-discovers", "local-narrator-thinks",
             "routing-hides-local", "routing-targets-are-flat",
             "settings-drops-local-route")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


AP = (ROOT / "modules" / "agent_provider.py").read_text(encoding="utf-8")
MON = (ROOT / "modules" / "_monitor.py").read_text(encoding="utf-8")
APP = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
IDX = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
SET = (ROOT / "modules" / "settings_io.py").read_text(encoding="utf-8")
API = (ROOT / "api" / "routes" / "settings.py").read_text(encoding="utf-8")
PRE = (ROOT / "modules" / "model_presets.py").read_text(encoding="utf-8")

if args.mutate == "local-as-job-backend":
    AP = AP.replace('AGENT_PROVIDERS = ("claude", "grok", "gpt")',
                    'AGENT_PROVIDERS = ("claude", "grok", "gpt", "local")', 1)
elif args.mutate == "pin-honoured-without-adapter":
    AP = AP.replace("and _target_ok(r, target)", "", 1)
elif args.mutate == "ui-offers-every-role":
    APP = APP.replace('if (provider === "local") {', "if (false) {", 1)
elif args.mutate == "output-capped":
    MON = MON.replace('"num_predict": -1', '"num_predict": 400', 1)
elif args.mutate == "unconfigured-pin-is-silent":
    MON = re.sub(r"\n    _gap = _local_cfg_gap\(provider, model\)"
                 r".*?_entry\(\"monitor\", \"warn\", _warn\)\)\n",
                 "\n", MON, count=1, flags=re.S)
elif args.mutate == "discovery-saves-silently":
    API = API.replace("            r[\"discovered\"] = True",
                      "            set_setting(\"ollama_url\", cand)\n"
                      "            r[\"discovered\"] = True", 1)
elif args.mutate == "narrator-auto-discovers":
    MON = MON.replace("    if not raw:\n        raw = os.environ.get(\"OLLAMA_URL\", \"\").strip()",
                      "    if not raw:\n        raw = _ollama_candidates()[0]", 1)
elif args.mutate == "local-narrator-thinks":
    MON = MON.replace('        "think": False,\n', "", 1)
elif args.mutate == "routing-hides-local":
    IDX = IDX.replace('<option value="local">Local (Ollama)</option>', "", 1)
elif args.mutate == "routing-targets-are-flat":
    APP = APP.replace("roleTargets(role).includes(v)",
                      'ROLE_TARGETS.concat("local").includes(v)', 1)
elif args.mutate == "settings-drops-local-route":
    SET = SET.replace("if r and p in _targets:", "if r and p in AGENT_PROVIDERS:", 1)
elif args.mutate == "model-guessed-by-id":
    MON = MON.replace('prefer_local = str(provider or "").strip().lower() == "local"',
                      'prefer_local = "gemma" in str(model or "").lower()', 1)

print("1. it cannot drive a job")
check("`local` is not a whole-job backend",
      'AGENT_PROVIDERS = ("claude", "grok", "gpt")' in AP)
check("...and no machine can fall onto it",
      'ROLE_FAILOVER_PROVIDERS: frozenset[str] = frozenset({"claude", "gpt"})' in AP)
check("...and normalize_provider never returns it",
      'return v if v in AGENT_PROVIDERS else "claude"' in AP)
check("it IS a routing target", '"claude", "gpt", "grok", "local"' in AP)

print("\n2. a pin without an adapter is ignored")
check("the capable set is explicit",
      'LOCAL_CAPABLE_ROLES: frozenset[str] = frozenset({"monitor"})' in AP)
check("the stamped path checks it", "and _target_ok(r, target)" in AP)
check("the live path checks it too", "if target and not _target_ok(r, target)" in AP)
check("...and the check is about `local` alone",
      'if str(target).strip().lower() != "local":' in AP)

print("\n3. the UI and the backend agree on which roles")
check("the UI restricts local to its own list",
      'if (provider === "local") {' in APP and "LOCAL_PRESET_ROLES" in APP)
check("...and that list is the adapter's",
      bool(re.search(r'const LOCAL_PRESET_ROLES\s*=', APP)))
_ui_lr = re.search(r'const LOCAL_CAPABLE_ROLES\s*=\s*\[([^\]]*)\]', APP)
_py_lr = re.search(r'LOCAL_CAPABLE_ROLES[^=]*=\s*frozenset\(\{([^}]*)\}\)', AP)
def _names(m):
    return {x.strip().strip('"\'') for x in (m.group(1).split(",") if m else []) if x.strip()}
check("...and the UI gates local on the SAME roles the server does",
      _names(_ui_lr) == _names(_py_lr) == {"monitor"})
check("there is a Local preset tab", 'data-preset-provider="local"' in IDX)
check("...and the preset store knows the provider",
      '"claude", "grok", "gpt", "local"' in PRE)

print("\n4. the adapter, and the cap that must not come back")
check("narration dispatches on the PROVIDER, not a model-id guess",
      'prefer_local = str(provider or "").strip().lower() == "local"' in MON)
check("...and the provider reaches the dispatch",
      "_narrate(bodies, model, _known_vuln_titles(job_id), provider)" in MON)
check("the output cap is removed", '"num_predict": -1' in MON)
# Anchored on the CLAIM, not on one sentence: this guard has already been
# broken once by an honest rewrite of the docstring it was reading.
_lm = MON.split("async def _narrate_local")[1].split("async def ")[0]
check("...and the docstring justifies it with a measurement, next to the code",
      "done_reason=length" in _lm
      and any(w in _lm for w in ("tokens", "chars"))
      and "num_predict" in _lm)
check("an unconfigured endpoint disables the target, quietly",
      'if not base:\n        return {}' in MON)

print("\n6. an unconfigured [Local] pin explains itself")
# The strict order ("local",) means a missing URL costs every batch its
# narration. Without a stated cause the feed looks like a broken narrator.
_gapfn = re.search(r"def _local_cfg_gap\(.*?\n(?=\n\ndef |\n\nasync def )",
                   MON, re.S)
check("the gap is computed", bool(_gapfn))
_g = _gapfn.group(0) if _gapfn else ""
check("...only for a local pin", '!= "local"' in _g and 'return ""' in _g)
check("...naming the URL when it is missing", '"Ollama URL"' in _g)
check("...and the tag when it is missing", '"Ollama model"' in _g)
check("...on the SAME condition the narrator gives up on",
      'os.environ.get("OLLAMA_MODEL", "")' in _g
      and 'os.environ.get("OLLAMA_MODEL", "")' in _lm)
check("the warning reaches the feed", '_entry("monitor", "warn", _warn)' in MON)
# .find, not .index: a guard whose own absence raises reports nothing at all,
# which is how a mutation gets mistaken for a broken test.
_wi = MON.find("_LOCAL_CFG_WARNED.add(job_id)")
_ni = MON.find("text = await _narrate(bodies, model")
check("...before the narration it explains",
      _wi >= 0 and _ni >= 0 and _wi < _ni)
check("...once per job, not once per batch", "_LOCAL_CFG_WARNED" in MON
      and "job_id not in _LOCAL_CFG_WARNED" in MON)
check("...and it does NOT fall back to a paid model",
      'order = ("local",)' in MON)

print("\n7. the endpoint is discovered, not typed")
check("discovery is its own route", '@router.get("/ollama/discover")' in API)
check("...and the candidate list is its own function",
      "def _ollama_candidates(" in API)
_cand = API.split("def _ollama_candidates(")[1].split("@router.get")[0]
check("the default gateway leads — it IS the host on a bridge",
      "/proc/net/route" in _cand and '"00000000"' in _cand)
check("...with the fixed WSL bridges behind it",
      '"172.17.0.1"' in _cand and '"172.18.0.1"' in _cand)
check("...and a bare host gets the port appended", ':11434"' in _cand)
_disc = API.split('@router.get("/ollama/discover")')[1].split("@router.get")[0]
check("every candidate is reported, not just the winner", '"tried"' in _disc)
check("discovery NEVER writes the setting",
      "set_setting" not in _disc and "save_settings" not in _disc)
check("...it reuses the probe rather than reimplementing reachability",
      "ollama_probe(url=cand" in _disc)
check("a walk of candidates cannot hang on one",
      "timeout: float = 1.5" in _disc and "min(float(timeout" in API)
check("the NARRATOR still reads only the saved value — never discovers",
      "_ollama_candidates" not in MON and "/ollama/discover" not in MON)
check("the UI offers it", 'data-action="ollama-discover"' in IDX)
check("...and something listens", 'data-action="ollama-discover"' in APP
      and "_discoverOllama()" in APP)
check("...it fills the field and stops there",
      "urlEl.value = d.url" in APP
      and "set_setting" not in APP.split("async function _discoverOllama")[1][:1400])
check("auto-run only when there is nothing to overrule",
      'if (_ourl && !String(_ourl.value || "").trim()) _discoverOllama();' in APP)

print("\n8. the local narrator does not deliberate")
_nl = MON.split("async def _narrate_local")[1].split("async def ")[0]
# Measured: thinking ON spent all 4096 context tokens reasoning and returned a
# ZERO-length body (done_reason=length) in 75s; OFF answered in 2.9s. Without
# this flag the local monitor is wired, slow, and silent.
check("thinking is turned off in the request", '"think": False' in _nl)
_ti, _oi = _nl.find('"think": False'), _nl.find('"options"')
check("...at the top level, not inside options (Ollama reads it there)",
      _ti >= 0 and _oi >= 0 and _ti < _oi)
check("the docstring states the measured reason, not a guess",
      "n_ctx_slot" in _nl and "2.9" in _nl)
check("...including what it costs a full board",
      "0.39 req/s" in _nl and "BATCH_MAX_S" in _nl)
check("the output stays uncapped", '"num_predict": -1' in _nl)

print("\n9. local is a ROUTING choice, and only where it has an adapter")
# This surface was missed once: the backend gained `local` as a role target
# while Settings > Agent & routing kept a static option list that never showed
# it, so the routing the server would honour could not be expressed.
_sel = dict(re.findall(r'<select[^>]*name="role_provider_(\w+)"(.*?)</select>', IDX, re.S))
check(f"every overridable role has a routing select ({len(_sel)})", len(_sel) >= 7, True)
_offers = {r for r, body in _sel.items() if 'value="local"' in body}
check("exactly the monitor select offers Local", _offers == {"monitor"})
check("...and the JS validates PER ROLE, not from one flat list",
      "function roleTargets(role)" in APP
      and "roleTargets(role).includes(want)" in APP)
check("...on save as well as on load", "roleTargets(role).includes(v)" in APP)
check("...so a flat list cannot leak local into another role",
      "ROLE_TARGETS.includes(want)" not in APP and "ROLE_TARGETS.includes(v)" not in APP)

print("\n10. a saved local route survives the trip to the resolver")
# It did not: Settings stored monitor->local, the UI read it back from the raw
# value and showed it, and this sanitizer dropped it on the way to the
# resolver — so a job created afterwards carried no monitor route at all.
_gar = SET.split("def get_agent_role_providers")[1].split("\ndef ")[0]
check("routes are checked against the ROUTING targets",
      "ROLE_TARGET_PROVIDERS" in _gar)
check("...and NOT against the job-backend set",
      "p in AGENT_PROVIDERS" not in _gar)
check("...which is imported, not copied into a second list",
      "from modules.agent_provider import" in _gar)
check("the two sets are still different upstream, which is the point",
      '"claude", "grok", "gpt")' in SET and "local" in AP.split("ROLE_TARGET_PROVIDERS")[1][:120])

print("\n5. settings and probe")
check("the endpoint is a setting", '("ollama_url", "OLLAMA_URL", str, "")' in SET)
check("the tag is a setting, with no guessed default",
      '("ollama_model", "OLLAMA_MODEL", str, "")' in SET)
check("the Settings block exists", 'name="ollama_url"' in IDX)
check("...and says it is not a job backend",
      "role target" in re.sub(r"\s+", " ", IDX))
check("a probe can test the typed value before saving",
      "url=${encodeURIComponent(url)}" in APP)
check("...and tells the three states apart",
      '"configured": False' in (ROOT / "api" / "routes" / "settings.py").read_text(encoding="utf-8"))

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
