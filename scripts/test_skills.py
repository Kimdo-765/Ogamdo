#!/usr/bin/env python3
"""Platform knowledge the agent can load, and that stays true.

WHY THIS EXISTS

Three lookups in one session concluded a tool was missing by asking the wrong
container: `zsteg` (it is in the misc image), `volatility` (a python module,
not a binary) and Ghidra (not on PATH anywhere). That knowledge now lives in
a skill the agent loads on demand — which only helps for as long as it is
accurate, so this suite checks the claims against the images themselves.

WHAT IT PROTECTS

  * A SKILL THAT CANNOT LOAD IS WORSE THAN NO SKILL. Frontmatter `name` must
    match the directory or the CLI will not resolve `ogamdo:<name>`.
  * THE ISOLATION IS THE POINT. `setting_sources` must be explicitly empty.
    Leaving it unset lets the SDK pick ["user","project"] once `skills` is on
    — which loads the operator's personal config into a CTF job and makes a
    challenge-supplied CLAUDE.md in the job's cwd an instruction source.
  * THE INVENTORY MUST STAY TRUE. Tools the skill calls absent must be
    absent, and tools it lists for the worker must be there.

Run from the repository root::

    python3 scripts/test_skills.py
    python3 scripts/test_skills.py --mutate settings-not-isolated
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "worker" / "plugin"
MUTATIONS = ("settings-not-isolated", "skill-name-drifts-from-directory",
             "claim-a-tool-that-is-absent", "a-site-without-the-plugin",
             "earth-claimed-working", "claim-an-unreachable-host")

ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


def frontmatter(md: str) -> dict:
    m = re.match(r"^---\n(.*?)\n---\n", md, re.S)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


print("\n1. the plugin is shaped the way the CLI expects")
manifest = PLUGIN / ".claude-plugin" / "plugin.json"
check("the manifest exists", manifest.is_file(), True)
data = json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}
check("it names the plugin", data.get("name"), "ogamdo")

skills = sorted(p for p in (PLUGIN / "skills").iterdir() if p.is_dir())
check("there is at least one skill", len(skills) >= 1, True)

print("\n2. every skill can actually resolve")
bad_name, no_desc = [], []
for d in skills:
    md = d / "SKILL.md"
    if not md.is_file():
        bad_name.append(f"{d.name}: no SKILL.md")
        continue
    fm = frontmatter(md.read_text(encoding="utf-8"))
    name = fm.get("name")
    if args.mutate == "skill-name-drifts-from-directory" and d == skills[0]:
        name = (name or "") + "-renamed"
    if name != d.name:
        bad_name.append(f"{d.name}: frontmatter name={name!r}")
    # The description is what the model reads when DECIDING to load it. An
    # empty one makes the skill invisible in practice.
    if len(fm.get("description", "")) < 40:
        no_desc.append(d.name)
check("frontmatter name matches the directory", bad_name, [])
check("each description is substantive enough to be chosen on", no_desc, [])

print("\n3. the wiring, at every session that drives a challenge")
SITES = ["modules/_common.py", "modules/misc/orchestrator.py",
         "modules/forensic/orchestrator.py"]
src = {f: (ROOT / f).read_text(encoding="utf-8") for f in SITES}
if args.mutate == "a-site-without-the-plugin":
    src["modules/misc/orchestrator.py"] = src["modules/misc/orchestrator.py"].replace(
        "plugins=plugins(),", "", 1)
missing = [f for f, t in src.items() if "plugins=plugins()" not in t]
check("each names the plugin", missing, [])

skl = (ROOT / "modules" / "_skills.py").read_text(encoding="utf-8")
if args.mutate == "settings-not-isolated":
    skl = skl.replace("SETTING_SOURCES: list[str] = []",
                      "SETTING_SOURCES = None")
check("setting_sources is explicitly empty, not defaulted",
      bool(re.search(r"SETTING_SOURCES: list\[str\] = \[\]", skl)), True)

print("\n4. the inventory is still true")
# Parsed from the skill, not hardcoded here: a second copy of the list is the
# thing that goes stale, and this suite exists because a stale list shipped.
tool_md = (PLUGIN / "skills" / "ogamdo-toolchain" / "SKILL.md").read_text(encoding="utf-8")
worker_sec = tool_md[tool_md.find("## Your container"):tool_md.find("## NOT installed")]
absent_sec = tool_md[tool_md.find("## NOT installed"):tool_md.find("## Sibling images")]

def marked(block: str) -> list[str]:
    """Backticked names only. Bold is used for section labels too, and
    treating those as tools is how this check first reported `Browser`
    and `Network` missing from the image."""
    return sorted(set(re.findall(r"`([A-Za-z0-9][A-Za-z0-9_.+-]*)`", block)))

NOISE = {"python3", "worker", "worker.browser", "worker.heap_probe",
         "opt", "gef.py", "pwndbg"}
py_line = worker_sec[worker_sec.find("**Python**"):]
py_names = {n for n in marked(py_line)}
bin_names = [t for t in marked(worker_sec)
             if t not in NOISE and t not in py_names and "." not in t]
# Only the fenced block, so a suggested ALTERNATIVE named in the prose
# beside it is never mistaken for a claim of absence. Excluding names by
# hand here is how that mistake hides.
_fence = re.search(r"```\n(.*?)```", absent_sec, re.S)
absent = sorted(set(_fence.group(1).split())) if _fence else []
check("the worker section names a real number of tools", len(bin_names) >= 8, True)
check("the absent list is not empty", len(absent) >= 4, True)
if args.mutate == "claim-a-tool-that-is-absent":
    bin_names = bin_names + ["radare2"]

docker = next((c for c in ("/snap/bin/docker", shutil.which("docker"))
               if c and Path(c).exists()), None)
ok = bool(docker) and subprocess.run(
    [docker, "inspect", "hextech_ctf_tool-worker-1"],
    capture_output=True).returncode == 0
if not ok:
    print("  skip the worker container is not reachable — nothing verified")
else:
    probe = subprocess.run(
        [docker, "exec", "hextech_ctf_tool-worker-1", "sh", "-lc",
         "for t in " + " ".join(bin_names + absent) + "; do "
         "command -v \"$t\" >/dev/null 2>&1 && echo HAVE:$t || echo NONE:$t; done"],
        capture_output=True, text=True, timeout=180)
    have = {l.split(":", 1)[1] for l in probe.stdout.splitlines() if l.startswith("HAVE:")}
    check(f"all {len(bin_names)} tools the skill lists for the worker are there",
          sorted(t for t in bin_names if t not in have), [])
    check("every tool the skill calls absent really is",
          sorted(t for t in absent if t in have), [])
    mods = sorted(py_names - NOISE)
    pyprobe = subprocess.run(
        [docker, "exec", "hextech_ctf_tool-worker-1", "python3", "-c",
         "import importlib.util as u,sys;"
         "print(' '.join(m for m in sys.argv[1:] if not u.find_spec(m)))",
         *mods], capture_output=True, text=True, timeout=120)
    check(f"all {len(mods)} python names the skill lists import",
          pyprobe.stdout.split(), [])

print("\n5. the OSINT skill's reachability claims")
osint = PLUGIN / "skills" / "ogamdo-osint" / "SKILL.md"
check("the OSINT skill exists", osint.is_file(), True)
otext = osint.read_text(encoding="utf-8") if osint.is_file() else ""
# Pinned because it is the expensive thing to re-learn: Earth Web renders a
# splash and then dies on WebGL. If someone gets it working, this check is
# the right place to find out.
earth_claim = "Google Earth does NOT work here" in otext
if args.mutate == "earth-claimed-working":
    earth_claim = False
check("it still records that Google Earth Web does not run here",
      earth_claim, True)
check("it warns that ArcGIS orders tiles y-before-x",
      "{y}/{x}" in otext and "{x}/{y}" in otext, True)

hosts = sorted(set(re.findall(r"https://([a-z0-9.-]+)/", otext)))
hosts = [h for h in hosts if h not in ("earth.google.com", "mt1.google.com")]
if args.mutate == "claim-an-unreachable-host":
    hosts = hosts + ["nonexistent.invalid"]
if not ok:
    print("  skip the worker container is not reachable — hosts not probed")
else:
    net = subprocess.run(
        [docker, "exec", "hextech_ctf_tool-worker-1", "sh", "-lc",
         "for h in " + " ".join(hosts) + "; do "
         "c=$(curl -s -o /dev/null -m 20 -w '%{http_code}' -A ogamdo-ctf/1.0 "
         "\"https://$h/\" 2>/dev/null); "
         "case \"$c\" in 000) echo DEAD:$h;; esac; done"],
        capture_output=True, text=True, timeout=240)
    dead = sorted(l.split(":", 1)[1] for l in net.stdout.splitlines()
                  if l.startswith("DEAD:"))
    # A non-200 is fine — a bare host often 301s or 404s. Only "no answer at
    # all" means the skill is pointing somewhere that no longer exists.
    check(f"all {len(hosts)} hosts it names still answer", dead, [])

print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
