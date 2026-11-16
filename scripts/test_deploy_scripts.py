#!/usr/bin/env python3
"""The deploy scripts must act on the right tree, and be able to succeed.

Two properties, both learned the hard way on 2026-09-02, both from scripts
that looked fine and were silently wrong.


WHAT THIS PREVENTS, found live on 2026-09-02:

    restart.sh:37  PROJECT_DIR="${PROJECT_DIR:-/home/yadohyun/HexTech_CTF_TOOL}"
    deploy.sh:47   PROJECT_DIR="${PROJECT_DIR:-/home/yadohyun/HexTech_CTF_TOOL}"

/home/yadohyun/ogamdo is a CLONE of that path, and the RUNNING stack was
brought up from the clone: the compose label
`com.docker.compose.project.working_dir` reads /home/yadohyun/ogamdo, and so
does every bind mount — modules, worker, api, web-ui and data.

So `./restart.sh`, launched from the live tree, would have run
`docker compose down --remove-orphans` and `up` against the OTHER checkout.
The stack would have come back with different code mounted and a different
data/ directory holding the jobs, and nothing in its output would have said
so — the one line that named the directory said HexTech_CTF_TOOL while the
operator was standing in ogamdo. It failed for an unrelated reason (`sudo`
had no tty), which is the only reason it did not happen.

THE PROPERTY: with no PROJECT_DIR in the environment, a deploy script resolves
to its OWN directory. Not the caller's cwd — a script run from /tmp must still
act on its own checkout — and not a path baked at authoring time.

Run from the repository root::

    python3 scripts/test_project_dir_is_this_checkout.py
    python3 scripts/test_project_dir_is_this_checkout.py --mutate baked-path
"""
from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Scripts that choose a project directory and then act destructively on it.
DEPLOY_SCRIPTS = ("restart.sh", "deploy.sh")

MUTATIONS = ("baked-path", "callers-cwd", "no-env-override",
             "health-probes-root")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

DERIVE = 'PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"'


def _mutate(text: str) -> str:
    if args.mutate == "health-probes-root":
        # Put the probe back on "/", the state in which every deploy ended in
        # "restarted api is not 200" against a healthy api.
        return (text
                .replace('"$API_URL/api/health"', '"$API_URL/"')
                .replace("http://localhost:8000/api/health",
                         "http://localhost:8000/"))
    if args.mutate == "baked-path":
        return text.replace(
            DERIVE, 'PROJECT_DIR="${PROJECT_DIR:-/home/yadohyun/HexTech_CTF_TOOL}"')
    if args.mutate == "callers-cwd":
        # Looks right and is not: `./restart.sh` from the wrong directory then
        # tears down whatever happens to be under the caller's cwd.
        return text.replace(DERIVE, 'PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"')
    if args.mutate == "no-env-override":
        return text.replace(
            DERIVE, 'PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"')
    return text


PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


def _make_probe(script_text: str, home: Path) -> Path | None:
    """Plant the script's OWN PROJECT_DIR line in `home` as a runnable probe.

    The line is lifted out of the real file and executed, so a mutation to the
    shipped script is what this exercises — not a re-implementation of it.
    """
    line = next((ln for ln in script_text.splitlines()
                 if ln.startswith("PROJECT_DIR=")), None)
    if line is None:
        return None
    probe = home / "probe.sh"
    probe.write_text("#!/usr/bin/env bash\n" + line + '\necho "$PROJECT_DIR"\n')
    probe.chmod(0o755)
    return probe


def _run(probe: Path, *, run_from: Path, env_override: str | None) -> str:
    env = {"PATH": "/usr/bin:/bin"}
    if env_override:
        env["PROJECT_DIR"] = env_override
    out = subprocess.run(["bash", str(probe)], cwd=str(run_from), env=env,
                         capture_output=True, text=True)
    return out.stdout.strip() or f"<empty: {out.stderr.strip()[:80]}>"


# --------------------------------------------------- the liveness probe

# WHAT THIS PINS
#
# deploy.sh's api_up() demanded exactly 200 from "$API_URL/". Once login was
# added, "/" answers 307 -> /login to an unauthenticated caller, so the check
# could not pass at all. Run live on 2026-09-02 the api was healthy — uvicorn
# logged "Application startup complete" and served /api/health 200 — and
# deploy.sh still ended:
#
#     [deploy] ERR: restarted api is not 200 — .last_deploy NOT advanced.
#
# A check that cannot pass is worse than no check: it never advanced
# .last_deploy (so `--changed` had nothing to diff against), and deploy.sh's
# shadowed-CLI diagnostic uses the same api_up() to tell "the CLI cannot see
# the stack" apart from "the stack is down" — so it reported the wrong one.
#
# The probe must therefore hit a path that is PUBLIC BY DESIGN. api/auth.py
# keeps that allowlist; /api/health is on it and answers {"status":"ok"}.
PUBLIC_PATHS_SRC = ROOT / "api" / "auth.py"


def _health_checks() -> None:
    public = PUBLIC_PATHS_SRC.read_text()
    for name in ("deploy.sh", "restart.sh"):
        text = _mutate((ROOT / name).read_text())
        probes = re.findall(r"curl[^\n]*?(?:\$API_URL|http://localhost:8000)(/\S*?)[\"\' ]",
                            text)
        # Only the liveness probes matter here; the collector probe is a POST
        # to a job-scoped path and is excluded by requiring a bare-ish path.
        live = [p for p in probes if not p.startswith("/api/collector")]
        check(f"H1 {name} probes something for liveness at all", bool(live), True)
        check(f"H2 {name} does not probe \"/\" — it redirects to /login",
              [p for p in live if p in ("/", "")], [])
        for probe in live:
            base = probe.split("?")[0]
            check(f"H3 {name} probes {base}, which api/auth.py exposes publicly",
                  f'"{base}"' in public, True)

    # Behavioural, when the stack happens to be up: the old probe must fail
    # and the new one must pass, or this suite is only reading strings.
    import urllib.request
    def _code(path: str):
        try:
            req = urllib.request.Request("http://localhost:8000" + path)
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k): return None
            op = urllib.request.build_opener(NoRedirect)
            return op.open(req, timeout=4).status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None
    root_code, health_code = _code("/"), _code("/api/health")
    if root_code is None and health_code is None:
        print("SKIP  H4 live probe (api not reachable on :8000)")
        return
    check("H4 live: /api/health answers 200", health_code, 200)
    check("H4 live: / does NOT answer 200 (this is why the old check hung)",
          root_code != 200, True)


# ------------------------------------------------------- the shipping guard

def _cachebuster_checks() -> None:
    """web-ui assets and their ?v= tags must move together, by derivation.

    Commit 9f916d7 — "the GPT-preset commits shipped app.js without moving the
    cache buster" — is the release this guards. A browser holding the previous
    app.js renders the previous UI against the new API, and the change looks
    like it silently did nothing.

    The tag is not free-form: scripts/test_role_provider_ui.js defines it as
    "a" + sha256(app.js || style.css)[:8], and index.html carries it on BOTH
    assets. An earlier draft of this guard only asked whether app.js's tag had
    CHANGED, and passed against a tree where the tag had been hand-picked and
    style.css's tag — edited in the same commit — had not moved at all. Asking
    the weaker question is what let that through, so ask the real one here too:
    a Python-only regression run must not be able to give the false all-clear.
    """
    def _head(path: str) -> str:
        out = subprocess.run(["git", "show", f"HEAD:{path}"], cwd=str(ROOT),
                             capture_output=True, text=True)
        return out.stdout if out.returncode == 0 else ""

    html_now = (ROOT / "web-ui" / "index.html").read_text()
    app_now = (ROOT / "web-ui" / "app.js").read_bytes()
    css_now = (ROOT / "web-ui" / "style.css").read_bytes()
    if not _head("web-ui/index.html"):
        print("SKIP  B cache-buster guard (no git HEAD to compare)")
        return

    import hashlib
    h = hashlib.sha256()
    h.update(app_now)
    h.update(css_now)
    want = "a" + h.hexdigest()[:8]

    tags = set(re.findall(r"\?v=([0-9a-z-]+)", html_now))
    check("B1 the buster is the derived asset hash, not a hand-picked value",
          tags, {want})
    check("B2 every versioned asset on the page carries the same tag",
          len(re.findall(r"\?v=[0-9a-z-]+", html_now)) >= 2, True)
    check("B3 ...and both app.js and style.css are among them",
          bool(re.search(r"app\.js\?v=", html_now))
          and bool(re.search(r"style\.css\?v=", html_now)), True)


def _ui_action_checks() -> None:
    """Every `data-action` the UI emits has something that listens for it.

    Not a style rule — a regression that actually happened. Replacing one
    delegated handler by source range silently took its NEIGHBOUR with it
    (the runner-stop button kept rendering and did nothing), and only a
    suite that happened to grep for that button's fetch caught it. A button
    wired to nothing is indistinguishable from a broken feature, which is the
    failure mode this repo keeps paying for.

    Prefix selectors count: the trace controls are dispatched through
    `[data-action^="trace-scale-"]`, so the individual names never appear.
    """
    import re as _re
    app = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
    emitted = sorted(set(_re.findall(r'data-action="([a-z0-9-]+)"', app + idx)))
    prefixes = _re.findall(r'data-action\^=\\?"([a-z0-9-]+)', app)
    orphans = []
    for a in emitted:
        if (f'data-action="{a}"]' in app
                or f'dataset.action === "{a}"' in app
                or any(a.startswith(pref) for pref in prefixes)):
            continue
        orphans.append(a)
    check(f"U1 every data-action has a listener ({len(emitted)} actions)",
          orphans, [])


def _mirror_drift_checks() -> None:
    """Every UI constant that claims to mirror a Python one, actually mirroring it.

    This is a recurring defect, not a hypothetical: `stopped` went missing from
    JOB_TERMINAL and cost a re-fetch of 256 KB every 2 s per open panel; `hold`
    went missing the same way when the Python set grew; and ROLE_TARGETS kept a
    three-provider list under a comment claiming it mirrored the server's, so a
    routing the server would have honoured could not be selected at all.

    Adding a member on the Python side reaches NOTHING in web-ui/ — the option
    lists are static markup and the sets are hand-copied — so the copy has to be
    checked rather than trusted.
    """
    app = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
    ap = (ROOT / "modules" / "agent_provider.py").read_text(encoding="utf-8")
    mon = (ROOT / "modules" / "_monitor.py").read_text(encoding="utf-8")

    def _js(name: str) -> set:
        m = re.search(rf"const {name}\s*=\s*(?:new Set\()?\[(.*?)\]", app, re.S)
        return {x.strip().strip("\"'") for x in (m.group(1).split(",") if m else [])
                if x.strip() and not x.strip().startswith("//")}

    def _py(src: str, name: str) -> set:
        m = re.search(rf"^{name}[^=\n]*=\s*(?:frozenset\()?\s*\{{(.*?)\}}",
                      src, re.S | re.M)
        body = re.sub(r"#[^\n]*", "", m.group(1)) if m else ""
        return {x.strip().strip("\"'") for x in body.split(",") if x.strip()}

    # NOT a subset relation, and this guard exists because assuming one broke
    # the hold feature: _TERMINAL is "the narrator stops", JOB_TERMINAL is "the
    # UI stops polling", and `hold` belongs to the first and NOT the second --
    # the exit from a hold is a button that only renders while the panel still
    # refreshes. Two questions, one name; pin the difference rather than the set.
    py_term, js_term = _py(mon, "_TERMINAL"), _js("JOB_TERMINAL")
    check("M1 the monitor treats `hold` as an end state", "hold" in py_term, True)
    check("M1 ...and the UI does NOT, or the resume button never renders",
          "hold" not in js_term, True)
    check(f"M1 ...while agreeing on every other finished status "
          f"(diff: {sorted((py_term ^ js_term) - {'hold', 'error'}) or 'none'})",
          (py_term ^ js_term) <= {"hold", "error"}, True)
    for name, src, pyname in (("ROLE_OVERRIDABLE", ap, "ROLE_OVERRIDABLE"),
                              ("LOCAL_CAPABLE_ROLES", ap, "LOCAL_CAPABLE_ROLES")):
        j, q = _js(name), _py(src, pyname)
        check(f"M2 {name} matches the server ({sorted(j)} vs {sorted(q)})",
              bool(q) and j == q, True)


def main() -> int:
    _ui_action_checks()
    for name in DEPLOY_SCRIPTS:
        text = _mutate((ROOT / name).read_text())
        # ONE stand-in checkout, probed from two different working directories.
        # (An earlier draft made a fresh temp dir per call and then compared
        # the two answers — they could never match, and the failure was the
        # harness's, not the script's.)
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "checkout"
            home.mkdir()
            probe = _make_probe(text, home)
            check(f"P0 {name} assigns PROJECT_DIR at all", probe is not None, True)
            if probe is None:
                continue
            # The script's own directory is the answer, wherever it is invoked
            # from. `home` stands in for "some other clone".
            from_home = _run(probe, run_from=home, env_override=None)
            from_tmp = _run(probe, run_from=Path("/tmp"), env_override=None)
            check(f"P1 {name} resolves to its own checkout",
                  (from_home == str(home), from_tmp == str(home)), (True, True))
            check(f"P1 {name} ...the caller's cwd does not change the answer",
                  from_home == from_tmp, True)
            # The override must survive, or an operator deploying elsewhere is
            # stuck.
            check(f"P3 {name} still honours an explicit PROJECT_DIR",
                  _run(probe, run_from=home, env_override="/somewhere/else"),
                  "/somewhere/else")

        # A baked absolute path is the defect this file exists for.
        assign = next((ln for ln in text.splitlines()
                       if ln.startswith("PROJECT_DIR=")), "")
        check(f"P2 {name} bakes no absolute path into the default",
              bool(re.search(r":-/(?!\$)", assign)), False)

    # start.sh already used $(pwd); it is not in DEPLOY_SCRIPTS because it is
    # the entry point an operator runs FROM the tree. Pin that it at least
    # never grew a baked path of its own.
    start = (ROOT / "start.sh").read_text()
    check("P4 start.sh bakes no absolute home path either",
          bool(re.search(r'PROJECT_DIR="?\$\{?PROJECT_DIR:-/home/', start)), False)

    _health_checks()
    _cachebuster_checks()
    _mirror_drift_checks()

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
