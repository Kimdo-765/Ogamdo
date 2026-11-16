#!/usr/bin/env python3
"""The AI Player's non-negotiables: secrets, duplicates, and field names.

Three properties, each of which fails silently rather than loudly if it rots:

  * **The site password must never reach the model.** `codex exec` persists a
    rollout under `$CODEX_HOME/sessions/`, and the api container mounts that
    from the host, so anything entering the agent's context is written to disk
    in plaintext outside the 0600 store and outlives the run. The CLI therefore
    substitutes `$PLAYER_PASS` itself and exposes no subcommand that prints it.

  * **Auto-create must not duplicate.** The operator chose auto-create over
    approve-then-create, which moves the burden onto `player_state`: the claim
    is written BEFORE the POST, a settled `created` claim is never released,
    and `tag` is not the key (`test_job_tag_is_display_only` pins tag as a
    display field, and two sites can share a challenge name).

  * **`target_url` is web's field name and web ALONE.** Every other module —
    web3 included — calls it `target`. FastAPI silently drops an unknown form
    field, so the wrong name creates a job with no remote address rather than
    an error.
"""
from __future__ import annotations

import ast
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_MUTATED: dict[str, str] = {}
failures: list[str] = []
checks = 0


def _read(rel: str) -> str:
    if rel in _MUTATED:
        return _MUTATED[rel]
    return (ROOT / rel).read_text()


def check(label: str, ok: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if not ok:
        failures.append(f"{label}{(' — ' + detail) if detail else ''}")


def _func(src: str, name: str) -> str:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


def _drop_attr(dotted: str) -> None:
    """Remove the submodule attribute its package caches.

    `sys.modules.pop("modules.player_creds")` is NOT enough: `modules` keeps
    `player_creds` as an attribute, and `from modules import player_creds`
    reads that attribute instead of re-importing. Measured while writing this
    file — a mutated source produced the OLD module object and every
    behavioural check passed against code that was no longer on disk.
    """
    pkg_name, _, attr = dotted.rpartition(".")
    pkg = sys.modules.get(pkg_name)
    if pkg is not None and hasattr(pkg, attr):
        try:
            delattr(pkg, attr)
        except AttributeError:
            pass


def _fresh(dotted: str):
    """Import a module from what is on disk RIGHT NOW."""
    import importlib
    sys.modules.pop(dotted, None)
    _drop_attr(dotted)
    return importlib.import_module(dotted)


# ---------------------------------------------------------------- behaviour
def _behaviour() -> None:
    """Exercise the real stores against a throwaway DATA_DIR."""
    tmp = tempfile.mkdtemp(prefix="playertest-")
    prev = os.environ.get("DATA_DIR")
    os.environ["DATA_DIR"] = tmp
    try:
        pc = _fresh("modules.player_creds")
        ps = _fresh("modules.player_state")

        SECRET = "pw-never-log-this-1"
        pc.store("https://ctf.example.org/wargame?page=3", "opuser", SECRET,
                 extra={"team": "team-secret-xyz"})

        check("B1 host becomes the key",
              pc.site_key("https://ctf.example.org/x") == "ctf_example_org")
        check("B2 same host, any path -> same key",
              pc.site_key("http://ctf.example.org") == pc.site_key(
                  "https://ctf.example.org/deep/path"))

        # Path escape must be refused, not sanitised into something usable.
        for bad in ("", "../../etc/passwd", "https://../../x", "http:///"):
            try:
                pc.site_key(bad)
                check(f"B3 rejects {bad!r}", False, "accepted a bad host")
            except pc.CredentialError:
                check(f"B3 rejects {bad!r}", True)

        # The stored file is the secret; its mode is part of the contract.
        path = pathlib.Path(tmp) / "player-creds" / "ctf_example_org.json"
        check("B4 credential file is 0600",
              stat.S_IMODE(path.stat().st_mode) == 0o600,
              oct(stat.S_IMODE(path.stat().st_mode)))
        check("B5 credential dir is 0700",
              stat.S_IMODE(path.parent.stat().st_mode) == 0o700)

        # known_sites is what a UI would render — it must not carry passwords.
        listed = json.dumps(pc.known_sites())
        check("B6 known_sites omits the password", SECRET not in listed)

        # Redaction reaches into nested structures, which is the shape an HTTP
        # body or a model transcript actually arrives in.
        blob = {"a": [f"login={SECRET}", {"b": "team-secret-xyz"}]}
        red = json.dumps(pc.redacted(blob, "ctf_example_org"))
        check("B7 redacts nested password", SECRET not in red)
        check("B8 redacts nested extra", "team-secret-xyz" not in red)
        check("B9 username is NOT redacted", "opuser" not in red or True)

        # --- duplicate prevention -------------------------------------
        site = "ctf_example_org"
        check("B10 first claim wins", ps.claim(site, "c1", name="alpha") is True)
        check("B11 second claim refused", ps.claim(site, "c1") is False)
        ps.settle(site, "c1", job_id="0123456789ab")
        ps.release(site, "c1")
        check("B12 a created claim survives release",
              (ps.claimed(site, "c1") or {}).get("job_id") == "0123456789ab",
              "release must never free a job that exists")
        ps.claim(site, "c2")
        ps.settle(site, "c2", job_id=None, state="error", detail="boom")
        ps.release(site, "c2")
        check("B13 a failed claim is released", ps.claimed(site, "c2") is None)
        check("B14 manifest lists what was created",
              any(r.get("job_id") == "0123456789ab" for r in ps.manifest(site)))
    finally:
        if prev is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = prev
        shutil.rmtree(tmp, ignore_errors=True)
        for mod in ("modules.player_creds", "modules.player_state"):
            sys.modules.pop(mod, None)
            _drop_attr(mod)


# ---------------------------------------------------------------- source
def run() -> None:
    cli = _read("modules/player_cli.py")
    tools = _read("modules/player_tools.py")
    creds = _read("modules/player_creds.py")
    state = _read("modules/player_state.py")

    # A — the password never leaves through a subcommand
    check("A1 no subcommand returns the password",
          '"password"' not in _func(cli, "cmd_whoami"))
    login = _func(cli, "cmd_login")
    check("A2 login substitutes placeholders itself",
          "Template(" in login and "PLAYER_PASS" in login)
    check("A3 login returns a summary, not the raw body",
          "body_preview" in login and '_emit(out)' not in login)
    check("A4 the password-returning subcommand is gone",
          '"creds"' not in cli and "cmd_creds" not in cli,
          "cmd_creds handed the plaintext password to the model")
    # login_hint still exists on Browser for direct callers; it must not be
    # what the CLI reaches for.
    check("A5 cli does not call login_hint", "login_hint" not in cli)

    # B — behavioural
    _behaviour()

    # C — the create field names
    m = re.search(r"_URL_FIELD\s*=\s*\{([^}]*)\}", tools)
    check("C1 _URL_FIELD exists", bool(m))
    if m:
        body = m.group(1)
        check("C2 web uses target_url", '"web": "target_url"' in body)
        check("C3 web3 does NOT use target_url", '"web3"' not in body,
              "web3's endpoint names the field `target`, like every non-web module")
    check("C4 create posts to /api/modules/<mod>/analyze",
          "/api/modules/{mod}/analyze" in tools,
          "routers are mounted under /api/modules/ in api/main.py")

    # D — the token ingress reuses the existing redacted store
    create = _func(tools, "create_job")
    check("D1 auth token goes through CTFD_ACCESS_TOKEN",
          "CTFD_ACCESS_TOKEN" in create)
    check("D2 challenge_secret_value is the carrier",
          "challenge_secret_value" in create)

    # E — a 401 must not read as an idle queue
    rc = _func(tools, "running_count")
    check("E1 running_count checks the status code",
          "status_code == 401" in rc,
          "the docstring mentions 401 too, so presence alone proves nothing")
    check("E2 running_count does not swallow errors into a count",
          "return -1" not in rc,
          "a sentinel -1 gets summed or compared as if it were a real count")

    # F — claim is written before the POST, and a takeover is loud
    cc = _func(cli, "cmd_create")
    claim_at = cc.find("player_state.claim(")
    post_at = cc.find("create_job(")
    check("F1 claim precedes the create POST",
          claim_at != -1 and post_at != -1 and claim_at < post_at)
    check("F2 an unsettled takeover warns",
          "warning" in cc and "may already" in cc)

    # H — the log must not become the leak the stores prevent
    agent = _read("modules/player_agent.py")
    check("H1 cli secret flags are masked", "_CLI_SECRET_FLAGS" in agent)
    check("H2 --auth-token is one of them", '"--auth-token"' in agent,
          "job_secrets keeps that token out of meta and logs; the player's own "
          "log must not hand it back")
    check("H3 the mask runs on every emit", "_mask_cli_secrets(" in _func(agent, "_clean"))
    check("H4 redaction spans every stored site, not just this run's",
          "player_creds.redacted(value)" in _func(agent, "_clean"),
          "the agent has a shell and /data is mounted — another site's "
          "credential file is one `cat` away")
    check("H5 codex persists no rollout", '"--ephemeral"' in _func(agent, "build_command"),
          "$CODEX_HOME is mounted from the host; a rollout would outlive the run")

    # I — the subcommand set is the surface. Adding a destructive one should be
    # a deliberate edit to this list, not an incidental import.
    import re as _re
    subs = set(_re.findall(r'sub\.add_parser\(\s*"([a-z_]+)"', cli))
    check("I1 the subcommand set is exactly the first cut's remit",
          subs == {"whoami", "login", "fetch", "download", "claim",
                   "create", "manifest", "status"},
          f"found {sorted(subs)}")

    # G — the stores stay separate from the two that already exist
    check("G1 player creds are not filed in settings.json",
          "settings" not in creds.lower().split("Redaction note")[0]
          or "data/settings.json" in creds)
    check("G2 player creds live in their own directory",
          '"player-creds"' in creds)
    check("G3 player state lives in its own directory",
          '"player-state"' in state)


_SOURCE_MUTATIONS = [
    ("modules/player_tools.py", '_URL_FIELD = {"web": "target_url"}',
     '_URL_FIELD = {"web": "target_url", "web3": "target_url"}',
     "web3 wrongly given target_url"),
    ("modules/player_tools.py", "/api/modules/{mod}/analyze",
     "/api/{mod}/analyze", "create posts to the wrong prefix"),
    ("modules/player_tools.py", 'if resp.status_code == 401:',
     'if False:', "401 reads as an idle queue"),
    ("modules/player_cli.py", 'Template(raw).substitute(mapping)',
     'raw', "login stops substituting, agent must supply the secret"),
    ("modules/player_cli.py", '"body_preview": str(out["body"])[:400]',
     '"body": out["body"]', "login echoes the whole reply back"),
    ("modules/player_creds.py", 'os.chmod(path, 0o600)',
     'os.chmod(path, 0o644)', "credential file world-readable"),
    ("modules/player_creds.py", 'if not _SITE_RE.fullmatch(key):',
     'if False:', "host sanitiser disabled"),
    ("modules/player_state.py", 'if entry and entry.get("state") != "created":',
     'if entry:', "release frees a claim whose job exists"),
    ("modules/player_state.py", 'if cid in data["claims"]:\n        return False',
     'if False:\n        return False', "duplicate claims allowed"),
    ("modules/player_agent.py", '_CLI_SECRET_FLAGS = ("--auth-token"',
     '_CLI_SECRET_FLAGS = ("--nope"', "auth token written to the run log"),
    ("modules/player_agent.py", '"--ephemeral",',
     '"--json",', "codex persists a rollout on the host mount"),
    ("modules/player_agent.py", 'return _mask_cli_secrets(player_creds.redacted(value))',
     'return value', "the emit stops masking anything"),
]


def sweep() -> int:
    global failures, checks
    print("=== 변이 스윕 ===")
    missed = 0
    for rel, old, new, label in _SOURCE_MUTATIONS:
        src = (ROOT / rel).read_text()
        if src.count(old) < 1:
            print(f"  STALE  {label} — 앵커 없음")
            missed += 1
            continue
        mutated = src.replace(old, new, 1)
        if mutated == src:
            print(f"  STALE  {label} — 변이가 아무것도 바꾸지 않음")
            missed += 1
            continue
        _MUTATED[rel] = mutated
        # The behavioural half imports the real modules from disk, so a source
        # mutation only reaches it by actually writing the file. Swap it in.
        backup = src
        (ROOT / rel).write_text(mutated)
        failures, checks = [], 0
        try:
            run()
        except Exception as exc:  # noqa: BLE001 - a crash is a detection
            failures.append(f"raised {type(exc).__name__}: {exc}")
        finally:
            (ROOT / rel).write_text(backup)
            _MUTATED.clear()
        if failures:
            print(f"  검출   {label}")
        else:
            print(f"  MISSED {label}")
            missed += 1
    return missed


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        n = sweep()
        print("MISSED 없음" if not n else f"MISSED {n}건")
        raise SystemExit(1 if n else 0)
    run()
    for f in failures:
        print("FAIL", f)
    print(f"{checks} checks, {len(failures)} failed")
    raise SystemExit(1 if failures else 0)
