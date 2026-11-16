"""The AI Player's hands: one subcommand per action, driven from bash.

The agent that runs this is a shell agent (`codex exec`), exactly like every
other agent in this platform, so its tools are argv rather than a function-call
schema. Each invocation is a fresh process, which is why `Browser` keeps its
cookie jar on disk — otherwise the login would not survive the first command.

Every subcommand prints ONE json object on stdout and exits 0 on success or 2
on a tool error, so the agent can branch without parsing prose. Errors carry
`{"error": ...}` and are already redacted.

Deliberately NOT here: anything that submits a flag, deletes a job, or changes
an operator setting. The first cut's remit is login, collect, create — a
narrower surface is also a smaller blast radius for an agent acting on its own.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from modules import player_creds, player_state
from modules.player_tools import VALID_MODULES, Browser, Ogamdo, ToolError


def _run_root(run_id: str) -> str:
    root = os.path.join(os.environ.get("DATA_DIR", "/data"), "player-runs", run_id)
    os.makedirs(root, exist_ok=True)
    return root


def _browser(args) -> Browser:
    site = player_creds.site_key(args.site_url)
    return Browser(
        args.site_url, site,
        jar_path=os.path.join(_run_root(args.run), "cookies.json"),
    )


def _emit(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, default=str))


def _fail(message: str) -> None:
    print(json.dumps({"error": str(message)[:800]}, ensure_ascii=False))
    raise SystemExit(2)


# --------------------------------------------------------------------------
def cmd_whoami(args) -> None:
    """The username only — enough to fill a form field, never the secret."""
    site = player_creds.site_key(args.site_url)
    data = player_creds.load(site) or {}
    if not data:
        _fail("no stored credentials for this site")
        return
    _emit({"username": data.get("username", ""),
           "has_password": True,
           "extra_keys": sorted((data.get("extra") or {}).keys())})


def cmd_login(args) -> None:
    """Submit the site's login form WITHOUT the password entering the agent.

    The agent discovers the shape — which endpoint, which field names, JSON or
    form — and writes it as a template with `$PLAYER_USER` / `$PLAYER_PASS`
    placeholders. Substitution happens here, one layer below the model, so the
    secret goes from a 0600 file straight onto the wire.

    This is not merely tidier than redacting afterwards. `codex exec` persists
    its own rollout under `$CODEX_HOME/sessions/`, and the api container mounts
    that from the host — anything that reaches the model context is written to
    disk in plaintext, outside this store, and survives the run. The password
    therefore must never reach the context in the first place.
    """
    site = player_creds.site_key(args.site_url)
    data = player_creds.load(site)
    if not data:
        _fail("no stored credentials for this site")
        return

    mapping = {
        "PLAYER_USER": str(data.get("username") or ""),
        "PLAYER_PASS": str(data.get("password") or ""),
    }
    for key, value in (data.get("extra") or {}).items():
        mapping[f"PLAYER_{str(key).upper()}"] = str(value)

    def _fill(raw: str | None):
        if not raw:
            return None
        from string import Template
        try:
            return Template(raw).substitute(mapping)
        except KeyError as exc:
            _fail(f"unknown placeholder {exc}; available: "
                  + ", ".join("$" + k for k in sorted(mapping)))
            raise

    body = _fill(args.json_template)
    form = _fill(args.form_template)
    headers = json.loads(args.headers) if args.headers else None

    b = _browser(args)
    out = b.fetch(
        args.endpoint, method=args.method,
        json_body=json.loads(body) if body else None,
        form=json.loads(form) if form else None,
        headers=headers,
    )
    b.save_cookies()
    # The response body can echo the submitted credentials back (a validation
    # error quoting the field). `fetch` already redacts, but the login reply is
    # the single most likely place for that, so only a summary is returned.
    _emit({"status": out["status"], "url": out["url"],
           "cookies_set": out["set_cookies"],
           "body_preview": str(out["body"])[:400]})


def cmd_fetch(args) -> None:
    b = _browser(args)
    body = json.loads(args.json_body) if args.json_body else None
    form = json.loads(args.form) if args.form else None
    headers = json.loads(args.headers) if args.headers else None
    out = b.fetch(args.url, method=args.method, json_body=body,
                  form=form, headers=headers)
    b.save_cookies()
    _emit(out)


def cmd_download(args) -> None:
    b = _browser(args)
    dest = args.dest or os.path.join(_run_root(args.run), "downloads")
    out = b.download(args.url, dest, filename=args.filename)
    b.save_cookies()
    _emit(out)


def cmd_claim(args) -> None:
    """Reserve a challenge before creating it. False means already handled."""
    site = player_creds.site_key(args.site_url)
    ok = player_state.claim(site, args.challenge_id, name=args.name or "",
                            module=args.module or "", url=args.url or "")
    _emit({"claimed": ok,
           "existing": player_state.claimed(site, args.challenge_id) if not ok else None})


def cmd_create(args) -> None:
    """Create one job. Claims first, settles after, so a re-run cannot duplicate."""
    site = player_creds.site_key(args.site_url)
    cid = str(args.challenge_id)
    takeover_warning = ""
    if not player_state.claim(site, cid, name=args.tag or "",
                              module=args.module, url=args.target or ""):
        existing = player_state.claimed(site, cid) or {}
        if existing.get("state") == "created":
            _emit({"skipped": "already created", "job_id": existing.get("job_id"),
                   "challenge_id": cid})
            return
        # A prior attempt claimed but never settled. The claim is written
        # BEFORE the POST, so this state has two causes and they are not
        # distinguishable from here: the create never happened, or it
        # succeeded and the process died before `settle`. Taking it over is
        # right for the first and creates a duplicate for the second. The API
        # has no idempotency key to tell them apart, so the only honest thing
        # is to proceed loudly.
        takeover_warning = (
            "prior claim never settled — a job for this challenge may already "
            "exist; check the manifest before letting it run"
        )
    og = Ogamdo(args.api, os.environ.get("OGAMDO_AUTH_TOKEN") or None)
    try:
        out = og.create_job(
            args.module, tag=args.tag, description=args.description,
            target=args.target, file_path=args.file,
            flag_format=args.flag_format,
            auth_token_value=args.auth_token,
            docker_challenge=bool(args.docker),
            output_language=args.output_language,
        )
    except ToolError as exc:
        player_state.settle(site, cid, job_id=None, state="error", detail=str(exc))
        player_state.release(site, cid)
        _fail(str(exc))
        return
    player_state.settle(site, cid, job_id=out["job_id"], state="created",
                        detail=takeover_warning)
    result = {"job_id": out["job_id"], "module": out["module"],
              "challenge_id": cid}
    if takeover_warning:
        result["warning"] = takeover_warning
    _emit(result)


def cmd_manifest(args) -> None:
    site = player_creds.site_key(args.site_url)
    rows = player_state.manifest(site)
    _emit({"site": site, "count": len(rows),
           "created": sum(1 for r in rows if r.get("state") == "created"),
           "claims": rows})


def cmd_status(args) -> None:
    og = Ogamdo(args.api, os.environ.get("OGAMDO_AUTH_TOKEN") or None)
    _emit({"running_or_queued": og.running_count(),
           "modules": list(VALID_MODULES)})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="player", description="AI Player tools")
    p.add_argument("--run", required=True, help="run id (scopes cookies/downloads)")
    p.add_argument("--site-url", required=True, help="the CTF site page url")
    p.add_argument("--api", default=os.environ.get("OGAMDO_API", "http://127.0.0.1:8000"))
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("whoami", help="the stored username (never the password)"
                   ).set_defaults(fn=cmd_whoami)

    lg = sub.add_parser("login", help="submit the login form; the password is "
                                      "substituted here, not by the agent")
    lg.add_argument("--endpoint", required=True)
    lg.add_argument("--method", default="POST")
    lg.add_argument("--json-template", dest="json_template",
                    help='e.g. \'{"email":"$PLAYER_USER","password":"$PLAYER_PASS"}\'')
    lg.add_argument("--form-template", dest="form_template")
    lg.add_argument("--headers")
    lg.set_defaults(fn=cmd_login)

    f = sub.add_parser("fetch", help="one HTTP request, cookies kept")
    f.add_argument("url")
    f.add_argument("--method", default="GET")
    f.add_argument("--json-body", dest="json_body")
    f.add_argument("--form")
    f.add_argument("--headers")
    f.set_defaults(fn=cmd_fetch)

    d = sub.add_parser("download", help="save an attachment")
    d.add_argument("url")
    d.add_argument("--dest")
    d.add_argument("--filename")
    d.set_defaults(fn=cmd_download)

    c = sub.add_parser("claim", help="reserve a challenge id")
    c.add_argument("challenge_id")
    c.add_argument("--name")
    c.add_argument("--module")
    c.add_argument("--url")
    c.set_defaults(fn=cmd_claim)

    n = sub.add_parser("create", help="create one job")
    n.add_argument("challenge_id")
    n.add_argument("--module", required=True)
    n.add_argument("--tag", required=True, help="the challenge name")
    n.add_argument("--description")
    n.add_argument("--target")
    n.add_argument("--file")
    n.add_argument("--flag-format", dest="flag_format")
    n.add_argument("--auth-token", dest="auth_token",
                   help="per-challenge token; stored outside the job dir")
    n.add_argument("--docker", action="store_true")
    n.add_argument("--output-language", dest="output_language")
    n.set_defaults(fn=cmd_create)

    sub.add_parser("manifest", help="what this run created").set_defaults(fn=cmd_manifest)
    sub.add_parser("status", help="queue occupancy").set_defaults(fn=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except ToolError as exc:
        _fail(str(exc))
    except player_creds.CredentialError as exc:
        _fail(str(exc))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - the agent must see the failure
        _fail(f"{type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
