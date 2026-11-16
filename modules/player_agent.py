"""The AI Player: an agent that uses this platform the way the operator does.

Placement, and why it is not a module under `modules/<name>/`: those run on a
worker slot. The thing that CREATES jobs must not compete for a slot with the
jobs it creates — one web job held a slot for 6.5 hours on 2026-09-09. It runs
in the api container instead, which was verified to have `codex` and an authed
`/root/.codex` mounted from the host, so it needs no slot and no new image.

It is given hands, not a script: `modules/player_cli.py` subcommands for
login / fetch / download / claim / create. There is no per-site adapter, so
the same agent is pointed at any CTF platform and works out the site's own API
the way a person would — which is what "사용자처럼" asked for.

Two hard rules the prompt cannot relax:

* The site password is never in the prompt or the transcript. `login` takes a
  `$PLAYER_PASS` template and substitutes below the model. `--ephemeral` keeps
  codex from persisting a rollout under the mounted `$CODEX_HOME/sessions/`.
  This one IS structural: no code path hands the value to the model.

* The agent is *asked* to create jobs and nothing else — and that boundary is
  a PROMPT, not a wall. Be honest about it: the run has bash with
  `danger-full-access`, `/data` (including `settings.json` and its
  `auth_token`), the docker socket, and write access to the bind-mounted
  `/app/modules`. It can `curl` any endpoint the operator can. Narrowing the
  subcommand set shrinks the obvious paths, not the reachable ones. The
  operator asked for a fully agentic player above the orchestrator and this is
  the cost of that; what must not happen is a later change built on the belief
  that the sandbox enforces the restriction.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from modules import player_creds, player_state

# The player reasons about an unfamiliar site — which endpoint lists
# challenges, which field is the attachment — and a wrong guess costs a real
# job. Measured 2026-09-09 on a rev challenge: low answered with a fabricated
# flag in 4 of 6 runs while ultra never did. Exploration is the same class of
# task, so it gets the same effort the solving jobs get.
DEFAULT_EFFORT = "ultra"
DEFAULT_MODEL = "gpt-daybreak-blue-latest"

# A site with 40 challenges takes a while; this is a wall-clock stop, not a
# ceiling on how many jobs it may create.
DEFAULT_TIMEOUT_S = 3600.0


# A per-challenge token reaches the CLI as `--auth-token <value>` on a command
# line, and the command line is echoed into this run's log. `job_secrets`
# exists precisely to keep that token out of a job's meta and logs — writing it
# to `player-runs/<id>/run.log` in plaintext would hand back what that module
# is built to withhold. Masked at the emit, so it never reaches the file.
_CLI_SECRET_FLAGS = ("--auth-token", "--json-template", "--form-template")
_CLI_SECRET_RE = re.compile(
    r"(" + "|".join(re.escape(f) for f in _CLI_SECRET_FLAGS) + r")"
    r"(\s*=\s*|\s+)"
    r"('[^']*'|\"(?:[^\"\\]|\\.)*\"|\S+)"
)


def _mask_cli_secrets(value: Any) -> Any:
    """Blank the argument that follows a secret-bearing flag.

    The templates are masked too. They contain `$PLAYER_PASS` rather than the
    password — that is the whole point of `cmd_login` — but a model that
    "helpfully" inlines a literal instead of the placeholder would otherwise
    write it straight to disk, and the flag is worth nothing if it only holds
    when the agent behaves.
    """
    if isinstance(value, str):
        return _CLI_SECRET_RE.sub(r"\1\2[REDACTED_ARG]", value)
    if isinstance(value, dict):
        return {k: _mask_cli_secrets(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_cli_secrets(v) for v in value]
    return value


def run_root(run_id: str) -> Path:
    root = Path(os.environ.get("DATA_DIR", "/data")) / "player-runs" / run_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def _prompt(site_url: str, run_id: str, *, language: str,
            note: str, username: str) -> str:
    return f"""You are the AI Player. You explore a CTF site the way its human
owner would, and you create one Ogamdo job per challenge you find.

SITE: {site_url}
ACCOUNT: {username}
RUN ID: {run_id}

Your hands are one command. Every call prints a single JSON object; exit code
2 means it failed and the object has an "error" key.

  P="python3 -m modules.player_cli --run {run_id} --site-url {site_url}"

  $P whoami
  $P login --endpoint <path> [--method POST] [--json-template '<json>'] [--form-template '<json>'] [--headers '<json>']
  $P fetch <url> [--method M] [--json-body '<json>'] [--form '<json>'] [--headers '<json>']
  $P download <url> [--filename NAME]
  $P claim <challenge_id> [--name N] [--module M] [--url U]
  $P create <challenge_id> --module M --tag "<challenge name>" [--description D]
        [--target host:port|url] [--file /path] [--flag-format F]
        [--auth-token VALUE] [--docker] [--output-language {language}]
  $P manifest
  $P status

YOU NEVER SEE THE PASSWORD, AND YOU MUST NOT ASK FOR IT.
`login` substitutes it. Work out the site's login shape first — fetch the
login page, read the form or the XHR it posts — then express it with the
placeholders $PLAYER_USER and $PLAYER_PASS. Example shape only; the real
endpoint and field names are yours to discover:

  $P login --endpoint /api/v1/session --json-template '{{"username":"$PLAYER_USER","password":"$PLAYER_PASS"}}'

Then confirm you are authenticated by fetching something only a logged-in
account can see. If login fails, diagnose it from the status and body preview
and try a different shape. Do not give up after one attempt.

HOW TO WORK

1. Log in. The site is a single-page app; the JSON API its pages call is what
   you want, not the HTML. Look at the network shape: paths like /api/...,
   pagination parameters, an id per challenge.
2. Enumerate every challenge. Page through until the list is exhausted; say
   how many you found.
3. For each challenge, gather what a job needs:
   - the challenge NAME, which becomes the job tag, verbatim;
   - its description;
   - attachments -> `download`, then pass the saved path to `--file`;
   - a remote address (host:port or URL) if it has one -> `--target`;
   - the flag format if the site states one -> `--flag-format`.
4. Pick the module from the evidence, not the site's category label:
     web      a URL to attack, a web app source tree
     pwn      a binary plus a remote host:port
     rev      a binary/bytecode to understand, no service
     crypto   ciphertext, keys, a protocol
     forensic a capture, an image, a memory dump, a disk
     misc     anything else, including a shell/jail
     web3     a contract, a chain RPC
   If a challenge needs a per-challenge AUTH TOKEN, find where the site issues
   one (an account or API page), create it, and pass it as `--auth-token`. It
   is stored outside the job and masked in the job's logs.
5. Create the job. `create` claims the challenge id first, so re-running this
   agent resumes instead of duplicating. If a create returns "skipped", that
   challenge already has a job — move on. If it returns a "warning", say so.
6. When done, run `$P manifest` and report: how many challenges the site has,
   how many you created, and every one you skipped WITH THE REASON.

RULES

- Create jobs. Do not submit flags, stop jobs, or change settings — no command
  does those things, and you must not try to reach them another way.
- One job per challenge. Never create a second for an id the manifest holds.
- If you cannot classify a challenge or cannot get its files, SKIP it and say
  why. A job created on the wrong module or with no artifact wastes a slot and
  the operator's money.
- Do not print the password, or any header or cookie that carries it.
- Report in {language}.

{note}

Begin.
"""


def build_command(run_id: str, *, model: str, effort: str) -> list[str]:
    return [
        "codex", "exec", "--json",
        "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
        # Persist nothing: the api container mounts $CODEX_HOME from the host,
        # so a rollout would outlive the run on disk. The player handles
        # credentials; it does not get a transcript.
        "--ephemeral",
        "--model", model,
        "--config", 'sandbox_mode="danger-full-access"',
        "--config", f'model_reasoning_effort="{effort}"',
        "-",
    ]


class PlayerRun:
    """One player run, streamed line by line to a log and to the UI."""

    def __init__(self, run_id: str, site_url: str, *,
                 language: str = "ko", note: str = "",
                 model: str = DEFAULT_MODEL, effort: str = DEFAULT_EFFORT,
                 timeout_s: float = DEFAULT_TIMEOUT_S,
                 on_event: Callable[[dict], None] | None = None):
        self.run_id = run_id
        self.site_url = site_url
        self.site = player_creds.site_key(site_url)
        self.language = language
        self.note = note
        self.model = model
        self.effort = effort
        self.timeout_s = timeout_s
        self.on_event = on_event
        self.root = run_root(run_id)
        self.log_path = self.root / "run.log"
        self.state_path = self.root / "state.json"
        self.proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- plumbing ---------------------------------------------------------
    def _clean(self, value: Any) -> Any:
        """Last line of defence. `login` keeps the password out of the model,
        so this should never have anything to do — which is exactly why it
        must stay: the day a new subcommand leaks, this is what catches it.

        Masks EVERY stored site, not just this run's: the agent has a shell and
        `/data` is mounted, so another site's credential file is one `cat`
        away and would otherwise pass through unmasked.
        """
        return _mask_cli_secrets(player_creds.redacted(value))

    def _write_state(self, **fields: Any) -> None:
        data = self.status()
        data.update(fields)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        os.replace(tmp, self.state_path)

    def status(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_path.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {"run_id": self.run_id, "site": self.site,
                "site_url": self.site_url, "state": "idle"}

    def _emit(self, kind: str, text: str) -> None:
        line = self._clean(str(text))
        stamp = time.strftime("%H:%M:%S")
        with open(self.log_path, "a") as fp:
            fp.write(f"[{stamp}] [{kind}] {line}\n")
        if self.on_event:
            try:
                self.on_event({"kind": kind, "text": line, "at": stamp})
            except Exception:  # noqa: BLE001 - a listener must not kill the run
                pass

    # -- lifecycle --------------------------------------------------------
    def start(self) -> dict[str, Any]:
        if shutil.which("codex") is None:
            raise RuntimeError("codex is not on PATH in this container")
        if not player_creds.load(self.site):
            raise RuntimeError(f"no stored credentials for {self.site}")
        creds = player_creds.load(self.site) or {}
        prompt = _prompt(self.site_url, self.run_id,
                         language=self.language, note=self.note,
                         username=str(creds.get("username") or ""))
        env = dict(os.environ)
        # The platform's own token, and the ONLY destination it may have is
        # the local API — which is what `Ogamdo` points at.
        from modules.settings_io import get_setting  # noqa: PLC0415
        try:
            token = str(get_setting("auth_token") or "").strip()
        except Exception:  # noqa: BLE001
            token = ""
        if token:
            env["OGAMDO_AUTH_TOKEN"] = token
        env.setdefault("OGAMDO_API", "http://127.0.0.1:8000")

        self._write_state(state="running", started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          created=0, finished_at=None, error=None)
        self._emit("player", f"start — {self.site_url} (effort={self.effort})")
        self.proc = subprocess.Popen(
            build_command(self.run_id, model=self.model, effort=self.effort),
            cwd="/app", env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        assert self.proc.stdin is not None
        self.proc.stdin.write(prompt)
        self.proc.stdin.close()
        self._thread = threading.Thread(target=self._pump, daemon=True,
                                        name=f"player-{self.run_id}")
        self._thread.start()
        return self.status()

    def _pump(self) -> None:
        deadline = time.time() + self.timeout_s
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for raw in self.proc.stdout:
                if self._stop.is_set():
                    break
                if time.time() > deadline:
                    self._emit("player", "timeout — stopping")
                    self.stop()
                    break
                self._handle(raw.strip())
        except Exception as exc:  # noqa: BLE001
            self._emit("error", f"stream ended: {type(exc).__name__}: {exc}")
        code = self.proc.wait() if self.proc else -1
        rows = player_state.manifest(self.site)
        created = sum(1 for r in rows if r.get("state") == "created")
        self._emit("player", f"done (exit={code}) — {created} job(s) created")
        self._write_state(state="finished" if code == 0 else "failed",
                          exit_code=code, created=created,
                          finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    def _handle(self, line: str) -> None:
        if not line.startswith("{"):
            if line:
                self._emit("raw", line[:2000])
            return
        try:
            event = json.loads(line)
        except ValueError:
            return
        etype = str(event.get("type") or "")
        item = event.get("item") or {}
        itype = str(item.get("type") or "")
        if etype == "item.completed" and itype == "agent_message":
            self._emit("agent", str(item.get("text") or "")[:4000])
        elif etype == "item.started" and itype == "command_execution":
            self._emit("cmd", str(item.get("command") or "")[:600])
        elif etype == "item.completed" and itype == "command_execution":
            out = str(item.get("aggregated_output") or "")[:1500]
            if out.strip():
                self._emit("out", out)
        elif etype == "turn.completed":
            usage = event.get("usage") or {}
            self._emit("player", f"usage {json.dumps(usage)}")
            rows = player_state.manifest(self.site)
            self._write_state(created=sum(1 for r in rows
                                          if r.get("state") == "created"))
        elif etype in ("error", "turn.failed"):
            self._emit("error", str(event)[:1200])

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                self.proc.kill()
        self._write_state(state="stopped",
                          finished_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        return self.status()

    def tail(self, limit: int = 400) -> list[str]:
        try:
            return self.log_path.read_text(errors="replace").splitlines()[-limit:]
        except OSError:
            return []
