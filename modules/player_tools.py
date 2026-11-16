"""The surface the AI Player agent acts through.

Two kinds of tool, deliberately separate:

* ``Browser`` — a cookie-keeping HTTP client for the CTF site. It is NOT a
  DOM automation layer. Both CTFd and Dreamhack are single-page apps whose
  pages call a JSON API, and the worker image has chromium but no
  playwright/selenium, so driving a browser would mean hand-rolled CDP. The
  agent reads the API the page reads. `fetch` therefore returns the body as
  text, plus a `looks_json` hint, and leaves interpretation to the agent —
  that is what "explores like a user" means here rather than a per-site
  adapter.

* ``Ogamdo`` — this platform's own create API, the same multipart endpoint
  the operator's UI posts to (`/api/modules/<module>/analyze`, mounted in
  api/main.py). The player is above the orchestrator, so it asks for a job
  exactly as a person would.

Everything that leaves either class passes through the site's redactor before
it can reach a log or a model transcript, because `job_secrets`'
`_REDACTABLE_KEYS` covers `CTFD_ACCESS_TOKEN` alone — a site password is not
masked by anything else in the repo.
"""

from __future__ import annotations

import io
import json
import mimetypes
import os
import re
import urllib.parse
from typing import Any

from modules import player_creds

# Bodies are handed to a model, so they are capped. A challenge list page is a
# few KB of JSON; a full HTML bundle can be megabytes and is never the useful
# part. The cap is per-fetch and the agent is told when it hit.
BODY_MAX = 60_000

# Downloads land in the job's upload staging area, not in memory.
DOWNLOAD_MAX = 512 * 1024 * 1024

VALID_MODULES = ("web", "pwn", "rev", "crypto", "forensic", "misc", "web3")

# The remote field is named `target_url` by web ALONE; every other module —
# web3 included, which is the one that looks like it should match web — calls
# it `target`. Verified against api/routes/*_module.py on 2026-09-09, because
# a wrong name is not an error: FastAPI drops the unknown form field and the
# job is created with no remote address at all.
_URL_FIELD = {"web": "target_url"}


class ToolError(RuntimeError):
    """A tool failed in a way the agent should see and can react to."""


def _requests():
    try:
        import requests  # noqa: PLC0415 - optional at import time
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"requests unavailable: {exc}") from exc
    return requests


class Browser:
    """One logged-in session against one CTF site."""

    def __init__(self, base_url: str, site_key: str, *, timeout: float = 30.0,
                 jar_path: str | None = None):
        requests = _requests()
        self.base_url = base_url.rstrip("/")
        self.site = site_key
        self.timeout = timeout
        # The agent drives these tools from bash, one process per call, so the
        # login has to survive process exit or every fetch would be anonymous.
        # A file-backed jar is what makes "log in once, then browse" true.
        self.jar_path = jar_path
        self.session = requests.Session()
        self._load_cookies()
        self.session.headers.update({
            # A default python-requests UA is refused by some CTF front ends.
            # This is the operator's own account on their own challenge
            # platform, so the UA is about being served, not about hiding.
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        })
        self.history: list[dict[str, Any]] = []

    # -- internals --------------------------------------------------------
    def _abs(self, url: str) -> str:
        raw = str(url or "").strip()
        if not raw:
            raise ToolError("empty url")
        if raw.startswith(("http://", "https://")):
            return raw
        return urllib.parse.urljoin(self.base_url + "/", raw.lstrip("/"))

    def _clean(self, value: Any) -> Any:
        return player_creds.redacted(value, self.site)

    def _record(self, method: str, url: str, status: int, note: str = "") -> None:
        self.history.append({"method": method, "url": url,
                             "status": status, "note": note[:200]})
        del self.history[:-200]

    # -- session persistence ----------------------------------------------
    def _load_cookies(self) -> None:
        if not self.jar_path or not os.path.isfile(self.jar_path):
            return
        try:
            raw = json.loads(open(self.jar_path).read())
        except (OSError, ValueError):
            return
        for c in raw if isinstance(raw, list) else []:
            try:
                self.session.cookies.set(
                    c["name"], c["value"],
                    domain=c.get("domain") or "", path=c.get("path") or "/",
                )
            except Exception:  # noqa: BLE001 - a malformed row must not block login
                continue

    def save_cookies(self) -> None:
        """Persist the jar. A session cookie IS the login, so mode 0600."""
        if not self.jar_path:
            return
        rows = [{"name": c.name, "value": c.value,
                 "domain": c.domain, "path": c.path}
                for c in self.session.cookies]
        d = os.path.dirname(self.jar_path)
        if d:
            os.makedirs(d, exist_ok=True, mode=0o700)
        tmp = self.jar_path + f".{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fp:
            json.dump(rows, fp)
        os.replace(tmp, self.jar_path)
        os.chmod(self.jar_path, 0o600)

    # -- tools ------------------------------------------------------------
    def fetch(self, url: str, *, method: str = "GET",
              json_body: Any = None, form: dict | None = None,
              headers: dict | None = None) -> dict[str, Any]:
        """One HTTP request. Returns status, headers of interest, and body text."""
        target = self._abs(url)
        try:
            resp = self.session.request(
                method.upper(), target, json=json_body, data=form,
                headers=headers or None, timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            self._record(method, target, 0, str(exc))
            raise ToolError(f"{method} {target} failed: {self._clean(str(exc))}") from exc
        body = resp.text or ""
        truncated = len(body) > BODY_MAX
        ctype = resp.headers.get("content-type", "")
        self._record(method, target, resp.status_code)
        return self._clean({
            "url": resp.url,
            "status": resp.status_code,
            "content_type": ctype,
            "looks_json": "json" in ctype.lower() or body[:1] in "{[",
            "truncated": truncated,
            "body": body[:BODY_MAX],
            "set_cookies": sorted(self.session.cookies.keys()),
        })

    def download(self, url: str, dest_dir: str, *,
                 filename: str | None = None) -> dict[str, Any]:
        """Stream a challenge attachment to disk. Never held in memory."""
        target = self._abs(url)
        os.makedirs(dest_dir, exist_ok=True)
        try:
            with self.session.get(target, stream=True, timeout=self.timeout) as resp:
                if resp.status_code >= 400:
                    self._record("GET", target, resp.status_code, "download refused")
                    raise ToolError(f"download {target}: HTTP {resp.status_code}")
                name = filename or _name_from_response(resp, target)
                path = os.path.join(dest_dir, _safe_name(name))
                written = 0
                with open(path, "wb") as fp:
                    for chunk in resp.iter_content(64 * 1024):
                        if not chunk:
                            continue
                        written += len(chunk)
                        if written > DOWNLOAD_MAX:
                            fp.close()
                            os.unlink(path)
                            raise ToolError("attachment exceeds the size cap")
                        fp.write(chunk)
                self._record("GET", target, resp.status_code, f"saved {written}B")
                return {"path": path, "filename": os.path.basename(path),
                        "bytes": written}
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"download failed: {self._clean(str(exc))}") from exc

    def login_hint(self) -> dict[str, Any]:
        """The stored credentials, for the agent to POST wherever the site wants.

        The password is returned because the agent must send it to the site —
        that is the whole point of the feature — but it is returned ONLY here,
        never echoed into `fetch` output, and callers must not log this dict.
        """
        data = player_creds.load(self.site) or {}
        if not data:
            raise ToolError("no stored credentials for this site")
        return {"username": data.get("username", ""),
                "password": data.get("password", ""),
                "extra": data.get("extra") or {}}


def _name_from_response(resp, url: str) -> str:
    disp = resp.headers.get("content-disposition", "")
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', disp)
    if m:
        return urllib.parse.unquote(m.group(1))
    path = urllib.parse.urlparse(url).path
    base = os.path.basename(path) or "attachment"
    if "." not in base:
        ext = mimetypes.guess_extension(
            (resp.headers.get("content-type", "").split(";")[0] or "").strip()
        ) or ""
        base += ext
    return base


def _safe_name(name: str) -> str:
    base = os.path.basename(str(name or "attachment").strip()) or "attachment"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base[:120] or "attachment"


class Ogamdo:
    """Create jobs the way the operator's own UI does."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000",
                 auth_token: str | None = None, *, timeout: float = 120.0):
        requests = _requests()
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if auth_token:
            # Only ever sent to the local API — the standing rule for the
            # platform's own token. `base_url` is not operator-supplied.
            self.session.headers["Authorization"] = f"Bearer {auth_token}"

    def create_job(self, module: str, *, tag: str,
                   description: str | None = None,
                   target: str | None = None,
                   file_path: str | None = None,
                   flag_format: str | None = None,
                   auth_token_value: str | None = None,
                   docker_challenge: bool = False,
                   output_language: str | None = None) -> dict[str, Any]:
        """POST one job. Mirrors the UI's multipart form exactly."""
        mod = str(module or "").strip().lower()
        if mod not in VALID_MODULES:
            raise ToolError(f"unknown module {mod!r}; pick one of {VALID_MODULES}")
        if not file_path and not target:
            raise ToolError("a challenge needs a file or a remote target")

        form: dict[str, Any] = {"tag": (tag or "")[:120]}
        if description:
            form["description"] = description
        if target:
            form[_URL_FIELD.get(mod, "target")] = target
        if flag_format:
            form["flag_format"] = flag_format
        if output_language:
            form["output_language"] = output_language
        if docker_challenge:
            form["docker_challenge"] = "true"
        if auth_token_value:
            # The one ingress the platform already has for a per-challenge
            # token: stored outside the job dir and redacted from meta/logs.
            form["challenge_secret_key"] = "CTFD_ACCESS_TOKEN"
            form["challenge_secret_value"] = auth_token_value

        files = None
        handle = None
        try:
            if file_path:
                if not os.path.isfile(file_path):
                    raise ToolError(f"no such file: {file_path}")
                handle = open(file_path, "rb")
                files = {"file": (os.path.basename(file_path), handle,
                                  "application/octet-stream")}
            resp = self.session.post(
                f"{self.base}/api/modules/{mod}/analyze",
                data=form, files=files, timeout=self.timeout,
            )
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"create failed: {exc}") from exc
        finally:
            if handle is not None:
                handle.close()

        if resp.status_code >= 400:
            raise ToolError(f"create rejected ({resp.status_code}): {resp.text[:300]}")
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001
            payload = {}
        job_id = (payload.get("job_id") or payload.get("id")
                  or (payload.get("job") or {}).get("id"))
        if not job_id:
            raise ToolError(f"create returned no job id: {str(payload)[:200]}")
        return {"job_id": str(job_id), "module": mod, "response": payload}

    def running_count(self) -> int:
        """How many jobs currently hold a slot — context for the agent.

        A 401 from the auth middleware is a JSON object (`{"detail": ...}`),
        so parsing it and reading `.get("jobs")` yields an empty list and the
        caller sees a confident "0 running jobs" for what is really "I could
        not ask". The status check is what keeps a missing token from looking
        like an idle queue.
        """
        try:
            resp = self.session.get(f"{self.base}/api/jobs", timeout=30)
        except Exception:  # noqa: BLE001
            raise ToolError("could not reach the Ogamdo API") from None
        if resp.status_code == 401:
            raise ToolError(
                "Ogamdo API refused the token — set OGAMDO_AUTH_TOKEN"
            )
        if resp.status_code >= 400:
            raise ToolError(f"/api/jobs returned HTTP {resp.status_code}")
        try:
            rows = resp.json()
        except Exception:  # noqa: BLE001
            raise ToolError("/api/jobs did not return JSON") from None
        if isinstance(rows, dict):
            rows = rows.get("jobs") or []
        if not isinstance(rows, list):
            raise ToolError("/api/jobs returned an unexpected shape")
        return sum(1 for r in rows
                   if isinstance(r, dict)
                   and str(r.get("status")) in ("running", "queued"))
