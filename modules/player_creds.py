"""Long-lived CTF *site* login credentials for the AI Player agent.

A THIRD credential store, deliberately separate from the two that already
exist, because it answers a question neither of them does:

* ``data/settings.json`` holds ``auth_token`` — the token that guards THIS
  platform's own API. Its standing rule is that it may only ever be sent to
  ``127.0.0.1``. A CTF site password is the exact opposite: its whole purpose
  is to be sent to a remote site. Filing them together is how the localhost
  rule gets applied to the wrong secret, or dropped from the right one.

* ``modules/job_secrets.py`` holds ``CTFD_ACCESS_TOKEN`` — job-scoped, copied
  on retry, TTL-cleaned with the job. A site login must outlive every job. Its
  own module documents two regressions caused by widening one frozenset to
  answer three different questions; this file exists so that set is not
  widened a third time.

The split in practice: the operator's site **login** lives here, and the
per-challenge **token** the player derives from it flows out through the
existing ``challenge_secret_key=CTFD_ACCESS_TOKEN`` ingress into the job that
needs it. Only the derived token ever reaches a job.

Redaction note: ``_REDACTABLE_KEYS`` in job_secrets is ``{CTFD_ACCESS_TOKEN}``
alone, so a site password written into a job description would persist
**unredacted** in meta.json and the run log. Nothing here may be placed in a
description, a tag, or a log line; ``redacted()`` is what callers print.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


class CredentialError(ValueError):
    """Rejected credential ingress — safe to surface, carries no secret."""


# A site id is the operator's own account name on a CTF platform. Kept to a
# conservative set so it can never be a path fragment or a shell metacharacter
# when it reaches a log line or a filename.
_SITE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")

_MAX_VALUE = 4096


def _root() -> Path:
    return Path(os.environ.get("DATA_DIR", "/data")) / "player-creds"


def _path(site: str) -> Path:
    safe = str(site or "").strip().lower()
    if not _SITE_RE.fullmatch(safe):
        raise CredentialError("invalid site key")
    return _root() / f"{safe}.json"


def site_key(url: str) -> str:
    """Stable per-site filename from a page URL.

    The player is pointed at a page, not at a name, so the store is keyed on
    the host. `https://dreamhack.io/wargame/challenges?page=2` and
    `https://dreamhack.io/` are the same account.
    """
    raw = str(url or "").strip()
    if not raw:
        raise CredentialError("empty site url")
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host = raw.split("/", 1)[0].split("@")[-1].split(":")[0].strip().lower()
    if not host:
        raise CredentialError("could not read a host from the url")
    # A host is dotted; the filename is not allowed to be, so that a crafted
    # host can never climb out of the directory.
    key = host.replace(".", "_")
    if not _SITE_RE.fullmatch(key):
        raise CredentialError("unsupported host")
    return key


def store(url: str, username: str, password: str, *, extra: dict | None = None) -> str:
    """Persist one site login. Returns the site key it was filed under."""
    user = str(username or "").strip()
    pw = str(password or "")
    if not user or not pw:
        raise CredentialError("username and password are both required")
    if len(user) > _MAX_VALUE or len(pw) > _MAX_VALUE:
        raise CredentialError("credential too long")
    key = site_key(url)
    payload: dict[str, Any] = {
        "site": key,
        "url": str(url).strip(),
        "username": user,
        "password": pw,
    }
    if extra:
        # Anything else the operator had to paste to get in (an org slug, a
        # team name). Values are stringified so the file stays flat.
        payload["extra"] = {str(k): str(v) for k, v in extra.items() if v}
    path = _path(key)
    root = path.parent
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    tmp = root / f".{path.name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fp:
            json.dump(payload, fp, separators=(",", ":"), ensure_ascii=False)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    return key


def load(url_or_key: str) -> dict[str, Any] | None:
    """Read one site login, or None. Callers must not log the result."""
    raw = str(url_or_key or "").strip()
    if not raw:
        return None
    key = raw.lower() if _SITE_RE.fullmatch(raw.lower()) else site_key(raw)
    try:
        data = json.loads(_path(key).read_text())
    except (OSError, ValueError, CredentialError):
        return None
    if not isinstance(data, dict) or not data.get("password"):
        return None
    return data


def forget(url_or_key: str) -> bool:
    try:
        raw = str(url_or_key or "").strip()
        key = raw.lower() if _SITE_RE.fullmatch(raw.lower()) else site_key(raw)
        _path(key).unlink()
        return True
    except (OSError, CredentialError):
        return False


def known_sites() -> list[dict[str, str]]:
    """What the operator has saved — usernames only, never passwords."""
    out: list[dict[str, str]] = []
    try:
        entries = sorted(_root().glob("*.json"))
    except OSError:
        return out
    for p in entries:
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        out.append({
            "site": str(data.get("site") or p.stem),
            "url": str(data.get("url") or ""),
            "username": str(data.get("username") or ""),
        })
    return out


def secret_values(url_or_key: str) -> list[str]:
    """Every string that must never appear in output for this site.

    Used as the needle list by `redacted`. The username is NOT a needle: it is
    not secret, and masking it would corrupt the very challenge listings the
    player is reading (a challenge author's handle can equal an account name).
    """
    data = load(url_or_key) or {}
    needles = [str(data.get("password") or "")]
    for value in (data.get("extra") or {}).values():
        needles.append(str(value))
    return [n for n in needles if len(n) >= 4]


def all_secret_values() -> list[str]:
    """Every stored site secret, not just the active one.

    The player agent runs with a full shell and `/data` mounted, so it can
    `cat` another site's credential file whether or not it was pointed at that
    site. Redacting only the active site would then mask nothing in exactly
    the case that matters, so the needle list spans the whole store.
    """
    needles: list[str] = []
    for row in known_sites():
        needles.extend(secret_values(row["site"]))
    # Longest first: a short password that is a substring of a longer one must
    # not blank out half of the longer one and leave the rest readable.
    return sorted({n for n in needles if len(n) >= 4}, key=len, reverse=True)


def redacted(text: Any, url_or_key: str | None = None) -> Any:
    """Mask stored site secrets in anything about to be logged or returned.

    Mirrors `job_secrets.redact_job_value`: an exact-substring replace, applied
    recursively, so a password embedded in a captured HTTP body or a model
    transcript does not escape through the player's own log. With no site
    given — or as a superset when one is — every stored site is masked.
    """
    needles = all_secret_values()
    if not needles:
        return text

    def _walk(value: Any) -> Any:
        if isinstance(value, str):
            out = value
            for needle in needles:
                if needle and needle in out:
                    out = out.replace(needle, "[REDACTED_SITE_SECRET]")
            return out
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_walk(v) for v in value]
        return value

    return _walk(text)
