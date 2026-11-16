"""Small, dependency-free redaction helpers for retrieved evidence.

This is a guard against accidentally placing old CTF answers or target
credentials in an index or prompt.  Callers with additional secret types can
redact their own source before passing it to the index.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit


_FLAG_PREFIXES = r"(?:flag|ctf|picoctf|htb|dh|secc?on)"
_COMMON_FLAG = re.compile(
    # A closed token whose body has no whitespace, ``%`` or nested brace.
    # ``struct flag{ int a; }``, ``printf("flag{%s}")`` and ``f"FLAG{i}"``
    # are code about the answer's shape, not the answer, and stay readable.
    _FLAG_PREFIXES + r"\{[^{}\s%]{4,400}\}"
    # An unclosed prefix left by a truncated log line is still answer-shaped.
    r"|" + _FLAG_PREFIXES + r"\{[A-Za-z0-9_-]{8,400}(?![A-Za-z0-9_}-])",
    re.IGNORECASE,
)
_FLAG_SHAPE = re.compile(r"^([A-Za-z0-9_]{2,32})\{.+\}$", re.DOTALL)
_DOTTED_NAME = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_BEARER = re.compile(r"(\bAuthorization\s*:\s*Bearer\s+)[^\s,;]+", re.IGNORECASE)
_BASIC = re.compile(r"(\bAuthorization\s*:\s*Basic\s+)[^\s,;]+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(\b(?:api[_-]?key|access[_-]?token|password|passwd|secret)\s*[:=]\s*)"
    r"(['\"]?)([A-Za-z0-9_./+~=-]{8,})(['\"]?)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)


def _mask_assignment(match: re.Match[str]) -> str:
    """Mask a literal credential, but leave an expression that reads one.

    ``password = request.form["pw"]`` is the vulnerable line of a report, not
    a secret. An unquoted value is an expression when it is a dotted name or
    is immediately indexed or called.
    """
    head, open_quote, value, close_quote = match.groups()
    if not open_quote:
        rest = match.string[match.end():match.end() + 1]
        if rest in {"(", "["} or _DOTTED_NAME.match(value):
            return match.group(0)
    return f"{head}{open_quote}[REDACTED_SECRET]{close_quote}"


def redact_text(
    text: str,
    *,
    flags: tuple[str, ...] | list[str] = (),
    target_urls: tuple[str, ...] | list[str] = (),
) -> str:
    """Mask known answers, target hosts, and common credential spellings.

    Exact known values are replaced first, so challenge-specific flag formats
    are covered even when they do not resemble the common ``FLAG{...}`` form.
    The function deliberately keeps URL paths: a route can be the transferable
    detail while its challenge host is not.
    """
    out = str(text or "")
    for flag in sorted({str(f) for f in flags if f}, key=len, reverse=True):
        out = out.replace(flag, "[REDACTED_FLAG]")
    # A case's own flags name the competition's prefix. Other tokens with
    # that prefix (a second flag, a decoy, a sample) are masked with them,
    # which covers formats the fixed prefix list has never heard of.
    learned = sorted({m.group(1) for f in flags if (m := _FLAG_SHAPE.match(str(f)))})
    for prefix in learned:
        out = re.sub(
            re.escape(prefix) + r"\{[^{}\s%]{1,400}\}", "[REDACTED_FLAG]", out,
            flags=re.IGNORECASE,
        )
    out = _COMMON_FLAG.sub("[REDACTED_FLAG]", out)

    for raw in sorted({str(u).strip() for u in target_urls if u}, key=len, reverse=True):
        # The complete literal often carries credentials or a challenge token
        # in its query string.  Replace it before looking for the bare host.
        out = re.sub(re.escape(raw), "[REDACTED_TARGET]", out, flags=re.IGNORECASE)
        try:
            parsed = urlsplit(raw if "://" in raw else f"//{raw}")
            netloc = parsed.netloc.rsplit("@", 1)[-1]
            # ``hostname`` drops the port. Matching on the netloc left the
            # bare host in every ``nc host 1234`` line of a report.
            host = parsed.hostname or ""
        except ValueError:
            netloc = host = ""
        for value in (netloc, host):
            if value and len(value) >= 4:
                out = re.sub(re.escape(value), "[REDACTED_TARGET]", out, flags=re.IGNORECASE)

    out = _BEARER.sub(r"\1[REDACTED_SECRET]", out)
    out = _BASIC.sub(r"\1[REDACTED_SECRET]", out)
    out = _ASSIGNMENT.sub(_mask_assignment, out)
    out = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", out)
    return out
