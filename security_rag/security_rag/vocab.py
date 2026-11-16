"""Shared names for primitives, outcomes and technique families.

A graph only connects cases that use the same word for the same thing. The
report phase names techniques freely (``house_of_apple_2`` beside
``house_of_apple2``, or either inside a longer chain name) and describes
primitives in sentences, so without this table almost every node belongs to
one case.

Values outside the vocabulary are not dropped by callers that want to grow
it: :func:`canonical` returns ``None`` and the caller decides.
"""

from __future__ import annotations

import re

# canonical -> other spellings (matched as whole-token phrases)
PRIMITIVES: dict[str, tuple[str, ...]] = {
    "aaw": ("arbitrary write", "arbitrary address write", "arbitrary memory write", "write what where"),
    "aar": ("arbitrary read", "arbitrary address read", "arbitrary memory read"),
    "partial-write": ("partial overwrite", "partial write"),
    "oob-write": ("relative write", "out of bounds write", "oob write"),
    "oob-read": ("relative read", "out of bounds read", "oob read"),
    "info-leak": ("address leak", "libc leak", "heap leak", "stack leak", "pie leak", "canary leak",
                  "kaslr leak", "info leak", "information leak", "memory disclosure"),
    "control-flow-hijack": ("pc control", "rip control", "eip control", "control flow hijack",
                            "return address overwrite", "function pointer overwrite", "vtable hijack"),
    "uaf": ("use after free", "dangling pointer", "dangling reference"),
    "type-confusion": ("type confusion",),
    "rce": ("code execution", "remote code execution", "command execution", "arbitrary code execution"),
    "file-read": ("arbitrary file read", "local file read", "file read", "file disclosure"),
    "file-write": ("arbitrary file write", "file write", "file upload"),
    "ssrf-request": ("server side request", "internal request", "ssrf"),
    "sql-query": ("sql injection", "sql execution", "query injection", "sqli"),
    "script-execution": ("javascript execution", "script execution", "js execution", "xss"),
    "auth-bypass": ("authentication bypass", "authorization bypass", "access control bypass", "auth bypass"),
    "token-forgery": ("forged token", "token forgery", "jwt forgery", "signature forgery", "cookie forgery"),
    "key-recovery": ("key recovery", "private key recovery", "secret key recovery", "seed recovery"),
    "plaintext-recovery": ("plaintext recovery", "decryption oracle", "message recovery"),
    "oracle": ("side channel", "timing oracle", "error oracle", "boolean oracle", "padding oracle"),
    "dos": ("denial of service", "crash"),
}

OUTCOMES: dict[str, tuple[str, ...]] = {
    "code-execution": ("shell", "rce", "remote code execution", "command execution", "arbitrary code execution"),
    "file-read": ("arbitrary file read", "flag file read", "file read"),
    "privilege-escalation": ("root", "privesc", "privilege escalation", "kernel privilege"),
    "sandbox-escape": ("sandbox escape", "vm escape", "container escape", "jail escape"),
    "account-takeover": ("admin access", "admin session", "account takeover", "session hijack"),
    "secret-recovery": ("key recovery", "secret recovery", "plaintext recovery", "password recovery"),
    "data-exfiltration": ("exfiltration", "data exfiltration", "data leak"),
    "input-recovery": ("valid input recovered", "input recovery", "license key", "correct input"),
    "dos": ("denial of service",),
}

# Families that recur inside longer, case-specific technique names.
TECHNIQUE_FAMILIES: dict[str, tuple[str, ...]] = {
    "tcache-poison": ("tcache poisoning",),
    "fastbin-poison": ("fastbin dup", "fastbin attack", "fastbin poisoning"),
    "unsafe-unlink": ("unsorted unlink",),
    "large-bin-attack": ("largebin attack",),
    "house-of-apple2": ("house of apple 2",),
    "house-of-water": (),
    "house-of-einherjar": (),
    "house-of-tangerine": (),
    "fsop": ("file stream oriented programming",),
    "heap-groom": ("heap grooming", "heap feng shui", "heap spray"),
    "rop": ("return oriented programming",),
    "srop": ("sigreturn",),
    "ret2libc": (), "ret2win": (), "ret2dlresolve": (), "ret2shellcode": (), "ret2usr": (),
    "stack-pivot": ("pivot",),
    "setcontext": (),
    "jit-spray": (),
    "dirty-pagetable": (), "dirty-cred": (), "dirty-pipe": (),
    "modprobe-path": (),
    "type-confusion": ("typer confusion",),
    "prototype-pollution": (),
    "ssti": ("sstemplate injection", "template injection"),
    "stored-xss": (), "reflected-xss": (),
    "xs-leak": ("xsleak", "xs search", "history sniffing"),
    "ssrf": (),
    "sqli": ("sql injection",),
    "nosql-injection": ("nosql",),
    "jwt-forgery": ("jwt",),
    "path-traversal": (),
    "lfi": ("local file inclusion",),
    "toctou-race": ("toctou", "race condition", "race"),
    "request-smuggling": (),
    "cache-poisoning": (),
    "sandbox-escape": ("vm escape", "jail escape"),
    "command-injection": (),
    "deserialization": (),
    "length-extension": (),
    "lattice": ("lll", "hidden number"),
    "padding-oracle": (),
    "side-channel": ("timing",),
    "static-emit": (), "dynamic-trace": (), "constraint-solver": ("z3", "smt"),
    "brute-force": ("bruteforce",),
}

_SPLIT = re.compile(r"\s*(?:\+|->|→|=>|,|&|;|\(|\)|\bvia\b|\bthen\b)\s*", re.IGNORECASE)
_TECH_ALIASES = {"house-of-apple-2": "house-of-apple2", "tcache-poisoning": "tcache-poison"}


def _words(value: str) -> list[str]:
    return re.findall(r"[^\W_]+", str(value or "").casefold(), re.UNICODE)


def _contains(haystack: list[str], needle: list[str]) -> bool:
    n = len(needle)
    return bool(n) and any(haystack[i:i + n] == needle for i in range(len(haystack) - n + 1))


def _slug(value: str) -> str:
    slug = "-".join(_words(value))
    slug = re.sub(r"(?<=[a-z])-(\d+)(?=-|$)", r"\1", slug)
    return _TECH_ALIASES.get(slug, slug)


def canonical(label: str, vocabulary: dict[str, tuple[str, ...]]) -> str | None:
    """Map a free-text label to a vocabulary key, or ``None`` if it has none.

    An exact key wins; otherwise the longest spelling found inside the label.
    """
    slug = _slug(label)
    if slug in vocabulary:
        return slug
    words = _words(label)
    best: tuple[int, str] | None = None
    for key, spellings in vocabulary.items():
        for spelling in (key.replace("-", " "),) + spellings:
            needle = _words(spelling)
            if _contains(words, needle) and (best is None or len(needle) > best[0]):
                best = (len(needle), key)
    return best[1] if best else None


def technique_nodes(name: str) -> list[str]:
    """Stable node labels for one report's ``technique_name``.

    The name is split at its joiners; each short part is kept under one
    spelling, and every family named anywhere in it is added. A long
    case-specific description yields only its families: it stays searchable
    as text, but is not a node that another case could ever share.
    """
    nodes: list[str] = []
    for part in _SPLIT.split(str(name or "")):
        slug = _slug(part)
        if not slug:
            continue
        words = slug.split("-")
        if len(words) <= 5 and len(slug) <= 48:
            nodes.append(slug)
        for family, spellings in TECHNIQUE_FAMILIES.items():
            for spelling in (family.replace("-", " "),) + spellings:
                if _contains(_words(part), _words(spelling)):
                    nodes.append(family)
                    break
    return list(dict.fromkeys(nodes))
