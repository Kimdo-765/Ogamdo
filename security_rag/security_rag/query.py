"""Turn a free-text question into the concepts a relevant passage must share.

A query is split into *units*. A unit is one concept the asker named; its
alternatives are the spellings that concept takes in the corpus (``uaf`` and
the phrase ``use after free``, or a Korean term and its English form). Search
ranks on any alternative but only keeps a passage that covers enough distinct
units, so a question about something the library has never seen returns
nothing instead of the least-bad passage.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_PIECE_RE = re.compile(r"[가-힣]+|[^\W_가-힣]+", re.UNICODE)
_HANGUL_RUN = re.compile(r"[가-힣]+")

STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does", "for",
    "from", "get", "how", "i", "in", "into", "is", "it", "of", "on", "or", "that",
    "the", "this", "to", "via", "we", "what", "when", "which", "with",
})

# Spellings of one concept. Matching is on whole tokens, in order.
_EQUIVALENTS: tuple[tuple[str, ...], ...] = (
    ("uaf", "use after free"),
    ("aar", "arbitrary read"),
    ("aaw", "arbitrary write"),
    ("rce", "remote code execution"),
    ("sqli", "sql injection"),
    ("ssrf", "server side request forgery"),
    ("csrf", "cross site request forgery"),
    ("xss", "cross site scripting"),
    ("xxe", "xml external entity"),
    ("ssti", "server side template injection"),
    ("lfi", "local file inclusion"),
    ("idor", "insecure direct object reference"),
    ("oob", "out of bounds"),
    ("bof", "buffer overflow"),
    ("fsop", "file stream oriented programming"),
    ("rop", "return oriented programming"),
    ("toctou", "time of check time of use"),
    ("fmt string", "format string"),
    ("int overflow", "integer overflow"),
)

# Korean term -> English spellings used by the report metadata. The last word
# of a key may carry a particle (``오버플로우를``); earlier words match exactly.
_KOREAN: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("해제 후 사용", ("use after free", "uaf")),
    ("이중 해제", ("double free",)),
    ("포맷 스트링", ("format string", "fmt string")),
    ("형식 문자열", ("format string", "fmt string")),
    ("경쟁 상태", ("race condition",)),
    ("레이스 컨디션", ("race condition",)),
    ("프로토타입 오염", ("prototype pollution",)),
    ("명령어 삽입", ("command injection",)),
    ("커맨드 인젝션", ("command injection",)),
    ("경로 순회", ("path traversal",)),
    ("경로 탐색", ("path traversal",)),
    ("타입 컨퓨전", ("type confusion",)),
    ("타입 혼동", ("type confusion",)),
    ("인증 우회", ("auth bypass",)),
    ("권한 상승", ("privilege escalation",)),
    ("샌드박스 탈출", ("sandbox escape",)),
    ("임의 주소 쓰기", ("arbitrary write", "aaw")),
    ("임의 쓰기", ("arbitrary write", "aaw")),
    ("임의 주소 읽기", ("arbitrary read", "aar")),
    ("임의 읽기", ("arbitrary read", "aar")),
    ("원격 코드 실행", ("remote code execution", "rce")),
    ("정수 오버플로우", ("integer overflow", "int overflow")),
    ("버퍼 오버플로우", ("buffer overflow", "bof")),
    ("오버플로우", ("overflow",)),
    ("오버플로", ("overflow",)),
    ("역직렬화", ("deserialization",)),
    ("인젝션", ("injection",)),
    ("취약점", ("vulnerability",)),
    ("힙", ("heap",)),
    ("스택", ("stack",)),
    ("커널", ("kernel",)),
    ("유출", ("leak",)),
    ("릭", ("leak",)),
    ("셸", ("shell",)),
    ("쉘", ("shell",)),
)
_PARTICLES = ("으로", "에서", "을", "를", "이", "가", "은", "는", "의", "에", "로", "와", "과", "도", "만")

_EQ_PHRASES: list[tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]] = sorted(
    (
        (tuple(phrase.split()), tuple(tuple(p.split()) for p in group))
        for group in _EQUIVALENTS for phrase in group
    ),
    key=lambda item: -len(item[0]),
)
_KO_PHRASES = sorted(
    ((tuple(key.split()), tuple(tuple(v.split()) for v in values)) for key, values in _KOREAN),
    key=lambda item: (-len(item[0]), -len(item[0][-1])),
)


def tokens(value: str) -> list[str]:
    """Lower-cased word pieces; a Hangul run and its Latin neighbor split."""
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return _PIECE_RE.findall(text.replace("_", " ").replace("-", " "))


def _is_hangul(token: str) -> bool:
    return bool(token) and "가" <= token[0] <= "힣"


def _bigrams(run: str) -> tuple[str, ...]:
    return (run,) if len(run) < 2 else tuple(run[i:i + 2] for i in range(len(run) - 1))


def hangul_index_text(text: str) -> str:
    """Overlapping syllable pairs of every Hangul run, for the ``ko`` column.

    Korean attaches particles to the noun, so a word index never sees
    ``취약점`` inside ``취약점을``. Pairs make the stem a phrase of the longer run.
    """
    runs = _HANGUL_RUN.findall(unicodedata.normalize("NFKC", str(text or "")))
    return " ".join(pair for run in runs for pair in _bigrams(run))


def _strip_particle(token: str) -> str:
    for particle in _PARTICLES:
        if token.endswith(particle) and len(token) - len(particle) >= 2:
            return token[: -len(particle)]
    return token


@dataclass(frozen=True)
class Alternative:
    words: tuple[str, ...]
    korean: bool = False

    def fts(self) -> str:
        if self.korean:
            pairs = " ".join(p for word in self.words for p in _bigrams(word))
            return 'ko : "' + pairs + '"'
        return '"' + " ".join(w.replace('"', '""') for w in self.words) + '"'

    def in_text(self, padded_words: str, raw: str) -> bool:
        if self.korean:
            return all(word in raw for word in self.words)
        return f" {' '.join(self.words)} " in padded_words


@dataclass(frozen=True)
class Unit:
    name: str
    alternatives: tuple[Alternative, ...]

    def fts(self) -> str:
        return " OR ".join(a.fts() for a in self.alternatives)

    def in_text(self, padded_words: str, raw: str) -> bool:
        return any(a.in_text(padded_words, raw) for a in self.alternatives)


def _korean_match(toks: list[str], at: int) -> tuple[int, tuple[tuple[str, ...], ...]] | None:
    for key, values in _KO_PHRASES:
        end = at + len(key)
        if end > len(toks) or toks[at:end - 1] != list(key[:-1]):
            continue
        last = toks[end - 1]
        if last == key[-1] or (last.startswith(key[-1]) and last[len(key[-1]):] in _PARTICLES):
            return len(key), values
    return None


def parse_query(query: str, *, max_units: int = 12) -> list[Unit]:
    toks = tokens(query)[:60]
    units: list[Unit] = []
    seen: set[str] = set()
    i = 0
    while i < len(toks) and len(units) < max_units:
        token = toks[i]
        unit: Unit | None = None
        step = 1
        if _is_hangul(token):
            found = _korean_match(toks, i)
            if found:
                step, english = found
                words = tuple(toks[i:i + step - 1]) + (_strip_particle(toks[i + step - 1]),)
                unit = Unit(" ".join(toks[i:i + step]), (
                    Alternative(words, korean=True),
                    *(Alternative(p) for p in english),
                ))
            else:
                unit = Unit(token, (Alternative((_strip_particle(token),), korean=True),))
        else:
            for phrase, group in _EQ_PHRASES:
                if tuple(toks[i:i + len(phrase)]) == phrase:
                    step = len(phrase)
                    unit = Unit(" ".join(phrase), tuple(Alternative(p) for p in group))
                    break
            if unit is None and token not in STOPWORDS and len(token) > 1:
                unit = Unit(token, (Alternative((token,)),))
        if unit is not None and unit.name not in seen:
            seen.add(unit.name)
            units.append(unit)
        i += step
    return units


def required_units(count: int) -> int:
    """How many distinct query concepts a passage must contain to be shown."""
    return 1 if count <= 1 else max(2, (count + 1) // 2)


def expand_labels(text: str) -> str:
    """Add the other spellings of every known concept found in ``text``."""
    toks = tokens(text)
    extra: list[str] = []
    i = 0
    while i < len(toks):
        for phrase, group in _EQ_PHRASES:
            if tuple(toks[i:i + len(phrase)]) == phrase:
                extra.extend(" ".join(p) for p in group if p != phrase)
                i += len(phrase) - 1
                break
        i += 1
    return " ".join(dict.fromkeys(extra))
