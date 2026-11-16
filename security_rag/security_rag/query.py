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
from typing import Any

_PIECE_RE = re.compile(r"[가-힣]+|[^\W_가-힣]+", re.UNICODE)
_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)
_HANGUL_RUN = re.compile(r"[가-힣]+")

STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does", "for",
    "from", "get", "how", "i", "in", "into", "is", "it", "of", "on", "or", "that",
    "the", "this", "to", "via", "we", "what", "when", "which", "with",
    # Words of a request rather than of its subject. A long question names
    # several of these, and each one used to count against the share of
    # concepts a passage must contain.
    "about", "after", "all", "already", "also", "am", "any", "anything", "been",
    "before", "being", "but", "could", "did", "doing", "done", "each", "else",
    "find", "found", "give", "had", "has", "have", "having", "help",
    "here", "if", "its", "just", "know", "let", "like", "make", "me", "more",
    "my", "need", "needed", "needs", "not", "now", "only", "other",
    "our", "out", "please", "should", "so", "some", "something",
    "still", "such", "tell", "than", "then", "there", "these", "they", "thing",
    "those", "try", "trying", "up", "use", "used", "using", "want", "wants",
    "was", "way", "were", "while", "why", "will", "would", "you", "your",
    "cant", "cannot", "dont", "doesnt", "didnt", "wont", "isnt", "arent", "wasnt",
    "enabled", "present", "available", "allowed", "allow", "both", "either", "instead",
    "possible", "none", "active", "enforced", "word", "words",
    # "got", "where", "next" and "show" stay concepts: GOT overwrite, write
    # what where, the next pointer.
})
KO_STOPWORDS = frozenset({
    "방법", "어떻게", "어떤", "무엇", "뭐", "뭘", "무슨", "어디", "다음", "이제",
    "그리고", "하지만", "근데", "그런데", "그래서", "현재", "지금", "상황", "경우",
    "때", "위해", "위한", "통해", "같은", "같이", "필요", "필요한", "필요해",
    "가능", "가능한", "있는", "있는데", "있음", "있다", "있고", "있어", "있을",
    "있으면", "있어서", "하는", "하고", "하면", "해서", "했는데", "할", "싶어",
    "싶다", "알려줘", "찾아줘", "해줘", "좀", "더", "또", "및", "등", "것", "수",
    "거", "이런", "그런", "그", "이", "저", "내", "나", "제", "우리", "문제", "값",
    "얻은", "얻었는데", "얻고", "얻을", "가진", "가졌는데", "가지고", "보이는",
    "보일", "정도", "후", "전", "중", "때문", "때문에", "안", "못", "왜", "다른",
    "이미", "아직", "먼저", "다시", "일부", "되는데", "되는", "된다", "됨", "돼",
    "해요", "해", "하기", "따기", "만들기", "찾기", "얻기", "보기",
    "돼요", "되요", "됩니다", "안돼", "안돼요", "있어요", "있습니다",
    # Quantifiers and adverbs that sit between a noun and its negation
    # ("카나리 PIE 둘 다 없음").
    "다", "둘", "셋", "전부", "모두", "전혀", "아예", "하나도", "아무것도", "딱히", "각각",
    # State words: "PIE 켜짐" says no more than "PIE".
    "켜짐", "켜져", "켜져있음", "켜진", "걸려", "걸림", "걸려있음", "적용", "적용됨",
    "활성화", "활성화됨", "존재", "성공", "가능함", "얻음", "됐음", "했음",
    # Verbs of use and their forms; the object of "쓸 수 없음" is the noun before.
    "사용", "이용", "활용", "쓸", "쓰는", "쓴", "씀", "써", "써요", "써야", "쓰면",
    "덮을", "덮어", "덮기", "덮음", "따는", "맞음", "안맞음", "모름", "못함", "안됨", "큼", "작음", "같음",
    "됐고", "하나", "할까", "될까", "되나", "인가", "건가", "뭐지", "뭘까",
    "없애", "없앨", "없앤", "없앴", "없애기", "매번", "항상", "계속", "그냥", "너무", "한번", "그대로",
    "바뀜", "바뀌는", "바뀌어서", "바뀌어요",
})
# Endings of a conjugated verb or adjective (막혔어요, 새는데, 키워서). A word
# the vocabulary does not know that ends in one is a predicate of the
# question, not a concept to look for; an English corpus never contains it.
_KO_PREDICATE_TAILS = (
    "었어요", "았어요", "였어요", "겠어요", "었는데", "았는데", "습니다", "합니다",
    "해요", "어요", "아요", "에요", "예요", "니다", "는데", "어서", "아서", "워서",
    "려고", "려면", "면서", "지만", "는지", "었음", "았음", "했음", "였음", "요",
    "어야", "아야", "여야", "해야", "은데", "한데", "할지", "을지", "니까", "으니",
)

# Negation. A concept the asker says they lack ("no canary", "hooks removed",
# "릭 없이") is not one a passage must contain; search uses it to lower cases
# that depend on it instead.
_NEG_BEFORE = frozenset({"no", "without", "non", "lacking"})
_NEG_AFTER = frozenset({
    "removed", "disabled", "unavailable", "missing", "absent", "gone",
    "없이", "없는", "없음", "없고", "없어", "없다", "없는데", "없어서", "없으면", "없을",
    "없어요", "없습니다", "없네요", "없었어요", "off",
    "제거된", "제거됨", "꺼짐", "꺼진", "꺼져", "꺼져있음", "꺼져있어요", "꺼졌어요", "꺼졌음",
    "비활성", "비활성화", "비활성화된",
})
# A filter or sandbox that blocks something ("execve 막힘", "underscore
# blocked") is the opposite case: the answers are about getting around that
# very thing, so the concept stays one to find and only the word is dropped.
_BLOCKED = frozenset({
    "blocked", "blocks", "blocking", "filtered", "filters", "forbidden", "banned",
    "disallowed", "killed",
    "막힘", "막힌", "막혀", "막혀서", "막혀있음", "막혔음", "막혔는데", "막혔다",
    "금지", "금지된", "금지됨", "불가", "불가능", "차단", "차단된", "차단됨",
})
_KO_NEG_SUFFIXES = ("없었어요", "없습니다", "없어요", "없는데", "없이", "없는", "없음", "없고", "없어", "없다")
# Korean negators and blocked forms are recognized by stem, so every
# inflection counts (없었음, 제거되었어요, 꺼져서, 차단되어, 금지라서).
_KO_NEG_STEMS = ("없", "제거되", "제거됐", "제거돼", "제거된", "제거됨", "삭제되", "삭제됐", "삭제돼", "삭제된", "삭제됨",
                 "빠져", "빠짐", "빠진", "비활성", "미적용", "꺼져", "꺼졌", "꺼짐", "꺼진")
# 삭제/제거 as a verb ("삭제 후 출력", "제거해야") is an action, not a lack;
# bare 삭제/제거 counts only when nothing verbal follows it.
_KO_NOT_NEG = ("빠져나", "없애", "없앨", "없앤", "없앴")
_KO_BLOCKED_STEMS = ("막혀", "막혔", "막힘", "막힌", "금지", "차단", "필터링", "불가")
# Korean "can't use / not usable" after a noun reads as that noun lacking.
_KO_NEGATION_REWRITES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), replacement) for pattern, replacement in (
        (r"(?:못|안)\s*(?:써요|써|씀|쓴다|쓰고|씁니다|사용)", " 없음 "),
        (r"사용\s*(?:불가능|불가|못함|안됨|못\s*함)", " 없음 "),
        (r"쓸\s*수\s*(?=없)", " "),
    )
)
# English negations of a verb, rewritten to the forms the parser reads;
# specific forms first, the generic "n't" last.
_NEGATION_REWRITES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), replacement) for pattern, replacement in (
        (r"\bw/o\b", " without "),
        # "can't leak the canary" lacks a canary leak, not a canary.
        (r"\b(?:cannot|can't|can\s+not|unable\s+to)\s+leak\b(?:\s+(?:the|a|an|any)\b)?(?:\s+([a-z0-9_.]+(?:\s+base)?)\b)?",
         r" without \1 leak "),
        (r"\b(?:cannot|can't|can\s+not|unable\s+to)\s+(?:get|obtain|find|use)\b", " without "),
        (r"\b(?:do|does|did)\s+not\s+(?:have|has|get|got|use|contain|enable)\b", " without "),
        (r"\b(?:don|doesn|didn)'?t\s+(?:have|has|get|got|use|contain|enable)\b", " without "),
        (r"\bha(?:ve|s)(?:n'?t|\s+not)\s+(?:got\s+)?", " without "),
        (r"\black(?:s|ing)?\s+of\b", " without "),
        (r"\b(?:neither|nor)\b", " no "),
        (r"\bno\s+longer\s+(?:exists?|available|works?|present|usable|there)\b", " removed "),
        # A filter that refuses something is "blocked", not "lacked".
        (r"\b(?:is|are|was|were)\s*(?:n't|\s+not)\s+allowed\b", " blocked "),
        (r"\bnot\s+allowed\b", " blocked "),
        (r"\bdisabled\s+by\s+(?=(?:the\s+|a\s+)?(?:seccomp|filter|waf|sandbox|policy|blacklist|denylist))", " blocked by "),
        (r"\b(?:no|without)\s+([a-z_]+(?:\s+[a-z_]+)?)\s+allowed\b", r" \1 blocked "),
        (r"\b(?:no|without)\s+((?:single\s+|double\s+|square\s+)?(?:spaces?|quotes?|slash(?:es)?|backslash(?:es)?|"
         r"parenthes[ie]s|brackets?|braces?|underscores?|dots?|periods?|letters?|digits?|numbers?|alphanumerics?|"
         r"keywords?|semicolons?|backticks?|pipes?|null\s+bytes?|newlines?|whitespace|commas?|colons?))\b", r" \1 blocked "),
        (r"\b(?:no|without)\s+([a-z0-9 _-]{1,30}?)\s+(?:because\s+of|due\s+to)\b(?=[^,.;]*\b(?:check|checks|filter|"
         r"filters|seccomp|waf|policy|sanitiz\w*|blacklist|denylist|whitelist|allowlist|validation)\b)",
         r" \1 blocked because "),
        (r"\b(?:is|are|was|were)\s+(?:impossible|not\s+possible)\b", " removed "),
        (r"\bno\s+longer\s+possible\b", " removed "),
        (r"\b(?:is|are|was|were)\s*(?:n't|\s+not)\s+(?:enabled|present|available|on)\b", " disabled "),
        (r"\bnot\s+(?:enabled|present|available)\b", " disabled "),
        (r"\bcan't\b", " cannot "),
        (r"\bwon't\b", " will not "),
        (r"n't\b", " not"),
    )
)
# Nouns that take a modifier: in "free hook removed" or "no libc leak" the
# negation covers the modifier as well. Capabilities are what an exploit
# gains on the way; lacking one ("no libc leak") is a state to get out of, so
# a case that builds it is still an answer. The other heads name the target
# environment (a hook, a mitigation), and a case that relies on one the
# asker lacks does not apply.
CAPABILITY_HEADS = frozenset({
    "leak", "leaks", "address", "addresses", "base", "pointer", "pointers",
    "primitive", "write", "read", "access", "control", "overflow", "bypass",
    "check", "checks",
})
# Protections. A case that faced one the asker lacks still applies (it
# solved a harder version), so a lacked protection only raises cases that
# also went without it; it never lowers one.
PROTECTION_HEADS = frozenset({
    "protection", "canary", "canaries", "pie", "relro", "nx", "aslr", "seccomp",
    "cet", "shstk", "ibt", "smep", "smap", "kaslr", "kpti", "pac", "mte", "cfi", "fortify",
})
# Targets: things an exploit uses that may simply not exist (a hook, a
# gadget); a case that relies on one the asker lacks does not apply.
_HEADS = CAPABILITY_HEADS | PROTECTION_HEADS | frozenset({"hook", "hooks", "gadget", "gadgets"})
# Commas do not end a clause: they stay as markers, so "canary, PIE and NX
# disabled" is one list while a negation still stops at them.
_CLAUSE_RE = re.compile(r"[.;:!?()\[\]{}\n]+")
# Words that end one statement and start another ("have X but Y missing",
# "X는 있고 Y는 없음"): a negation never reaches across them.
_BOUNDARY_WORDS = frozenset({
    "but", "however", "though", "although", "yet", "whereas", "except", "so",
    "because", "since", "하지만", "그런데", "근데", "그래서", "그러나",
    # "NX enabled, canary disabled": a state word closes what it describes.
    "enabled", "on", "present", "active", "enforced", "found",
    # A note-style statement ends at its state word: "libc 릭 있음 힙 릭 없음".
    "있음", "있어요", "있습니다", "됨", "됐음", "얻음", "켜짐", "켜져있음", "성공", "가능", "가능함",
    "했음", "걸려있음", "적용됨",
})
_KO_BOUNDARY_TAILS = ("는데", "지만", "인데", "있고", "없고", "었고", "았고", "되고", "했고", "니까",
                      "됐고", "한데", "은데", "켜져있고")
# Korean endings that join two nouns in a list ("카나리랑 PIE", "카나리도 PIE도").
_KO_COORDINATORS = ("이랑", "랑", "와", "과", "하고", "이나", "나", "도")
_COMMA = "\x00,"

# Spellings of one concept. Matching is on whole tokens, in order.
# These groups also expand the stored case labels (``expand_labels``), so a
# change to them changes what gets indexed: bump INDEXER_VERSION and rebuild.
_LABEL_EQUIVALENTS: tuple[tuple[str, ...], ...] = (
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
# Groups read only from questions; stored labels are not expanded with them.
_QUERY_EQUIVALENTS: tuple[tuple[str, ...], ...] = (
    ("off by one",),
    ("high bits", "top half", "upper bits", "msb", "most significant bits"),
    ("double free",),
    ("safe linking",),
    ("one gadget", "onegadget"),
    ("read only", "readonly"),
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
    # Exploitation terms a Korean question uses where the corpus is English.
    # Every English spelling below has passages in the index.
    ("레이스", ("race",)),
    ("경쟁 조건", ("race condition",)),
    ("난수 상태", ("prng state", "rng state", "random state", "mt19937")),
    ("메르센 트위스터", ("mersenne twister", "mt19937")),
    ("난수", ("random", "prng", "rng")),
    ("시드", ("seed",)),
    ("템플릿 인젝션", ("template injection", "ssti")),
    ("템플릿", ("template",)),
    ("임의 파일 읽기", ("arbitrary file read", "file read", "lfi")),
    ("임의 파일 쓰기", ("arbitrary file write", "file write")),
    ("파일 읽기", ("file read",)),
    ("파일 쓰기", ("file write",)),
    ("파일 업로드", ("file upload", "upload")),
    ("업로드", ("upload",)),
    ("파일", ("file",)),
    ("읽기", ("read",)),
    ("쓰기", ("write",)),
    ("부분 덮어쓰기", ("partial overwrite",)),
    ("덮어쓰기", ("overwrite",)),
    ("스택 피벗", ("stack pivot",)),
    ("스택 피버팅", ("stack pivot",)),
    ("피벗", ("pivot",)),
    ("카나리", ("canary",)),
    ("캐너리", ("canary",)),
    ("원샷 가젯", ("one gadget",)),
    ("원가젯", ("one gadget",)),
    ("가젯", ("gadget",)),
    ("셸코드", ("shellcode",)),
    ("쉘코드", ("shellcode",)),
    ("시스템 콜", ("syscall",)),
    ("시스콜", ("syscall",)),
    ("널 바이트", ("null byte",)),
    ("오프 바이 원", ("off by one",)),
    ("언솔티드 빈", ("unsorted bin",)),
    ("패스트빈", ("fastbin",)),
    ("티캐시", ("tcache",)),
    ("리턴 주소", ("return address",)),
    ("리턴", ("return", "ret")),
    ("함수 포인터", ("function pointer",)),
    ("포인터", ("pointer",)),
    ("가상 함수 테이블", ("vtable",)),
    ("브이테이블", ("vtable",)),
    ("주소 유출", ("address leak", "leak")),
    ("베이스 주소", ("base address", "base")),
    ("주소", ("address",)),
    ("오프셋", ("offset",)),
    ("청크", ("chunk",)),
    ("할당", ("malloc", "allocation")),
    ("해제", ("free",)),
    ("훅", ("hook",)),
    ("후킹", ("hook",)),
    ("구조체", ("struct",)),
    ("전역 변수", ("global",)),
    ("전역", ("global",)),
    ("배열", ("array",)),
    ("인덱스", ("index",)),
    ("음수", ("negative",)),
    ("부호", ("signed", "sign")),
    ("스택 오버플로우", ("stack overflow", "stack buffer overflow", "bof")),
    ("힙 오버플로우", ("heap overflow",)),
    ("보호 기법", ("mitigation",)),
    ("우회", ("bypass",)),
    ("필터", ("filter",)),
    ("심볼릭 링크", ("symlink",)),
    ("해시 충돌", ("hash collision", "collision")),
    ("길이 확장", ("length extension",)),
    ("패딩 오라클", ("padding oracle",)),
    ("디컴파일", ("decompile",)),
    ("난독화", ("obfuscation", "obfuscated")),
    ("안티 디버깅", ("anti debug", "anti debugging")),
    ("패킹", ("packer", "packing")),
    ("쿠키", ("cookie",)),
    ("세션", ("session",)),
    ("토큰", ("token",)),
    ("웹셸", ("webshell",)),
    ("웹쉘", ("webshell",)),
    ("리다이렉트", ("redirect",)),
    ("캐시 포이즈닝", ("cache poisoning",)),
    ("요청 위조", ("request forgery",)),
    ("크로스 사이트 스크립팅", ("xss",)),
    ("스크립트", ("script",)),
    ("관리자", ("admin",)),
    ("브라우저", ("browser",)),
    ("봇", ("bot",)),
    ("데이터 유출", ("exfiltration", "exfiltrate", "leak")),
    ("데이터", ("data",)),
    ("잔액", ("balance",)),
    ("출금", ("withdraw",)),
    ("중복", ("duplicate", "double")),
    ("검사", ("check",)),
    ("명령 실행", ("command execution",)),
    ("명령어 실행", ("command execution",)),
    ("코드 실행", ("code execution",)),
    ("실행", ("execution", "execute")),
    ("파이썬", ("python",)),
    ("출력", ("output",)),
    ("복구", ("recover", "recovery")),
    ("예측", ("predict", "prediction")),
    ("바이트코드", ("bytecode",)),
    ("가상 머신", ("vm",)),
    ("입력", ("input",)),
    ("역산", ("invert", "inverse", "reverse")),
    ("플래그", ("flag",)),
    ("언더바", ("underscore",)),
    ("언더스코어", ("underscore",)),
    ("대괄호", ("bracket", "brackets")),
    ("블랙리스트", ("blacklist", "denylist")),
    ("화이트리스트", ("whitelist", "allowlist")),
    ("바이너리", ("binary",)),
    ("암호문", ("ciphertext",)),
    ("평문", ("plaintext",)),
    ("복호화", ("decrypt",)),
    ("암호화", ("encrypt",)),
    ("서명", ("signature",)),
    ("타원 곡선", ("elliptic curve",)),
    ("격자", ("lattice",)),
    ("소인수분해", ("factorization", "factor")),
    ("개인키", ("private key",)),
    ("공개키", ("public key",)),
    ("논스", ("nonce",)),
    ("드라이버", ("driver",)),
    ("모듈", ("module",)),
    ("권한", ("privilege", "permission")),
    ("인증", ("auth", "authentication")),
    ("로그인", ("login",)),
    ("비밀번호", ("password",)),
    ("직렬화", ("serialization",)),
    ("정규식", ("regex",)),
    ("정규표현식", ("regex",)),
    ("샌드박스", ("sandbox",)),
    ("시간", ("time",)),
    ("더블 프리", ("double free",)),
    ("쓰기 프리미티브", ("write primitive",)),
    ("프리미티브", ("primitive",)),
    ("베이스", ("base",)),
    ("후크", ("hook",)),
    ("디렉터리 트래버설", ("path traversal", "directory traversal")),
    ("디렉토리 트래버설", ("path traversal", "directory traversal")),
    ("인수분해", ("factorization", "factor")),
    ("상위 비트", ("high bits",)),
    ("하위 비트", ("low bits",)),
    ("기법", ("technique",)),
    ("버그", ("bug",)),
    ("힙 스프레이", ("heap spray", "spray")),
    ("탈출", ("escape",)),
    ("빠져나가기", ("escape",)),
    ("스프레이", ("spray",)),
)
_PARTICLES = ("으로", "에서", "을", "를", "이", "가", "은", "는", "의", "에", "로", "와", "과", "도", "만")
# What may follow a Korean stem in one word: particles, and the endings of
# 하다/되다 verbs built on a noun (우회해서, 실행은, 오염된). Longest first.
_KO_SUFFIXES = tuple(sorted({
    *_PARTICLES, "밖에", "이나", "나", "으로는", "에서는", "에게서", "에게", "까지", "부터", "처럼", "보다",
    "이랑", "이라", "라고", "랑", "하려면", "하는데", "했는데", "하려고", "되는데",
    "해야", "해서", "하는", "하고", "하면", "하기", "했다", "했음", "되는", "되면",
    "되어", "돼서", "할", "한", "함", "된", "됨",
    # The copula on a noun: 오버플로우인데, 버그라서.
    "인데", "인가", "이고", "이며", "이면", "인지", "이라서", "이라면", "입니다", "이에요", "라서",
}, key=lambda s: (-len(s), s)))

_EQUIVALENTS = _LABEL_EQUIVALENTS + _QUERY_EQUIVALENTS


def _phrases(groups: tuple[tuple[str, ...], ...]) -> list[tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]]:
    return sorted(
        ((tuple(phrase.split()), tuple(tuple(p.split()) for p in group)) for group in groups for phrase in group),
        key=lambda item: -len(item[0]),
    )


_EQ_PHRASES = _phrases(_EQUIVALENTS)
_LABEL_PHRASES = _phrases(_LABEL_EQUIVALENTS)
_KO_PHRASES = sorted(
    ((tuple(key.split()), tuple(tuple(v.split()) for v in values)) for key, values in _KOREAN),
    key=lambda item: (-len(item[0]), -len(item[0][-1])),
)
# Multi-word terms are also written without spaces (스택피벗, 원샷가젯); the
# joined form maps to the spaced term.
_KO_JOINED = sorted(
    ((key.replace(" ", ""), tuple(key.split()), tuple(tuple(v.split()) for v in values))
     for key, values in _KOREAN if " " in key),
    key=lambda item: -len(item[0]),
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


_CASE_PARTICLES = ("이", "가", "을", "를", "은", "는", "도", "만")


def _strip_particle(token: str) -> str:
    """A Korean word's stem: one particle or 하다/되다 ending removed.

    A one-syllable noun keeps a case particle only when it is the whole
    word ("수가" -> "수", "키를" -> "키").
    """
    if len(token) == 2 and token[1] in _CASE_PARTICLES:
        return token[0]
    for suffix in _KO_SUFFIXES:
        if token.endswith(suffix) and len(token) - len(suffix) >= 2:
            # A loanword's own last syllable is not a particle (스프레이, 게이트웨이).
            if suffix == "이" and token.endswith(("레이", "웨이", "데이", "케이")):
                continue
            return token[: -len(suffix)]
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


def _korean_match(
    toks: list[str], at: int,
) -> tuple[int, tuple[tuple[str, ...], ...], tuple[str, ...]] | None:
    """Tokens a known Korean term spans, its English spellings, and the term."""
    for key, values in _KO_PHRASES:
        end = at + len(key)
        if end > len(toks) or toks[at:end - 1] != list(key[:-1]):
            continue
        last = toks[end - 1]
        if last == key[-1] or (last.startswith(key[-1]) and last[len(key[-1]):] in _KO_SUFFIXES):
            return len(key), values, key
    word = toks[at]
    for joined, key, values in _KO_JOINED:
        if word == joined or (word.startswith(joined) and word[len(joined):] in _KO_SUFFIXES):
            return 1, values, key
    return None


@dataclass(frozen=True)
class QueryPlan:
    """How a question was read.

    ``units`` are the concepts a passage should contain. ``negated`` holds
    each span the asker said they lack, in query order; its last unit is
    the head noun (``("free", "hook")`` for "free hook removed").
    ``optional`` concepts help ranking but are never required: a question
    naming a blocked thing ("quotes filtered") also fits general filter
    bypasses.
    """
    units: tuple[Unit, ...]
    negated: tuple[tuple[Unit, ...], ...]
    optional: tuple[Unit, ...] = ()


_BEFORE = "before"
_AFTER = "after"
_FILTER_UNIT = Unit("filter", tuple(Alternative((w,)) for w in (
    "filter", "filtered", "blocked", "bypass", "waf", "blacklist", "denylist", "sanitizer",
)))


@dataclass(frozen=True)
class _Item:
    """A unit, a negation marker or a comma, with the token span it came from."""
    kind: str  # "unit", "comma", _BEFORE or _AFTER
    start: int
    end: int
    unit: Unit | None = None
    before: str = ""  # the token written just before this one
    word: str = ""  # the last token as written (with its particle)

    @property
    def marked(self) -> bool:
        """A Korean particle closes the noun phrase (힙 오버플로우로)."""
        if not _is_hangul(self.word) or self.unit is None:
            return False
        return not any(a.korean and a.words and a.words[-1] == self.word for a in self.unit.alternatives)


def _unit_at(toks: list[str], i: int) -> tuple[Unit | None, int]:
    """The concept starting at ``toks[i]`` and how many tokens it spans."""
    token = toks[i]
    if _is_hangul(token):
        found = _korean_match(toks, i)
        if found:
            # Named by the vocabulary term, so 릭은 and 릭이 are one concept.
            step, english, key = found
            return Unit(" ".join(key), (
                Alternative(key, korean=True),
                *(Alternative(p) for p in english),
            )), step
        stem = _strip_particle(token)
        # A particle on a Latin word ("seccomp로") arrives as its own piece.
        if token in _KO_SUFFIXES or token in KO_STOPWORDS or stem in KO_STOPWORDS:
            return None, 1
        if any(token.endswith(t) and len(token) > len(t) for t in _KO_PREDICATE_TAILS):
            return None, 1
        if stem == token and token.endswith(_KO_BOUNDARY_TAILS):
            return None, 1  # a clause-ending predicate (됐고, 가능한데)
        if len(stem) < 2:
            return None, 1  # one syllable the vocabulary does not know
        return Unit(stem, (Alternative((stem,), korean=True),)), 1
    for phrase, group in _EQ_PHRASES:
        if tuple(toks[i:i + len(phrase)]) == phrase:
            return Unit(" ".join(phrase), tuple(Alternative(p) for p in group)), len(phrase)
    if (token == "house" and i + 2 < len(toks) and toks[i + 1] == "of" and toks[i + 2] not in STOPWORDS
            and _WORD_RE.fullmatch(toks[i + 2])):
        # "house of apple2" is one technique; "house of apple 2" is the same one.
        name = toks[i + 2]
        step = 3
        if i + 3 < len(toks) and toks[i + 3].isdigit() and name.isalpha():
            name, step = name + toks[i + 3], 4
        spaced = re.sub(r"(?<=[a-z])(?=\d)", " ", name)
        alts = {("house", "of", name)} | ({("house", "of", *spaced.split())} if spaced != name else set())
        return Unit(f"house of {name}", tuple(Alternative(a) for a in sorted(alts))), step
    if token in STOPWORDS or len(token) <= 1:
        return None, 1
    return Unit(token, (Alternative((token,)),)), 1


def _is_head(unit: Unit) -> bool:
    return any(a.words and a.words[-1] in _HEADS for a in unit.alternatives)


def is_capability(unit: Unit) -> bool:
    """Whether a unit names something an exploit gains, such as a leak."""
    return any(a.words and a.words[-1] in CAPABILITY_HEADS for a in unit.alternatives)


def is_protection(unit: Unit) -> bool:
    """Whether a unit names a protection such as a canary or PIE."""
    return any(a.words and a.words[-1] in PROTECTION_HEADS for a in unit.alternatives)


def _is_env(unit: Unit) -> bool:
    """A head that names the environment (protection or target), not a capability."""
    return _is_head(unit) and not is_capability(unit)


def _kind(unit: Unit) -> str:
    return "protection" if is_protection(unit) else "capability" if is_capability(unit) else "target"


def _ko_marker(token: str) -> str | None:
    """_AFTER for a Korean negation, "blocked" for a blocked form, by stem."""
    if not _is_hangul(token) or token.startswith(_KO_NOT_NEG):
        return None
    if token in _NEG_AFTER or token.startswith(_KO_NEG_STEMS):
        return _AFTER
    if token in _BLOCKED or token.startswith(_KO_BLOCKED_STEMS):
        return "blocked"
    return None


def _split_attached(token: str) -> list[str]:
    """"가젯없어서" -> ["가젯", "없어서"]: a known noun with a negation written on."""
    if not _is_hangul(token) or _korean_match([token], 0):
        return [token]
    for suffix in _KO_NEG_SUFFIXES:
        if token.endswith(suffix) and len(token) > len(suffix):
            return [token[: -len(suffix)], suffix]
    for cut in range(1, len(token)):
        rest = token[cut:]
        if (_ko_marker(rest) or rest.startswith(("안", "못"))) and _korean_match([token[:cut]], 0):
            return [token[:cut], rest]
    return [token]


def _segments(toks: list[str]) -> tuple[list[list[_Item]], bool]:
    """Units, negation markers and commas of one clause, cut at statement boundaries.

    Also says whether a blocked word was seen.
    """
    split: list[str] = []
    for token in toks:
        split.extend(_split_attached(token))
    segments: list[list[_Item]] = [[]]
    blocked = False
    cancel_next = False  # "가젯밖에 없음" means only a gadget, not none
    i = 0
    while i < len(split):
        token = split[i]
        step = 1
        before = split[i - 1] if i else ""
        # A known phrase wins over a negator it starts with ("off by one").
        phrase = next((len(p) for p, _ in _EQ_PHRASES if len(p) > 1 and tuple(split[i:i + len(p)]) == p), 0)
        marker = None if phrase else (_ko_marker(token) or (
            _BEFORE if token in _NEG_BEFORE else _AFTER if token in _NEG_AFTER else
            "blocked" if token in _BLOCKED else None
        ))
        if token in ("제거", "삭제") and not phrase:
            following = split[i + 1] if i + 1 < len(split) else ""
            if not following.startswith(("후", "메뉴", "하", "해", "할", "한", "합", "기능")):
                marker = _AFTER
        if token == "not" and not phrase:
            # "binary is not PIE": "not" negates a protection or target noun.
            j = i + 1
            while j < len(split) and split[j] in STOPWORDS:
                j += 1
            ahead = _unit_at(split, j)[0] if j < len(split) else None
            marker = _BEFORE if ahead is not None and _is_env(ahead) else None
        if token == _COMMA:
            segments[-1].append(_Item("comma", i, i + 1))
        elif marker == _AFTER and cancel_next:
            cancel_next = False
        elif marker in (_BEFORE, _AFTER):
            segments[-1].append(_Item(marker, i, i + 1))
        elif marker == "blocked":
            blocked = True
        elif token not in _BOUNDARY_WORDS and token != "not":
            unit, step = _unit_at(split, i)
            if unit is not None:
                segments[-1].append(_Item("unit", i, i + step, unit, before, split[i + step - 1]))
        last = split[i + step - 1]
        cancel_next = cancel_next or (_is_hangul(last) and last.endswith("밖에"))
        if last in _BOUNDARY_WORDS or (_is_hangul(last) and last.endswith(_KO_BOUNDARY_TAILS)):
            segments.append([])
            cancel_next = False
        i += step
    return [seg for seg in segments if seg], blocked


def _negated_spans(items: list[_Item]) -> list[list[int]]:
    """Positions of the units each negation marker covers, within one segment.

    A leading negator ("no", "without") covers the run of adjacent units
    after it up to its last head noun ("no stack canary", "no libc base
    leak", "no free or malloc hooks"). The run ends after a protection or
    target noun unless a capability follows it ("no PIE leak" lacks a leak of
    PIE; "no PIE stack overflow" lacks PIE), and further protections joined
    by "or" get spans of their own. With nothing after it, a leading negator
    covers the unit before it ("PIE not").

    A trailing negator ("removed", "없이") covers the unit before it and,
    when that is a head noun, the units directly before it, at every place
    the head occurs before it up to a comma ("free hook and malloc hook
    removed"). Protections or targets listed before it get spans of their
    own ("canary, PIE and NX are disabled", "카나리랑 PIE 없음").
    """
    units = [j for j, item in enumerate(items) if item.kind == "unit"]

    def next_unit(j: int) -> int | None:
        return next((k for k in units if k > j), None)

    def prev_unit(j: int, cross_commas: bool = False) -> int | None:
        for k in range(j - 1, -1, -1):
            if items[k].kind == "unit":
                return k
            if items[k].kind == "comma" and not cross_commas:
                return None
        return None

    def modifiers(k: int) -> list[int]:
        """Units written immediately before unit ``k``, nearest last."""
        found: list[int] = []
        cursor = k
        while len(found) < 2:
            before = prev_unit(cursor)
            # A word ending in a particle is a phrase of its own, not a
            # modifier: "힙 오버플로우로 free hook 없이" lacks only the hook.
            # Two protections side by side are a list ("카나리 PIE 없음").
            if (before is None or items[before].end != items[cursor].start or items[before].marked
                    or (_is_env(items[before].unit) and _is_env(items[k].unit))):
                break
            found.insert(0, before)
            cursor = before
        return found

    def listed_before(k: int) -> list[list[int]]:
        """Protections or targets listed right before unit ``k`` and its modifiers."""
        found: list[list[int]] = []
        cursor = (modifiers(k) or [k])[0]
        while True:
            j = cursor - 1
            via_comma = j >= 0 and items[j].kind == "comma"
            if via_comma:
                j -= 1
            if j < 0 or items[j].kind != "unit" or not _is_env(items[j].unit):
                break
            explicit = (
                items[cursor].before in ("and", "or", "및", "&", *_KO_COORDINATORS)
                or items[j].word.endswith(_KO_COORDINATORS)
            )
            implicit = via_comma or items[j].end == items[cursor].start
            if any(items[m].unit.name in ("full", "partial") for m in modifiers(j)):
                break  # "Full RELRO, PIE off": RELRO is stated present
            # "Full RELRO, hooks removed" is not a list: a bare comma or
            # juxtaposition joins only nouns of the same kind.
            if not (explicit or (implicit and _kind(items[j].unit) == _kind(items[cursor].unit))):
                break
            span = modifiers(j) + [j]
            found.append(span)
            cursor = span[0]
        return found

    spans: list[list[int]] = []
    for idx, item in enumerate(items):
        if item.kind == _BEFORE:
            first = next_unit(idx)
            if first is None or any(items[x].kind == "comma" for x in range(idx + 1, first)):
                before = prev_unit(idx)
                if before is not None:
                    spans.append([before])
                continue
            run = [first]
            while len(run) < 4:
                current = items[run[-1]]
                following = next_unit(run[-1])
                if following is None or following != run[-1] + 1:
                    break
                gap = items[following].start - current.end
                # "no free or malloc hooks": only an "or" may sit inside the run.
                if gap > 1 or (gap == 1 and items[following].before != "or") or current.marked:
                    break
                if _is_env(current.unit) and not is_capability(items[following].unit):
                    break
                run.append(following)
            heads = [n for n, k in enumerate(run) if _is_head(items[k].unit)]
            span = run[: heads[-1] + 1] if heads else run
            spans.append(span)
            # "no canary or PIE": a protection joined by "or" is lacked too.
            cursor = span[-1]
            while True:
                following = next_unit(cursor)
                if (following is None or following != cursor + 1 or items[following].before != "or"
                        or items[following].start - items[cursor].end != 1
                        or not _is_env(items[following].unit) or not _is_env(items[cursor].unit)):
                    break
                spans.append([following])
                cursor = following
        elif item.kind == _AFTER:
            last = prev_unit(idx)
            if last is None:
                continue
            head = items[last].unit
            if not _is_head(head):
                spans.append(modifiers(last) + [last])
            else:
                for k in range(last, -1, -1):
                    if items[k].kind == "comma":
                        break
                    if items[k].kind == "unit" and items[k].unit.name == head.name:
                        spans.append(modifiers(k) + [k])
            if _is_env(head):
                spans.extend(listed_before(last))
    return spans


def analyze_query(query: str, *, max_units: int = 12) -> QueryPlan:
    """Split a question into concepts to find and concepts the asker lacks.

    A unit counts as lacked only when every mention of it is negated; "libc
    leak but no heap leak" still looks for ``leak``.
    """
    text = unicodedata.normalize("NFKC", str(query or "")).replace("’", "'")
    for pattern, replacement in _NEGATION_REWRITES + _KO_NEGATION_REWRITES:
        text = pattern.sub(replacement, text)
    positive: dict[str, Unit] = {}
    lacked: dict[tuple[str, ...], tuple[Unit, ...]] = {}
    any_blocked = False
    budget = 60
    for clause in _CLAUSE_RE.split(text):
        toks: list[str] = []
        for n, part in enumerate(clause.split(",")):
            piece = tokens(part)[: max(0, budget - len(toks))]
            if n and toks and piece:
                toks.append(_COMMA)
            toks.extend(piece)
        budget -= len([t for t in toks if t != _COMMA])
        segments, blocked = _segments(toks)
        any_blocked = any_blocked or blocked
        for items in segments:
            spans = _negated_spans(items)
            covered = {j for span in spans for j in span}
            for j, item in enumerate(items):
                if item.kind == "unit" and j not in covered:
                    positive.setdefault(item.unit.name, item.unit)
            for span in spans:
                units = tuple(items[j].unit for j in span)
                lacked.setdefault(tuple(u.name for u in units), units)
        if budget <= 0:
            break
    units = tuple(list(positive.values())[:max_units])
    optional = (_FILTER_UNIT,) if any_blocked and _FILTER_UNIT.name not in positive else ()
    return QueryPlan(units, tuple(lacked.values()), optional)


def parse_query(query: str, *, max_units: int = 12) -> list[Unit]:
    """The concepts a passage should contain; negated ones are left out."""
    return list(analyze_query(query, max_units=max_units).units)


def required_units(count: int) -> int:
    """How many distinct query concepts a passage must contain to be shown.

    Half the concepts, at least two, and at most four: one passage of a
    relevant case seldom repeats five or six words of a long question.
    """
    return 1 if count <= 1 else min(4, max(2, (count + 1) // 2))


def expand_labels(text: str) -> str:
    """Add the other spellings of every known concept found in ``text``.

    Uses the index-time groups only, so stored labels stay what
    INDEXER_VERSION promises.
    """
    toks = tokens(text)
    extra: list[str] = []
    i = 0
    while i < len(toks):
        for phrase, group in _LABEL_PHRASES:
            if tuple(toks[i:i + len(phrase)]) == phrase:
                extra.extend(" ".join(p) for p in group if p != phrase)
                i += len(phrase) - 1
                break
        i += 1
    return " ".join(dict.fromkeys(extra))
