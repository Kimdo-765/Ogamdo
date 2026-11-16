#!/usr/bin/env python3
"""`reap_chal_images` reclaims a job's challenge image tags — and only those.

Why this exists: containers were never the leak (end-of-job reaping is
demonstrably complete), images were. Measured 2026-09-09 on job a2f6b23bad64:
13 `chal_<id>*` tags for ONE job, of which the pre-existing path
(`_chalbox.remove_image`, pwn only) reclaimed exactly one, and 134 `chal_*`
images box-wide belonging to jobs that had finished days earlier.

The two properties that must never regress:

  * a short/empty job id must NOT expand the glob to `chal_*` and reap the
    whole box;
  * deletion goes by `repository:tag`, never by image ID — identically-built
    images share an ID and `rmi -f <id>` would untag a sibling job's image.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMMON = ROOT / "modules" / "_common.py"
MODULES = {
    "web": "modules/web/analyzer.py",
    "pwn": "modules/pwn/analyzer.py",
    "web3": "modules/web3/analyzer.py",
    "rev": "modules/rev/analyzer.py",
    "misc": "modules/misc/orchestrator.py",
    "forensic": "modules/forensic/orchestrator.py",
}

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


def _func_src(src: str, name: str) -> str:
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


def run() -> None:
    common = _read("modules/_common.py")
    fn = _func_src(common, "reap_chal_images")

    # A — the function exists and is job-scoped
    check("A1 reap_chal_images exists", bool(fn))
    check("A2 globs on the job id", "reference=chal_{ident}*" in fn or
          'reference=chal_' in fn and "ident" in fn)

    # B — the short-id guard. Without it an empty id makes the glob `chal_*`.
    check("B1 sanitises the id", "re.sub(" in fn and "ident" in fn)
    guard = re.search(r"len\(ident\)\s*<\s*(\d+)", fn)
    check("B2 refuses a short id", bool(guard))
    if guard:
        check("B3 threshold >= 8", int(guard.group(1)) >= 8,
              f"threshold={guard.group(1)}")
        # the guard must RETURN, not merely log
        after = fn[guard.end():guard.end() + 120]
        check("B4 short id returns early", "return 0" in after)

    # C — deletes by tag, never by image ID
    check("C1 asks docker for repository:tag",
          "{{.Repository}}:{{.Tag}}" in fn)
    check("C2 never lists image ids for removal",
          not re.search(r'"images",\s*"-q"', fn),
          "`images -q` would hand rmi an ID shared with a sibling job")
    check("C3 skips dangling <none> tags", "<none>" in fn)
    # The repository:tag format string appears twice (the initial listing and
    # the post-rmi recount). Asserting only its PRESENCE lets a mutation swap
    # one of them for `{{.ID}}` unnoticed, so forbid the ID format outright.
    check("C4 never formats an image ID", "{{.ID}}" not in fn,
          "an ID is shared by identically-built images across jobs")

    # D — teardown must never break a job, and must not prune the build cache
    check("D1 swallows exceptions", "except Exception" in fn)
    check("D2 does not prune the builder cache",
          "builder" not in fn.replace("builder cache", "") or
          '"prune"' not in fn)

    # E — every module reclaims images at job END
    for mod, rel in MODULES.items():
        src = _read(rel)
        check(f"E1[{mod}] imports reap_chal_images",
              "reap_chal_images," in src)
        calls = re.findall(r"reap_chal_images\(", src)
        check(f"E2[{mod}] calls it", len(calls) >= 1)
        check(f"E3[{mod}] only at job end",
              "startup sweep" not in src.split("reap_chal_images")[-1][:200],
              "image reclamation must not run on the startup sweep")

    # F — the container reaper is untouched (containers are NOT the leak)
    creap = _func_src(common, "reap_chal_containers")
    check("F1 container reaper still exists", bool(creap))
    check("F2 container reaper still ignores images",
          '"rmi"' not in creap,
          "image removal belongs in reap_chal_images, not here")


_SOURCE_MUTATIONS = [
    ("modules/_common.py", "len(ident) < 8", "len(ident) < 0",
     "short-id guard disabled"),
    ("modules/_common.py", "{{.Repository}}:{{.Tag}}", "{{.ID}}",
     "deletes by image ID"),
    ("modules/_common.py", 'if len(ident) < 8:\n        return 0',
     'if len(ident) < 8:\n        pass', "guard no longer returns"),
    ("modules/web/analyzer.py", "    reap_chal_images,\n", "",
     "web drops the import"),
    ("modules/rev/analyzer.py", "reap_chal_images(", "reap_chal_containers(",
     "rev never reclaims images"),
]


def sweep() -> int:
    global failures, checks
    print("=== 변이 스윕 ===")
    missed = 0
    for rel, old, new, label in _SOURCE_MUTATIONS:
        src = (ROOT / rel).read_text()
        if src.count(old) < 1:
            print(f"  STALE  {label} — 앵커 없음: {old[:40]!r}")
            missed += 1
            continue
        _MUTATED[rel] = src.replace(old, new, 1)
        if _MUTATED[rel] == src:
            print(f"  STALE  {label} — 변이가 아무것도 바꾸지 않음")
            missed += 1
            _MUTATED.clear()
            continue
        failures, checks = [], 0
        run()
        if failures:
            print(f"  검출   {label}")
        else:
            print(f"  MISSED {label}")
            missed += 1
        _MUTATED.clear()
    return missed


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        m = sweep()
        print("MISSED 없음" if not m else f"MISSED {m}건")
        raise SystemExit(1 if m else 0)
    run()
    for f in failures:
        print("FAIL", f)
    print(f"{checks} checks, {len(failures)} failed")
    raise SystemExit(1 if failures else 0)
