#!/usr/bin/env python3
"""A chal that ships a kernel is not a glibc heap chal.

WHAT WENT WRONG, measured on job 24225668a27d (a kernel-pwn lineage):

    chal/src/mod.c         kzalloc(...) / kfree(slots[i])   <- shipped kernel module
    _HEAP_SOURCE_KEYWORDS  ... "free(" ...
    run.log                [autoboot] heap_advanced=True via WORK-TREE signal

`"free(" in "kfree(slots[i])"` is True, so a kernel-pwn challenge was routed
into the glibc heap regime.  `kmalloc` contains `malloc` the same way.

That routing is not cosmetic.  Every `heap_advanced` branch is glibc-only:

  * analyzer.py  pre-recon extras demand a custom allocator's header
    layout and a `__free_hook` cross-check against libc_profile.json
  * analyzer.py  _HEAP_MANDATORY_SECTIONS gates the reply on INT-OVERFLOW
    ANALYSIS / HEAP STATE MATRIX / ENV-AWARE PATHS / RCE TARGET TABLE, and
    RESPAWNS the recon when one is missing — a spawn this repo prices at
    2-6 min
  * prompts.py   announces "HEAP / FSOP CHALLENGE DETECTED" and points at the
    FSOP cheat-sheet
  * prompts.py   the START block orders `ghiant ./bin/<binary>`, on a bundle
    whose own autoboot line reads "contained no ELF"

The observed recon paid the cheap half in full: HEAP STATE MATRIX came back as
six rows of "?", and HOOKS_ALIVE / ALLOC-FREE SIG / INT-OVERFLOW ANALYSIS /
RECOMMENDED CHAIN as "N/A - 커널 challenge".  The expensive half is the
respawn ladder, armed by the same misclassification, waiting on a recon that
omits a glibc-only section instead of writing N/A into it.

WHAT THIS SUITE PINS
  * keyword hits anchor on the LEFT edge, so a longer allocator name is not
    read as the shorter one it ends with
  * a kernel image or a loadable module in the work tree VETOES the glibc
    regime, whatever the keywords and the description say
  * the veto is LOGGED — the misroute survived because nothing said it
    happened
  * the veto does not fire on an actual glibc heap chal

The functions are extracted from the shipped analyzer and executed, rather
than imported, because modules/pwn/analyzer.py pulls in modules/_runner.py ->
`import docker`, which is not installed where this suite runs.  Extraction is
also what makes --mutate possible.

Run from the repository root::

    python3 scripts/test_kernel_not_glibc_heap.py
    python3 scripts/test_kernel_not_glibc_heap.py --mutate no-kernel-veto
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ANALYZER = ROOT / "modules" / "pwn" / "analyzer.py"
ANALYZER_SRC = ANALYZER.read_text()

MUTATIONS = ("no-kernel-veto", "unanchored-keywords", "silent-veto",
             "kernel-veto-ignores-modules", "points-at-deleted-archive")
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()


def _replace_once(source: str, old: str, new: str) -> str:
    n = source.count(old)
    if n != 1:
        raise RuntimeError(f"mutation anchor count={n}, expected 1: {old!r}")
    return source.replace(old, new, 1)


def _mutated(src: str) -> str:
    if args.mutate == "no-kernel-veto":
        # Ship the classification as it was when the kernel chal was routed
        # into the glibc regime.
        src = _replace_once(
            src,
            "    heap_kw = (desc_match or work_match) and not kernel_shape",
            "    heap_kw = desc_match or work_match",
        )
    elif args.mutate == "unanchored-keywords":
        # Restore the bare `in` test that read "kfree(" as "free(".
        src = _replace_once(
            src,
            "        if i == 0 or not _IDENT_CHAR.match(text_low[i - 1]):\n"
            "            return True",
            "        return True",
        )
    elif args.mutate == "silent-veto":
        src = _replace_once(src, '[autoboot] heap_advanced VETOED', '')
    elif args.mutate == "points-at-deleted-archive":
        # Restore the fallback that named the archive autoboot had already
        # removed, so the agent is sent hunting a file that does not exist.
        src = _replace_once(
            src,
            "    if effective_binary_name and not (\n"
            "        work_dir / \"bin\" / effective_binary_name\n"
            "    ).is_file():",
            "    if False:")
    elif args.mutate == "kernel-veto-ignores-modules":
        # A .ko is often the ONLY kernel artifact beside a rootfs the chal
        # never unpacks; dropping it is how a veto looks correct and misses.
        src = _replace_once(
            src,
            '                if name.endswith(".ko"):\n'
            '                    return True\n',
            "",
        )
    return src


SRC = _mutated(ANALYZER_SRC)

# ---- extract just what we need, so the import chain never runs -------------
WANT_FUNCS = {"_keyword_hit", "_kernel_challenge_present",
              "_heap_signals_present", "_build_pre_recon_prompt"}
WANT_ASSIGN = {
    "_HEAP_SOURCE_KEYWORDS", "_HEAP_STRONG_KEYWORDS", "_HEAP_BUG_KEYWORDS",
    "_KERNEL_IMAGE_NAMES", "_IDENT_CHAR",
}

tree = ast.parse(SRC)
pieces: list[str] = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in WANT_FUNCS:
        pieces.append(ast.get_source_segment(SRC, node))
    elif isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in WANT_ASSIGN:
                pieces.append(ast.get_source_segment(SRC, node))

missing = WANT_FUNCS - {n.split("(")[0].removeprefix("def ").strip()
                        for p in pieces for n in p.splitlines()[:1]}
NS = types.ModuleType("_kernel_heap_ns")
from modules.pwn.prompts import kernel_launcher_available
NS.__dict__.update({
    "re": re,
    "Path": Path,
    "kernel_launcher_available": kernel_launcher_available,
})
exec(compile("\n\n".join(pieces), str(ANALYZER), "exec"), NS.__dict__)

PASSED = FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


# --------------------------------------------------------------- anchoring

def _anchor_checks() -> None:
    hit = NS._keyword_hit
    # THE bug: the kernel's allocator names end with the glibc ones.
    check("K1 kfree( is not a hit on free(", hit("kfree(slots[i]);", "free("),
          False)
    check("K1 kmalloc is not a hit on malloc", hit("p = kmalloc(0x40);",
                                                   "malloc"), False)
    for name in ("vfree(", "kvfree(", "__kfree("):
        check(f"K1 ...nor is {name}", hit(f"x = {name}p);", "free("), False)
    # ...and the real thing still matches, or the veto is a mute button.
    check("K2 a genuine free( still hits", hit("free(p);", "free("), True)
    check("K2 a genuine malloc still hits", hit("p = malloc(8);", "malloc"),
          True)
    check("K2 ...at the very start of a file too", hit("free(p);", "free("),
          True)
    check("K2 ...and after a non-identifier char", hit("if (!free(p))",
                                                       "free("), True)


# ------------------------------------------------------------ kernel shape

def _tree(tmp: Path, files: dict[str, str]) -> Path:
    work = tmp / "work"
    for rel, body in files.items():
        f = work / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    work.mkdir(parents=True, exist_ok=True)
    return work


def _shape_checks() -> None:
    kern = NS._kernel_challenge_present
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        # The measured job's shape.
        w = _tree(base / "a", {
            "chal/bzImage": "\x7fELF-ish",
            "chal/rootfs.cpio": "cpio",
            "chal/src/mod.c": "p = kzalloc(0x40); kfree(slots[i]);",
        })
        check("S1 a bundle shipping bzImage is a kernel chal", kern(w), True)

        # A module with no image beside it: the rootfs is often never unpacked.
        w2 = _tree(base / "b", {"chal/vuln.ko": "elf", "chal/run.sh": "qemu"})
        check("S1 ...and so is one shipping only a .ko", kern(w2), True)

        for nm in ("vmlinux", "vmlinuz-6.1", "Image.gz"):
            w3 = _tree(base / ("c" + nm), {f"chal/{nm}": "k"})
            check(f"S1 ...and one shipping {nm}", kern(w3), True)

        arm = _tree(base / "arm", {
            "chal/Image": "arm64 kernel",
            "chal/run.sh":
                "qemu-system-aarch64 -machine virt -kernel ./Image\n",
        })
        check("S1 ...and an architecture-neutral QEMU launcher", kern(arm), True)

        # A real glibc heap chal must NOT be vetoed, or the fix has simply
        # turned the heap regime off.
        w4 = _tree(base / "d", {
            "chal/Dockerfile": "FROM ubuntu:24.04",
            "chal/src/note.c": "char *p = malloc(0x80); free(p);",
        })
        check("S2 a userspace glibc chal is NOT a kernel chal", kern(w4), False)

        # An empty tree claims nothing.
        w5 = _tree(base / "e", {})
        check("S2 ...and an empty work tree claims nothing", kern(w5), False)


# ------------------------------------------------ the two together, and the log

def _composition_checks() -> None:
    sig = NS._heap_signals_present
    kern = NS._kernel_challenge_present
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        # The kernel chal: after anchoring, its source no longer even LOOKS
        # like a heap chal — belt. The veto is braces.
        w = _tree(base / "a", {
            "chal/bzImage": "k",
            "chal/src/mod.c":
                "static void *slots[16];\n"
                "slots[i] = kzalloc(0x40, GFP_KERNEL);\n"
                "kfree(slots[i]);\n",
        })
        check("C1 the kernel chal's source no longer trips the keyword scan",
              sig(w, []), False)
        check("C1 ...and the shape veto would catch it even if it did",
              kern(w), True)

        # The glibc chal keeps firing, through both paths.
        w2 = _tree(base / "b", {
            "chal/src/note.c": "p = malloc(0x80); free(p); // tcache\n"})
        check("C2 a glibc heap chal still fires the keyword scan",
              sig(w2, []), True)
        check("C2 ...and is not vetoed", kern(w2), False)

        # Inventory is not exploitability: a dependency name or routine STL
        # use plus an unrelated stack-overflow label must not activate the
        # glibc heap/FSOP handbook.
        w3 = _tree(base / "c", {})
        check("C2 allocator-looking custom-lib name alone is not a heap signal",
              sig(w3, ["liballocator.so"]), False)
        w4 = _tree(base / "d", {
            "chal/src/main.cc":
                "std::string name; std::vector<int> ids; void stack_overflow();\n"
        })
        check("C2 routine STL plus generic stack-overflow naming is not enough",
              sig(w4, []), False)

    # The classification site must actually compose the two. A veto that
    # exists and is never consulted is the bug with extra code.
    check("C3 the veto is wired into heap_kw",
          "heap_kw = (desc_match or work_match) and not kernel_shape" in SRC,
          True)
    # A description saying "heap" must not override the shape. This is why
    # the veto sits on heap_kw and not inside _heap_signals_present.
    check("C3 ...and it outranks the description, not just the work tree",
          bool(re.search(r"heap_kw = \(desc_match or work_match\) and not",
                         SRC)), True)

    # S8-style: a reclassification nobody can see is how this survived.
    check("C4 the veto announces itself in the job log",
          "[autoboot] heap_advanced VETOED" in SRC, True)
    check("C4 ...and the summary records which branch decided",
          '"kernel-veto"' in SRC, True)


# ---------------------------------------- the bundle that carries no ELF

def _binaryless_checks() -> None:
    """A name that resolves to nothing must not be handed to the agent.

    autoboot unpacks the bundle and then DELETES it ("removed bundle
    <uuid>.zip from ./bin/"). With no ELF inside, effective_binary_name fell
    back to that archive's filename, and the prompt told the agent to
    `ghiant ./bin/<uuid>.zip`. Three consecutive kernel jobs opened by
    answering "지정 경로에 해당 ZIP이 없습니다" and then searching the tree
    for it (24225668a27d, 7b8bd665f130, 20a2b843e843).
    """
    build = getattr(NS, "_build_pre_recon_prompt", None)
    check("B0 the pre-recon prompt builder is reachable", build is not None, True)
    if build is None:
        return
    # The binary-less shape: no name, but an unpacked tree to read.
    out = build(binary_name=None, target="h:1", heap_advanced=False,
                chal_unpacked=True)
    check("B1 no './bin/None' reaches the agent", "./bin/None" in out, False)
    check("B1 ...and no ghiant on a binary that does not exist",
          "ghiant" in out, False)
    check("B2 it names the tree that IS there instead",
          "./chal/" in out and "NO STANDALONE BINARY" in out, True)
    check("B3 ...and says the archive was removed, so nobody hunts it",
          "removed it" in out, True)
    # A real binary keeps the behaviour it always had.
    out2 = build(binary_name="prob", target=None, heap_advanced=False,
                 chal_unpacked=True)
    check("B4 a real binary is still named and still decompiled",
          "./bin/prob" in out2 and "ghiant ./bin/prob" in out2, True)

    # The drop must be WIRED, and pre-recon must still run without a binary —
    # the kernel case is exactly where its triage is worth most.
    check("B5 the analyzer drops a name that is not a file in ./bin/",
          'work_dir / "bin" / effective_binary_name' in SRC
          and "effective_binary_name = None" in SRC, True)
    check("B6 pre-recon still spawns for a binary-less unpacked chal",
          "if (effective_binary_name or chal_unpacked) and not resume_sid:"
          in SRC, True)
    check("B7 the drop is logged, not silent",
          "is not in ./bin/" in SRC, True)


def main() -> int:
    _anchor_checks()
    _shape_checks()
    _composition_checks()
    _binaryless_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
