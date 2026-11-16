"""Exact-build libc decision contracts rendered into Pwn pre-recon prompts.

This module intentionally contains no nearest-version exploit recipe table.
Allocator internals, FILE layouts, hook invocation and usable triggers can vary
across vendor builds even when the major.minor label matches. The renderer
therefore supplies verification requirements rather than inherited offsets or
named-house prescriptions.
"""

from __future__ import annotations


def render_fsop_leak_table(libc_version: str | None) -> str:
    """Render an exact-build FSOP-leak verification contract."""
    if not libc_version:
        return ""
    return (
        f"FSOP-AS-LEAK TABLE — VERIFY ON EXACT BUILD (detected label "
        f"{libc_version}). `_IONBF` alone neither proves nor refutes a FILE "
        f"leak. Before proposing one, record: exact libc/build ID; the "
        f"attacker write range; observed source/destination relation; FILE "
        f"layout and required flag/guard predicates from matched source or "
        f"debug symbols; the next reachable output call; and a gdb/runtime "
        f"observation of leaked bytes. Do not import a fixed flag magic, "
        f"main_arena offset, struct size or trigger from another build."
    )


def render_rce_table(libc_version: str | None) -> str:
    """Render an exact-build end-of-chain decision contract."""
    if not libc_version:
        return ""
    return (
        f"RCE TARGET TABLE — BUILD-SPECIFIC ROUTING (detected label "
        f"{libc_version}). First write the actual flag/win target; direct AAR, "
        f"ORW or a logic path may be terminal without RCE. For any libc target, "
        f"verify on the exact build: symbol presence and invocation, allocator/"
        f"FILE guards and layouts, pointer mangling, seccomp/calling constraints, "
        f"reachable trigger and required write/read primitive. Use profile and "
        f"how2heap entries only as candidates. Do not inherit a technique or "
        f"numeric offset from the nearest lower major.minor release."
    )
