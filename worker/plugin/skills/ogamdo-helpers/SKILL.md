---
name: ogamdo-helpers
description: The platform helpers that already exist - browser, solver smoke-run, heap probe, libc staging, Ghidra, targeted stego re-carve, Sage timing. Read this before writing your own driver or harness for any of those.
---

# Helpers that already exist

Every one of these is reachable as `python3 -m worker.<name>` from your shell.
They exist because a job wrote the same thing from scratch first. Check here
before building a driver, a harness, or a wrapper.

## `worker.browser` - a real browser

    python3 -m worker.browser render <url> --out p.html [--wait 12] [--shot s.png]
    python3 -m worker.browser eval   <url> --js "document.title"
    python3 -m worker.browser click  <url> --selector "#go" --out after.html
    python3 -m worker.browser upload <url> --selector "input[type=file]" --file a.png

Headful chromium under Xvfb over CDP. Use it whenever the DOM is not the HTTP
response: an SPA, client-side crypto, a payload that only runs after script.
`click` is a real mouse press, not `element.click()`. A JS exception comes
back as `JS_ERROR:`, not a silent empty value. Every run prints `FINAL_URL:` -
read it first, a redirect explains most "the page was empty" confusion.

Job ba2725c84be2 wrote three CDP drivers before it could look at one page.
Do not write a fourth.

`--stealth` hides automation markers. Off by default, and REFUSED in code
against anything that is not this job's declared target or a private address
— job 117c98fac9b8 turned it on against google.com when the flag was only
documented. You will see `STEALTH_REFUSED: <reason>` and the page still
renders without it.

It is also usually the wrong instinct. If the page does not need JavaScript,
`curl` is both simpler and less likely to be blocked: a plain curl gets 200 on
a Google search query at the moment CDP-driven chromium gets /sorry.

## `worker.solver_smoke` - run the solver the way the platform will

    python3 -m worker.solver_smoke exploit.py

Runs it in the REAL runner sandbox. The point is dev/run parity: an import
that works in your shell and not in the sandbox is the single most common way
a finished solver fails at auto-run time.

## `worker.sage_smoke` - time the Sage step you cannot run

    python3 -m worker.sage_smoke <solver.sage>

There is no `sage` in your container; a `.sage` solver otherwise ships with
its Groebner/variety/small_roots step never once executed, and finds out in
production whether it fits the round budget.

## `worker.heap_probe` - heap state as a JSON timeline

A gdb harness that emits the heap as structured state rather than a wall of
`x/40gx`. Reach for it before hand-parsing gdb output across many rounds.

## `worker.chal_libc_fix` - libc/ld staging

Normally already ran before your first turn: it patchelfs a writable copy of
the binary against the challenge's own libc + ld under `./.chal-libs/` and
writes `./.chal-libs/libc_profile.json`. **Read that profile before choosing a
technique** - it carries the glibc version, safe-linking, tcache-key and hook
state that decide which chain is even possible. Run it yourself only when
staging is absent or you are deliberately selecting a different `--libs`.

## `worker.ghiant_cli` - Ghidra without the GUI

Ghidra is in a sibling image, not on your PATH. Decompilation normally already
happened: look in `./decomp/` first. Use this only for a function the
pre-pass did not cover.

## `worker.misc_recarve` - one targeted stego/carve run

    python3 -m worker.misc_recarve <tool> [args...]     # files at /job/<name>

Runs zsteg / steghide / outguess / binwalk / foremost / pdftotext / 7z in the
misc image. For ONE thing the fixed sweep did not do. `findings.json` already
holds the sweep; re-running it whole spends a turn to learn nothing.
