---
name: ogamdo-toolchain
description: Which tool is installed WHERE on this platform - worker vs the sibling misc/forensic/decompiler images - what is NOT installed, and how to reach a tool that lives elsewhere. Read this before concluding a tool is missing, and before installing anything.
---

# Where things actually are

Five images, not one. `command -v x` in your container answers for **your**
container only. Three separate lookups got this wrong in one session: `zsteg`
was reported missing after checking the worker (it is in the misc image),
`volatility` after checking PATH (it is a python module), and Ghidra likewise
(it is not on PATH anywhere).

## Your container: `worker`

Far more than you would guess. This list is the image diffed against its base
(`python:3.12-slim`) — everything below was deliberately installed, and an
earlier version of this skill named about five percent of it.

**Native reversing** — `objdump`, `readelf`, `nm`, `strings`, `srch_strings`,
`file`, `ldd`, `pahole` (+ `pfunct`, `pdwtags`, `codiff`, `btfdiff`),
`upx`, `yara`, `vivbin` (vivisect), `floss` (obfuscated strings),
`ROPgadget`, `one_gadget`, `checksec`, `seccomp-tools`.
Cross-arch binutils: `aarch64-linux-gnu-objdump`, `arm-linux-gnueabi-objdump`
and the matching `-nm`, `-readelf`, `-strip`.

**Debugging** — `gdb` (GEF at /opt/gef.py, pwndbg at /opt/pwndbg),
`gdb-multiarch`, `gdbserver`, `gcore`, `gstack`, `strace`, `ltrace`,
`frida` and its whole family (`frida-trace`, `frida-ps`, `frida-ls-devices`,
`frida-kill`), `chal-libc-fix`, `heap-probe`.

**pwntools on the command line** — `shellcraft`, `cyclic`, `asm`, `disasm`,
`constgrep`, `elfpatch`, `elfdiff`, `pwnstrip`, `disablenx`, `hex`, `errno`.

**Android** — `jadx`, `apktool`, `androguard`, `d2j-dex2jar`, `apksigner`,
`aapt`, `aapt2`, `zipalign`, `adb`, `apkInspector`.

**.NET / Mono** — `ilspycmd`, `monodis`, `ikdasm`, `pedump`, `mono`, `mcs`,
`csharp`, `peverify`.

**Go and kernel** — `redress` (stripped Go), `vmlinux-to-elf`,
`kallsyms-finder`, `gofmt`.

**WebAssembly** — `wasm2wat`, `wat2wasm`, `wasm-objdump`, `wasm-decompile`,
`wasm2c`, `wasm-validate`, `wasm-strip`, `wast2json`.

**Windows binaries** — `wine` (plus `winedbg`, `winefile`, `winepath`).

**Emulation** — `qemu-*-static` for roughly 25 architectures (aarch64, arm,
mips, mipsel, ppc64, riscv64, s390x, sparc64, loongarch64, hexagon, xtensa
and more), `qemu-system-x86_64`, `qemu-img`, `qemu-nbd`.

**Web** — `curl`, `wcurl`, `wget`, `nmap`, `nping`, `dig`, `socat`, `nc`,
`sqlmap`, `sqlmapapi`, `ffuf`, `dirb`, `chromedriver` (a real WebDriver, and
what a bot-simulation challenge wants), `chromium`, `Xvfb`.
Packet work: `tshark`, `tcpdump`, `sharkd`, `rawshark`, `editcap`,
`mergecap`, `text2pcap`, `capinfos`.

**Web3** — `solc`, `solc-select`, `slither` (+ `slither-read-storage`,
`slither-check-erc`, `slither-flat`), `crytic-compile`, `forge`, `anvil`,
`evm`, `geth`.

**Crypto and solvers** — `z3`, `cvc5`, `pyboolector`, and the SAT solvers
`minisat`, `picosat`, `cadical`, `kissat`, `cryptominisat5`.

**Forensics — IN THIS CONTAINER, not only the forensic image.** Sleuthkit
(`fls`, `icat`, `istat`, `fsstat`, `mmls`, `blkcat`, `blkls`, `ffind`,
`ifind`, `jls`, `tsk_recover`, `tsk_loaddb`, `sorter`, `mactime`, `hfind`,
`usnjls`, `fiwalk`), EWF (`ewfinfo`, `ewfexport`, `ewfmount`, `ewfacquire`),
NTFS (`ntfsls`, `ntfscat`, `ntfsundelete`, `ntfsinfo`, `ntfsrecover`),
Windows artefacts (`evtx_dump`, `regedit`), carving (`photorec`, `testdisk`,
`scalpel`, `binwalk`, `foremost`), `ftkimager`, `uefi-firmware-parser`,
`volshell`. The forensic image is for volatility3 memory work; a disk image
you can handle here.

**Images and documents** — `magick` / `identify` / `montage` / `mogrify`
(ImageMagick 7), `exiftool`, `jpeg_extract`, `dump-nskeyedarchiver`.

**Text and code** — `rg` (the binary is `rg`), `ast-grep`, `ipython`,
`pygmentize`, `git`, `patch`, `make`, `gcc`, `g++`, `xxd`, `7z`, `zip`,
`unzip`, `tar`, `bzip2`, `xz`, `cpio`.

**Runtimes** — `node`, `npm`, `php`, `ruby`, `gem`, `perl`, `java`, `javac`,
`go`, `dotnet`, `mono`, and the `docker` CLI.

**Python** — `pwn` (pwntools), `requests`, `httpx`, `bs4`, `lxml`, `Crypto`
(pycryptodome), `cryptography`, `ecdsa`, `gmpy2`, `sympy`, `numpy`, `PIL`,
`websockets`, `paramiko`, `scapy`, `jwt`, `yaml`, `magic`, `docker`, `rq`.

  - reversing: `angr`, `capstone`, `keystone`, `unicorn`, `elftools`,
    `pefile`, `dnfile`
  - solvers: `z3`, `cvc5`, `pyboolector`
  - heap: `libheap`, a gdb plugin for glibc heap inspection
  - forensics: `Evtx`, `Registry`, `dissect`
  - bitcoin / taproot: `coincurve` (libsecp256k1; sign_schnorr returns a
    64-byte BIP340 signature — use the real primitive, do not reimplement
    Schnorr), `bitcoinutils` (pip name bitcoin-utils; taproot addresses plus
    Transaction/TxInput/TxOutput, the short path to a raw hex tx — call
    bitcoinutils.setup.setup(network) first), `embit` (pure python,
    embit.script.p2tr), `btclib` (btclib.ecc.ssa, BIP340 at the primitive
    level, for when the signature scheme IS the challenge).
    `ecdsa` alone is NOT enough for Taproot: no BIP340 Schnorr, no x-only
    keys, no BIP341 sighash. And the web3 module's tooling (solc, slither,
    forge, anvil, geth) is Ethereum end to end — it will not build a Bitcoin
    transaction.

If something plausible is not named here, probe before concluding it is
missing — this image has surprised its own documentation once already.

## NOT installed anywhere - stop looking

```
radare2 r2 ropper hashcat john scipy rustc cargo selenium
stegseek regripper hivexsh hexdump sage vim
```

Reach for these instead: `ROPgadget` in place of ropper, `xxd` in place of
hexdump, `numpy` where a writeup wants scipy, `nano` as the editor. SageMath
has its own sandbox — see below.

## Installing something that is not here

You can: the container is root, PyPI and deb.debian.org both answer, and the
filesystem is writable. But WHERE you install decides whether it survives.

**A plain install is lost.** `pip install X` and `apt-get install X` land in
your container's own filesystem. Your solver does not run there — auto-run
starts a FRESH container from the same image, and the package is gone.
Measured: `humanize` absent from the image, installed, visible in that
container, absent again in the next one.

**Vendoring into the job directory survives**, because that directory is
mounted into the sandbox:

    pip install --target ./.pydeps <package>

then at the top of the solver, before the import:

    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pydeps"))

Measured end to end: vendored in one container, imported in a different one
that shared only the mount. The sandbox runs the same image, so a compiled
wheel matches its Python and architecture.

Two cautions. Keep it small — the job directory is collected and read back.
And prefer what is already here: a vendored dependency is one more thing that
can fail at auto-run, so reach for it only when nothing installed does the job.

`python3 -m worker.solver_smoke <solver.py>` runs the solver in the REAL
sandbox. If you vendored anything, that is how you find out it works before
it matters.

## Sibling images, and how to reach them

### misc - stego and carving
zsteg, steghide, outguess, binwalk, foremost, pdftotext, pdfinfo,
imagemagick `convert`, exiftool, 7z.

    python3 -m worker.misc_recarve <tool> [args...]     # files appear at /job/<name>

Use it for one targeted run the fixed sweep did not do - a specific zsteg
bit-plane, `steghide extract -p <passphrase you found>`, an offset-specific
binwalk. Do not re-run the whole sweep; `findings.json` already holds it.

### forensic - disk and memory
`sleuthkit` (mmls, fls, icat), `ewf-tools`, `qemu-utils`, `binutils`, and
**volatility3 2.28.0 as a python module** plus `yara-python`. There is no
`volatility` binary and no `vol.py`; it is `python3 -m volatility3`.

### decompiler - Ghidra
Ghidra lives at `/opt/ghidra` with helper scripts at `/opt/ghiant`. It is not
on PATH. Decompilation normally already ran before your first turn - look in
`./decomp/` before you consider invoking it yourself.

### Sage
SageMath is in its own sandbox that the runner spawns at auto-run time; there
is no `sage` in your container. A `.sage` solver therefore ships with its most
expensive step never executed. Time that step first:

    python3 -m worker.sage_smoke <solver.sage>

# Checking, rather than assuming

    command -v <tool>                     # answers for YOUR container only
    python3 -c "import x, sys; print(x.__file__)"   # a module is not a binary

If something is genuinely absent and would change the outcome, say so with
the command and its output rather than working around it silently.
