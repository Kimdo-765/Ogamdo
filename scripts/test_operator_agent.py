#!/usr/bin/env python3
"""The operator stopped classifying challenges, so something else has to.

WHY THIS EXISTS

The dashboard used to open with eight tabs and refuse the job until the
operator had already decided what kind of challenge they were holding: web or
pwn or rev, tick Docker, tick capture-remote-flag, tick auto-run. Every one of
those is a judgement about a bundle that is sitting in the request. So
`modules/_operator.py` reads it and decides, and the operator supplies only
what nobody else can know.

That moves a decision from a person to a model, which is exactly the kind of
move that needs a suite around it.

WHAT THIS SUITE PROTECTS

  * THE MODULE IS NEVER INVENTED. A reply naming something outside CHOICES is
    not a near miss to be repaired into the closest name -- it is an answer to
    a different question -- so it falls back whole. A coerced "kernel" -> "pwn"
    would look like a decision and be a guess.
  * A GUESS IS LABELLED A GUESS. `decided_by` separates "the agent chose pwn"
    from "nothing answered so we derived pwn", because on a job that went
    nowhere the second one is the fact worth seeing.
  * CHECKABLE CLAIMS ARE CHECKED. docker_challenge is a claim about files, so
    the archive listing answers it; a model that says yes about a bundle with
    no Dockerfile has found nothing. capture_remote_flag needs somewhere remote
    to capture from. Same discipline as the manager agent's derived
    `steps_done`.
  * PLACEMENT FOLLOWS THE ANSWER. web wants `src/`, pwn and rev want
    `bin/<name>`, forensic and misc want the job root -- and the module is not
    known until after the upload. The upload is staged, then moved, and the
    move consumes it.
  * EACH MODULE'S CALL SHAPE. rev takes no target; forensic takes
    image_type/target_os; misc takes a passphrase. Passing web's shape to rev
    would fail somewhere far from here.
  * THE PASSPHRASE STAYS OFF THE KEY/VALUE RAIL. modules/job_secrets.py records
    two measured regressions from letting MISC_PASSPHRASE through the operator
    ingress: it overwrote a real CTFd token, and it became a redaction needle
    that ate meta['filename'].
  * NO OVERFIT. The fallback reads file magic, extensions and target shape.
    A ladder that recognises one challenge's filenames has been fitted to it.

Run from the repository root::

    python3 scripts/test_operator_agent.py
    python3 scripts/test_operator_agent.py --mutate believe-docker-claim
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "coerce-unknown-module",
    "believe-docker-claim",
    "capture-without-target",
    "fallback-not-recorded",
    "rev-gets-a-target",
    "placement-copies-instead-of-moves",
    "dont-look-inside-the-wrapper",
    "swallow-the-provider-failure",
    "retired-model-back-in-the-menu",
    "drop-the-no-tools-instruction",
    "extract-without-limits",
    "follow-archive-symlinks",
    "misc-unpacks-in-place",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="operator-test-"))
os.environ["DATA_DIR"] = str(tmp)
(tmp / "jobs").mkdir()

import modules._operator as OP  # noqa: E402
import modules.ingest_placement as PL  # noqa: E402
from modules.storage import JOBS_DIR  # noqa: E402

# --- mutations --------------------------------------------------------------
if args.mutate == "coerce-unknown-module":
    def _coerce(raw, signals):
        got = dict(raw or {})
        m = str(got.get("module") or "").lower()
        if m not in OP.CHOICES:
            got["module"] = "pwn"      # "close enough"
        out = _real_normalize(got, signals)
        return out
    _real_normalize = OP._normalize
    OP._normalize = _coerce
elif args.mutate == "believe-docker-claim":
    OP._has_docker_evidence = lambda signals: True
elif args.mutate == "capture-without-target":
    _real_norm2 = OP._normalize
    def _cap(raw, signals):
        out = _real_norm2(raw, signals)
        out["capture_remote_flag"] = bool((raw or {}).get("capture_remote_flag"))
        return out
    OP._normalize = _cap
elif args.mutate == "fallback-not-recorded":
    _real_norm3 = OP._normalize
    def _hide(raw, signals):
        out = _real_norm3(raw, signals)
        out["decided_by"] = "agent"
        return out
    OP._normalize = _hide
elif args.mutate == "rev-gets-a-target":
    _real_args = PL.run_args
    def _bad(module, slots, **kw):
        if module == "rev":
            return (slots["binary_name"], kw["target"], kw["description"],
                    kw.get("auto_run", True), kw["model"])
        return _real_args(module, slots, **kw)
    PL.run_args = _bad
elif args.mutate == "extract-without-limits":
    PL.MAX_EXTRACT_BYTES = 1 << 60
    PL.MAX_EXTRACT_RATIO = 1 << 30
elif args.mutate == "follow-archive-symlinks":
    _real_safe = PL._safe_member_path
    PL._safe_member_path = lambda out, name: (out / name.lstrip("/")).resolve()
elif args.mutate == "misc-unpacks-in-place":
    _real_place = PL.place_upload
    def _in_place(module, job_id, raw_path, filename):
        got = _real_place(module, job_id, raw_path, filename)
        if module == "misc" and got.get("unpacked_root"):
            got["fname"] = None      # the original is no longer what runs
        return got
    PL.place_upload = _in_place
elif args.mutate == "drop-the-no-tools-instruction":
    _real_sys = OP._sys_prompt
    OP._sys_prompt = lambda: _real_sys().split("You have NO TOOLS")[0]
elif args.mutate == "swallow-the-provider-failure":
    # What every wrapper used to do: fail, and say nothing about it.
    _real_ask = OP._ask_grok
    async def _mute(prompt, model, why=None):
        return await _real_ask(prompt, model, None)
    OP._ask_grok = _mute
elif args.mutate == "retired-model-back-in-the-menu":
    import modules.agent_provider as _ap
    _ap.DEFAULT_GROK_MODEL = "grok-build"
elif args.mutate == "dont-look-inside-the-wrapper":
    OP._peek_nested = lambda zf, names: []
elif args.mutate == "placement-copies-instead-of-moves":
    PL._move = lambda src, dst: (dst.parent.mkdir(parents=True, exist_ok=True),
                                 shutil.copy2(str(src), str(dst)))


def sig(desc="", target=None, name=None, magic="", entries=None):
    return {"description": desc, "target": target, "targets": [],
            "flag_format": None,
            "upload": {"name": name, "size": 1, "magic": magic,
                       "entries": entries or [], "entry_count": len(entries or []),
                       "truncated": False}}


print("\n1. the module is derived, never invented")
DOCK = sig(name="c.zip", magic="ZIP", entries=["app/app.py", "app/Dockerfile",
                                               "docker-compose.yml"],
           target="http://chal:8080")
good = {"module": "web", "docker_challenge": True, "capture_remote_flag": True,
        "confidence": "high", "rationale": "flask app behind http"}
t = OP._normalize(good, DOCK)
check("an answer inside CHOICES is taken as given",
      (t["module"], t["decided_by"]), ("web", "agent"))
t = OP._normalize({**good, "module": "kernel"}, DOCK)
check("an answer OUTSIDE it falls back whole, not to the nearest name",
      (t["module"], t["decided_by"]), ("web", "fallback"))
check("...and its confidence drops with it", t["confidence"], "low")
t = OP._normalize(None, DOCK)
check("no answer at all is a fallback, and says so",
      t["decided_by"], "fallback")
check("every fallback the ladder can produce is a real module",
      sorted({OP.fallback_module(s)[0] for s in (
          sig(name="d.raw"), sig(name="c.pcapng"),
          sig(name="c.zip", magic="ZIP", entries=["V.sol", "foundry.toml"]),
          sig(name="v", magic="ELF", target="h:1337"),
          sig(name="v", magic="ELF"),
          sig(target="http://x"), sig(desc="break the RSA key"),
          sig(desc="a picture"),
      )} - set(OP.CHOICES)), [])

print("\n2. a claim about files is answered by the files")
check("docker: claimed AND evidenced -> true", OP._normalize(good, DOCK)["docker_challenge"], True)
NODOCK = sig(name="c.zip", magic="ZIP", entries=["app/app.py", "README.md"],
             target="http://chal:8080")
check("docker: claimed with NO Dockerfile in the archive -> false",
      OP._normalize(good, NODOCK)["docker_challenge"], False)
check("...and the evidence itself is reported, not just the verdict",
      OP._normalize(good, NODOCK)["docker_evidence"], False)
# A non-archive upload has no listing to check against, so the model's read of
# the description is the only evidence there is.
BARE = sig(name="vuln", magic="ELF", target="h:1337")
check("an unlistable upload leaves the claim to the model",
      OP._normalize({**good, "module": "pwn"}, BARE)["docker_challenge"], True)
check("a compose file counts as a runtime too",
      OP._has_docker_evidence(sig(name="c.zip", magic="ZIP",
                                  entries=["compose.yaml"])), True)
check("a bundle that merely mentions docker does not",
      OP._has_docker_evidence(sig(name="c.zip", magic="ZIP",
                                  entries=["docs/docker-notes.md"])), False)

print("\n3. a remote flag needs somewhere remote")
check("capture: asked for, with a target -> true",
      OP._normalize(good, DOCK)["capture_remote_flag"], True)
check("capture: asked for, with NO target -> false",
      OP._normalize(good, sig(name="v", magic="ELF"))["capture_remote_flag"], False)

print("\n4. placement follows the answer, and consumes the upload")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("chall/readme.txt", "hi")
    zf.writestr("chall/vuln", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200)
ZIP = buf.getvalue()
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200

def place(module, name, data):
    job = f"p-{module}"
    raw = JOBS_DIR / job / "_ingest" / name
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_bytes(data)
    slots = PL.place_upload(module, job, raw, name)
    tree = sorted(str(p.relative_to(JOBS_DIR / job))
                  for p in (JOBS_DIR / job).rglob("*") if p.is_file())
    return slots, tree, raw

slots, tree, raw = place("web", "src.zip", ZIP)
check("web extracts under src/ and points src_root at the extraction",
      (tree[:2], slots["src_root"].endswith("/src/extracted")),
      (["src/extracted/chall/readme.txt", "src/extracted/chall/vuln"], True))
slots, tree, _ = place("pwn", "vuln", ELF)
check("pwn lands one executable at bin/<name>",
      (tree, slots["binary_name"]), (["bin/vuln"], "vuln"))
slots, tree, _ = place("rev", "bundle.zip", ZIP)
check("rev unpacks the zip and re-resolves to the real binary",
      slots["binary_name"], "vuln")
slots, tree, _ = place("forensic", "disk.raw", b"\x00" * 4096)
check("forensic keeps the image in the job root",
      (tree, slots["image_name"]), (["disk.raw"], "disk.raw"))
slots, tree, _ = place("misc", "thing.png", b"\x89PNG" + b"\x00" * 64)
check("misc keeps its artefact in the job root",
      (tree, slots["fname"]), (["thing.png"], "thing.png"))
check("the staged upload is CONSUMED, not left behind as a second copy",
      raw.exists(), False)
check("every placeable module has a run entry point",
      sorted(set(PL.PLACEABLE) - set(PL.RUN_JOB)), [])


print("\n3b. a wrapper archive is not the challenge")
# Job 35a98fd7b823, measured. Its upload was a zip holding exactly one entry,
# `<name>_<hash>.tar.gz`, so the only thing the agent was shown was that
# filename. It routed to pwn on the host:port target alone at confidence LOW;
# six seconds later the solver unpacked the same archive and found source that
# pointed to another category. Re-asked with one filename more visible, the
# same model answered that category at confidence medium.
import tarfile  # noqa: E402
_tb = io.BytesIO()
with tarfile.open(fileobj=_tb, mode="w:gz") as _tf:
    _i = tarfile.TarInfo("chal.py"); _d = b"import hashlib\n"
    _i.size = len(_d); _tf.addfile(_i, io.BytesIO(_d))
_wrap = tmp / "wrap.zip"
with zipfile.ZipFile(_wrap, "w") as _z:
    _z.writestr("bundle_abc.tar.gz", _tb.getvalue())
_up = OP.inspect_upload(_wrap)
check("the wrapper's own listing is still just the wrapper",
      _up["entries"], ["bundle_abc.tar.gz"])
check("...and one level in, the real file is visible",
      _up.get("nested"), ["bundle_abc.tar.gz :: chal.py"])
check("what is inside reaches the model's prompt",
      "INSIDE THE NESTED ARCHIVE" in OP._user_prompt(
          {"description": "", "target": "h:1", "targets": [], "flag_format": None,
           "upload": _up}), True)
# Narrow on purpose: a bundle with a real tree already shows its own shape, and
# recursing into everything is how a nested bomb becomes someone's CPU bill.
_big = tmp / "big.zip"
with zipfile.ZipFile(_big, "w") as _z:
    for _n in range(12):
        _z.writestr(f"src/f{_n}.py", "x")
    _z.writestr("inner.tar.gz", _tb.getvalue())
check("a bundle that already shows a tree is not recursed into",
      OP.inspect_upload(_big).get("nested"), None)
check("nothing is written to disk to read a nested archive",
      sorted(q.name for q in tmp.iterdir() if q.is_file()), ["big.zip", "wrap.zip"])

print("\n4b. the two placement policies have not drifted apart")
# There are two: the seven /analyze routes still place their own uploads for
# the AI Player, and ingest_placement does it for the operator's handoff.
# Refactoring seven production endpoints was not part of this change, so the
# duplication is real and this is the tripwire on it. Divergence in WHERE a
# module's file goes is the part that breaks things — it is what `binary_name`
# and `src_root` in meta.json mean, and what every prompt's `./bin/<name>`
# points at.
_ROUTE_DIR = {
    # module: (what the route writes into, which family placement puts it in)
    "web": ('save_upload(', "_SRC_MODULES"),
    "crypto": ('save_upload(', "_SRC_MODULES"),
    "web3": ('save_upload(', "_SRC_MODULES"),
    "pwn": ('bin_dir / binary_name', "_BIN_MODULES"),
    "rev": ('bin_dir / binary_name', "_BIN_MODULES"),
    "forensic": ('job_dir(job_id) / image_name', "_ROOT_MODULES"),
    "misc": ('job_dir(job_id) / fname', "_ROOT_MODULES"),
}
_pl_src = (ROOT / "modules" / "ingest_placement.py").read_text(encoding="utf-8")
_drift = []
for _m, (_needle, _family) in _ROUTE_DIR.items():
    _route = (ROOT / "api" / "routes" / f"{_m}_module.py").read_text(encoding="utf-8")
    if _needle not in _route:
        _drift.append(f"{_m}: route no longer writes via {_needle!r}")
    if _m not in getattr(PL, _family):
        _drift.append(f"{_m}: placement no longer in {_family}")
check("every module's route and the shared placement still agree on the directory",
      _drift, [])
check("...and rev's binary re-resolution is in the shared copy too",
      "pick_challenge_binary" in _pl_src and "safe_extract" in _pl_src, True)
check("the duplication is documented where someone would hit it, as duplication",
      "KNOWN DUPLICATION" in _pl_src
      and "do NOT call this yet" in _pl_src, True)

print("\n4c. every module unpacks — and two of them do it beside, not instead")
import tarfile as _tar  # noqa: E402

def _mk_tar(members):
    b = io.BytesIO()
    with _tar.open(fileobj=b, mode="w") as tf:
        for info, fh in members:
            tf.addfile(info, fh)
    return b.getvalue()

def _tinfo(name, data=b"x", typ=_tar.REGTYPE, link=""):
    i = _tar.TarInfo(name); i.type = typ; i.linkname = link
    i.size = len(data) if typ == _tar.REGTYPE else 0
    return i, io.BytesIO(data)

# Reproduced on this box before the limits existed: tarfile.extractall walked
# out of its directory on 3.10, which has no `filter=` (that is 3.12). An
# absolute member only failed on the host for permissions — the runner is root.
_esc = tmp / "esc.tar"
_esc.write_bytes(_mk_tar([_tinfo("../escaped.txt"), _tinfo("/abs/rooted.txt"),
                          _tinfo("ok.txt")]))
_r = PL.safe_extract(_esc, tmp / "esc_out")
check("a member that climbs out of the directory is refused, not written",
      (_r["files"], sorted(_r["skipped"])),
      (1, ["../escaped.txt", "/abs/rooted.txt"]))
check("...and nothing landed outside it",
      sorted(q.name for q in (tmp / "esc_out").rglob("*") if q.is_file()), ["ok.txt"])
# A symlink member is a write primitive for everything it points at.
_ln = tmp / "ln.tar"
_ln.write_bytes(_mk_tar([_tinfo("link", typ=_tar.SYMTYPE, link="/etc"),
                         _tinfo("real.txt")]))
_r = PL.safe_extract(_ln, tmp / "ln_out")
check("a symlink member is skipped, not created",
      ((tmp / "ln_out" / "link").is_symlink(), _r["skipped"]), (False, ["link"]))
# 499 KB -> 524 MB was measured through the old extract_if_archive, which had
# no cap of any kind.
_bomb = tmp / "bomb.zip"
_bb = io.BytesIO()
with zipfile.ZipFile(_bb, "w", zipfile.ZIP_DEFLATED) as _z:
    for _i in range(40):
        _z.writestr(f"f{_i}", b"\0" * (80 * 1024 * 1024))
_bomb.write_bytes(_bb.getvalue())
_bomb_out = tmp / "bomb_out"
try:
    PL.safe_extract(_bomb, _bomb_out)
    check("a decompression bomb is refused", "extracted", "refused")
except PL.UnsafeArchive as _exc:
    check("a decompression bomb is refused",
          "ratio" in str(_exc) or "size" in str(_exc), True)
# Checking as it went meant a refused bomb still landed 560 MB before the
# ratio tripped — measured. Both formats declare member sizes in their
# headers, so the total is known before a byte is written.
check("...before writing anything, and leaving nothing behind",
      (_bomb_out.exists(), sum(1 for _ in _bomb_out.rglob("*")) if _bomb_out.exists() else 0),
      (False, 0))
check("...and the check is still enforced DURING the write, in case a header lies",
      "_guard(info.file_size)" in _pl_src and "_declared_total" in _pl_src, True)
# The three /analyze routes the AI Player posts to shared the unguarded
# extractor; hardening the shared function covers all of them at once.
_storage = (ROOT / "modules" / "storage.py").read_text(encoding="utf-8")
check("the shared extract_if_archive goes through the same limits",
      "safe_extract(path, out)" in _storage
      and ".extractall(" not in _storage, True)
for _m in ("web", "crypto", "web3"):
    _r = (ROOT / "api" / "routes" / f"{_m}_module.py").read_text(encoding="utf-8")
    check(f"...and {_m}'s route turns a refusal into a 400, not a 500",
          "archive refused" in _r, True)
# A name is not evidence of a format.
_png = tmp / "flag.png"
_png.write_bytes(ZIP)
check("an archive named .png is still detected", PL.is_archive(_png), "zip")
check("...and a file that is not an archive is not one", PL.is_archive(_esc.with_suffix(".none")) if _esc.with_suffix(".none").exists() else None, None)

def _place(module, name, data):
    job = f"x-{module}"
    raw = JOBS_DIR / job / "_ingest" / name
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_bytes(data)
    return PL.place_upload(module, job, raw, name), JOBS_DIR / job

# pwn shipped its archive sealed, so `binary_name` was the zip and the
# prompt's `./bin/<name>` pointed at an archive. Job 013dfdc4d8e4 landed that.
_s, _d = _place("pwn", "chal.zip", ZIP)
check("pwn now resolves to the binary inside, not the archive",
      _s["binary_name"], "vuln")
check("...and rev still does", _place("rev", "chal.zip", ZIP)[0]["binary_name"], "vuln")
# misc's archive IS often the artefact: _spawn_misc hands the ORIGINAL to the
# tool sweep with --passphrase, and the prompt names "archives with extra
# entries" as a hiding place. forensic's collector takes ONE image path.
for _m, _slot in (("misc", "fname"), ("forensic", "image_name")):
    _s, _d = _place(_m, "chal.zip", ZIP)
    check(f"{_m} still hands its tools the ORIGINAL file",
          _s[_slot], "chal.zip")
    check(f"...and the archive is still there to hand over",
          (_d / "chal.zip").is_file(), True)
    check(f"...with the contents unpacked BESIDE it, for the agent to read",
          bool(_s.get("unpacked_root")) and (_d / "unpacked").is_dir(), True)
# A refusal is not a failed job: the sealed archive stays and the agent can
# open it with whatever limits it likes.
_s, _d = _place("pwn", "bomb.zip", _bomb.read_bytes())
check("a refused archive leaves the job runnable",
      (bool(_s.get("unpack_refused")), (_d / "bin" / "bomb.zip").is_file()), (True, True))

print("\n5. each module is called with its OWN shape")
S = PL.empty_slots()
S.update({"src_root": "/s", "binary_name": "b", "image_name": "i", "fname": "f"})
kw = dict(target="http://t", description="d", model="m")
check("web/crypto/web3 take (src_root, target, description, auto_run, model)",
      [PL.run_args(m, S, **kw) for m in ("web", "crypto", "web3")],
      [("/s", "http://t", "d", True, "m")] * 3)
check("pwn takes its binary and a target", PL.run_args("pwn", S, **kw),
      ("b", "http://t", "d", True, "m"))
# rev's run_job has no target parameter at all. Passing one shifts every
# argument after it by a position.
check("rev takes NO target", PL.run_args("rev", S, **kw), ("b", "d", True, "m"))
check("forensic keeps image_type/target_os on auto, as its own form defaulted",
      PL.run_args("forensic", S, **kw), ("i", "auto", "auto", "d", False, False, "m"))
check("misc carries the passphrase on its own parameter",
      PL.run_args("misc", S, passphrase="pw", **kw), ("f", "pw", "d", False, "m"))

print("\n6. auto-run is not a question any more")
route_src = (ROOT / "api" / "routes" / "jeopardy.py").read_text(encoding="utf-8")
op_src = (ROOT / "modules" / "_operator.py").read_text(encoding="utf-8")
html = (ROOT / "web-ui" / "index.html").read_text(encoding="utf-8")
check("the ingest writes auto_run true, unconditionally",
      '"auto_run": True' in route_src, True)
check("...the handoff passes it too", "auto_run=True" in op_src, True)
check("...and the form does not offer it",
      'name="auto_run"' in html, False)

print("\n7. what the operator is still asked for, and what is gone")
i = html.index('<section id="panel-jeopardy"')
panel = html[i:html.find('<section id="panel-', i + 1)]
import re  # noqa: E402
fields = re.findall(r'name="([a-z_]+)"', panel)
check("exactly the fields the operator can answer and nobody else can",
      sorted(set(fields)),
      sorted({"tag", "output_language", "file", "description",
              "challenge_secret_key", "challenge_secret_value",
              "archive_passphrase", "flag_format", "model", "effort",
              "job_timeout"}))
for gone in ("auto_run", "docker_challenge"):
    check(f"...{gone} is not among them", gone in fields, False)
check("...nor is the capture-remote-flag checkbox",
      "capture-remote-flag-cb" in panel, False)
check("the eight module tabs are one",
      sorted(set(re.findall(r'data-tab="([a-z0-9-]+)"', html))),
      ["containers", "dashboard", "exploits", "jeopardy", "live-fire",
       "player", "settings"])

print("\n7b. the role is actually selectable, not merely registered")
# Registering a role in ROLE_OVERRIDABLE is not enough to make it selectable:
# the selects are DECLARED in index.html and the JS reads them with
# `form.querySelector(...)` behind an `if (sel)`. A role added to the list with
# no control renders nothing, saves nothing, and fails silently — which is
# exactly what happened to `operator` on its first pass.
from modules.agent_provider import ROLE_OVERRIDABLE as _OVERRIDABLE  # noqa: E402
_missing = sorted(r for r in _OVERRIDABLE
                  if f'name="role_provider_{r}"' not in html)
check("every routable role has a provider control in Settings", _missing, [])
check("...including operator",
      'name="role_provider_operator"' in html, True)
check("...offering every provider it can be routed to",
      all(f'value="{p}"' in html.split('name="role_provider_operator"')[1][:400]
          for p in ("claude", "gpt", "grok")), True)
# The model-pin side is generated from the API's configurable_roles, so this
# only has to be in the list the UI falls back to when that call has not landed.
app_js_src = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
from modules.model_presets import CONFIGURABLE_ROLES as _PINNABLE  # noqa: E402
check("operator can be pinned to a model, in the backend list and the UI default",
      "operator" in _PINNABLE
      and '"operator", "main"' in app_js_src, True)

print("\n7c. a fallback says WHY, and the grok catalog matches the CLI")
# Job b3c331302651 fell back in eight seconds and the reason was unrecoverable:
# every provider wrapper swallowed its failure whole, so "the model did not
# answer usably" was the entire diagnosis. A fallback with no cause cannot be
# fixed, only guessed at.
import asyncio  # noqa: E402
import types as _types  # noqa: E402

def _stub_grok(text=None, error=None, raises=None):
    mod = _types.ModuleType("modules.grok_acp")
    async def _q(**kw):
        if raises:
            raise raises
        return {"text": text or "", "error": error}
    mod.query_grok_once = _q
    mod.resolve_grok_bin = lambda: "/stub/grok"
    sys.modules["modules.grok_acp"] = mod

_real_grok_mod = sys.modules.get("modules.grok_acp")
_stub_grok(text="I'd rather talk about something else.")
_why = []
asyncio.run(OP._ask_grok("classify this", "definitely-not-a-model", _why))
check("a reply with no JSON is a recorded failure, not a silent one",
      bool(_why) and "no parseable JSON" in _why[0], True)
check("...naming the model it used, so a retired id is visible",
      "definitely-not-a-model" in _why[0], True)
_stub_grok(error="model not found")
_why2 = []
asyncio.run(OP._ask_grok("classify this", "gone", _why2))
check("a provider error is recorded with its text",
      bool(_why2) and "model not found" in _why2[0], True)
_stub_grok(raises=RuntimeError("boom"))
_why3 = []
asyncio.run(OP._ask_grok("classify this", "x", _why3))
check("a raised call is recorded with its type",
      bool(_why3) and "RuntimeError" in _why3[0], True)
# A reply that IS usable must leave no complaint behind.
_stub_grok(text='{"module":"web","docker_challenge":false,'
                '"capture_remote_flag":false,"confidence":"high","rationale":"r"}')
_why4 = []
_got = asyncio.run(OP._ask_grok("classify this", "x", _why4))
check("a usable reply records nothing", (_got or {}).get("module"), "web")
check("...and leaves no spurious reason", _why4, [])
if _real_grok_mod is not None:
    sys.modules["modules.grok_acp"] = _real_grok_mod
else:
    sys.modules.pop("modules.grok_acp", None)
_op_src = (ROOT / "modules" / "_operator.py").read_text(encoding="utf-8")
for _p in ("_ask_claude", "_ask_gpt", "_ask_grok"):
    check(f"{_p} can report why it gave up",
          f"async def {_p}(prompt" in _op_src
          and "why: list | None = None" in _op_src.split(f"async def {_p}(")[1][:200],
          True)
check("the reason reaches the decision only when it actually fell back",
      'if out["decided_by"] == "fallback" and why:' in _op_src, True)
check("...and is logged where the operator reads the job",
      '"[operator] why: "' in _op_src, True)

# `grok models` on the installed CLI (1.0.13) lists exactly grok-4.6 and
# grok-4.5. `grok-build` was the default here while it did not exist. The CLI
# silently substitutes its default for an unknown id, so this never raised --
# it just meant nobody could tell which model had answered.
from modules.agent_provider import DEFAULT_GROK_MODEL  # noqa: E402
_js = (ROOT / "web-ui" / "app.js").read_text(encoding="utf-8")
_catalog = _js.split("const GROK_MODELS = [")[1].split("]")[0]
check("the grok default is a model the CLI actually lists",
      DEFAULT_GROK_MODEL, "grok-4.6")
check("the retired id is gone from the menu",
      "grok-build" in _catalog, False)
check("...along with the other four the CLI no longer offers",
      [m for m in ("grok-4", "grok-3", "grok-3-mini", "grok-code-fast-1")
       if f'"{m}"' in _catalog], [])
check("...and both live models are in it",
      all(f'"{m}"' in _catalog for m in ("grok-4.6", "grok-4.5")), True)
# Nothing validates a saved model string against this list, so an older job
# that stored a retired id still runs; the list only populates the menu.
check("the catalog is a menu, not a validator",
      "VALID_MODELS" in (ROOT / "modules" / "model_presets.py").read_text(encoding="utf-8"),
      False)

print("\n7d. the model is told it has no tools")
# Job 765ba3200f17: grok attempted `run_terminal_command`, the text-only
# helper refused with `tool_use_in_text_only_role`, and the operator fell back
# on EVERY grok-routed job. The wrappers already disable tools —
# allow_tools=False, enable_tools=False, allowed_tools=[] — but the model does
# not know that unless the prompt says so. modules/_harvester.py learned this
# from job 8e12a5fb1475 and wrote the fix down; this prompt had not read it.
#
# Measured after: the same bundle and prompt through grok-4.6, three for three,
# module=pwn docker=True confidence=high — where the fallback had said
# docker=False confidence=low, and the bundle ships a Dockerfile.
_sys = OP._sys_prompt()
check("the prompt says outright that there are no tools",
      "You have NO TOOLS" in _sys, True)
check("...and what a tool attempt costs",
      "discards" in _sys and "text-only" in _sys, True)
check("...and that an unsure answer still beats no answer",
      "still answer" in _sys, True)
# Every wrapper must ALSO disable them: the prompt is the model's belief, the
# flag is the enforcement, and neither alone is enough.
for _flag in ("allowed_tools=[]", "enable_tools=False"):
    check(f"the wrappers still enforce it ({_flag})", _flag in _op_src, True)

print("\n8. the passphrase stays off the key/value rail")
from modules.job_secrets import (  # noqa: E402
    ALLOWED_SECRET_KEYS, _OPERATOR_INGRESS_KEYS,
)
check("MISC_PASSPHRASE is storable", "MISC_PASSPHRASE" in ALLOWED_SECRET_KEYS, True)
# It once overwrote a real CTFd token through this door, and then became a
# redaction needle that ate meta['filename'].
check("...and still NOT settable through the operator key/value form",
      "MISC_PASSPHRASE" in _OPERATOR_INGRESS_KEYS, False)
check("the jeopardy route uses the typed entry point instead",
      "store_misc_passphrase" in route_src
      and "archive_passphrase" in route_src, True)
check("...and the form gives it its own field, not the key dropdown",
      'name="archive_passphrase"' in panel
      and "MISC_PASSPHRASE" not in panel, True)

print("\n9. the fallback reads shapes, not names")
# A ladder that recognises a particular challenge's filenames has been fitted
# to that challenge. These are the only things it is allowed to look at.
check("no bundle-specific filename appears in the ladder",
      [w for w in ("base.zip", "chal.zip", "trafficops", "k-exchange")
       if w in op_src.lower()], [])
check("the ladder is anchored on magic, extensions and target shape",
      all(k in op_src for k in ("_IMAGE_EXT", "_BIN_MAGIC", "_looks_hostport",
                                "_looks_http")), True)

print("\n10. the wiring, end to end, with no model and no solve")
import types  # noqa: E402
calls = []
for _mod, _dotted in PL.RUN_JOB.items():
    _name, _fn = _dotted.rsplit(".", 1)
    _stub = types.ModuleType(_name)
    setattr(_stub, _fn, (lambda m: (lambda job_id, *a: calls.append((m, job_id, a))))(_mod))
    sys.modules[_name] = _stub

job = "wire"
raw = JOBS_DIR / job / "_ingest" / "chal.zip"
raw.parent.mkdir(parents=True, exist_ok=True)
raw.write_bytes(ZIP)
(JOBS_DIR / job / "meta.json").write_text(json.dumps({
    "id": job, "module": "jeopardy", "status": "queued", "filename": "chal.zip",
    "ingest_path": str(raw), "target_url": "http://c:8080",
    "description": "login bypass", "auto_run": True, "model": None}))

async def _fake_decide(_):
    return {"module": "web", "docker_challenge": True, "capture_remote_flag": True,
            "confidence": "high", "rationale": "flask app", "decided_by": "agent",
            "fallback_module": "web", "docker_evidence": True,
            "provider": "stub", "model": "stub"}
OP.decide = _fake_decide
OP.route_job(job)

meta = json.loads((JOBS_DIR / job / "meta.json").read_text())
check("the decision is written where a later reader can find it",
      (meta["module"], meta["auto_run"], meta["docker_challenge"]),
      ("web", True, True))
check("...including how it was reached",
      meta["operator_decision"]["decided_by"], "agent")
check("the staged path is cleared once the file has moved off it",
      meta.get("ingest_path"), None)
check("the remote-flag mandate is folded into the description, once",
      (meta["description"] or "").lower().count("capture remote flag"), 1)
check("the handoff calls the chosen module in-process",
      [(c[0], c[1]) for c in calls], [("web", "wire")])
events = [json.loads(l) for l in
          (JOBS_DIR / job / "events.jsonl").read_text().splitlines() if l.strip()]
check("the routing is on the job's own event stream",
      [(e["phase"], e["kind"]) for e in events],
      [("operator", "start"), ("operator", "decided"), ("operator", "handoff")])
check("...under a declared phase, not a `?` tag",
      [e for e in events if e["phase"].startswith("?")], [])
check("meta goes through write_meta, which stamps the worker slot deploy.sh reads",
      "from modules._common import log_line, write_meta" in op_src, True)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
