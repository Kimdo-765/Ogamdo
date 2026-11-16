#!/usr/bin/env python3
"""A guardrail written only in prose is a suggestion.

WHY THIS EXISTS

`worker/browser.py` shipped `--stealth` off by default, documented as "for a
target you are authorised to test that gates on them — not for a third-party
service you are merely using as a tool". Job 117c98fac9b8 turned it on against
google.com and wrote so in its own blocked.json. The prose did not hold, so
the check is code now and this suite is what keeps it honest.

WHAT IT PROTECTS

  * AUTHORISED MEANS THE JOB'S OWN TARGET. `meta.target_url` (and
    `target_urls`), or a loopback/private address, which is this platform's
    own sandbox. Nothing else.
  * A JOB WITH NO TARGET AUTHORISES NOTHING. That is exactly the OSINT case
    that went wrong: `target_url` was null and stealth was used anyway.
  * REFUSING IS NOT FAILING. The page still renders; only the evasion is
    dropped, and it says so rather than downgrading silently.

Run from the repository root::

    python3 scripts/test_browser_stealth.py
    python3 scripts/test_browser_stealth.py --mutate allow-when-no-target
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = ("allow-when-no-target", "allow-any-public-host",
             "refuse-the-sandbox", "silent-downgrade")
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

PASSED = FAILED = 0


def check(label, got, want):
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"  ok   {label}")
    else:
        FAILED += 1
        print(f"  FAIL {label}\n         got  {got!r}\n         want {want!r}")


tmp = Path(tempfile.mkdtemp(prefix="stealth-test-"))
os.environ["DATA_DIR"] = str(tmp)


def job(name, meta):
    d = tmp / "jobs" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return name


from worker.browser import _authorised_for_stealth as AUTH  # noqa: E402

if args.mutate == "allow-when-no-target":
    _real = AUTH
    def AUTH(url):  # noqa: E302
        ok, why = _real(url)
        return (True, why) if "declares no target" in why else (ok, why)
elif args.mutate == "allow-any-public-host":
    AUTH = lambda url: (True, "anything goes")  # noqa: E731
elif args.mutate == "refuse-the-sandbox":
    _real2 = _authorised_for_stealth if False else AUTH
    def AUTH(url):  # noqa: E302
        ok, why = _real2(url)
        return (False, why) if "private address" in why else (ok, why)

print("\n1. the platform's own sandbox is authorised")
for u in ("http://127.0.0.1:8899/", "http://172.18.0.1:31337/x",
          "http://10.0.0.5/", "http://192.168.1.9:80/"):
    ok, why = AUTH(u)
    check(f"{u} -> allowed", ok, True)

print("\n2. a job that declares no target authorises nothing")
os.environ["JOB_ID"] = job("osintlike", {"target_url": None})
ok, why = AUTH("https://www.google.com/")
check("google.com is refused on a targetless job", ok, False)
check("...and the reason names the cause", "declares no target" in why, True)

print("\n3. only the job's own target, and only that one")
os.environ["JOB_ID"] = job("weblike", {"target_url": "http://target.invalid:12345/"})
ok, _ = AUTH("http://target.invalid:12345/admin")
check("the declared target is allowed", ok, True)
ok, why = AUTH("https://www.google.com/search?q=x")
check("another public host is refused", ok, False)
check("...and the refusal names the real target", "target.invalid" in why, True)
ok, _ = AUTH("http://target.invalid.evil.test/")
check("a suffix look-alike is not the target", ok, False)

print("\n4. missing context refuses rather than assumes")
os.environ.pop("JOB_ID", None)
ok, why = AUTH("https://www.google.com/")
check("no JOB_ID -> refused", ok, False)
os.environ["JOB_ID"] = "nosuchjob"
ok, why = AUTH("https://www.google.com/")
check("unreadable meta -> refused", ok, False)
ok, why = AUTH("not-a-url")
check("no host at all -> refused", ok, False)

print("\n5. a refusal is spoken, not silent")
src = (ROOT / "worker" / "browser.py").read_text(encoding="utf-8")
if args.mutate == "silent-downgrade":
    src = src.replace('print(("STEALTH_ON: " if allowed else "STEALTH_REFUSED: ") + why)', "")
check("the refusal is printed", "STEALTH_REFUSED" in src, True)
check("...and the page still renders (refusal is not an exit)",
      "stealth = allowed" in src and "raise SystemExit" not in
      src.split("stealth = allowed")[0].split("allowed, why =")[-1], True)

import shutil  # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
