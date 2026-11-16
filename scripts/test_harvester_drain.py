#!/usr/bin/env python3
"""The harvester must still be reading when the flag is written.

WHY THIS EXISTS

Job 19cf9578a0fc solved a dreamhack web challenge in 63 minutes and the
harvester's entire contribution was one false positive. Both halves of that
have the same shape: the component stopped looking, or was never allowed to
look, at the bytes that mattered.

    09:38:03  job starts
    10:21:44  flag_grain.txt  <planted value>   confidence 0.86
    10:25:47  flag_grain.txt  error  TimeoutError
    10:41:03  meta.status -> finished        <-- the old loop returned HERE
    10:41:10  run.log  ...{"stage":"stage-2"}...
    10:41:16  run.log  FLAG_CANDIDATE: <real flag, withheld>

State left behind by that run:

    run.log            offset 439684 / size 457012    17,328 B never read
    gpt-events.jsonl   offset 479907 / size 501336    21,429 B never read

The real flag was inside the tail, so the exit condition `if terminal and not
pending: return` is not a corner case — the flag is ALWAYS written last, which
makes any status-keyed exit structurally blind to the one line the feature
exists to catch. Thirteen seconds separated the status flip from the winning
line; the drain window is sized against that measurement, not a guess.

The other two defects on the same run:

  * `adjudicated.add(key)` ran BEFORE `await _adjudicate(...)`, so the 10:25:47
    TimeoutError retired that batch permanently. Losing candidates silently is
    precisely the failure this feature was built to prevent.

  * `LOCAL{...}` is OUR OWN scaffolding — modules/_prompts.py tells the agent
    to plant local test flags in that deliberately non-real shape, and
    job_flag_format_re already excludes them. The harvester was the only net
    that did not, and the prompt rule meant to cover it ("a locally-planted
    test flag, when the line says so") did not fire, because the model saw the
    value echoed back by the local container over HTTP and read that as output
    the run produced. No wording survives that; the exclusion has to be
    structural.

WHAT THIS GUARDS, AND HOW

These are behaviours, not strings. Every case here DRIVES run_harvester against
a fake job whose status flips to terminal and whose run.log then grows. A suite
that merely asserted `DRAIN_QUIET_POLLS` exists, or that the exit-condition
source had changed, would stay green with the fix inert — which is the failure
mode this file is written to avoid.

One thing this must NOT do is turn the declared flag_format into a gate. The
harvester exists because the regex sometimes misses; requiring a format match
would put the same hole in both nets. The format is evidence, and F3 pins that.

Run:
    python3 scripts/test_harvester_drain.py
    python3 scripts/test_harvester_drain.py --mutate exit-on-status
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SRC = (ROOT / "modules" / "_harvester.py").read_text()

MUTATIONS = (
    "exit-on-status",      # return the moment status flips — the shipped bug
    "dedup-before-await",  # a failed batch is retired and never retried
    "no-local-filter",     # our own planted LOCAL{...} reaches the model again
    "format-is-a-gate",    # the declared shape becomes a filter, not evidence
    "drain-window-tiny",   # the window is too short for the measured 13 s gap
    "no-tally",            # a quiet success reports nothing — the 5c4a18e68834 gap
    "tally-ignores-failures",  # the tally exists but cannot show a broken run
    "tally-counts-returned",   # counts what the model returned, not what was kept
    "timeout-back-to-60",      # the deadline that measurably cut real findings
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()
_S0 = SRC

if args.mutate == "exit-on-status":
    _i = SRC.index("        if terminal and not pending:")
    _j = SRC.index("        await asyncio.sleep(POLL_S)", _i)
    SRC = SRC[:_i] + "        if terminal and not pending:\n            return\n" + SRC[_j:]
elif args.mutate == "dedup-before-await":
    SRC = SRC.replace(
        "                findings = await _adjudicate(batch, model, provider, job_id)",
        "                adjudicated.add(key)\n"
        "                findings = await _adjudicate(batch, model, provider, job_id)", 1)
elif args.mutate == "no-local-filter":
    SRC = SRC.replace('    probe = _LOCAL_PLANT_RE.sub("", line)', "    probe = line", 1)
elif args.mutate == "format-is-a-gate":
    SRC = SRC.replace(
        '        "Treat it as EVIDENCE, not as a filter. A string matching it is very "',
        '        "Reject every string that does not match this shape. "', 1)
elif args.mutate == "drain-window-tiny":
    SRC = SRC.replace("DRAIN_QUIET_POLLS = 10", "DRAIN_QUIET_POLLS = 1", 1)
elif args.mutate == "no-tally":
    SRC = SRC.replace(
        "                    note_tally(job_id, n_ok, n_written, n_fail, n_drop)\n", "", 1)
elif args.mutate == "timeout-back-to-60":
    SRC = SRC.replace("ADJUDICATE_TIMEOUT_S = 150.0", "ADJUDICATE_TIMEOUT_S = 60.0", 1)
elif args.mutate == "tally-counts-returned":
    SRC = SRC.replace(
        "                        n_written += append_grain(\n"
        "                            job_id, findings, [s for s, _ in batch])",
        "                        n_written += 1\n"
        "                        append_grain(job_id, findings, [s for s, _ in batch])", 1)
elif args.mutate == "tally-ignores-failures":
    SRC = SRC.replace("                    n_fail += 1\n", "", 1)

if args.mutate and SRC == _S0:
    raise SystemExit(f"MUTATION {args.mutate!r} CHANGED NOTHING — anchor is stale.")

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# Exec the (possibly mutated) module. Everything above module level is stdlib,
# so this is a faithful load — importing instead would silently use the real
# source and every mutation would report a false PASS.
_CODE = compile(SRC, "modules/_harvester.py", "exec")


def fresh_ns() -> dict:
    """A NEW module namespace per case.

    `dict(ns)` will not do: a function's __globals__ stays bound to the dict it
    was defined in, so overriding JOBS_DIR/POLL_S/_adjudicate in a copy leaves
    the real ones in force and every case silently tests unmodified code. This
    suite failed exactly that way before the loop was ever driven.
    """
    ns: dict = {"__name__": "_harvester_under_test"}
    exec(_CODE, ns)
    return ns


NS = fresh_ns()

# Shaped like the flag that was missed, deliberately NOT its value: a real
# captured flag in a tracked file is the incident test_no_committed_secrets.py
# exists to prevent, and this suite would have introduced one.
REAL_FLAG = "DH{deadbeefcafebabe0123456789abcdef}"
PLANT = "LOCAL{0123456789abcdef0123456789abcdef}"


class Harness:
    """A fake job, driven in miniature: POLL_S is shrunk, nothing else is."""

    def __init__(self, tmp, *, fail_times=0, emit=None):
        self.root = Path(tmp)
        self.dir = self.root / "job1"
        self.dir.mkdir(parents=True)
        self.log = self.dir / "run.log"
        self.log.write_text("")
        (self.dir / "gpt-events.jsonl").write_text("")
        self.status = "running"
        self._write_meta()
        self.seen: list[str] = []      # every line handed to the adjudicator
        self.calls = 0
        self.fail_times = fail_times
        # Verdicts handed back one per successful call. `append_grain` keeps
        # only `verdict == "real"`, so a rejection is the case that separates
        # "the model answered" from "a candidate reached the file".
        self.emit = list(emit or [])
        self.grain = ""        # captured before the temp dir is torn down

    def _write_meta(self, flag_format=None):
        m = {"status": self.status}
        if flag_format:
            m["flag_format"] = flag_format
        (self.dir / "meta.json").write_text(json.dumps(m))

    def append(self, line):
        with self.log.open("a") as fp:
            fp.write(line + "\n")

    def finish(self):
        self.status = "finished"
        self._write_meta()

    async def adjudicate(self, batch, model, provider, job_id=None):
        self.calls += 1
        self.seen.extend(t for _, t in batch)
        if self.calls <= self.fail_times:
            return None            # the failure shape: never answered
        if self.emit:
            return [self.emit.pop(0)]
        return []                  # judged, nothing qualified

    def install(self, ns):
        ns["JOBS_DIR"] = self.root
        ns["POLL_S"] = 0.01
        ns["BATCH_MAX_S"] = 0.01
        ns["_adjudicate"] = self.adjudicate


def drive(build, *, timeout=8.0, fail_times=0, flag_format=None, emit=None):
    """Run run_harvester to completion beside a writer that drives the job."""
    tmp = tempfile.mkdtemp()
    try:
        ns = fresh_ns()
        h = Harness(tmp, fail_times=fail_times, emit=emit)
        if flag_format:
            h._write_meta(flag_format)
        h.install(ns)

        async def main():
            task = asyncio.ensure_future(ns["run_harvester"]("job1", model="m"))
            await build(h)
            await asyncio.wait_for(task, timeout=timeout)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(main())
            return h, True
        except asyncio.TimeoutError:
            return h, False
        finally:
            loop.close()
            g = h.dir / "flag_grain.txt"
            h.grain = g.read_text() if g.exists() else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- D: the tail written after the status flips ----------------------------
def _drain_checks():
    print("\nD — output written AFTER the job goes terminal")

    async def late_flag(h):
        h.append("[10:40:00] [main] TOOL_RESULT: starting")
        await asyncio.sleep(0.15)
        h.finish()                       # <- the old loop returned here
        await asyncio.sleep(0.05)
        h.append(f"[10:41:16] [main] TOOL_RESULT: FLAG_CANDIDATE: {REAL_FLAG}")

    h, done = drive(late_flag)
    check("D0 the harvester still exits — the drain is bounded", done)
    # THE case. On the real job this line was never read at all.
    check("D1 a flag written after `finished` still reaches the adjudicator",
          any(REAL_FLAG in t for t in h.seen))

    # It must not simply run forever: once nothing more is written, it leaves.
    async def quiet_after(h):
        h.append("[10:40:00] [main] noise")
        await asyncio.sleep(0.1)
        h.finish()

    _, done2 = drive(quiet_after, timeout=6.0)
    check("D2 a genuinely quiet job is not held open", done2)

    # The window is a measurement, not a preference: 13 s separated the status
    # flip from the winning line on 19cf9578a0fc.
    window = NS["DRAIN_QUIET_POLLS"] * NS["POLL_S"]
    check(f"D3 the drain window ({window:.0f}s) covers the measured 13s gap",
          window >= 13.0)
    check("D4 ...and is capped, so a chatty job cannot pin the task open",
          NS["DRAIN_MAX_S"] <= 600.0)


# --- R: a failed adjudication is retried, not retired ----------------------
def _retry_checks():
    print("\nR — an adjudication that FAILED is not an adjudication that found nothing")

    async def one_batch(h):
        h.append(f"[10:00:00] [main] TOOL_RESULT: FLAG_CANDIDATE: {REAL_FLAG}")
        await asyncio.sleep(0.2)
        h.finish()

    h, done = drive(one_batch, fail_times=1)
    check("R0 the run completes", done)
    # The batch that timed out must come back. Before the fix its key was
    # already in `adjudicated`, so it could never be presented again.
    check("R1 a timed-out batch is presented again", h.calls >= 2)
    check("R2 ...carrying the same candidate",
          sum(1 for t in h.seen if REAL_FLAG in t) >= 2)

    # Bounded: a permanently failing adjudicator must not spin forever.
    h2, done2 = drive(one_batch, fail_times=99, timeout=8.0)
    check("R3 repeated failure gives up rather than looping", done2)
    check("R4 ...after exactly ADJUDICATE_TRIES attempts",
          h2.calls, NS["ADJUDICATE_TRIES"])
    check("R5 ...and the operator is told the batch was dropped",
          "dropped" in h2.grain)


# --- T: the run reports its own counts, so silence is legible --------------
def _tally_checks():
    print("\nT — an adjudication that found nothing must still report itself")

    async def one_batch(h):
        h.append(f"[10:00:00] [main] TOOL_RESULT: FLAG_CANDIDATE: {REAL_FLAG}")
        await asyncio.sleep(0.2)
        h.finish()

    # The Harness adjudicator returns [] — judged, nothing qualified. That is
    # the healthy quiet run, and before the tally it wrote NOTHING, so it was
    # byte-identical to a harvester that never ran.
    h, done = drive(one_batch)
    check("T0 the run completes", done)
    check("T1 the adjudicator was actually called", h.calls >= 1)
    check("T2 a run whose every verdict was empty still writes a line",
          "tally" in h.grain)
    check("T3 ...counting the successes that produced no candidate",
          f"adjudicated={h.calls}" in h.grain)
    check("T4 ...and saying nothing reached the file",
          "accepted=0" in h.grain)
    check("T5 ...claiming no failures it did not have",
          "failed=0\tdropped=0" in h.grain)

    # The shape job 5c4a18e68834 actually had: errors in the file, nothing
    # accepted. The whole point of the tally is that this is now separable
    # from T2 — same absence of candidates, opposite diagnosis.
    h2, done2 = drive(one_batch, fail_times=99, timeout=8.0)
    check("T6 the run completes", done2)
    check("T7 an all-failing run is DISTINGUISHABLE from a quiet one",
          "adjudicated=0" in h2.grain
          and f"failed={NS['ADJUDICATE_TRIES']}" in h2.grain)
    check("T8 ...and the dropped batch is counted, not just mentioned",
          "dropped=1" in h2.grain)

    # `accepted` counts what append_grain WROTE. Counting what _adjudicate
    # returned instead printed `with_findings=3` over a file holding no
    # candidate at all on job 4aa002418ca0, because a batch can come back
    # entirely rejections. The number has to cross-check the file it sits in.
    _REJECTED = {"flag": REAL_FLAG, "verdict": "not_a_flag",
                 "confidence": 0.20, "why": "our own scaffolding"}
    _ACCEPTED = {"flag": REAL_FLAG, "verdict": "real",
                 "confidence": 0.91, "why": "printed by the challenge binary"}

    def _flag_lines(g):
        return sum(1 for ln in g.splitlines() if ln.startswith("flag="))

    h3, _ = drive(one_batch, emit=[_REJECTED])
    check("T9 a batch the model ANSWERED but rejected counts nothing accepted",
          "accepted=0" in h3.grain)
    check("T10 ...matching the file, which holds no candidate", _flag_lines(h3.grain), 0)

    h4, _ = drive(one_batch, emit=[_ACCEPTED])
    check("T11 an accepted candidate is counted", "accepted=1" in h4.grain)
    check("T12 ...and the count equals the flag lines it wrote",
          _flag_lines(h4.grain), 1)


# --- X: the adjudication deadline is a measured number ---------------------
def _timeout_checks():
    print("\nX — the deadline has to clear what adjudication actually costs")
    # Replaying job d94336686a22's own batches through _adjudicate: 76.6 s for
    # the largest, 53.6 s for one that had ALSO failed at 60 s on an earlier
    # run. The model was not hanging; 60 s simply cut it off, all three retries
    # died the same way, and batch 0's 8 real findings went in the bin. The
    # bound is asserted against the measurement, not against the literal, so a
    # deliberate retune stays legal and a quiet revert does not.
    check(f"X1 the deadline ({NS['ADJUDICATE_TIMEOUT_S']:.0f}s) clears the "
          f"measured worst case of 76.6s with margin",
          NS["ADJUDICATE_TIMEOUT_S"] >= 120.0)
    check("X2 ...and the measurement is recorded where the number is",
          "76.6 s ok" in SRC and "d94336686a22" in SRC)
    # The cost of a longer deadline is a longer hold on a genuinely stuck call.
    # Worth naming next to the number so a future retune weighs both.
    check("X3 the retry budget is stated in wall-clock, not just in tries",
          "7.5 min" in SRC)


# --- L: our own planted stand-in never reaches the model -------------------
def _local_checks():
    print("\nL — LOCAL{...} is scaffolding this platform plants itself")
    interesting = NS["_interesting"]
    docker = ("docker run -d --rm --name chal --network container:x "
              f"-e 'FLAG={PLANT}' img")
    check("L1 the line that planted it is not a candidate", interesting(docker), False)
    # This is the one that actually fooled the model: the local container
    # echoing the value back reads exactly like output the run produced.
    check("L2 nor the local container echoing it back",
          interesting(f'HTTP/1.1 200 OK  {{"flag": "{PLANT}"}}'), False)
    check("L3 nor even when marked as a candidate",
          interesting(f"FLAG_CANDIDATE: {PLANT}"), False)
    # The exclusion is our scaffolding only — it must not narrow the hunt.
    check("L4 a real flag is still a candidate",
          interesting(f"TOOL_RESULT: {REAL_FLAG}"))
    check("L5 ...including one sharing a line with a plant",
          interesting(f"planted {PLANT} then got {REAL_FLAG}"))
    check("L6 ...and an unknown prefix, which is the whole point",
          interesting("output: SOMECTF{a_shape_no_regex_knows}"))


# --- F: the declared format is evidence, never a gate ----------------------
def _format_checks():
    print("\nF — flag_format informs the verdict, it does not decide it")
    tmp = tempfile.mkdtemp()
    try:
        ns = fresh_ns()
        h = Harness(tmp)
        ns["JOBS_DIR"] = h.root
        fc = ns["_format_context"]
        check("F1 no declared format changes the prompt not at all", fc("job1"), "")
        h._write_meta(r"DH\{[0-9a-f]{32}\}")
        note = fc("job1")
        check("F2 a declared format reaches the adjudicator",
              r"DH\{[0-9a-f]{32}\}" in note)
        # The feature exists BECAUSE the regex misses. Gating on the same
        # regex would put the identical hole in both nets.
        check("F3 ...as evidence, explicitly not as a filter",
              "not as a filter" in note and "Never reject" in note)
        check("F4 ...and says a non-matching string stays reportable",
              "lower confidence" in note)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    _drain_checks()
    _retry_checks()
    _tally_checks()
    _timeout_checks()
    _local_checks()
    _format_checks()
    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
