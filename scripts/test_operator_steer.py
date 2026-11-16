#!/usr/bin/env python3
"""One sentence into a running job, at the turn boundary, and nowhere else.

WHY THIS EXISTS

Before this, everything that could reach a running job ENDED it. `/stop` kills
the session; `/retry` and `/resume` act only after it has finished and start a
new one. An operator watching a job go wrong could let it finish being wrong or
throw away what it had learned.

Job 340e62bdcd32 is the argument. From 03:10 its own instruments said it had
stopped learning -- the evidence budget saturated at 4 distinct states and fell
to -10 against a limit of 3, and the orchestrator logged "main is not acting on
it" sixteen times. Every automated signal fired correctly and none could act.
It ran to 05:09, when a human woke up and pressed stop. What was needed at
03:10 was neither halt nor continue.

WHAT THIS SUITE PROTECTS

  * The PLACEMENT. Below FINAL_DRAFT, above every automated nudge. Above
    FINAL_DRAFT and an operator note can cost a job its last-chance draft;
    below soft-eject and the automation outranks the person watching.
  * The CLEARING. A queue that is read without being emptied delivers the same
    instruction on every subsequent turn, forever.
  * The REFUSAL on a finished job -- the failure mode this feature must never
    have is an operator believing they redirected something they did not.
  * That the injected turn SAYS it is from the operator. The model has no other
    way to tell it from the orchestrator's own nudges, and the difference is
    the whole point: the operator can see the live log and the target.

Run from the repository root::

    python3 scripts/test_operator_steer.py
    python3 scripts/test_operator_steer.py --mutate steer-not-cleared
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MUTATIONS = (
    "steer-not-cleared",
    "steer-above-final-draft",
    "steer-below-soft-eject",
    "steer-no-pending-cap",
    "steer-keeps-control-chars",
    "steer-anonymous-turn",
    "steer-allows-terminal-job",
)
parser = argparse.ArgumentParser()
parser.add_argument("--mutate", choices=MUTATIONS)
args = parser.parse_args()

PASSED = 0
FAILED = 0


def check(label: str, got, want) -> None:
    global PASSED, FAILED
    if got == want:
        PASSED += 1
        print(f"PASS  {label}")
    else:
        FAILED += 1
        print(f"FAIL  {label}\n      got={got!r}\n     want={want!r}")


from modules import steer  # noqa: E402

if args.mutate == "steer-not-cleared":
    steer.take = steer.pending
if args.mutate == "steer-no-pending-cap":
    # Drops the TRIM, not the constant. Raising MAX_PENDING instead also raises
    # the loop bound below and queues a million messages -- which is what the
    # first draft did, and it HUNG the suite instead of failing a check. A
    # mutation that cannot finish reports as caught on the exit code alone.
    import json as _json
    import uuid as _uuid

    def _uncapped(work_dir, text):
        clean = steer.sanitize(text)
        if not clean:
            raise ValueError("steer message is empty")
        msgs = steer._read(work_dir)
        msgs.append({"id": _uuid.uuid4().hex[:12], "text": clean, "ts": ""})
        (Path(work_dir) / steer.STEER_FILE).write_text(
            _json.dumps(msgs, ensure_ascii=False), encoding="utf-8")
        return {"queued": len(msgs), "dropped": 0, "id": msgs[-1]["id"]}

    steer.queue = _uncapped
if args.mutate == "steer-keeps-control-chars":
    steer.sanitize = lambda t: (t or "").strip()[:steer.MAX_TEXT]
if args.mutate == "steer-anonymous-turn":
    steer.render_user_turn = lambda msgs: "\n".join(m["text"] for m in msgs)


# ---------------------------------------------------------------------------
# 1. The queue.
# ---------------------------------------------------------------------------
tmp = Path(tempfile.mkdtemp(prefix="steer-test-"))
check("an empty queue reads as empty", steer.pending(tmp), [])

steer.queue(tmp, "  the instance is dead  ")
steer.queue(tmp, "check the oracle staleness")
check("two messages queue", len(steer.pending(tmp)), 2)
check("...whitespace is trimmed", steer.pending(tmp)[0]["text"], "the instance is dead")
check("...each carries an id", all(m.get("id") for m in steer.pending(tmp)), True)

# Reading MUST empty it. A queue that is read without being cleared re-delivers
# the same sentence at every turn boundary for the rest of the job.
took = steer.take(tmp)
check("take returns everything queued", len(took), 2)
check("...and CLEARS the queue", steer.pending(tmp), [])
check("...so a second take returns nothing", steer.take(tmp), [])

try:
    steer.queue(tmp, "   ")
    _empty_refused = False
except ValueError:
    _empty_refused = True
check("an empty message is refused, not queued as nothing", _empty_refused, True)

# The cap drops the OLDEST: past ten queued messages the early ones are the
# stale ones, and an operator who kept typing meant the later ones.
for i in range(steer.MAX_PENDING + 4):
    steer.queue(tmp, f"message {i}")
_p = steer.pending(tmp)
check("the pending queue is capped", len(_p), steer.MAX_PENDING)
check("...dropping the OLDEST, not the newest",
      _p[-1]["text"], f"message {steer.MAX_PENDING + 3}")
steer.take(tmp)

check("a long message is truncated, not rejected",
      len(steer.sanitize("x" * (steer.MAX_TEXT + 500))), steer.MAX_TEXT)
# A terminal-control sequence inside a prompt is a way to make the log lie
# about what was sent.
check("control characters are stripped", steer.sanitize("a\x00b\x1bc\td"), "abc\td")
check("...but tab and newline survive", "\n" in steer.sanitize("a\nb"), True)

# ---------------------------------------------------------------------------
# 2. The injected turn must name its author.
# ---------------------------------------------------------------------------
turn = steer.render_user_turn([{"text": "stop tuning the replica selector"}])
check("the turn says it is from the operator", "OPERATOR STEER" in turn, True)
check("...that it is a human, not an automated nudge",
      "not an automated nudge" in turn, True)
check("...and carries the message", "stop tuning the replica selector" in turn, True)
# Told to obey blindly, an agent that has REFUTED the instruction with evidence
# has nowhere to put that; told it may refuse, it will. The turn asks for both.
check("...it demands a change of course", "change what you are doing NOW" in turn, True)
check("...while leaving room to report an impossibility",
      "impossible" in turn and "cite the evidence" in turn, True)

# ---------------------------------------------------------------------------
# 3. PLACEMENT in the injection ladder, read from the shipped source.
# ---------------------------------------------------------------------------
import modules._common as _Cm  # noqa: E402

src = Path(_Cm.__file__).read_text(encoding="utf-8")
if args.mutate == "steer-above-final-draft":
    src = src.replace("# ---- FINAL_DRAFT last-chance injection ----", "# ---- moved ----", 1)
    src = "# ---- OPERATOR STEER ----\n" + src
if args.mutate == "steer-below-soft-eject":
    src = src.replace("# ---- OPERATOR STEER ----", "# ---- moved ----", 1)
    src = src + "\n# ---- OPERATOR STEER ----\n"


def at(marker: str) -> int:
    i = src.find(marker)
    return i if i >= 0 else 10**9


_final = at("# ---- FINAL_DRAFT last-chance injection ----")
_steer = at("# ---- OPERATOR STEER ----")
_soft = at("# ---- Soft-eject (budget 80%) user-turn injection ----")
_empty = at("# ---- EMPTY WAIT correction ----")

check("the ladder still has all four rungs",
      all(x < 10**9 for x in (_final, _steer, _soft, _empty)), True)
# FINAL_DRAFT exists to stop a run ending with nothing to show. An operator
# note is worth a turn; it is not worth the job's last one.
check("FINAL_DRAFT outranks the operator", _final < _steer, True)
# ...and everything automated is beneath the person watching the live log.
check("the operator outranks soft-eject", _steer < _soft, True)
check("...and EMPTY WAIT", _steer < _empty, True)

check("the rung records its origin so a job's history shows who steered it",
      '"hint_source": "operator"' in src and '"hint_origin": "steer"' in src, True)
check("a steering fault cannot end a turn",
      "steer read failed" in src, True)

# ---------------------------------------------------------------------------
# 4. The api refuses a job that can never read the message.
# ---------------------------------------------------------------------------
jobs_src = (ROOT / "api" / "routes" / "jobs.py").read_text(encoding="utf-8")
if args.mutate == "steer-allows-terminal-job":
    jobs_src = jobs_src.replace("_STEER_TERMINAL = {", "_STEER_TERMINAL = set() or {", 1)
    jobs_src = jobs_src.replace("if status in _STEER_TERMINAL:", "if False:", 1)

check("a terminal job is refused rather than silently queued",
      "if status in _STEER_TERMINAL:" in jobs_src, True)
_term = re.search(r"_STEER_TERMINAL = \{([^}]*)\}", jobs_src)
_terms = set(re.findall(r'"([a-z_]+)"', _term.group(1) if _term else ""))
# check() compares got == want, so a condition goes in as `got` against True.
# Written with the term list as `want` first, and the suite reported correct
# code as broken -- the second time this session that the negative/boolean
# argument slot has bitten, which is why these checks stay behavioural.
check(f"...and every finished state is in that set {sorted(_terms)}",
      {"finished", "stopped", "failed"} <= _terms, True)
# Sliced from the GUARD, not from the constant: `_STEER_TERMINAL` appears
# twice, so splitting on it and taking [1] lands between the definition and
# the guard -- before the message this is looking for.
_refusal = jobs_src.split("if status in _STEER_TERMINAL:", 1)[-1][:600]
check("the refusal points at the tool that DOES work after a job ends",
      "/retry" in _refusal, True)
check("the dashboard can see what has NOT been delivered",
      'async def steer_pending' in jobs_src, True)

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n== summary: {PASSED} passed, {FAILED} failed; "
      f"mutation={args.mutate or 'none'} ==")
raise SystemExit(1 if FAILED else 0)
