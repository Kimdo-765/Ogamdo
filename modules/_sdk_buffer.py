"""One ceiling for the SDK's stdout JSON buffer, and the measurement behind it.

The Agent SDK accumulates each CLI message in a string and raises
``SDKJSONDecodeError`` once it passes ``max_buffer_size`` -- 1 MB by default
(``claude_agent_sdk/_internal/transport/subprocess_cli.py``). That error is
NOT a tool failure the agent can see and retry: it propagates out of
``receive_messages()`` and ends the whole session.

Job a6d33960680b died there, on an OSINT challenge whose entire task is to
LOOK at a photograph. The agent did the careful thing -- it downscaled the
3,305,640-byte PNG to a 630,721-byte JPEG before reading it -- and the read
still produced a message over 1,048,576 bytes. Measured expansion is at least
1.66x, more than base64's 1.33x, so the CLI inflates an image beyond a plain
encode. The exact factor was NOT established; this ceiling does not depend on
knowing it, and no code here should claim otherwise.

The image was never the problem. 1556x1061 is inside the API's own limit and
costs ~2,200 tokens to view. The transport refused to carry what the model
would have read for one percent of its context.

WHY A NUMBER AND NOT "UNLIMITED"

Images are the trigger because ``Read`` passes them whole; Bash output is
truncated by the CLI before it ever reaches here, which is why pwn/rev/web
jobs ran 3,900 tool calls without meeting this wall. 8 MB carries a ~2 MB
artifact at the measured expansion and still bounds a runaway. The buffer is
transient per message, not a per-session reservation.
"""

AGENT_MAX_BUFFER_BYTES = 8 * 1024 * 1024

# ---------------------------------------------------------------------------
# WHAT THE CORPUS SAYS ABOUT THIS CEILING, AND WHY THERE IS NO SPILL
# ---------------------------------------------------------------------------
# `strix/tools/output_store.py` implements the pattern this repo has twice
# considered: bound an oversized tool result, hand the agent a head+tail slice
# plus a path, let it read the rest with its own file tools. Measured against
# every Read call in the corpus (from run.log -- sdk.jsonl under-captures Read
# and reports only 2 of the 131), it has nothing here to bound:
#
#     Read calls            131 (119 still on disk)
#     TEXT reads              2, largest 20,407 B, none over 100 KB
#     IMAGE reads           117, largest 4,662,046 B, 33 over 1 MB
#
# Zero large text reads, and an image is the one result spill must NOT touch:
# the model needs the pixels, not a path to them. Bash never reaches this
# buffer oversized either -- the CLI truncates it first, which is why ~3,900
# tool calls across pwn/rev/web never met the 1 MB wall and an image Read did.
#
# SIZE ON THE WIRE IS NOT FILE SIZE. The CLI downscales an image whose long
# edge exceeds 1568 px, so the big ones are cheap; the expensive ones are just
# under that line and travel whole. Of 111 distinct images read, 75 are
# <=1568 px. The largest of those is 3,305,640 B -> 4.41 MB of base64, which
# is what this ceiling actually has to carry. 4,662,046 B rgrid.png reads fine
# under a 6 MB ceiling precisely because it is 2051 px and gets resized.
#
# So 8 MB holds the worst measured case at roughly 55% headroom. An earlier
# note in this session claimed ~250 KB of headroom by applying the 1.663x
# expansion (measured on a 630 KB, 1556 px JPEG) to a 4.66 MB file. That was
# wrong: the 4.66 MB file is downscaled and the expansion does not apply to
# it. Corrected here so the number is not repeated.
