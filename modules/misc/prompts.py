from modules._common import CTF_PREAMBLE, TOOLS_MISC, ctf_category_block, split_retry_hint

SYSTEM_PROMPT = CTF_PREAMBLE + ctf_category_block("misc") + TOOLS_MISC + "\n" + """You are a CTF misc challenge solver.

When a file was uploaded, you are given the output of an automated tool sweep
over it. Heavy carving already ran in the sibling misc image; interpret and
extend it selectively. A job may instead be description-only, target-only, or
both. In that mode there is no sweep to assume: classify the puzzle/service
from its observed behaviour and work directly from the supplied context.

File-backed inputs (in your cwd when present):
- findings.json — file type, exiftool, strings/flag candidates, zsteg,
                  steghide, binwalk extracted file list, pdfinfo,
                  archive listing, etc.
- extracted/    — anything binwalk/steghide pulled out (read-only)
- analyze.log   — raw tool output trail

WORKFLOW
--------
1. If findings.json exists: Read findings.json FIRST. Note any flag candidates already found.
   The sweep records raw regex matches, including possible examples/placeholders,
   so every surfaced value still needs derivation and context verification.
   If it does not exist, inventory the current directory and probe the supplied
   target/context with the cheapest format- or protocol-identifying test.
2. If a flag-shaped candidate is present, verify its derivation and semantic
   context. Put a verified value at the top of report.md; keep an unverified
   hit under leads and continue. Prefix shape alone is not a stop condition.
3. No verified flag? Go one level deeper: Read/Bash/Grep on extracted/
   and the file types that look anomalous (PNG with appended data,
   PDFs with hidden streams, archives with extra entries).
4. List the top suspicious leads:
   - Embedded files of unusual type
   - Anomalous LSB / channel-XOR output (the sweep tried common bits; if
     findings.json hints at a specific plane/channel, re-run it TARGETED
     via `python3 -m worker.misc_recarve zsteg …` — see Constraints)
   - exif fields with hidden text
   - Append-after-EOF data
5. Produce `./report.md`:
   - A verified flag at the top as `FLAG_CANDIDATE: <flag>`; put suspected or
     unverified values under a clearly labelled Leads section without the marker
   - Exact input-to-output derivation for every decoded/carved layer
   - 1-3 promising leads with concrete commands the user can run to verify
   - Tools tried + verdict for each (1-line per tool)

Constraints
-----------
- Quote a line or two per finding, NOT full dumps.
- Don't BLINDLY re-run the whole sweep (findings.json already has it),
  but a TARGETED re-run the sweep DIDN'T do IS available: the heavy tools
  (zsteg / steghide / binwalk / foremost / outguess / 7z /
  pdftotext) are NOT in your container but ARE in the sibling misc image —
    python3 -m worker.misc_recarve <tool> [args...]   # files at /job/<name>
  Use it for a specific zsteg bit-plane, `steghide extract -p <passphrase
  you discovered>`, an offset/format-specific binwalk, etc.
- After ~10 tool calls without a draft report, write what you have
  and iterate.
"""


def build_user_prompt(filename: str | None, description: str | None, flag_format: str | None = None) -> str:
    base_desc, retry_hint = split_retry_hint(description)
    parts: list[str] = []
    if (flag_format or "").strip():
        where = (
            "in findings.json / extracted/ and the original artifact"
            if filename else
            "in the supplied description, live protocol and any concrete files present"
        )
        parts.append(
            f"Expected flag format: {flag_format.strip()} — the flag matches "
            "this shape. The standard-prefix sweep may MISS it, so hunt for it "
            f"specifically {where}. Print it as `FLAG_CANDIDATE: <flag>` only "
            "after its derivation and challenge context verify it; matching the "
            "shape alone is not success."
        )
    if retry_hint:
        parts.append(
            "⚠ PRIORITY GUIDANCE (from prior-attempt review — read first):\n"
            + retry_hint
        )
    if filename:
        parts.append(f"Input filename: {filename}")
        parts.append("Working directory contents: findings.json, extracted/, analyze.log")
    else:
        parts.append(
            "No input file was provided for this job — there is no misc tool "
            "sweep (findings.json) to read. Work from the user-provided context "
            "below and any files already present in the working directory."
        )
    if base_desc:
        parts.append(f"User-provided context:\n{base_desc}")
    if not retry_hint and filename:
        parts.append("Begin by reading findings.json.")
    return "\n\n".join(parts)
