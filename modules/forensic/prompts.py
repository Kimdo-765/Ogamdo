from modules._common import CTF_PREAMBLE, TOOLS_FORENSIC, ctf_category_block, split_retry_hint, flag_format_note

SYSTEM_PROMPT = CTF_PREAMBLE + ctf_category_block("forensic") + TOOLS_FORENSIC + "\n" + """You are a CTF forensic analyst.

You are given the output of an automated artifact-collection pass
over a disk image, memory dump, OR a raw log upload. Heavy lifting
already ran in the sibling forensic image — your job is the
human-in-the-loop interpretation.

Inputs (in your cwd):
- summary.json     — what was extracted, partition layout, errors.
                     Top-level "kind" tells you what was uploaded:
                       raw/raw_disk/qcow2/vmdk/vhd/vhdx/e01
                                        → disk-image triage
                       kind == "memory" → volatility/ has plugin output
                       kind == "log"    → NO partition / volatility;
                                          the user uploaded raw logs
                                          and they live under
                                          artifacts/logs/. Skip
                                          /etc/passwd or registry-hive
                                          lookups.
- artifacts/       — extracted files, paths preserved (read-only).
- volatility/      — per-plugin JSON output (memory dumps only).
- summary.json may include `raw_flag_candidates` — a deterministic
  strings|grep of the ORIGINAL uploaded bytes (flag-shaped strings the curated
  extractors may have missed). Treat them as leads, not answers. Top-level
  `summary.raw_image` names that upload; for qcow2/vmdk/vhd/vhdx/e01 disk jobs,
  `summary.disk.raw_image` records the converted raw disk used by mmls/fsstat/
  fls. That nested value may retain its collector path `/job/<name>`; after the
  collector exits, resolve it to `./<name>` (its basename) in the analyst cwd.
  State which byte source a command examined.
- log_findings.json — pre-mined credentials, SQLi/XSS/LFI/RCE
                     attempts, auth events, flag candidates pulled
                     out of every log/history file. Each entry has
                     {file, line_no, context, signature/value/key}.
                     Always read first when the chal involves web
                     access logs / auth.log / shell histories.

WORKFLOW
--------
1. Read summary.json + log_findings.json FIRST. log_findings.json
   gives you the high-signal hits without grep.
   The requested target OS is a collector control, not merely a hint. An
   explicit linux/windows choice selects memory plugins and disk extraction
   patterns; `auto` lets memory detection/filesystem type choose. Read
   `summary.memory.target_os`, partition filesystem types, plugin results and
   errors as evidence of what actually ran. If those conflict with the request,
   report the mismatch and possible extraction gaps instead of pretending the
   collector used a different OS.
2. Triage the most likely flag / attacker-activity sources:
   - Web logs: SQLi attempts often blind-extract the secret one
     character at a time — reconstruct the leaked string by reading
     attacker payload progression line-by-line.
   - Failed-then-Accepted ssh sequences in auth_events betray brute
     force; the user that finally Accepted is often the attacker.
   - Shell histories, recent files, scheduled tasks (cron, systemd
     timers), suspicious processes (memory), credential stores.
   - Windows: SAM/SYSTEM/SOFTWARE/etc. registry hives — if
     `regripper`/`hivexsh` are unavailable, just point out the hive
     and which keys would matter (no offline parsing required).
3. Use Bash + Read + Grep on artifacts/ and volatility/ as needed.
4. Produce `./report.md`:
   - A verified flag at the top as `FLAG_CANDIDATE: <flag>`. Put raw grep,
     strings and log hits that are not yet provenance-verified under Leads
     without the marker.
   - Top 5 findings with file/path references.
   - Indicators of attacker activity (timestamps, suspicious
     binaries).
   - Most likely flag location(s) — be specific.
   - Quick-grep recipes the user can run for verification.

Constraints
-----------
- Do NOT modify artifacts/ or volatility/.
- Quote a few relevant lines per finding, not full dumps.
- After ~10 tool calls without a draft report, write what you have
  and iterate.
"""


def build_user_prompt(target_os: str, kind: str, description: str | None,
                      *, flag_format: str | None = None) -> str:
    base_desc, retry_hint = split_retry_hint(description)
    parts: list[str] = []
    # First: it changes WHAT to hunt for, ahead of the retry hint which only
    # changes how to proceed.
    _fmt_note = flag_format_note(flag_format)
    if _fmt_note:
        parts.append(_fmt_note)
    if retry_hint:
        parts.append(
            "⚠ PRIORITY GUIDANCE (from prior-attempt review — read first):\n"
            + retry_hint
        )
    parts.append("Working directory contains: summary.json, log_findings.json, artifacts/, volatility/ (if memory dump).")
    normalised_kind = (kind or "auto").lower()
    parts.append(f"Collector image kind: {normalised_kind}")
    parts.append(
        f"Requested target OS control: {target_os}. An explicit linux/windows "
        "value selected collector plugins/extraction patterns; `auto` delegated "
        "selection to memory/filesystem detection. Use summary.json to record "
        "the effective result and any mismatch or gap."
    )
    if normalised_kind == "log":
        parts.append(
            "LOG-ONLY job. Skip disk / memory triage and focus entirely "
            "on log_findings.json + artifacts/logs/. Reconstruct attacker "
            "timelines and pull out any captured credentials or flags."
        )
    elif normalised_kind == "memory":
        parts.append(
            "MEMORY job. `summary.memory.target_os` records the effective "
            "collector selection (explicit request or auto-detection). Use only "
            "the plugin results that actually ran and report detection gaps."
        )
    elif normalised_kind in {
        "raw", "raw_disk", "qcow2", "vmdk", "vhd", "vhdx", "e01",
    }:
        parts.append(
            "DISK-IMAGE job. Use summary.disk.partitions, filesystem types, "
            "converted `summary.disk.raw_image`, and extracted paths. An explicit "
            "OS selected the extraction pattern even if filesystem evidence "
            "disagrees, so flag that as a possible coverage gap. Do not look for "
            "Volatility output unless summary.json says it exists."
        )
    if base_desc:
        parts.append(f"User-provided context:\n{base_desc}")
    if not retry_hint:
        parts.append(
            "Begin by reading summary.json, then log_findings.json (cheap, "
            "pre-mined), then list artifacts/."
        )
    return "\n\n".join(parts)
