/**
 * A model in the catalog must be a model that exists.
 *
 * WHY THIS EXISTS
 *
 * The operator asked for the newest models to appear in the Settings
 * dropdowns. Probing for them on 2026-09-05 produced a trap worth encoding.
 *
 * `codex exec --model X "Reply: PROBE_OK"` ANSWERS for slugs that do not
 * exist. Eight invented `gpt-6-*` names all returned a correct reply, and so
 * did `gpt-6-zzz-fake`. The CLI prints
 *
 *     warning: Model metadata for `X` not found. Defaulting to fallback
 *     metadata; this can degrade performance and cause issues.
 *
 * and then serves the request from a fallback. A success probe therefore
 * proves NOTHING; only the absence of that warning distinguishes a real model
 * from a silent downgrade. Adding those eight would have put seven inventions
 * into a catalog whose stated convention is verified-only.
 *
 * Three outcomes, and the middle one is why nothing is deleted casually:
 *   OK       answered, no metadata warning.
 *   ACCOUNT  400 "not supported when using Codex with a ChatGPT account" —
 *            the model EXISTS, this auth cannot reach it. Keep and mark.
 *   UNKNOWN  metadata warning — not in the CLI's catalogue. Must not ship.
 *
 * Verified this way: gpt-6-astra is real and works; gpt-6-astra-mini and
 * -codex are real but need an API key; `gpt-6`, `gpt-5.6` and `gpt-5.4` are
 * UNKNOWN and were removed. `gpt-5.6` had sat here labelled "the Responses
 * API flagship alias" while codex had no metadata for it at all.
 *
 * Run:
 *   node scripts/test_model_catalog.js
 *   node scripts/test_model_catalog.js --mutate readd-unknown
 */
const fs = require("fs");
const path = require("path");

const MUTATIONS = [
  "none",
  "readd-unknown",      // a slug the CLI has no metadata for is back in the list
  "drop-account-gated", // a real-but-API-key-only model is deleted instead of marked
  "no-astra",           // the newest verified model is missing
  "no-fable-51",        // the Claude list loses the model verified alongside it
  "lose-the-lesson",    // the comment stops warning that a probe can lie
];
const _mi = process.argv.indexOf("--mutate");
const MUTATE = _mi > -1 ? process.argv[_mi + 1] : "none";
if (!MUTATIONS.includes(MUTATE)) {
  console.error(`unknown mutation ${MUTATE}; one of ${MUTATIONS.join(", ")}`);
  process.exit(2);
}

const ROOT = path.resolve(__dirname, "..");
let app = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");
const _a0 = app;

if (MUTATE === "readd-unknown") {
  app = app.replace('  "gpt-6-astra",', '  "gpt-6-astra",\n  "gpt-5.6",');
} else if (MUTATE === "drop-account-gated") {
  app = app.replace('  "gpt-6-astra-mini",         // ACCOUNT — real, needs an API key\n', "");
} else if (MUTATE === "no-astra") {
  app = app.replace('  "gpt-6-astra",              // OK — newest, works on ChatGPT OAuth\n', "");
} else if (MUTATE === "no-fable-51") {
  app = app.replace('  "claude-fable-5-1",\n', "");
} else if (MUTATE === "lose-the-lesson") {
  app = app.replace("// HOW THE UNKNOWNS WERE CAUGHT, because a plain probe cannot:",
                    "// Models were probed:");
}
if (MUTATE !== "none" && app === _a0) {
  console.error(`MUTATION ${MUTATE} CHANGED NOTHING — its anchor no longer matches.`);
  process.exit(2);
}

let PASS = 0, FAIL = 0;
function check(label, got, want = true) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a === b) PASS++;
  else { FAIL++; console.log(`FAIL  ${label}\n        got  = ${a}\n        want = ${b}`); }
}

function listOf(name) {
  const m = new RegExp(`const ${name} = \\[([\\s\\S]*?)\\n\\];`).exec(app);
  if (!m) return null;
  // Strip line comments FIRST. The block ends with a note recording which
  // slugs were removed — and it names them in quotes, so a naive extraction
  // reported the removed models as still present and the suite failed against
  // its own documentation.
  const code = m[1].split("\n").map((l) => l.replace(/\/\/.*$/, "")).join("\n");
  return [...code.matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

const GPT = listOf("GPT_MODELS");
const CLAUDE = listOf("CLAUDE_MODELS");
const GROK = listOf("GROK_MODELS");

// Measured 2026-09-05 against codex-cli 0.153.1. UNKNOWN = the CLI printed
// "Model metadata for `X` not found".
const UNKNOWN_SLUGS = ["gpt-6", "gpt-5.6", "gpt-5.4"];
const VERIFIED_OK = ["gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna",
                     "gpt-daybreak-blue-latest", "gpt-5.5", "gpt-5.4-mini",
                     "gpt-5.3-codex-spark"];
const ACCOUNT_GATED = ["gpt-6-astra-mini", "gpt-6-astra-codex"];

check("the three lists parse", [GPT, CLAUDE, GROK].every(Boolean));

// --- the core rule ---------------------------------------------------------
for (const slug of UNKNOWN_SLUGS) {
  check(`a slug with no CLI metadata is not offered: ${slug}`, GPT.includes(slug), false);
}
for (const slug of VERIFIED_OK) {
  check(`a verified-working model is offered: ${slug}`, GPT.includes(slug));
}
// Existing-but-unreachable is a different thing from non-existent. Deleting
// these would remove a choice that works wherever an API key is configured.
for (const slug of ACCOUNT_GATED) {
  check(`an account-gated but REAL model is kept: ${slug}`, GPT.includes(slug));
  check(`...and marked so the operator knows why it fails`,
    new RegExp(`"${slug.replace(/\./g, "\\.")}",\\s*//\\s*ACCOUNT`).test(app));
}

// --- the newest model leads ------------------------------------------------
check("gpt-6-astra is first — the newest verified model leads the list",
  GPT[0], "gpt-6-astra");
check("claude-fable-5-1 was added", CLAUDE.includes("claude-fable-5-1"));
check("...with its long-context variant", CLAUDE.includes("claude-fable-5-1[1m]"));
check("...ahead of plain fable-5",
  CLAUDE.indexOf("claude-fable-5-1") < CLAUDE.indexOf("claude-fable-5"));

// --- grok was fully verified, including the slow one -----------------------
check("every grok entry survived probing", GROK.length, 6);
check("grok-4 is kept — it was slow, not missing", GROK.includes("grok-4"));
check("...and the comment says so, so nobody trims it later",
  /grok-4.*(slow, not missing|150s)/s.test(app));

// --- the lesson has to stay readable --------------------------------------
// This is the part a future edit is most likely to drop, and dropping it is
// how the next person re-probes with a success test and re-adds inventions.
// AND, not OR. The two sentences carry different halves of the lesson —
// "a probe cannot detect this" and "success is not evidence" — and an OR let
// the mutation delete one while the other kept the check green.
check("the comment says a plain probe cannot catch an unknown slug",
  /a plain probe cannot/.test(app));
check("...and that a successful answer is not evidence",
  /Success proves nothing/.test(app));
check("...naming the fake slug that proved it", /gpt-6-zzz-fake/.test(app));
check("...and the warning string to look for", /Model metadata/.test(app));
check("the removal of the unknowns is recorded, not silent",
  /Removed 2026-09-05/.test(app));

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
