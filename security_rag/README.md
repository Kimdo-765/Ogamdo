# Security RAG

`security_rag` is a standalone, standard-library Python package for finding
security techniques and the evidence that connects them. It keeps the source
documents, search index, and relationship graph separate from the language
model. Ogamdo and a local Strata model can use the same JSON results and
rendered context.

The core path is:

```text
root cause → primitive/capability → technique → outcome
                  ↑                    ↑
             preconditions       blockers/alternatives
```

Every relationship should be read as a documented observation or a candidate
for investigation. Sharing a document, keyword, or graph neighbor does not by
itself establish that a technique works in a different target.

## Install and try it

The package requires Python 3.10 or newer. From the Ogamdo repository root:

```sh
python3 -m pip install -e ./security_rag
security-rag sync-exploits \
  --library ./data/exploits --db ./data/security-rag.sqlite \
  --collection ogamdo
security-rag search \
  --db ./data/security-rag.sqlite --collection ogamdo \
  --module pwn --query 'use-after-free arbitrary read' --limit 5
security-rag explore \
  --db ./data/security-rag.sqlite --collection ogamdo \
  --node arbitrary-read --depth 2
security-rag related \
  --db ./data/security-rag.sqlite --collection ogamdo \
  --node uaf --kind technique --limit 10
security-rag context \
  --db ./data/security-rag.sqlite --collection ogamdo \
  --query 'use-after-free arbitrary read' \
  --node uaf --kind technique
```

`sync-exploits`, `search`, `explore`, and `related` print JSON. `related`
ranks directly supported links separately from concepts that merely occur in
the same case. The latter are labeled `co_observed`; they are research leads,
not evidence that one technique enables another. `context` prints a bounded
plain-text evidence block suitable for a prompt. Its text is reference data,
not a set of instructions for an agent. With `--node`, it includes related
concepts and explicitly marks `co_observed` as a same-case association with
no causal link established.

When the original Ogamdo job directories still contain structured findings,
add `--source-jobs ./data/jobs` to `sync-exploits`, `watch-exploits`, or
`upsert-exploit`. The report-only path still works after job cleanup.

For a long-running local indexer, `watch-exploits` checks for changes every
15 seconds by default and periodically performs a full reconciliation:

```sh
security-rag watch-exploits \
  --library ./data/exploits --db ./data/security-rag.sqlite \
  --interval 15
```

Hosts that already receive save/delete events can update one case directly:

```sh
security-rag upsert-exploit \
  --entry ./security_rag/examples/pwn-example --db ./data/security-rag.sqlite
security-rag delete-case \
  --id pwn-example --db ./data/security-rag.sqlite --collection ogamdo
```

The example entry contains fictional data. For production, point `--entry` to
an existing library entry after Ogamdo saves or imports it.

## How a query is matched

A query is split into the concepts it names. `uaf` and `use after free` are
one concept, matched as a phrase rather than as the words *use*, *after* and
*free*; English words are stemmed, so `heap overflows` finds `heap-overflow`.
Korean terms are matched inside longer words (`취약점` in `취약점을`) and common
ones are also tried in English (`힙 오버플로우` → `heap overflow`), because the
library's metadata keys are English.

A passage is returned only if it contains enough of those concepts: the one
concept of a one-concept query, otherwise at least two and at least half. A
question about something the library has not seen returns no hits, and
`context` then renders nothing, instead of the least-bad passage. Each hit
lists the concepts it matched in `matched_terms`.

`scripts/eval_search.py --db <index>` reports precision and reciprocal rank
for a fixed query set, using each case's own `bug_classes` and
`technique_name` as labels. Run it before and after changing the matcher.

## Fill in primitives and outcomes for saved reports

Ogamdo records what a bug gave the attacker only for pwn, and only for
entries saved after that field was harvested. For everything else,
`backfill` asks a chat model to pick primitives and outcomes from a fixed
vocabulary (`security_rag/vocab.py`) and to quote the report for each:

```sh
security-rag backfill \
  --library ./data/exploits \
  --base-url http://127.0.0.1:47831/v1 --model iq3_s \
  --api-key-file ~/.apikey/strata.key
```

A label is kept only when its quote is found in the report; that location is
the line span the graph cites. The result is written to
`<library>/../security-rag-extracted/<id>.json`, bound to the report's hash;
the library itself is only read. (Ogamdo writes entries from a container, so
a host user usually cannot write inside them.) Unlike the SQLite index, these
files cost model time to recreate: keep them when rebuilding the index. The
next sync turns it into `candidate` links: bug class → primitive → technique
→ outcome. Entries that already have a current result are skipped, so
the command can be rerun after new saves or an interruption. `--no-reasoning`
is about four times faster on a thinking model and finds fewer labels.

## Use it with a local Strata model

The `answer` command retrieves evidence, renders a bounded context, and sends
it to an OpenAI-compatible chat endpoint. Run this example on the host, where
`127.0.0.1` refers to the local model service:

```sh
security-rag answer \
  --db ./data/security-rag.sqlite \
  --collection ogamdo \
  --query 'Which documented techniques relate to use after free?' \
  --node uaf --kind technique \
  --base-url http://127.0.0.1:47831/v1 \
  --model iq3_s
```

If the endpoint requires authentication, provide its key through the
`SECURITY_RAG_API_KEY` environment variable. The CLI does not accept a key
argument or store it in the index. Inside Docker, `127.0.0.1` points at that
container, so use a reachable host address or run the command on the host.
This adapter calls only the chat endpoint; retrieval and relationship analysis
remain independent of the generation backend. The prompt receives the same
`co_observed` qualification as `context`; the model must treat it as a lead to
check, not as a proven exploit chain.

## Serve retrieval to a remote Strata host

Run the indexer and the read-only HTTP server as separate processes. The
server returns evidence and graph results as JSON; Strata can use the returned
context with its own model without copying the SQLite index or calling the
model endpoint from Ogamdo.

On this Ogamdo host, the server is installed as the `security-rag.service`
user service. Control that service with the included script:

```sh
./security_rag/rag-server.sh start
./security_rag/rag-server.sh status
./security_rag/rag-server.sh stop
```

The script controls the HTTP server only. The incremental index watcher and
the Cloudflare tunnel have separate services. `stop` affects the current
session; the server's existing boot-time enablement remains in place.

```sh
export SECURITY_RAG_SERVER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
security-rag serve \
  --db ./data/security-rag.sqlite --host 127.0.0.1 --port 8765
```

The token is independent of `SECURITY_RAG_API_KEY`, which authenticates the
optional model endpoint. Store and distribute the server token securely, and
provide the same value to the Strata client. An authorized client can request
a bounded prompt context like this:

```sh
curl -fsS http://127.0.0.1:8765/v1/context \
  -H "Authorization: Bearer ${SECURITY_RAG_SERVER_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"query":"use-after-free arbitrary read","node":"uaf","kind":"technique","collection":"ogamdo","limit":5}'
```

The server also provides `POST /v1/search`, `/v1/related`, and `/v1/explore`,
plus `GET /healthz`. Search and graph responses retain their source locators
and relationship status, including `co_observed`. Index updates remain local
through `sync-exploits`, `watch-exploits`, or the host's save events; the HTTP
API has no ingestion or deletion route.

The dependency-free [`examples/strata_remote_client.py`](examples/strata_remote_client.py)
can be copied to the Strata host. Configure `SECURITY_RAG_URL` with the HTTPS
origin and `SECURITY_RAG_SERVER_TOKEN` with the separate RAG token, then call
`fetch_context(question, node="uaf", kind="technique")`. It returns the
bounded model context together with cited hits and relationship statuses.
The model request stays inside Strata. For a command-line check on that host:

```sh
python3 strata_remote_client.py \
  --query 'Which documented techniques relate to use after free?' \
  --node uaf --kind technique
```

`127.0.0.1` in the example is reachable only on the Ogamdo host. For remote
Strata, expose the loopback server through a private VPN or an HTTPS reverse
proxy/tunnel, then configure Strata with that reachable RAG URL and the server
token. The local model URL `http://127.0.0.1:47831/v1` is a separate service
and does not provide the RAG URL. Remote network reachability depends on the
chosen VPN or proxy configuration.

## Ingest cases from another platform

Any platform can export one JSON case per line and ingest it without importing
Ogamdo code. A synthetic input template is in
[`examples/strata_cases.jsonl`](examples/strata_cases.jsonl).

```sh
security-rag ingest-jsonl \
  --file ./security_rag/examples/strata_cases.jsonl \
  --db ./data/security-rag.sqlite --collection strata
security-rag search \
  --db ./data/security-rag.sqlite --collection strata \
  --query 'authorization check bypass'
```

Add `--replace-missing` to `ingest-jsonl` only when the file is a complete
snapshot of that collection. It removes indexed cases in that collection that
are absent from the file.

The collection name is a namespace. A stable case ID within that namespace
lets a later export update the same case. The index may hold several platform
collections at once; pass `--collection` when the caller needs isolation.
The example file is fictional test data; no Strata repository or source-data
integration is present in this workspace.

Each JSONL line is one case with these fields:

| Field | Meaning |
| --- | --- |
| `id`, `title`, `body` | Stable ID within the collection, display title, and searchable source text |
| `source_type`, `source_uri` | Provenance such as `research_note` and a source locator or URL |
| `module`, `metadata` | Optional domain label and additional structured properties supplied by the host |
| `relations` | Source-backed or candidate links between concepts |

`relations` is a list of objects shaped like this:

```json
{
  "from": {"kind": "root_cause", "label": "missing ownership check"},
  "type": "produces",
  "to": {"kind": "primitive", "label": "cross-account read"},
  "status": "observed",
  "evidence": {"section": "Root Cause", "line_start": 1, "line_end": 4},
  "conditions": ["authenticated requester"]
}
```

Use `verified` for separately checked links, `observed` for links stated in
the cited case, `candidate` for hypotheses, and `taxonomy` for catalog
relationships. These are caller-supplied labels; the package preserves them
and their evidence instead of treating every link as validated.

Python callers can use the same interface:

```python
from security_rag import RagIndex, render_context

index = RagIndex("./data/security-rag.sqlite")
index.sync_exploit_library(
    "./data/exploits", collection="ogamdo", source_job_root="./data/jobs"
)
hits = index.search(
    "use-after-free arbitrary read", module="pwn", collection="ogamdo", limit=5
)
links = index.related("uaf", kind="technique", collection="ogamdo")
context = render_context(hits, links=links)

# A Strata exporter can call index.upsert_case(case_dict, collection="strata")
# and index.delete_case(case_id, collection="strata") instead of writing JSONL.
```

`source_job_root` is optional. When the original source job and its structured
findings are still present, the Ogamdo adapter can use those findings to add
more precise observed labels for weaknesses and primitives. The saved report
remains sufficient when the source job has been deleted.

Search results are provider-neutral JSON with `case_id`, `collection`, `title`,
`source_type`, `source_uri`, `module`, `section`, `heading_path`, `line_start`,
`line_end`, `excerpt`, `score`, `matched_terms`, and `metadata`. `explore` returns `query`, `nodes`, and
`edges`, following causal links only unless `--include-cases` (HTTP:
`"include_cases": true`) is given; each edge has `source`, `type`, `target`, `status`, `conditions`, and
`supports`. The same result can be passed to a local open-weight model or
another generation backend. The retriever itself does not call a
generation-model SDK.

## Incremental indexing

`data/exploits/<id>/` remains Ogamdo's source of truth. `sync-exploits`
compares each entry's content fingerprint to the indexed revision and processes
new or changed entries. It removes entries that disappeared from the source
collection. Re-running it against unchanged data is safe. Importing a batch or
editing files directly only requires another sync; `watch-exploits` performs
that reconciliation continuously. Event-driven callers may use `upsert-exploit`
and `delete-case` after Ogamdo's save, overwrite, import, and delete actions.

An updated case replaces its own excerpts and relationship evidence. Shared
relationships remain available while another case still supports them. The
SQLite file is derived data and can be rebuilt from the source documents.

## Evidence and boundaries

The Ogamdo adapter reads `meta.json` and `report.md`. It uses report sections
as searchable evidence and records the source entry and section so a result can
be checked against the original. The adapter redacts captured flags and known
target values before they enter the index or prompt context. Keep raw reports
and scripts in the source library; do not distribute them as if the redacted
index were a sanitized archive.

The relationship graph distinguishes source-backed observations from inferred
links. Inspect the cited passage and the target's preconditions before using a
link as a research conclusion. A missed or weakly expressed relationship in a
report may remain a text-search result without becoming a graph edge.

The package does not make Ogamdo's current local model a full job-solving
agent. Ogamdo currently routes its local model only to the monitor role; a
separate main-agent runtime adapter is needed for that use case. The `answer`
command provides a standalone retrieval-and-answer path through the local
model endpoint.
