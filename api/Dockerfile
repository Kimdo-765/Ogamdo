FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Node + Claude/Codex CLIs — retry, judge, report and monitor turns may run
# directly inside the api container. Claude is PINNED to >=2.1.156
# (fixes the opus-4-8 thinking-block API 400); the SDK is made to use this
# system CLI via the bundle-removal step after pip install below.
ARG CLAUDE_CLI_VERSION=latest
ARG CODEX_CLI_VERSION=latest
ARG GROK_CLI_VERSION=latest
COPY scripts/install-agent-clis.sh /usr/local/libexec/install-agent-clis.sh
# Node 22, not 20: @anthropic-ai/claude-code declares
# engines.node ">=22.0.0" from 2.1.2xx on, and the installer runs npm with
# engine-strict, so a Node-20 base fails the BUILD (correctly) the first
# time the resolver picks up a current Claude release. Observed here the
# moment the pin moved 2.1.158 -> 2.1.258: EBADENGINE, build aborted, old
# images left in place. Codex only needs >=16, so 22 satisfies both.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && CLAUDE_CLI_VERSION="$CLAUDE_CLI_VERSION" \
    CODEX_CLI_VERSION="$CODEX_CLI_VERSION" \
    GROK_CLI_VERSION="$GROK_CLI_VERSION" \
    /usr/local/libexec/install-agent-clis.sh

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Remove the SDK's stale bundled `claude` CLI so the transport falls through to
# the npm system CLI pinned above (>=2.1.156). The bundle (SDK 0.2.87 -> CLI
# 2.1.150) still triggers the opus-4-8 thinking-block API 400. The /retry +
# reviewer turns run here too, so the api needs the same fix as the worker.
# memory: sdk_bundled_cli_thinking_400.
RUN find /usr -type f -path "*/claude_agent_sdk/_bundled/claude" -delete 2>/dev/null; \
    echo "SDK bundled CLI removed; system CLI = $(command -v claude) / $(claude --version 2>&1)"

COPY api /app/api

# Same sandbox flag the worker sets so the bundled claude CLI accepts
# --dangerously-skip-permissions even though api runs as root.
ENV IS_SANDBOX=1

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
