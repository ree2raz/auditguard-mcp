---
title: AuditGuard MCP
emoji: 🔒
colorFrom: blue
colorTo: gray
sdk: docker
pinned: false
license: mit
---

# auditguard-mcp

A reference implementation of a compliance-aware AI tool gateway. When an LLM calls a tool (e.g., `sql_query`), that call passes through a 7-stage audit pipeline before execution — and the result passes through it again before returning. Every stage is pluggable, every decision is logged, and no raw PII leaves the system.

Built on OpenAI's Privacy Filter (1.5B params, April 2026), running locally on CPU. This is not a library you install — it's a complete system demonstrating how to build production-grade AI safety infrastructure for regulated industries.

**Live demo:** [![Live Demo](https://img.shields.io/badge/Live-Demo-blue)](https://auditguard.rituraj.info)

## Why this exists

This is a portfolio artifact — a self-contained system that demonstrates how I think about architecture, security, and infrastructure for AI systems handling sensitive data. Every design decision is intentional and documented. The code is the documentation.

## What it demonstrates

### Architecture — Ports and Adapters

The pipeline uses a ports-and-adapters (hexagonal) pattern. Stage logic lives in `pipeline/stages.py` as pure functions — no IO, no framework dependencies, easy to test. Each orchestration backend (`async_runner.py`, `temporal_runner.py`) is a thin adapter that calls those functions in sequence. Adding a third backend (e.g., AWS Step Functions) is ~100 lines of adapter code.

The design is **fail-closed**: unparseable SQL always triggers `RBACDenied`, missing policy categories default to `ALLOW` explicitly, and audit records never contain raw PII.

See [`docs/architecture.md`](docs/architecture.md) for the full design rationale.

### PII Detection — Local 1.5B Model

Most PII detection in production is regex. Regex catches SSNs and emails but misses contextual PII: "the Henderson trust's primary contact" has no syntactic pattern, but a token classifier identifies "Henderson" as a `private_person` span.

This project integrates OpenAI's Privacy Filter — a 1.5B-parameter bidirectional token classifier supporting 8 PII categories. It runs locally on CPU, no data sent to any API. We built robust BIOES span decoding (`privacy.py`) to map token predictions back to exact character offsets — the unglamorous part most integrations skip.

The model occasionally over-redacts public entities and flags numeric financial values (e.g., `496959.67`) as phone numbers. We handle this with a post-detection numeric guard in `policy.py` rather than trying to force the model to behave differently — detection is a primitive, not a pipeline.

### Security — RBAC, Policy Engine, Audit Trails

**RBAC** uses `sqlglot` to parse SQL into an AST, extracting tables and columns for access validation. Handles subqueries, JOINs, `SELECT *`, and table-prefixed columns. Column filtering uses union logic across JOINs, not intersection.

**The policy engine** supports six actions — `ALLOW`, `REDACT`, `HASH`, `VAULT`, `REVIEW`, `BLOCK` — with per-category, per-direction, per-role mappings. The `HASH` action replaces PII with `[category:sha256-first-8]`, preserving identity consistency so analysts can `GROUP BY` pseudonymized data without seeing real names.

Two bundled policies demonstrate opposite compliance philosophies:
- `permissive_analyst`: Hashes names/emails so analysts can correlate records across tables
- `strict_financial`: Replaces all PII with generic `[category]` tags, preventing even statistical correlation

**Audit records** never store raw PII. Original queries and outputs are SHA-256 hashed. Detection text is replaced with `[category]` placeholders. One JSONL record per request, containing the full decision trace.

### Infrastructure — Temporal, Docker, Async

Two orchestration backends for the same 7-stage pipeline:

| | Async (default) | Temporal |
|---|---|---|
| Latency overhead | None | ~50-100ms per stage |
| Durability | Lost on crash | Resumes from last completed stage |
| Human-in-the-loop | No | 24-hour signal timeout |
| Retry per stage | No | Independent policies (RBAC: 3 attempts, Audit: 20) |
| Operational cost | Zero | Temporal cluster + worker process |

The Temporal workflow (`temporal_runner.py`) handles `ActivityError` unwrapping for RBAC denial, heartbeating for long model inference, and human review signals. Temporal tests use an in-memory server — no Docker needed for CI.

### Quality — Tests, Eval, Benchmarks

- **108 tests** across unit, integration, and pipeline stages (`tests/`)
- **Golden-set eval harness** with 15 test cases measuring RBAC accuracy, PII detection accuracy, and audit completeness (`eval/`)
- **Latency benchmarks** reporting p50/p90/p95/p99 for the 1.5B model on CPU (`benchmarks/`)

### Full-Stack — Web Demo, Agent, Synthetic Data

- **Interactive web demo** (`web/index.html`) — single-page app with real-time pipeline visualization, MCP Streamable HTTP client, and animated 7-step status indicators. Shows backend type (async/temporal) and links to Temporal UI for workflow inspection.
- **LangGraph ReAct agent** (`examples/agent/`) — 3-node agent consuming the MCP server via stdio transport
- **Synthetic financial dataset** (`scripts/seed_data.py`) — realistic data with deliberate PII edge cases (aliases, compound identifiers, one-hop references)

## How it works

Every tool call flows through a 7-step pipeline. Cheapest checks first, most expensive last.

```
    User Query
       │
       ▼
[1] RBAC Gate ────── fail-closed set membership check (O(1))
       │
       ▼
[2] Inbound PII Scan ── 1.5B Privacy Filter detects 8 categories
       │
       ▼
[3] Inbound Policy ──── ALLOW | REDACT | HASH | VAULT | REVIEW | BLOCK
       │
       ▼
[4] Tool Execution ──── bounded, with timeouts
       │
       ▼
[5] Outbound PII Scan ── canonical JSON scan (sort_keys=True)
       │
       ▼
[6] Outbound Policy ──── redact/hash/vault results before returning
       │
       ▼
[7] Audit Logging ───── append-only JSONL (SHA-256, no raw PII)
       │
       ▼
    LLM Response
```

## Running it

```bash
# Prerequisites: Python 3.11+, uv

git clone https://github.com/ree2raz/auditguard-mcp.git
cd auditguard-mcp
make install
make seed
MOCK_PII=1 make demo
# → http://localhost:7860
```

For Temporal backend:
```bash
docker compose -f docker/docker-compose.temporal.yml up -d   # Temporal cluster
AUDITGUARD_BACKEND=temporal python -m auditguard_mcp.pipeline.temporal_worker  # Worker
AUDITGUARD_BACKEND=temporal uv run uvicorn web_app:app --port 7860             # Server
# → http://localhost:8080 for Temporal UI
```

## Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.14 |
| MCP Server | FastMCP (stdio + Streamable HTTP) |
| PII Detection | OpenAI Privacy Filter 1.5B (local CPU) |
| SQL Parsing | sqlglot |
| Orchestration | asyncio / Temporal |
| Web Framework | FastAPI + Uvicorn |
| Database | SQLite (synthetic) |
| Container | Docker (multi-layer, CPU-only ML deps) |

## Extending this

To take this from reference to production:
1. **Async Review Queue**: The `REVIEW` action is currently synchronous. In production, hold the request, return "pending", and wait for an out-of-band human approval webhook.
2. **KMS Vaulting**: Replace the local `vault.jsonl` writer with AWS KMS or HashiCorp Vault.
3. **Client-side TLS**: The `stdio` transport assumes a trusted local client. For SSE transport, add mTLS client certificate validation.
