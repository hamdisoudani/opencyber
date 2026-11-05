# OpenCyber (`Aegis-GitOps`)

**Orchestrated Multi-Agent Attack Surface Management (ASM) & Security Posture Assessment Platform**

OpenCyber (`Aegis-GitOps`) separates LLM reasoning and orchestration from untrusted command execution, enforces non-bypassable scope and rate-limit governance via an externalized HTTP Egress Gateway, isolates subagent discovery and posture checks inside Git worktrees (`git worktree`), and gates all findings behind deterministic CI validation, tool-less LLM PR review, and mandatory Human-in-the-Loop (HITL) sign-off.

---

## Monorepo Architecture

```text
opencyber/
├── packages/
│   ├── shared/           # @opencyber/shared — Zod v4 domain schemas, scope.yaml parser, URL canonicalizer, HMAC & fencing tokens
│   ├── egress-gateway/   # @opencyber/egress-gateway — Mandatory HTTP proxy (451 scope guard, 429 token-bucket RPS, Session Vault, HAR SHA-256 capture)
│   ├── gitops-engine/    # @opencyber/gitops-engine — Fencing-token LockManager, simple-git WorktreeManager, Stage 3 CI Gate, Surface Reducer, PGlite DB, BlobVault
│   ├── sandbox-runner/   # @opencyber/sandbox-runner — E2B Cloud Sandbox SDK runner + Local fallback with command budgets & Dead-Man's Switch
│   └── agents/           # @opencyber/agents — Multi-provider LLM router + SSE streaming (OpenRouter stealth/crouton-alpha + Groq qwen3.8-27b & llama-prompt-guard-2-86m), Bugcrowd brief ingestor, Babel AST extractor, Recon & Posture subagents
└── apps/
    ├── control-plane/    # @opencyber/control-plane — Hono SSE Chat Orchestrator (/api/chat/stream), Multi-Program Workspace Manager (/api/programs/:id/*), 5-Stage GitOps Pipeline & Demo Target server
    └── dashboard/        # @opencyber/dashboard — Chat-First Bugcrowd Program Orchestrator + Program-Scoped Live Logs, Scope YAML, Attack Surface Graph, HITL Findings, GitOps & Traffic Console
```

---

## Core Security & Concurrency Guarantees

0. **Chat-First Bugcrowd Program Workspaces:** Paste any raw Bugcrowd program brief directly into the Orchestrator chat. `stealth/crouton-alpha` extracts In-Scope domains/wildcards, Out-of-Scope hosts (`excludedHosts`) & paths (`excludedPaths`), rate limits (`maxRpsPerHost`), and compliance headers into a versioned `scope.yaml`, spins up a dedicated GitOps repository + PGlite state store + Egress Gateway + E2B sandbox session for that exact program, and streams live execution logs, telemetry refreshes, and Markdown analysis over SSE.
1. **Externalized Egress Gateway & Session Vault:** Subagents never receive raw session cookies or API keys in prompts. Every request carries a short-lived HMAC-SHA256 task token bound to `(taskId, fencingToken, allowedAuthProfiles)`. Out-of-scope hosts/exclusions/paths are rejected with `451 Unavailable For Legal Reasons`, rate-limit spikes return `429`, non-read-only methods return `405`, and credentials are injected in transit and redacted (`[REDACTED_BY_SESSION_VAULT]`) in SHA-256 HAR captures.
2. **Zero-Conflict Discovery Reducer:** Recon and zero-target-traffic Babel AST subagents commit immutable `observations/*.json` and `schemas/*.json` batches in isolated `git worktree` checkouts. A deterministic reducer canonicalizes concrete and parameterized paths (`/v1/users/42/roles` + `/v1/users/:id/roles` -> `/v1/users/{param}/roles`) into single YAML definitions on `main` and syncs into embedded PostgreSQL (`@electric-sql/pglite`).
3. **Fencing-Token Locks & Sandbox Dead-Man's Switch:** Monotonic lock epochs reject split-brain commits at Stage 3 CI if a subagent stalls past its TTL, while `ManagedSandboxSession` enforces hard command budgets (`maxCommands`) and heartbeat timeouts across E2B cloud sandboxes.
4. **Defense-in-Depth Prompt Injection Guard & Multi-Provider Orchestration:** Untrusted target metadata passes through **Meta Llama Prompt Guard 2 (`meta-llama/llama-prompt-guard-2-86m`)** and structural sanitization before reaching the **tool-less** Stage 4 Lead Orchestrator (**OpenRouter `stealth/crouton-alpha`** with Groq `openai/gpt-oss-120b` failover), which can only emit typed review verdicts (`APPROVE_MERGE | REJECT_COMPLIANT | REQUEST_RETRY`).
5. **Mandatory Human-in-the-Loop (HITL) Queue:** Merged posture findings enter `PENDING_HUMAN_REVIEW` until explicitly approved or rejected by an engineer.

---

## Quickstart

### 1. Configure Environment
```bash
cp .env.example .env
# Populate E2B_API_KEY, OPENROUTER_API_KEY, and GROQ_API_KEY in .env
```

### 2. Build, Typecheck & Run Full Test Suite
```bash
pnpm build
pnpm typecheck
pnpm test
```

### 3. Launch Control Plane & HITL Dashboard
```bash
# Start Control Plane API (http://127.0.0.1:4100 — also serves built dashboard assets)
pnpm dev:api

# Optional: run Vite dev server with HMR on http://127.0.0.1:5173
pnpm dev:ui
```
