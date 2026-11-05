# OpenCyber (`Aegis-GitOps`) — Hardened v2 Architecture Specification

**OpenCyber (`Aegis-GitOps`)** is a multi-agent Attack Surface Management (ASM) and defensive Security Posture Assessment platform built around **externalized scope/rate-limit governance**, **cloud sandbox isolation (E2B)**, **conflict-free GitOps worktrees**, and **mandatory Human-in-the-Loop (HITL) verification**.

---

## 1. Key Architectural Improvements Over v1 Draft

1. **Externalized Egress Gateway + HMAC Per-Task Proxy Tokens (`@opencyber/egress-gateway`):**
   - Runs *outside* untrusted agent sandboxes in the Control Plane network boundary.
   - Authenticates every subagent HTTP request via short-lived HMAC-SHA256 tokens bound to `(taskId, engagementId, allowedAuthProfiles, fencingToken, expiresAt)`.
   - Rejects out-of-scope hostnames or excluded paths with `451 Unavailable For Legal/Scope Reasons`, enforces per-host RPS token buckets (`429 Too Many Requests`), blocks unauthorized HTTP methods (`GET`/`HEAD`/`OPTIONS` only for read-only posture checks), injects compliance headers + Session Vault credentials in transit (so LLMs never see raw secrets), and records SHA-256 content-addressed HAR evidence.
2. **Observation-to-Surface Reducer + Fencing-Token Locks (`@opencyber/gitops-engine`):**
   - Eliminates parallel discovery merge conflicts: Recon and Static JS subagents write immutable `observations/<runId>.json` and `schemas/<bundleSha>.routes.json` files inside isolated `git worktree` checkouts.
   - A deterministic reducer canonicalizes concrete URLs (`/v1/users/42/roles` -> `/v1/users/{param}/roles`) into collision-free `surface/hosts/<host>/endpoints/<METHOD>_<slug>_<hash8>.yaml` files.
   - Monotonic **fencing tokens** prevent split-brain commits if a subagent stalls past its lock TTL.
3. **Unified PostgreSQL Operational & Graph Store (`@electric-sql/pglite`):**
   - Replaces three-way Neo4j + PostgreSQL + Git drift with an embedded real PostgreSQL engine storing the hierarchical asset graph (`domains -> hosts -> endpoints -> schemas`), audit tombstones (`compliant` endpoints), lock ledger, and `PENDING_HUMAN_REVIEW` queue.
4. **Defense-in-Depth Prompt Injection Mitigation & Multi-Provider LLM Routing (`@opencyber/agents`):**
   - Combines **Meta Llama Prompt Guard 2 (`meta-llama/llama-prompt-guard-2-86m`)** on Groq with **strict capability isolation**: the Stage 4 Lead Orchestrator defaults to **OpenRouter (`stealth/crouton-alpha`)** (with resilient failover to Groq `openai/gpt-oss-120b`), operates with zero shell/network/merge tools, and emits strictly typed review verdicts (`APPROVE_MERGE | REJECT_COMPLIANT | REQUEST_RETRY`) executed by deterministic backend code.

---

## 2. Monorepo Structure

| Workspace Package | Responsibility |
| --- | --- |
| `@opencyber/shared` | Zod domain schemas, `scope.yaml` parser, URL/route canonicalizer, HMAC task tokens & fencing tokens. |
| `@opencyber/egress-gateway` | External HTTP proxy enforcing `scope.yaml`, token-bucket RPS (`rate-limiter-flexible`), Session Vault header injection, and HAR ledger. |
| `@opencyber/gitops-engine` | `simple-git` worktree manager, Stage 3 deterministic CI gate, canonical surface reducer, PGlite PostgreSQL store, and SHA-256 Blob Vault. |
| `@opencyber/sandbox-runner` | Real E2B Cloud Sandbox (`e2b` SDK) lifecycle manager with TTL/dead-man switch + deterministic local fallback provider. |
| `@opencyber/agents` | Multi-provider `AegisModelRouter` (**OpenRouter `stealth/crouton-alpha`** Lead Orchestrator + **Groq `qwen/qwen3.8-27b`** Subagents & **`meta-llama/llama-prompt-guard-2-86m`** Prompt Guard), Babel AST zero-traffic JS route extractor, Recon Subagent, Posture Auditor, and Lead Orchestrator Reviewer. |
| `@opencyber/control-plane` | Hono REST + SSE API server, 5-stage GitOps pipeline coordinator, and safe local Mock Enterprise Target server. |
| `@opencyber/dashboard` | Interactive HITL Governance & Attack Surface Web UI (React 19 + Vite + bespoke CSS design system). |
