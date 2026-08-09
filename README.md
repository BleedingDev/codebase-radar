# Codebase Radar

Codebase Radar turns a public GitHub repository into a short, evidence-backed improvement backlog. It combines fast static analyzers with TraceDecay's structural evidence, keeps confidence and impact separate, and gives humans and coding agents the same ranked facts in different forms.

The current MVP is deliberately narrow: public GitHub repositories containing TypeScript or JavaScript, with first-class framework detection for React, Angular, Vue, Svelte, and Solid.

## What it returns

- One prioritized backlog with `fix now`, `investigate`, `monitor`, and `do not fix` actions.
- Separate consequence, blast-radius, confidence, effort, change-exposure, and priority scores.
- Direct evidence, explicit inference labels, analyzer coverage, and honest partial-result reporting.
- Technical, executive, and security communication profiles without changing the underlying ranking.
- Snapshot comparison against the previous scan of the same repository.
- Read-only MCP tools for scan discovery, backlog retrieval, and agent-ready finding taskpacks.

Security or financial references are advisory context. They are never presented as proof that a repository is vulnerable or that a business impact has occurred.

## Analysis profile

| Analyzer | MVP responsibility |
| --- | --- |
| `@tsconfig/strictest` comparator | Finds gaps between the repository's TypeScript configuration and a strict baseline. |
| Oxlint + Ultracite | Fast TypeScript/JavaScript diagnostics; React receives native enrichment and Vue receives limited script enrichment. |
| JSCPD | Bounded duplicate-code signals. |
| zizmor | Offline GitHub Actions static analysis. |
| OSV-Scanner | Lockfile-based dependency advisories without installing repository dependencies. |
| TraceDecay | Structural health, complexity, coupling, cycles, hotspots, test risk, and selected blast-radius evidence. |

Angular, Svelte, and Solid still receive universal TypeScript/JavaScript analysis, but the MVP does not claim native template semantics for them. Analyzer failures produce explicit partial coverage instead of failing the entire scan.

## Architecture

The Zerops deployment has exactly two services:

```text
Browser / coding agent
        │
        ▼
UltraModern.js radar service
  React UI
  Effect HttpApi server + derived frontend client
  Effect MCP server
  PostgreSQL-backed scan loop
  bounded direct analyzer subprocesses
        │
        ▼
PostgreSQL 18
```

`RadarApi` is the single Effect HTTP contract. The backend implements it through `HttpApiBuilder`; the browser derives its client directly with `makeEffectHttpApiClient(RadarApi)`. There is no generated or duplicated API model.

The same application process runs scans at concurrency one. TraceDecay is started as a per-scan child process on an isolated local socket and stopped during scoped cleanup; it is not another deployed service.

## Repository safety boundary

A scan performs a shallow, non-recursive clone of a public GitHub repository. It does not install dependencies, run builds or tests, execute repository scripts or hooks, initialize submodules, or execute repository configuration. Every analyzer runs as a bounded child process with timeout and output limits.

This is a strong MVP boundary, not a complete hostile-tenant sandbox. Private repositories and arbitrary clone hosts are intentionally out of scope.

## Local development

Requirements: Node.js 24+, pnpm 11.17.0, Git, and PostgreSQL if persistence is desired.

```bash
pnpm install --frozen-lockfile
cp .env.example .env
pnpm check
pnpm test
pnpm dev
```

Without `DATABASE_URL`, Radar uses an in-memory store. The JavaScript analyzers are available from the workspace install; Linux-only pinned binaries are prepared by the Zerops build and report partial coverage when unavailable locally.

Build and preview the exact production artifact:

```bash
pnpm run build:production
PORT=3000 node apps/radar/.output/index.js
```

The web application is then available at `http://localhost:3000`. Health and readiness endpoints are `/api/health` and `/api/ready`.

## MCP

The Streamable HTTP MCP endpoint is `/api/mcp`. It is implemented with Effect's MCP stack and currently negotiates protocol version `2025-06-18`.

Available tools:

- `list_scans`
- `get_scan`
- `get_improvement_backlog`
- `get_prioritization_brief`
- `get_finding_taskpack`

All tools are declared read-only, non-destructive, idempotent, and closed-world. Requests carrying an invalid `Origin` are rejected. Public-repository access is unauthenticated in this challenge MVP; private-repository authorization is deferred.

### ZCP agent review

The official Zerops `zcp@1` workspace can host Codex or Claude Code beside the two application services. ZCP remains the development workspace and Zerops control surface; it is not another Codebase Radar runtime. After adding the official ZCP service and authenticating the chosen agent, connect Radar's read-only MCP endpoint:

```bash
codex mcp add radar --url https://radar-21d6-3000.prg1.zerops.app/api/mcp
claude mcp add --transport http radar https://radar-21d6-3000.prg1.zerops.app/api/mcp
```

The agent calls `get_prioritization_brief` to challenge the deterministic shortlist, then `get_finding_taskpack` for the selected work. It must not treat a composite score, finding volume, or an inferred impact claim as proof.

## Deploy to Zerops

[`zerops-import.yaml`](./zerops-import.yaml) creates PostgreSQL 18 and the single Node.js radar service. [`zerops.yaml`](./zerops.yaml) pins the build, analyzer preparation, runtime environment, health check, and readiness check.

Import `zerops-import.yaml` into Zerops, or connect this repository to an existing project using the `radar` setup. The build downloads only pinned analyzer artifacts and verifies checksums before deployment.

Optional LLM reranking is disabled unless `LLM_API_KEY` is configured. Deterministic ranking remains the source of truth, and an unavailable LLM never prevents a scan from completing.

## Verification

```bash
pnpm check
pnpm test
pnpm run build:production
```

`pnpm check` includes a source-policy gate for application TypeScript: no type assertions, no `unknown`, and no `any`. External data is decoded through concrete Effect Schemas.

## License

[MIT](./LICENSE)
