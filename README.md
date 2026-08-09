# Codebase Radar

**[Open the live app](https://radar-21d6-3000.prg1.zerops.app)** · [Zerops Challenge](https://www.wemakedevs.org/hackathons/zerops)

Codebase Radar turns a public GitHub repository into a short, evidence-backed list of what to fix first, why it matters, and what is probably noise. It explains the same evidence differently for technical leaders, executives, and security stakeholders, while preserving a machine-readable view for coding agents.

## Repository-first reviews

Radar treats the repository—not an individual scan—as the durable product object.

- Recent repositories show each repository once, so repeat scans do not crowd the dashboard.
- Every repository keeps its complete review history and compares the current snapshot with the previous one.
- Repository pages and individual review snapshots have stable, shareable URLs.
- Starting another review adds a snapshot to that repository instead of creating another disconnected recent item.

Each completed review produces one priority list with clear actions: `fix now`, `investigate`, `monitor`, or `do not fix`. Consequence, blast radius, confidence, effort, and change exposure remain separate so a single opaque score cannot hide uncertainty.

## Supported today

The challenge MVP scans public TypeScript and JavaScript repositories. It detects React, Angular, Vue, Svelte, and Solid projects, including common meta-frameworks.

| Project | Current coverage |
| --- | --- |
| React | TypeScript/JavaScript checks plus React-aware enrichment |
| Vue | TypeScript/JavaScript checks plus limited Vue script enrichment |
| Angular, Svelte, Solid | TypeScript/JavaScript checks and framework detection; no template-semantic claims |
| Other TypeScript/JavaScript | Framework-neutral static and structural analysis |

Radar combines strict TypeScript configuration checks, fast linting, duplication signals, dependency advisories, GitHub Actions checks, and TraceDecay structural evidence. Findings are normalized before prioritization so several tools reporting the same underlying problem do not masquerade as several priorities.

People can optionally connect their own Codex or Claude account for a second opinion on the ordering. Each profile has separate persisted login state, receives only the bounded evidence pack, and cannot modify the scanned repository. The same read-only evidence is available to external coding agents through MCP.

## What the MVP does not claim

A scan is deliberately static and read-only. Radar shallow-clones a public GitHub repository, then runs bounded analyzers with time and output limits. It does not install dependencies, run builds or tests, execute repository scripts or hooks, or initialize submodules.

That boundary means:

- Radar does not prove runtime behavior, exploitability, incidents, revenue impact, or production performance.
- Security and financial references are context for investigation, never proof that harm occurred.
- Angular, Svelte, and Solid template semantics are not analyzed yet.
- Analyzer failures are reported as partial coverage rather than hidden or treated as a clean bill of health.
- Private repositories, arbitrary Git hosts, and a complete hostile-tenant sandbox are outside this challenge MVP.

## Built and deployed on Zerops

The live product runs as two Zerops services: one Radar application service and PostgreSQL. The application serves the website and API, runs the bounded scan queue, exposes read-only MCP tools, and isolates each connected agent profile inside the same product deployment. PostgreSQL preserves repositories, review history, comparisons, and encrypted provider state across restarts.

[`zerops-import.yaml`](./zerops-import.yaml) creates both services. [`zerops.yaml`](./zerops.yaml) defines the reproducible build, pinned analyzer preparation, runtime environment, and health checks.

## Local development

Requirements: Node.js 24+, pnpm 11.17.0, Git, and PostgreSQL when persistent history is needed.

```bash
pnpm install --frozen-lockfile
cp .env.example .env
pnpm check
pnpm test
pnpm dev
```

Without `DATABASE_URL`, Radar uses an in-memory store. Linux-only analyzers report partial coverage when their pinned binaries are unavailable locally.

Build and run the production artifact:

```bash
pnpm run build:production
PORT=3000 node apps/radar/.output/index.js
```

Health and readiness endpoints are `/api/health` and `/api/ready`.

## Read-only MCP

The Streamable HTTP MCP endpoint is:

```text
https://radar-21d6-3000.prg1.zerops.app/api/mcp
```

It exposes scan discovery, prioritized backlogs, bounded prioritization briefs, and finding taskpacks. The tools are read-only and cannot change a repository. Public-repository access is unauthenticated in this challenge MVP; private-repository authorization is deferred.

## Verification

```bash
pnpm check
pnpm test
pnpm run build:production
```

## License

[MIT](./LICENSE)
