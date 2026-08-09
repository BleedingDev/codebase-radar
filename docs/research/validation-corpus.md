# Cross-framework MVP validation corpus

**Research date:** 2026-08-09  
**Scope:** Static-only Codebase Radar MVP for public TypeScript repositories  
**Verdict:** Use five maintained, bounded public repositories as live end-to-end smoke/realism targets, plus deterministic golden fixtures for normalization, ranking, comparison, and audience claims. Public repositories alone are not a ranking oracle.

## Decision summary

The minimum credible live corpus is:

1. React — [`alan2207/bulletproof-react`](https://github.com/alan2207/bulletproof-react)
2. Angular — [`realworld-apps/angular-realworld-example-app`](https://github.com/realworld-apps/angular-realworld-example-app)
3. Vue — [`mutoe/vue3-realworld-example-app`](https://github.com/mutoe/vue3-realworld-example-app)
4. Svelte — [`spences10/sveltest`](https://github.com/spences10/sveltest)
5. Solid — [`super-productivity/plainspace`](https://github.com/super-productivity/plainspace)

Add [`TanStack/virtual`](https://github.com/TanStack/virtual) only after the five primary targets pass. It is a useful multi-framework collision case, not a launch blocker.

Do **not** claim that a plausible top five on these repositories is correct merely because the scan completes. The live corpus proves ingestion, framework recognition, bounded execution, coverage reporting, and presentation on realistic code. A small golden fixture pack and a human relevance judgment prove the priority pipeline.

## Method and limits

I queried the GitHub repository API on 2026-08-09 for public/archive/default-branch/size/activity metadata, then cloned candidates into throwaway storage with:

```sh
git -c protocol.file.allow=never clone \
  --depth 1 --filter=blob:none --no-tags \
  https://github.com/OWNER/REPO.git /tmp/TARGET
```

I did not initialize submodules, install dependencies, invoke package scripts, build, test, or execute repository-owned code. I inspected tracked paths, manifests, lockfiles, framework versions, and line/file counts. Approximate source lines are physical lines across tracked `*.ts`, `*.tsx`, `*.vue`, and `*.svelte` files; they are a scale indicator, not semantic LOC. Local checkout size is `du -sk` including the shallow `.git` directory.

No product analyzer was run, so this report makes **no claim that any selected repository contains a particular defect**. “Analyzable signals” below means the repository contains bounded static surfaces—source graphs, compiler config, lockfiles, workflows, tests, and framework syntax—not that a finding has been manually verified.

GitHub exposes both `default_branch` and `size` in its [repository REST representation](https://docs.github.com/en/rest/repos/repos). GitHub also notes that shallow clones reduce server burden and may perform better, but its general repository limits are far above an MVP scanner’s safe operating budget; Radar therefore needs its own much lower caps ([GitHub repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits)).

## Selection criteria

A primary target had to satisfy all of these at the inspected snapshot:

- public, unarchived, and with repository activity in 2026;
- the intended framework is an actual dependency at the default-branch snapshot;
- TypeScript-bearing framework source is present (`.ts`, `.tsx`, or SFC `<script lang="ts">`), not merely a TypeScript dev dependency;
- shallow checkout is comfortably below the proposed MVP caps;
- enough application/library structure exists to exercise imports, configuration, duplication, workflows, dependency metadata, and/or tests;
- no dependency installation is required to inventory it;
- an explicit license file exists (all selected targets contain an MIT license file).

The framework projects’ own documentation confirms that the source shapes are materially different: React uses TypeScript through `.tsx` and JSX ([React TypeScript guide](https://react.dev/learn/typescript)); Angular’s components are TypeScript classes and decorators ([Angular components](https://angular.dev/guide/components)); Vue SFC TypeScript is selected with `lang="ts"` and may require `vue-tsc` for full SFC checking ([Vue TypeScript guide](https://vuejs.org/guide/typescript/overview)); Svelte places TypeScript in `<script lang="ts">` within `.svelte` files ([Svelte TypeScript guide](https://svelte.dev/docs/svelte/typescript)); and Solid’s JSX compiler requires Solid-specific TypeScript JSX configuration ([Solid TypeScript guide](https://docs.solidjs.com/configuration/typescript)). This is evidence for framework-aware coverage reporting, not evidence that every proposed analyzer supports every framework.

## Recommended live corpus

Metadata and measurements are pinned to the exact inspected default-branch commit. GitHub `size` and expanded shallow checkout size measure different things, so both are shown rather than pretending they agree.

| Framework | Repository / default branch / inspected commit | GitHub size | Local shallow checkout | Tracked files | TS/framework files and lines | Static surfaces | Why representative |
|---|---|---:|---:|---:|---:|---|---|
| React | [`alan2207/bulletproof-react`](https://github.com/alan2207/bulletproof-react), `master`, [`9506629ed003`](https://github.com/alan2207/bulletproof-react/tree/9506629ed003a561c6627735480cce4994244bb4) | 2,249 KiB | 4,976 KiB | 535 | 422 files / 21,925 lines | 4 manifests, 3 TS configs, 3 Yarn locks, 3 workflow files, 40 test/spec files | A maintained architecture example with Vite React and two Next.js variants. It exercises multiple project roots, React/Next enrichment, duplicate lockfiles, tests, and structural boundaries without being huge. The inspected apps use React 18.3.1. |
| Angular | [`realworld-apps/angular-realworld-example-app`](https://github.com/realworld-apps/angular-realworld-example-app), `main`, [`dd99ed2cf39c`](https://github.com/realworld-apps/angular-realworld-example-app/tree/dd99ed2cf39c805d719f943c5d7061a5683d98a8) | 2,100 KiB | 920 KiB | 88 | 50 files / 4,004 lines | 1 manifest, 3 TS configs, Bun lock, 4 workflow files, 6 test/spec files | A small but nontrivial CRUD/auth/routing application. Its [`package.json`](https://github.com/realworld-apps/angular-realworld-example-app/blob/dd99ed2cf39c805d719f943c5d7061a5683d98a8/package.json) pins Angular core/router 21.2.12, making it the strongest bounded Angular smoke target. |
| Vue | [`mutoe/vue3-realworld-example-app`](https://github.com/mutoe/vue3-realworld-example-app), `main`, [`a3b07312d4c4`](https://github.com/mutoe/vue3-realworld-example-app/tree/a3b07312d4c416c3976a3012e64cf39053060708) | 4,160 KiB | 1,324 KiB | 125 | 91 files / 5,237 lines | 1 manifest, 3 TS configs, pnpm lock, 3 workflow files, 29 test/spec files | A Vue 3 Composition API/SFC RealWorld app with Pinia and Vue Router. Its [`package.json`](https://github.com/mutoe/vue3-realworld-example-app/blob/a3b07312d4c416c3976a3012e64cf39053060708/package.json) declares Vue 3.5.32, Pinia 3.0.4, and Vue Router 5.0.4. It tests mixed `.ts` plus `.vue` normalization. |
| Svelte | [`spences10/sveltest`](https://github.com/spences10/sveltest), `main`, [`09d8a77ab477`](https://github.com/spences10/sveltest/tree/09d8a77ab4771c9ee0165b46fcb4bbb5e5ace197) | 4,066 KiB | 2,772 KiB | 264 | 195 files / 30,644 lines; 67 SFCs explicitly use `lang="ts"` | 3 manifests, 2 TS configs, pnpm lock, 2 workflow files, 68 test/spec files | A maintained Svelte 5 testing/example workspace rather than a toy starter. Its website [`package.json`](https://github.com/spences10/sveltest/blob/09d8a77ab4771c9ee0165b46fcb4bbb5e5ace197/apps/website/package.json) declares Svelte 5.55.5 and SvelteKit 2.58.0. It deliberately stresses `.svelte` parsing and test-heavy code. |
| Solid | [`super-productivity/plainspace`](https://github.com/super-productivity/plainspace), `main`, [`70da9b9a0838`](https://github.com/super-productivity/plainspace/tree/70da9b9a08389c96d33bf2e389c640bd61a3ba7e) | 1,585 KiB | 5,092 KiB | 394 | 228 files / 37,243 lines | 5 manifests, 6 TS configs, npm lock, 1 workflow file, 78 test/spec files | A small maintained full-stack workspace with web, server, shared, and E2E packages. Its web [`package.json`](https://github.com/super-productivity/plainspace/blob/70da9b9a08389c96d33bf2e389c640bd61a3ba7e/packages/web/package.json) declares Solid 1.9.14 and Solid Router 0.15.3. It checks that Solid is recognized inside a mixed server/client TypeScript monorepo. |

### Optional collision target

[`TanStack/virtual`](https://github.com/TanStack/virtual), `main`, inspected [`d2cf98beea16`](https://github.com/TanStack/virtual/tree/d2cf98beea1696c7187c06b57c9e724d1957963c), is 9,545 KiB in GitHub metadata and 7,360 KiB as a local shallow checkout (821 tracked files; 274 TS/framework files; 25,942 lines; 69 package manifests). It has React, Angular, Vue, Svelte, and Solid packages/examples in one maintained monorepo.

Use it to verify that framework detection can return a set with evidence and scopes rather than forcing one misleading repository-wide label. It is optional because its 69 manifests and 99 TS config files add runtime and normalization noise that should not block the first five-framework demo.

### Useful rejected candidates

- [`sveltejs/realworld`](https://github.com/sveltejs/realworld) is current, small, and official, but the inspected Svelte files did not use `lang="ts"` and it had no tracked TS config. It is a Svelte smoke target, not a TypeScript/Svelte acceptance target.
- [`sveltejs/kit-template-default`](https://github.com/sveltejs/kit-template-default) is an official 23-file starter, but its inspected SFCs were not TypeScript-bearing and it is too small to support ranking claims.
- [`solidjs/solid-realworld`](https://github.com/solidjs/solid-realworld) is a compact comparable RealWorld app, but its latest repository push was in 2023; using it would weaken the “maintained current framework” claim.
- [`solidjs/templates`](https://github.com/solidjs/templates) is official and current, but the inspected checkout is a template collection with many lockfiles rather than one representative app. Keep it as a fallback Solid detection fixture, not the primary realism target.
- [`huntabyte/shadcn-svelte`](https://github.com/huntabyte/shadcn-svelte) and [`solidjs/solid-start`](https://github.com/solidjs/solid-start) are current but substantially larger than necessary for the deadline-constrained gate.

## Required acceptance gates

These gates distinguish “the demo returns something” from “the product claim is supported.” Thresholds are deliberately executable within the eight-hour MVP; they can be tightened after Zerops measurements.

### G1 — Public clone and immutable identity

For each of the five primary URLs:

- accept only a canonical public `https://github.com/{owner}/{repo}` identity (following GitHub’s repository rename redirect is acceptable, but persist the canonical owner/name);
- resolve and persist the default branch plus the full 40-character HEAD commit before analysis;
- shallow-clone that branch without tags, submodules, LFS smudging, dependency installation, hooks, or package execution;
- finish clone plus inventory within 45 seconds on the intended Zerops service;
- pass preflight only below 50,000 KiB GitHub-reported size, then enforce a 128 MiB expanded checkout cap, 25,000 tracked-file cap, and 5 MiB single-file analysis cap;
- on timeout, cap breach, rename failure, private repository, or missing default branch, emit a typed terminal state such as `clone_timeout`, `repository_too_large`, or `repository_unavailable`; do not create an empty successful scan.

**Pass:** all five persist the exact commit identity and stay inside the caps. The optional TanStack target must also pass before claiming mixed-framework monorepo support.

### G2 — Framework detection is evidence-bearing

For each primary repository, the detected framework set must contain the table’s framework and cite the manifest path and dependency that established it. File-extension heuristics alone are insufficient. The detector must also record relevant roots (for example, `packages/web` for Plainspace and each app root for Bulletproof React).

**Pass:** 5/5 exact primary detections, zero false repository-wide framework claims, and a machine-readable coverage record. On the optional TanStack target, return multiple framework scopes rather than choosing one winner.

### G3 — Analyzer coverage is explicit, not implied

Every configured analyzer gets one status in the canonical Scan Result:

`succeeded | skipped_unsupported | skipped_no_input | timed_out | failed | invalid_output`

The status includes analyzer/version, duration, applicable roots/files, raw finding count, normalized finding count, and a short reason when not successful. A framework name in the UI must not imply framework-native rules if only universal TypeScript checks ran.

**Pass:** no configured analyzer disappears silently on any corpus target; the UI and MCP return the same coverage matrix; universal TypeScript coverage is distinguishable from framework enrichment.

### G4 — Partial results survive isolated analyzer failure

Run one corpus scan three times with an injected analyzer wrapper that respectively exits nonzero, exceeds its timeout, and emits malformed JSON.

**Pass:** each run reaches `partial`, retains all successful analyzer evidence, excludes the failed analyzer’s unvalidated findings, exposes the coverage gap in the summary and MCP, and still renders a backlog if at least one evidence-producing analyzer succeeded. Clone/inventory failure or zero usable analyzer results must be `failed`, not `partial` or `complete`.

### G5 — Finding normalization is lossless enough to audit

Every accepted Normalized Finding must contain:

- stable finding fingerprint and scan-local ID;
- analyzer, analyzer version, rule/check ID, and raw-result reference;
- evidence class (`direct`, `strong_proxy`, `context`, or `inference`);
- repository-relative artifact path and valid line/symbol when the analyzer supplied one;
- technical statement, bounded plain-language consequence, confidence, severity, blast radius, effort, change exposure, priority score, and action class;
- all contributing provenance when equivalent findings are deduplicated;
- zero or more External References, explicitly separated from applicability evidence.

Feed a deterministic raw-output fixture containing duplicates, missing optional locations, repository-level config findings, malformed records, and two analyzers reporting the same underlying issue.

**Pass:** 100% of valid inputs are represented once or intentionally merged with all provenance; every rejected record has a reason; malformed records cannot enter ranking; repeated normalization is byte-stable after canonical ordering; all numeric dimensions remain within their documented ranges.

### G6 — Ranking credibility has both deterministic and human gates

Public repositories have no ground-truth “correct backlog.” Add a tiny golden fixture snapshot for each framework (it may live in test fixtures and need not be deployable) plus deterministic raw analyzer outputs. Across the five fixtures, seed at least one example of each MVP evidence family: lint/type strictness, duplication, structural blast radius/complexity, dependency advisory, and GitHub Actions security. Include low-value/noisy observations that should not outrank stronger evidence.

**Deterministic pass:** planted high-confidence/direct findings rank ahead of planted contextual or low-confidence observations; no `do not fix` item enters the top five; identical input produces identical deterministic base scores; bounded LLM reranking cannot add/drop findings, alter evidence or numeric dimensions, or move an item beyond the configured rank window; invalid LLM output falls back to deterministic order.

Then have at least one technical reviewer grade every top-five item on the five live repositories as `2 = fix/investigate is justified`, `1 = plausible monitor`, or `0 = irrelevant/unsupported/do not fix`, while viewing the evidence.

**Human pass:** at least 20 of 25 top-five items score 1 or 2 (precision@5 >= 0.80), no unsupported security/financial certainty appears, and mean nDCG@5 against the reviewer grades is at least 0.75. Record the labels; do not replace this gate with an LLM judging its own ranking.

### G7 — Audience Profile changes communication, never truth

Render the same completed scan as a technical profile (CTO/tech lead) and a less-technical profile (CEO/customer/CISO).

**Pass:** finding IDs, top-five order, action classes, numeric dimensions, evidence classes, and comparison state are byte-identical. Only summary language, terminology explanation, and default expansion differ. The first screen shows at most five collapsed priorities plus repository/coverage health. Expanding an item reveals evidence, uncertainty, scores, references, and agent taskpack. External articles/CVEs are labeled context unless package/version or weakness matching establishes applicability.

### G8 — Current-versus-previous comparison is stable

Use two controlled snapshots under the same repository identity and Tooling Profile version: B removes one planted finding, retains one with shifted line numbers, and adds one. Also scan B twice.

**Pass:** A→B reports exactly one `resolved`, one `new`, and the retained finding as `persisting`; B→B reports zero new/resolved and all findings persisting; counts reconcile with both Scan Results; comparison uses fingerprints rather than scan-local IDs or line numbers. If no previous comparable completed/partial scan exists, or the Tooling Profile version changed, the UI says comparison is unavailable/incompatible instead of showing a false zero delta.

### G9 — Read-only Streamable HTTP MCP returns canonical truth

Exercise the deployed MCP endpoint using the protocol initialize/list/call flow. The MCP specification requires a single Streamable HTTP endpoint and defines tool discovery/invocation ([transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)). Tool annotations are hints, not enforcement, so database immutability must also be tested ([schema](https://modelcontextprotocol.io/specification/2025-11-25/schema)).

**Pass:**

- `tools/list` exposes only `get_scan`, `list_findings`, `explain_finding`, and `get_taskpack` for the MVP, each with `readOnlyHint: true` and an output schema;
- structured results validate against the same Scan Result/Finding schemas used by the UI/API, and IDs/order/scores/evidence match stored canonical data;
- pagination/filtering is deterministic, unknown or cross-repository IDs return non-leaking typed errors, and oversized requests are bounded;
- 100 repeated calls leave repositories, profiles, scans, findings, and job rows byte/count unchanged;
- no scan submission, rescan, profile update, raw shell, arbitrary file read, or TraceDecay mutation tool is discoverable or callable through MCP;
- invalid `Origin` is rejected as required by the Streamable HTTP security guidance.

### G10 — Deadline-level end-to-end gate

On the intended Zerops service limits, scan the five primary repositories sequentially from clean temporary directories.

**Pass:** each scan terminates within 180 seconds; all five finish within 12 minutes total; each temporary checkout is deleted after result persistence; at least one scan is demonstrated through UI, JSON download/API, comparison, and MCP without data disagreement. A slower analyzer may time out into a visible partial result, but the service process must remain responsive and the scan must terminate.

## Finding verdicts

### Claim: the five primary repositories are a bounded, current cross-framework smoke corpus

**Verdict:** SUPPORTED  
**Evidence:** Six independent GitHub repositories (five primary plus one collision target) were checked through repository metadata and shallow default-branch inspection. The five primary checkouts are approximately 0.9–5.1 MiB locally, are unarchived, show 2026 repository activity, contain the named framework dependency, and contain meaningful TypeScript/framework source.  
**Inference:** These sizes and source surfaces should fit a tightly bounded static MVP and expose common single-app and monorepo shapes.  
**Applicability:** This does not prove behavior on large repositories, nonstandard package managers, generated code, or hostile input.  
**Confidence:** High for corpus identity and boundedness; medium for runtime until measured on Zerops with the final analyzer set.  
**What would change in our design:** If any primary target exceeds the final service budget, narrow the applicable analyzer set or lower the launch support claim; do not silently sample files and still claim full coverage.

### Claim: equal framework support cannot be inferred from a universal TypeScript label

**Verdict:** SUPPORTED  
**Evidence:** Official React, Angular, Vue, and Solid documentation describes different TypeScript integration points, and inspected repositories use `.tsx`, Angular-decorated `.ts`, Vue SFCs, Svelte SFCs, and Solid-specific `.tsx`/JSX configuration. The rejected official Svelte RealWorld candidate demonstrates that a framework repository may not actually be TypeScript-bearing.  
**Inference:** Framework detection and analyzer applicability need evidence and root/file scopes; a single “TypeScript supported” badge would overstate coverage.  
**Applicability:** Some universal analyzers may parse all syntax, but that must be proven tool by tool in the analyzer research rather than assumed here.  
**Confidence:** High.  
**What would change in our design:** Store a framework set and per-analyzer coverage matrix; present “universal TS baseline” separately from “framework enrichment.”

### Claim: public live repositories alone can establish top-five ranking quality

**Verdict:** INCONCLUSIVE  
**Evidence:** The repositories provide realistic code, but none supplies a maintained ground-truth backlog mapping Radar’s proposed evidence dimensions to the correct top five. Static inspection did not verify product findings.  
**Inference:** A scan that returns five polished cards can still be confidently wrong; deterministic fixtures and an external human relevance judgment are required.  
**Applicability:** The proposed fixture/reviewer gates are sufficient for an MVP claim of “credible prioritization,” not statistical product validation or maintainer demand.  
**Confidence:** High that live-only validation is insufficient; medium that one reviewer and five repos are enough beyond the challenge demo.  
**What would change in our design:** If no human review can happen before submission, describe ranking as experimental and demonstrate deterministic evidence/order constraints rather than claiming validated usefulness.

### Claim: a multi-framework collision target is necessary for the initial five-framework claim

**Verdict:** WEAK  
**Evidence:** TanStack Virtual contains packages/examples for all five target frameworks and is still bounded enough to scan, but most public MVP demonstrations will be single-framework apps.  
**Inference:** It is a high-value test of detector honesty and root scoping, but it may consume disproportionate implementation/debug time.  
**Applicability:** Optional for challenge submission; required before advertising robust mixed-framework monorepo support.  
**Confidence:** Medium.  
**What would change in our design:** Keep it outside the launch-critical five; run it as soon as the primary corpus passes.

## Immediate recommendation

1. Pin the five exact commits above in an automated smoke manifest, while the deployed product continues to scan each repository’s current default-branch commit.
2. Implement G1–G5 before tuning prose or LLM ranking; without typed coverage and normalization, priority output is unauditable.
3. Create deterministic raw-output fixtures for ranking immediately. Do not spend the deadline trying to discover “known bad” issues in third-party repositories.
4. Run the five live scans on Zerops and record durations/statuses as deployment evidence. If a tool fails, use the partial-results gate rather than removing the repository from the corpus.
5. Treat TanStack Virtual as the first post-primary stress test and mixed-framework proof.

## Sources and relevance

- [GitHub REST repository endpoint](https://docs.github.com/en/rest/repos/repos) — authoritative source for repository metadata fields used in selection.
- [GitHub repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits) — authoritative context for shallow clone behavior and why product-specific caps must be much smaller.
- [React: Using TypeScript](https://react.dev/learn/typescript) — authoritative `.tsx`/JSX TypeScript source expectations.
- [Angular component guide](https://angular.dev/guide/components) — authoritative Angular TypeScript/decorator source shape.
- [Vue: Using Vue with TypeScript](https://vuejs.org/guide/typescript/overview) — authoritative SFC `lang="ts"`, `vue-tsc`, and TS config expectations.
- [Svelte TypeScript guide](https://svelte.dev/docs/svelte/typescript) — authoritative SFC `<script lang="ts">`, preprocessor, and TS config expectations.
- [Solid TypeScript guide](https://docs.solidjs.com/configuration/typescript) and [Solid quick start](https://docs.solidjs.com/quick-start) — authoritative Solid JSX TypeScript configuration and official TS template availability.
- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), and [schema](https://modelcontextprotocol.io/specification/2025-11-25/schema) — authoritative acceptance basis for the read-only MCP surface.
- The six linked GitHub repositories and exact commit trees in the corpus tables — primary source for manifests, source shapes, licenses, and reproducible snapshots.
