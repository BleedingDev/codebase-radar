# Safe multi-framework TypeScript analyzer profile

**Project:** Codebase Radar Zerops MVP
**Research date:** 2026-08-09
**Boundary:** Public TypeScript repositories; no target dependency installation and no target build, test, hook, package script, submodule, binary, or JavaScript/TypeScript configuration execution.

## Decision

Ship this default profile in the combined UltraModern.js service. The service may spawn bounded application-owned binaries directly; no scan-worker service is required.

1. **Oxlint `1.77.0` + Ultracite `7.10.2`:** universal syntax-only JavaScript/TypeScript analysis, with native React enrichment and limited Vue `<script>` enrichment.
2. **Strictest TSConfig comparator:** an in-process, Radar-owned comparison against `@tsconfig/strictest@2.0.8`; one expandable policy-gap result, not one backlog item per option.
3. **JSCPD `5.0.14`:** lexical/token clone evidence across JS/TS/JSX/TSX/Vue/Svelte/markup, aggressively grouped and filtered.
4. **zizmor `1.29.0`:** offline GitHub Actions/workflow security evidence.
5. **OSV-Scanner `2.5.0`:** online advisory matching for explicit JavaScript lockfiles only.
6. **Knip `6.32.0`: defer from the default MVP.** Stock Knip deliberately executes repository-owned tooling configs. A deny-all static profile can avoid that, but without installed dependency metadata and dynamic framework config its dead-code/dependency results are not credible enough to rank independently.

The honest framework promise is **universal TypeScript analysis with detected-framework enrichment where it exists**, not equal native analysis for every framework:

| Detected framework | Oxlint coverage in this profile | Explicit gap |
|---|---|---|
| React | Universal JS/TS plus 86 enabled native React/hooks/JSX/a11y rules from Ultracite | Disable the experimental `react/react-compiler` rule until corpus validation; React Doctor is not part of this baseline. |
| Vue | Universal script analysis plus 18 native Vue script rules | Templates are not linted. |
| Angular | Universal TypeScript analysis of components/services/etc. | Ultracite's Oxlint Angular preset is empty; Angular templates are not linted. |
| Svelte | Universal analysis of extracted `<script>` blocks | Ultracite's Oxlint Svelte preset is empty; template semantics are not linted. |
| Solid | Universal JSX/TSX analysis | Ultracite's Oxlint Solid preset is empty; Solid-specific rules would require an unvalidated alpha JS-plugin bridge. |

Framework detection should be workspace-aware and static: inspect `package.json`, lockfiles, `angular.json`, and relevant file extensions. A monorepo may activate more than one framework profile. Detection selects only application-owned configuration; it never imports repository configuration.

## Decision-changing findings

### Claim: the proposed profile can remain inside one application service

**Verdict:** SUPPORTED
**Evidence:** Oxlint, JSCPD, and zizmor support local, non-mutating static modes; OSV-Scanner can parse explicit lockfiles without package-manager execution; the Strictest comparison is inert JSON parsing. Every tool exposes machine-readable output and can be started as a direct bounded child process except the small in-process comparator.
**Inference:** A separate networked scan worker would add deployment and failure-handling burden without creating a security boundary. Process limits are still required because parser subprocesses receive hostile bytes.
**Applicability:** Suitable for this deadline-constrained public-repository demo, not equivalent to production-grade tenant isolation.
**Confidence:** High.
**What changes in the design:** Keep UI/API/MCP/scanning in UltraModern.js plus PostgreSQL; use one internal subprocess manager and a low global scan-concurrency semaphore.

### Claim: Ultracite does not currently provide equal Oxlint presets for all five frameworks

**Verdict:** SUPPORTED
**Evidence:** In Ultracite `7.10.2`, the core preset has 534 configured/472 enabled rule entries, React has 103/86, and Vue has 18/18. The published Angular, Svelte, and Solid Oxlint preset objects contain zero rules. Oxlint's compatibility documentation independently says Vue/Svelte/Angular templates are not linted and Solid-specific rules require JS plugins.
**Inference:** Framework names in setup UI or exported preset paths cannot be presented as equal framework-native coverage.
**Applicability:** Angular still gets strong TypeScript and TraceDecay structural coverage; Svelte/Vue script blocks and Solid TSX are still parseable.
**Confidence:** High.
**What changes in the design:** Persist and display per-framework coverage, including explicit unavailable/template gaps.

### Claim: Knip is unsafe in its normal mode under the no-target-execution rule

**Verdict:** SUPPORTED
**Evidence:** Knip documents dynamic tooling-config loading. Tagged `6.32.0` source loads non-data configs through `jiti`, invokes exported config functions, and its tests demonstrate config side effects. Its normal accuracy also depends on installed dependency manifests/types and config-derived entrypoints.
**Inference:** A timeout or Node heap cap limits resource use but does not prevent target config from accessing the filesystem, network, or subprocess APIs.
**Applicability:** This is a mismatch with Radar's hostile static checkout, not a criticism of Knip in trusted local/CI use.
**Confidence:** High on execution behavior; medium on the exact quality loss of a hardened dependency-free profile because Knip publishes no benchmark for that unsupported shape.
**What changes in the design:** Defer Knip. If later shown experimentally, disable all 182 pinned plugins first, enable only source-audited static adapters, label output `investigate`, and require TraceDecay corroboration before ranking.

### Claim: OSV references can establish advisory applicability, but not exploitability

**Verdict:** SUPPORTED
**Evidence:** OSV-Scanner matches a resolved package/version from a supported lockfile against machine-readable affected ranges and groups OSV/GHSA/CVE aliases. The records include advisory IDs, ranges, severity vectors, fixes, and references.
**Inference:** Lockfile presence does not prove the vulnerable code path is imported, runtime-reachable, internet-exposed, or financially material.
**Applicability:** This is the strongest source of relevant CVE/advisory links in the MVP, provided the UI labels reachability and consequence as unknown/inferred.
**Confidence:** High.
**What changes in the design:** Link the matched OSV/advisory record; never attach arbitrary security articles or duplicate aliases as separate findings.

### Claim: the Strictest preset should be a policy comparison, not a compiler scan

**Verdict:** SUPPORTED
**Evidence:** `@tsconfig/strictest@2.0.8` contains inert JSON and no scanner. TypeScript inheritance is base-first/child-last, supports multiple bases, and external package bases may be unavailable because Radar does not install target dependencies.
**Inference:** A missing safeguard is evidence of configuration exposure, not evidence that a corresponding bug exists or that adoption is trivial.
**Applicability:** Local inheritance chains can be resolved confidently; unresolved external bases must make the result partial.
**Confidence:** High.
**What changes in the design:** Build a small versioned comparator and group all differences into one expandable finding/observation.

## Exact tool and license pins

| Component | Exact pin | License | Distribution/runtime note |
|---|---:|---|---|
| Oxlint | `1.77.0` | MIT | npm package selects a Linux native binding. Install into the app image; never resolve with `npx` during a scan. |
| Ultracite | `7.10.2` | MIT | Consume its exported Oxlint configs; do not run `ultracite init` or `ultracite check` on targets. |
| Strictest baseline | `@tsconfig/strictest@2.0.8` | MIT | Inert JSON policy baseline. |
| Comparator parser | `typescript@7.0.2` | Apache-2.0 | Radar-owned JSONC/config parser only; it does not imply target compatibility with TypeScript 7. |
| JSCPD | `5.0.14` | MIT | Rust v5 binary selected by npm wrapper; no v4 Node API assumptions. |
| zizmor | `1.29.0` | MIT | Pin the release binary and checksum in the image. |
| OSV-Scanner | `2.5.0` | Apache-2.0 | Pin release binary/checksum; v2 promises CLI/JSON compatibility within the major. |
| Knip, deferred | `6.32.0` | ISC | Node `^20.19.0 || >=22.12.0`; ordinary mode is for trusted installed projects. |

All tool licenses are permissive. Retain the corresponding license notices with the image. OSV advisory records come from several upstream databases with their own data licenses; link the authoritative records and avoid republishing an unbounded advisory corpus as product-authored content.

## Adapter contracts and commands

Commands below describe argument arrays. Production code must use direct `spawn` with `shell: false`, never interpolate repository data into a shell command.

### 1. Oxlint + Ultracite

Install exact packages at image build time. Use app-owned configs that extend the pinned Ultracite core and detected React/Vue presets. Override `react/react-compiler` to `off`. Do not enable type-aware mode: official guidance expects installed dependencies and, for monorepos, built declaration outputs; it also documents high-memory cases.

```text
/app/node_modules/.bin/oxlint
  --disable-nested-config
  --no-error-on-unmatched-pattern
  --config=/app/config/radar-<profile>.mjs
  --format=json
  --threads=1
  /scan/<opaque-id>/repo
```

Do not use `--fix`, `--fix-suggestions`, `--fix-dangerously`, `--type-aware`, `--type-check`, JS plugins, target configs, `ultracite check`, `ultracite init`, or scan-time package runners.

JSON is one object with:

```text
{
  diagnostics: [{ message, code, severity, causes, url, help,
                  filename, labels: [{ span }], related }],
  number_of_files, number_of_rules, threads_count, start_time
}
```

The JSON has no schema/tool version field. Store `oxlintVersion`, `ultraciteVersion`, selected presets, profile hash, and measured wall duration separately. Convert filenames to validated repository-relative paths. Retain all evidence spans. Rule URLs are External References, not proof of generic consequences.

Exit handling is output-first:

- valid JSON + exit `0`: successful, no configured error diagnostics;
- valid JSON + exit `1`: successful with findings;
- non-JSON + nonzero: tool/config failure;
- timeout/signal/output cap: incomplete; discard partial JSON or mark the Analyzer Run incomplete;
- zero matched files: `not_applicable`, not “healthy.”

SARIF 2.1.0 is also supported, but JSON is smaller and exposes Oxlint help URLs directly. Keep fixture tests for the exact pinned JSON contract.

### 2. Strictest TSConfig comparator

The exact baseline options are:

```json
{
  "strict": true,
  "allowUnusedLabels": false,
  "allowUnreachableCode": false,
  "exactOptionalPropertyTypes": true,
  "noFallthroughCasesInSwitch": true,
  "noImplicitOverride": true,
  "noImplicitReturns": true,
  "noPropertyAccessFromIndexSignature": true,
  "noUncheckedIndexedAccess": true,
  "noUnusedLocals": true,
  "noUnusedParameters": true,
  "isolatedModules": true,
  "esModuleInterop": true,
  "skipLibCheck": true
}
```

Implementation contract:

1. Find root-confined `tsconfig.json` and `tsconfig.*.json` files, including project-reference leaves.
2. Parse JSON/JSONC using Radar's pinned parser. Never evaluate `plugins` or any JavaScript.
3. Follow only relative `extends` files that resolve inside the checkout. Apply multiple bases left-to-right and the child last; record each option's origin.
4. An unavailable package base becomes `unresolvedExtends` and `resolution: partial`; do not fetch it or accidentally resolve it from `/app/node_modules`.
5. Detect the target's declared TypeScript range as data. All current baseline options require approximately TypeScript 4.4 or newer; older/unknown targets get a compatibility note.
6. Expand `strict` carefully: an explicit child option such as `strictNullChecks: false` is an opt-out even when `strict: true`.

Version the result as `radar.tsconfig-gap/v1`, with project path, resolution, target compiler range, unresolved bases, and typed differences. Use these difference classes:

- `weaker`: a correctness/hygiene guard is absent or disabled;
- `explicit-opt-out`: a strict-family member overrides `strict`;
- `different-policy`: interoperability/compilation choices such as `isolatedModules` or `esModuleInterop`;
- `stronger-or-tradeoff`: for example, `skipLibCheck: false` must not be scored as worse simply because Strictest sets it to `true`.

Config syntax errors, cycles, root escapes, more than 64 configs, files over 1 MiB, or unresolved bases produce explicit incomplete coverage. Collapse applicable differences into one result such as “TypeScript guardrails leave four checks disabled.”

### 3. JSCPD

Use a Radar-owned config:

```json
{
  "minTokens": 50,
  "minLines": 5,
  "maxSize": "1mb",
  "mode": "mild",
  "format": ["typescript", "tsx", "javascript", "jsx", "vue", "svelte", "markup"],
  "crossFormats": ["js-ts"],
  "ignore": [
    "**/.git/**", "**/node_modules/**", "**/dist/**", "**/build/**",
    "**/coverage/**", "**/.next/**", "**/.nuxt/**", "**/.svelte-kit/**",
    "**/vendor/**", "**/generated/**", "**/*.min.js"
  ],
  "reporters": ["json", "silent"],
  "workers": 2,
  "blame": false,
  "absolute": false
}
```

```text
/app/tools/jscpd
  /scan/<opaque-id>/repo
  --config=/app/config/radar-jscpd.json
  --reporters=json,silent
  --output=/scan/<opaque-id>/out/jscpd
  --workers=2
```

Never enable blame, symlink following, threshold exit behavior, target config, or `--max-lines` (the current implementation and documentation disagree about its meaning).

Read `jscpd-report.json`; the reporter writes a file rather than JSON to stdout. The root contains `statistics` and `duplicates`. Each duplicate has format, line/token count, fragment, and first/second file ranges. Validate only consumed fields because there is no published JSON compatibility policy. Bound or discard `fragment` after producing a short evidence excerpt.

Important adapter quirks:

- examples still contain old snake_case statistic keys while current source/tests use camelCase; tolerate both;
- SARIF hard-codes tool version `5.0.3` even in `5.0.14`; record the actual subprocess version separately;
- unreadable/invalid-UTF-8 files can be silently skipped and a nonexistent path can yield empty success; compare eligible input count with `statistics.total.sources`;
- v5 defaults to all CPU cores and each Rayon worker uses a large stack, so pin two workers and apply external memory/time limits.

JSCPD proves token similarity, not that abstraction is beneficial. Group clone pairs into clone families, suppress generated/test/fixture/snapshot/migration noise, and combine overlapping TraceDecay structural evidence without double-counting harm.

### 4. zizmor

```text
/app/tools/zizmor
  --offline
  --no-config
  --no-ignores
  --collect=workflows,actions
  --persona=regular
  --format=json-v1
  --no-progress
  --color=never
  /scan/<opaque-id>/repo
```

Remove `GH_TOKEN`, `GITHUB_TOKEN`, and `ZIZMOR_GITHUB_TOKEN` from the child environment. Do not use `--fix`. `--offline` is a documented no-network guarantee and skips audits that require GitHub facts. Persist `coverage.onlineAudits = false`.

JSON v1 is a flat array with finding identity/description/URL, `determinations { confidence, severity, persona }`, symbolic/concrete locations, and optional fixes. JSON v1 rows are zero-based. Pin `json-v1`, not the moving `json` alias.

Exit `0` and `11..14` are successful executions (none, informational, low, medium, high). Exit `1` is tool/audit error, `2` argument error, and `3` no inputs. Treat `3` as `not_applicable` only if Radar's own manifest found no workflow/action; otherwise mark incomplete.

The finding is direct evidence of a risky workflow construct. Attacker reachability and business consequence remain inference. Preserve zizmor severity and confidence separately; its documentation URL is an External Reference.

### 5. OSV-Scanner

Use Radar's root-confined walker to discover only `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock`, then pass those exact paths:

```text
/app/tools/osv-scanner scan source
  --format=json
  --verbosity=error
  --no-resolve
  --config=/app/config/empty-osv-scanner.toml
  -L=/scan/<opaque-id>/repo/pnpm-lock.yaml
  -L=/scan/<opaque-id>/repo/apps/web/package-lock.json
```

Do not pass the repository directory, recursive scan, `fix`, call analysis, native package-manager data sources, or experimental plugins. A trusted empty config prevents target `osv-scanner.toml` ignores from affecting Radar. `--no-resolve` prevents extra manifest/deps.dev/native-registry resolution; the explicit lockfiles already contain resolved versions.

This recommended MVP mode is static with respect to the repository but online: package coordinates are sent to OSV's API. No credentials are needed. Display that network behavior; for later private repositories, evaluate pre-downloaded offline databases.

JSON goes to stdout and contains `results[]`, each with a lockfile source and packages. Packages carry identity/version/ecosystem, vulnerability records, and alias `groups`. Generate one Radar observation per vulnerability group/package occurrence, not one per OSV/GHSA/CVE alias. Preserve IDs, affected ranges, severity vectors, fixed versions/events, modified time, and references.

- exit `0`: packages found, no known matches;
- exit `1`: packages found with matches; successful analyzer run;
- exit `128`: no packages found; skipped/incomplete depending on expected lockfile contents;
- exit `127` or invalid/truncated JSON/network timeout: incomplete, never “no vulnerabilities.”

Record scanner version, query time, lockfile hash, OSV IDs, and each advisory's modified time. A rescan of the same commit may change because advisory intelligence changed; label that separately from a repository change.

### 6. Knip, explicitly deferred

The important distinction is safety versus usefulness:

- Ordinary Knip auto-enables plugins from dependencies and dynamically imports config such as `vite.config.ts`, `webpack.config.js`, `nuxt.config.ts`, and React Router configuration through `jiti`.
- It does not ordinarily run package scripts just to build the graph, but config module evaluation itself has normal filesystem/network/subprocess capabilities.
- A safe adapter is possible only by passing an absolute Radar JSON config, overriding every graph-shaping field, setting all 182 pinned plugin names to `false`, then enabling only audited JSON/static-AST adapters.
- That adapter loses installed dependency entrypoints/types/bin metadata and custom framework aliases/routes/entries—the context Knip uses to reduce false positives.

Therefore it cannot satisfy both **safe** and **credible as a default priority source** under this boundary and deadline. If later prototyped, output must be low-confidence `dead_code_candidate`/`unused_dependency_candidate`, suppressed whenever entrypoints are uncertain, and never produce deletion advice or a Knip-only `fix now`.

Knip's JSON reporter is one object `{ issues: [...] }`, not JSONL. It omits analyzer/schema version and crucial configuration hints, another reason a future Radar adapter would need its own wrapper contract.

## Shared subprocess and failure contract

All adapters must emit an `AnalyzerRun` envelope independent of their native output:

```text
{
  analyzer, analyzerVersion, profileVersion, profileHash,
  status: complete | partial | not_applicable | failed | timed_out | truncated,
  durationMs,
  coverage: { eligibleFiles, analyzedFiles, omittedCapabilities, warnings },
  observations,
  rawOutputRetained: boolean
}
```

Required controls:

- exact build-time pins/integrities/checksums and startup version checks;
- direct argv spawning with no shell and no scan-time package download;
- server-created opaque checkout/output paths, root confinement after `realpath`, and no symlink following;
- minimal child environments with credentials removed; OSV receives network but no credentials, all other default analyzers need none;
- repository/file/byte caps before spawning;
- process-group timeout and kill, stdout/stderr/report caps, per-tool diagnostic caps, and low global concurrency;
- compare eligible-file counts with tool-reported counts where possible;
- preserve warnings and omitted capability metadata;
- never infer “clean” from failure, timeout, truncation, unresolved config, missing lockfile, skipped online zizmor audits, or zero supported files.

Starting deadline-oriented wall budgets: TSConfig `5s`, Oxlint `30–60s`, JSCPD `30s`, zizmor `15s`, OSV `45s`. Tune only from the validation corpus. These are operational recommendations, not upstream guarantees.

The process boundary constrains resource failures but is not a hostile-code sandbox. Parser vulnerabilities still share the app container's identity; production tenant hardening remains deferred.

## Cross-tool normalization and priority

Keep every raw observation and provenance record. Group related evidence for display and ranking; do not destructively merge or sum tool severities.

| Raw signal | Directly established | Normalization rule |
|---|---|---|
| Oxlint diagnostic | A source location violates a pinned rule/policy. | Group repeated rule/location/symbol results. Ultracite's `error` is source policy severity, not consequence or priority. |
| TSConfig difference | Effective/partially resolved config differs from pinned Strictest policy. | One project/scan-level guardrail result. Missing policy does not prove a bug. |
| JSCPD clone | Regions exceed configured token/line similarity threshold. | Form clone families; use TraceDecay for structure/blast radius; do not double-score. |
| zizmor audit | Workflow/action construct matches a documented audit at stated severity/confidence. | Keep reachability and consequence separate; link its audit documentation. |
| OSV match | Resolved package/version falls in an advisory affected range. | Collapse aliases; retain reachability/exposure as unknown or separately evidenced. |
| TraceDecay structural signal | Structural relationship/metric/impact exists in the indexed snapshot. | Use to enrich blast radius and corroborate, not to convert proxies into verified runtime/security/business impact. |

Every Analyzer Run should preserve source severity, source confidence, evidence strength, blast radius, effort estimate, and change exposure as distinct fields. The LLM may produce audience-specific explanation and bounded reranking, but deterministic validation must reject any path, caller, CVE, severity, or consequence not backed by structured evidence.

## Telemetry and network summary

| Analyzer | Scan-time network | Telemetry / target execution assessment |
|---|---|---|
| Oxlint + Ultracite configs | Not required | No formal no-telemetry guarantee found; exact package/wrapper source showed no normal-result upload. Only application-owned configs run. |
| Strictest comparator | None | Inert local data parsing; no target execution. |
| JSCPD | None documented | Local tokenizer/native binary; no runtime telemetry feature found. No blame/symlinks. |
| zizmor | None in `--offline` mode | Officially documented offline behavior; no target execution. |
| OSV-Scanner | Yes, OSV API | Sends extracted ecosystem/package/version coordinates; no target execution in explicit lockfile mode. |
| Knip ordinary mode | Arbitrary via target config | Knip itself has no runtime telemetry found, but executed repository configs can perform arbitrary network/process/file actions. |

Negative source inspection is not the same as a contractual privacy guarantee. State “scan-time network not required/observed” rather than an absolute no-network promise, except for zizmor's documented offline mode.

## Completion gate and remaining gaps

This ticket is decision-complete for implementation:

- exact pins, licenses, commands, native contracts, result/failure exits, and boundaries are specified;
- framework coverage is honest and displayable;
- Knip's exclusion is explained and has a later safe experiment path;
- security reference applicability is separated from exploitability;
- all analyzers fit direct subprocesses in the combined service.

Remaining gaps are validation work, not unanswered profile design:

- measure noise/runtime/output on the selected multi-framework corpus;
- fixture-test each pinned native contract, especially JSCPD's drift quirks;
- tune per-rule grouping/suppression and process limits;
- re-evaluate Angular/Svelte/Solid native enrichment after the demo;
- evaluate Knip only inside a dedicated hostile-fixture/corpus experiment.

## Authoritative sources

1. [Oxlint `1.77.0` release](https://github.com/oxc-project/oxc/releases/tag/apps_v1.77.0) — exact release identity and binary version.
2. [Oxlint compatibility matrix](https://oxc.rs/compatibility.html) — framework/template limitations and Solid JS-plugin status.
3. [Oxlint built-in plugins](https://oxc.rs/docs/guide/usage/linter/plugins) — native plugin inventory and Vue script qualification.
4. [Oxlint CLI and output formats](https://oxc.rs/docs/guide/usage/linter/cli), [JSON/SARIF formats](https://oxc.rs/docs/guide/usage/linter/output-formats) — exact runtime/output flags and contracts.
5. [Oxlint type-aware guidance](https://oxc.rs/docs/guide/usage/linter/type-aware.html) and [JS-plugin guidance](https://oxc.rs/docs/guide/usage/linter/js-plugins) — dependency/build/memory requirements and alpha/custom-parser limits.
6. [Ultracite `7.10.2` release](https://github.com/haydenbleasel/ultracite/releases/tag/ultracite%407.10.2) and [version-pinned Oxlint configs](https://github.com/haydenbleasel/ultracite/tree/ultracite%407.10.2/packages/cli/config/oxlint) — exact presets and empty Angular/Svelte/Solid configs.
7. [`@tsconfig/strictest@2.0.8` registry record](https://registry.npmjs.org/@tsconfig/strictest/2.0.8) and [TSConfig Bases](https://github.com/tsconfig/bases) — exact baseline, license, and policy maintenance model.
8. [TypeScript TSConfig inheritance/reference](https://www.typescriptlang.org/tsconfig/explainFiles.html) and [TypeScript 4.4 notes](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-4-4.html) — inheritance semantics and option-version caveats.
9. [JSCPD `5.0.14` release](https://github.com/kucherenko/jscpd/releases/tag/v5.0.14), [v5 documentation](https://github.com/kucherenko/jscpd/blob/v5.0.14/rust/jscpd/README.md), and [JSON reporter source](https://github.com/kucherenko/jscpd/blob/v5.0.14/rust/crates/cpd-reporter/src/json_reporter.rs) — exact engine, CLI, formats, and machine shape.
10. [zizmor `1.29.0` release](https://github.com/zizmorcore/zizmor/releases/tag/v1.29.0), [usage](https://docs.zizmor.sh/usage/), and [audit catalog](https://docs.zizmor.sh/audits/) — version, JSON v1, offline mode, exits, and coverage.
11. [OSV-Scanner `2.5.0` release](https://github.com/google/osv-scanner/releases/tag/v2.5.0), [supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/), [output contract](https://google.github.io/osv-scanner/output/), and [configuration](https://google.github.io/osv-scanner/configuration/) — exact scanner, JS lockfiles, JSON/exits, and trusted config override.
12. [OSV guided-remediation safety warning](https://google.github.io/osv-scanner/experimental/guided-remediation/) and [OSV data sources](https://google.github.io/osv.dev/data/) — why `fix` is forbidden and provenance/licenses of advisory data.
13. [Knip `6.32.0` tagged package](https://github.com/webpro-nl/knip/tree/knip%406.32.0/packages/knip), [plugin execution model](https://knip.dev/explanations/plugins), and [tagged loader](https://github.com/webpro-nl/knip/blob/f21bcbb653377682dd690fb99b0f02977ac524d2/packages/knip/src/util/loader.ts) — exact version and dynamic config execution.
14. [Knip CI](https://knip.dev/guides/using-knip-in-ci), [FAQ](https://knip.dev/reference/faq), and [handling findings](https://knip.dev/guides/handling-issues) — installed-project assumptions and false-positive causes.

## Research coverage and evidence limits

This synthesis used three independent subareas: Oxlint/framework presets, Knip safety/fidelity, and the remaining static analyzers. It includes more than twelve primary official source groups, version-pinned source inspection, registry/release metadata, and local output-contract checks.

No published comparative accuracy benchmark proves that this exact composite profile yields a useful top five. That claim remains **INCONCLUSIVE** until the validation-corpus ticket measures precision, coverage, runtime, output size, and maintainer usefulness. The profile above is safe and implementable under the stated boundary; ranking quality still requires empirical calibration.
