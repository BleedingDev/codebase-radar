# Analyzer notices

- TraceDecay 0.0.73 — MIT; copyright (c) 2025 Enzo Lombardi. Its required distribution notice and the Apache-2.0 attribution for adapted `mnemon` work are reproduced below.
- Calldiff 0.4.1 — MIT; copyright (c) 2026 Tanishq Kancharla.
- Tree-sitter 0.25.1, tree-sitter-javascript 0.23.1, and
  tree-sitter-typescript 0.23.2 — MIT; copyright their respective contributors.
- Oxlint 1.77.0 — MIT; copyright (c) 2024-present VoidZero Inc. & Contributors and copyright (c) 2023 Boshen.
- Ultracite 7.10.2 — MIT; copyright (c) 2022 — Present Hayden Bleasel.
- JSCPD 5.0.14 — MIT; copyright (c) 2013-2024 Andrey Kucherenko.
- zizmor 1.29.0 — MIT; copyright (c) 2024 William Woodruff.
- OSV-Scanner 2.5.0 executable code — Apache-2.0.
- OSV npm vulnerability-database snapshot — non-executable advisory data
  aggregated and published by the Open Source Vulnerabilities (OSV) project.
  It contains records originating from multiple upstream data sources with
  different license and attribution terms. The snapshot is not labeled
  Apache-2.0 and is not relicensed by Codebase Radar. Its immutable source
  identity, preservation rules, upstream attribution authorities, and legal
  release caveat are recorded in
  `licenses/osv-database/PROVENANCE.json`. Attribution and byte preservation
  alone do not establish permission to redistribute this aggregate: an
  independent legal review and approval remains an external release
  requirement before any public redistribution.
- Bubblewrap 0.9.0-1ubuntu0.1 — LGPL-2.0-or-later. It is a separately
  provisioned Ubuntu host component, never bundled into this package; its raw
  `/usr/bin/bwrap` bytes are pinned by the production resource boundary.
- util-linux 2.39.3-9ubuntu6.5 (`prlimit`) — GPL-2.0-or-later. It is a
  separately provisioned Ubuntu host component, never bundled into this
  package; its raw `/usr/bin/prlimit` bytes are pinned by the production
  resource boundary.
- Semantic runner bundle: Effect 4.0.0-beta.102, `@effect/platform-node`
  4.0.0-beta.102, and `@effect/platform-node-shared` 4.0.0-beta.102 — MIT;
  copyright (c) 2023 Effectful Technologies Inc.
- Semantic runner bundle: fast-check 4.9.0 — MIT; copyright (c) 2017 Nicolas
  DUBIEN; pure-rand 8.4.2 — MIT; copyright (c) 2018 Nicolas DUBIEN.
- Semantic runner bundle: strip-json-comments 5.0.3 — MIT; copyright Sindre
  Sorhus.

The pinned license texts are bundled under `licenses/<tool>/LICENSE`. TraceDecay's
upstream notice is also bundled verbatim at `licenses/tracedecay/NOTICE`.
The exact licenses for dependencies compiled into the semantic runner are
bundled under `licenses/semantic-runner-*/LICENSE`.

## TraceDecay 0.0.73 NOTICE

tracedecay

Copyright (c) the tracedecay contributors. Licensed under the MIT license (see LICENSE).

This product includes material adapted from third-party projects:

mnemon (https://github.com/mnemon-dev/mnemon)

Licensed under the Apache License, Version 2.0
(http://www.apache.org/licenses/LICENSE-2.0).

The negation / state-change cue list and the write-time diff combination rule
in src/memory/diff.rs are adapted from mnemon's internal/search/diff.go.
