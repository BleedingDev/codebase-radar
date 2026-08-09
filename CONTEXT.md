# Codebase Radar

Shared language for a continuous product that turns repository analysis into a prioritized codebase-improvement backlog.

## Language

**Codebase Radar**:
The continuous product that analyzes a codebase over time and prioritizes improvements. Its first usable state may contain only one scan without becoming a one-off audit.
_Avoid_: Audit, scanner wrapper, TraceDecay extension

**Codebase Scan**:
One immutable analysis run over a repository at a specific snapshot, identified by its commit and analysis configuration.
_Avoid_: Radar, audit

**Finding**:
A specific issue or risk observed during a Codebase Scan and backed by repository or analyzer evidence.
_Avoid_: Generic recommendation, metric, AI opinion

**Improvement Backlog**:
The single ordered list of Findings produced from a Codebase Scan. Each entry keeps its underlying scores separate while receiving one action class: `fix now`, `investigate`, `monitor`, or `do not fix`.
_Avoid_: Lint report, issue dump, single quality score

**Scan Result**:
The canonical machine-readable representation of a Codebase Scan, including evidence, Findings, scores, the Improvement Backlog, and analyzer coverage.
_Avoid_: Executive report, UI copy

**Audience Profile**:
A person's preferred explanation depth and vocabulary, such as technical or nontechnical. It changes presentation without changing Scan Results or priorities.
_Avoid_: Separate analysis mode, permission role

**Scan Comparison**:
The change between a current Codebase Scan and the preceding scan of the same codebase, including new, resolved, and changed Findings and score deltas.
_Avoid_: Scan, trend

**External Reference**:
A CVE, CWE, advisory, article, or similar resource that explains a Finding's mechanism or possible consequence. It is contextual material, not evidence that the repository is affected unless applicability is established.
_Avoid_: Evidence, verified impact
