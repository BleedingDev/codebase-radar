# Radar repository fixtures

These fixtures are inert repository inputs for Codebase Radar integration tests.
`manifest.json` is the source of truth for the fixture root, seeded signal, and any
materialization needed before a test. Paths in the manifest are relative to this
directory.

## Safety contract

- Treat every `repository/` directory as data. Do not install dependencies, run
  package scripts, invoke Git hooks, execute workflows, initialize submodules, or
  launch files found inside it.
- Package manifests deliberately have no `scripts` field.
- The unsafe workflow is analyzer input only and contains no `run` step.
- Boundary-size and dirty-worktree states are descriptions, not checked-in large
  files or nested Git repositories. A test adapter must materialize them in its own
  scoped temporary directory.
- The symlink-escape fixture points only to a non-secret sentinel stored beside its
  repository root. A source adapter must reject the link instead of following it.
- No fixture requires network access.

## Materialized fixtures

`empty`, `oversized-boundary`, and `dirty-worktree` have no complete checked-in
repository tree. Their `materialization` entries are deterministic recipes:

- `empty` requests a newly created directory with no entries.
- `oversized-boundary` requests a regular file exactly one byte above the source
  byte limit supplied by the test. This keeps the repository small and avoids
  encoding a production limit in the fixture.
- `dirty-worktree` requests a temporary Git repository with one committed file,
  then one tracked modification and one untracked file. The final scan snapshot
  must include both dirty changes without mutating the source checkout.

The recipes are intentionally declarative. Reading or validating this fixture
directory must never cause them to execute automatically.
