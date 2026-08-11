# Radar golden artifacts

These fixtures are intentionally outside the testkit package export surface.
The focused suite uses strict accepted codecs for Scan Results, progress, and
analysis failures; the frozen app `ScanRecord`; and the existing CLI
`DoctorReportSchema`. Golden-only provenance and scripted-runtime transcript
schemas remain private to this directory.

- `complete-scan-result.json` is the complete seven-analyzer canonical result.
- `cli-json.json` is the production Scan Result JSON encoding plus exactly one
  trailing newline.
- `human-backlog.txt` is the deterministic all-findings human rendering of the
  same canonical result.
- `http-persisted-*.json` are strict frozen-app `ScanRecord` payloads,
  including the accepted legacy migration shape.
- `runtime-manifest-provenance.json` records the immutable analyzer identity,
  exact seven tuples, policy, and digest used by each dependent artifact.
- `runtime-doctor-*.json` are strict existing-CLI doctor reports, not a new
  runtime transport schema.
- `scripted-runtime-transcript.json` is private scripted-adapter evidence with
  exact seven-run lifecycle identity.

Run the focused fixture suite without changing package discovery:

```sh
pnpm --dir packages/radar-testkit exec vitest run --config golden/vitest.config.ts
```
