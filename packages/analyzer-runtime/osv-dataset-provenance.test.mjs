import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const provenancePath = join(
  packageRoot,
  'licenses/osv-database/PROVENANCE.json',
);
const provenance = JSON.parse(readFileSync(provenancePath, 'utf8'));

test('pins the immutable non-executable npm OSV dataset identity', () => {
  assert.equal(
    provenance.schemaVersion,
    'codebase-radar.osv-dataset-provenance/v1',
  );
  assert.deepEqual(provenance.artifact, {
    kind: 'vulnerability-advisory-dataset',
    execution: 'non-executable',
    ecosystem: 'npm',
    installedPath: 'databases/osv/osv-scalibr/npm/all.zip',
    sourceUrl:
      'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=1786418349414076',
    generation: '1786418349414076',
    sha256:
      '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69',
    byteLength: 218758368,
    publishedAt: '2026-08-11T03:19:09Z',
    maximumAgeSeconds: 604800,
  });
});

test('does not relicense or overstate redistribution approval for the aggregate', () => {
  assert.equal(provenance.licensing.aggregateLicenseConclusion, 'NOASSERTION');
  assert.equal(provenance.licensing.treatment, 'mixed-upstream-licenses');
  assert.equal(provenance.licensing.scannerCodeLicense.spdxExpression, 'Apache-2.0');
  assert.equal(provenance.licensing.scannerCodeLicense.appliesToDataset, false);
  assert.deepEqual(provenance.licensing.recordPolicy, {
    preserveRecordsUnmodified: true,
    relicenseAggregate: false,
    retainUpstreamAttributionAndTerms: true,
  });
  assert.equal(
    provenance.licensing.redistributionApproval,
    'required-before-public-release',
  );
  assert.match(
    provenance.licensing.releaseCaveat,
    /Independent legal review and approval remains required/u,
  );

  const notice = readFileSync(join(packageRoot, 'THIRD_PARTY_NOTICES.md'), 'utf8');
  assert.match(notice, /OSV-Scanner 2\.5\.0 executable code — Apache-2\.0/u);
  assert.match(notice, /snapshot is not labeled\s+Apache-2\.0/u);
  assert.match(notice, /independent legal review and approval remains an external release\s+requirement/u);
});
