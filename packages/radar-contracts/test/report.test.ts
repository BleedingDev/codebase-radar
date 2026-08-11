import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalysisSource,
  AnalyzerCoverageSchema,
  AttemptedAnalyzerRun,
  CanonicalRepositoryPathSet,
  CodebaseId,
  CompleteAnalyzerRunSchema,
  ContractLimits,
  decodeAnalysisSource,
  decodeScanResult,
  decodeScanResultJson,
  EvidenceSchema,
  EmptyRepositoryPathSetDigest,
  encodeCanonicalRepositoryPathSet,
  encodeScanResult,
  encodeScanResultJson,
  ExternalReference,
  FindingSchema,
  LegacyScanResult,
  LocalSourceIdentity,
  NotApplicableAnalyzerRunSchema,
  RequiredAnalyzerIds,
  RepositoryPathSetDigest,
  ScanResult,
  ScanResultFromV1,
  ScanResultJson,
  ScanResultSchemaVersion,
  ScanResultV2,
  ScanComparisonSchema,
  SourceIdentity,
  SuccessfulAnalyzerRun,
  SuccessfulScanResultSchema,
} from '../src/index.js';
import {
  analyzerRuns,
  codebaseId,
  commitSha,
  finding,
  githubIdentity,
  successfulResult,
  singlePathSetDigest,
  v1Result,
} from './fixtures.js';

const decodeExit = Schema.decodeUnknownExit;

describe('source contracts', () => {
  it('requires an explicit tagged GitHub revision', () => {
    const revisions = [
      { _tag: 'DefaultBranchRevision' },
      { _tag: 'BranchRevision', branch: 'feature/contracts' },
      { _tag: 'TagRevision', tag: 'v1.0.0' },
      { _tag: 'CommitRevision', commitSha },
    ];
    for (const revision of revisions) {
      expect(
        Exit.isSuccess(
          decodeExit(AnalysisSource)({
            _tag: 'GitHubSource',
            owner: 'Owner',
            repository: 'Repository',
            revision,
          }),
        ),
      ).toBe(true);
    }
    expect(
      Exit.isFailure(
        decodeExit(AnalysisSource)({
          _tag: 'GitHubSource',
          owner: 'Owner',
          repository: 'Repository',
        }),
      ),
    ).toBe(true);
  });

  it('rejects fields from a different source variant', () => {
    const exit = Effect.runSync(
      Effect.exit(
        decodeAnalysisSource({
          _tag: 'GitHubSource',
          owner: 'Owner',
          repository: 'Repository',
          revision: { _tag: 'DefaultBranchRevision' },
          directory: '/private/repository',
        }),
      ),
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('rejects relative local paths and repository dot segments', () => {
    expect(
      Exit.isFailure(
        decodeExit(AnalysisSource)({
          _tag: 'LocalDirectorySource',
          directory: 'relative/repository',
          codebaseId: 'local:repository-one',
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(AnalysisSource)({
          _tag: 'GitHubSource',
          owner: '..',
          repository: 'Repository',
          revision: { _tag: 'DefaultBranchRevision' },
        }),
      ),
    ).toBe(true);
    for (let codePoint = 0x80; codePoint <= 0x9f; codePoint += 1) {
      expect(
        Exit.isFailure(
          decodeExit(AnalysisSource)({
            _tag: 'LocalDirectorySource',
            directory: `/work/${String.fromCodePoint(codePoint)}repository`,
            codebaseId: 'local:repository-one',
          }),
        ),
      ).toBe(true);
    }
  });

  it('rejects ambiguous Git reference syntax', () => {
    const unsafeRevisions = [
      { _tag: 'BranchRevision', branch: 'main~1' },
      { _tag: 'BranchRevision', branch: 'main^' },
      { _tag: 'BranchRevision', branch: '@' },
      { _tag: 'BranchRevision', branch: 'HEAD' },
      { _tag: 'BranchRevision', branch: 'head' },
      { _tag: 'BranchRevision', branch: 'FETCH_HEAD' },
      { _tag: 'TagRevision', tag: 'orig_head' },
      { _tag: 'BranchRevision', branch: 'foo.lock' },
      { _tag: 'BranchRevision', branch: 'with space' },
      { _tag: 'TagRevision', tag: 'release/.hidden' },
    ];
    for (const revision of unsafeRevisions) {
      expect(
        Exit.isFailure(
          decodeExit(AnalysisSource)({
            _tag: 'GitHubSource',
            owner: 'Owner',
            repository: 'Repository',
            revision,
          }),
        ),
      ).toBe(true);
    }
  });

  it('validates GitHub owner and repository names independently', () => {
    const invalidNames = [
      { owner: '-owner', repository: 'repository' },
      { owner: 'owner-', repository: 'repository' },
      { owner: 'owner_name', repository: 'repository' },
      { owner: 'owner--name', repository: 'repository' },
      { owner: 'o'.repeat(40), repository: 'repository' },
      { owner: 'owner\nname', repository: 'repository' },
      { owner: 'owner', repository: '.git' },
      { owner: 'owner', repository: 'repository.git' },
      { owner: 'owner', repository: 'repository/name' },
      { owner: 'owner', repository: 'r'.repeat(101) },
    ];
    for (const names of invalidNames) {
      expect(
        Exit.isFailure(
          decodeExit(AnalysisSource)({
            _tag: 'GitHubSource',
            ...names,
            revision: { _tag: 'DefaultBranchRevision' },
          }),
        ),
      ).toBe(true);
    }
    expect(
      Exit.isSuccess(
        decodeExit(AnalysisSource)({
          _tag: 'GitHubSource',
          owner: 'Mixed-Case',
          repository: 'Repository.Name',
          revision: { _tag: 'DefaultBranchRevision' },
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        decodeExit(AnalysisSource)({
          _tag: 'GitHubSource',
          owner: 'a'.repeat(39),
          repository: 'R'.repeat(100),
          revision: { _tag: 'DefaultBranchRevision' },
        }),
      ),
    ).toBe(true);
    const invalidCodebaseIds = [
      'github:owner_name/repository',
      'github:-owner/repository',
      'github:owner--name/repository',
      'github:owner/repository.git',
      `github:${'a'.repeat(40)}/repository`,
      `github:owner/${'r'.repeat(101)}`,
      `local:${'x'.repeat(ContractLimits.identifierCharacters)}`,
    ];
    for (const identity of invalidCodebaseIds) {
      expect(Exit.isFailure(decodeExit(CodebaseId)(identity))).toBe(true);
    }
    expect(
      Exit.isSuccess(
        decodeExit(CodebaseId)(
          `github:${'a'.repeat(39)}/${'r'.repeat(100)}`,
        ),
      ),
    ).toBe(true);
  });

  it('keeps local source paths out of encoded results', () => {
    const source = new LocalSourceIdentity({
      codebaseId: 'local:repository-one',
      repository: 'repository-one',
      snapshotDigest:
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      dirty: true,
    });
    const encoded = Schema.encodeSync(SuccessfulScanResultSchema)(
      successfulResult(source),
    );
    const decoded = Schema.decodeSync(SuccessfulScanResultSchema)(encoded);
    const attackedExit = Effect.runSync(
      Effect.exit(
        decodeScanResult({
          ...successfulResult(source),
          source: {
            ...source,
            directory: '/Users/example/private/repository',
          },
        }),
      ),
    );
    const serialized = JSON.stringify(encoded);
    expect(serialized).not.toContain('/Users/example/private/repository');
    expect(serialized).not.toContain('directory');
    expect(serialized).toContain('local:repository-one');
    expect(decoded.source).toEqual(source);
    expect(Exit.isFailure(attackedExit)).toBe(true);
  });

  it('rejects source identity fields that disagree', () => {
    const identity = githubIdentity();
    const invalidIdentities = [
      { ...identity, codebaseId: 'github:other/repository' },
      {
        ...identity,
        snapshotDigest:
          'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
      { ...identity, defaultBranch: '../unsafe' },
      {
        _tag: 'LocalSourceIdentity',
        codebaseId: 'local:repository-one',
        repository: 'repository-one',
        snapshotDigest:
          'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        branch: 'main~1',
        dirty: true,
      },
      {
        _tag: 'LocalSourceIdentity',
        codebaseId: 'local:repository-one',
        repository: 'repository-one',
        snapshotDigest: `git:${commitSha}`,
        commitSha,
        dirty: true,
      },
      {
        _tag: 'LocalSourceIdentity',
        codebaseId: 'local:repository-one',
        repository: 'repository-one',
        snapshotDigest:
          'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        branch: 'main',
        dirty: false,
      },
    ];
    for (const invalid of invalidIdentities) {
      expect(Exit.isFailure(decodeExit(SourceIdentity)(invalid))).toBe(true);
    }
  });
});

describe('Scan Result v2', () => {
  it('validates and encodes only canonical UTF-8 repository path sets', () => {
    const canonical = ['src/\uE000.ts', 'src/\u{10000}.ts'];
    const decoded = Schema.decodeUnknownSync(CanonicalRepositoryPathSet)(canonical);
    expect(Array.from(encodeCanonicalRepositoryPathSet(decoded))).toEqual(
      Array.from(new TextEncoder().encode(JSON.stringify(canonical))),
    );
    for (const invalid of [
      [...canonical].reverse(),
      ['src/duplicate.ts', 'src/duplicate.ts'],
    ]) {
      expect(
        Exit.isFailure(Schema.decodeUnknownExit(CanonicalRepositoryPathSet)(invalid)),
      ).toBe(true);
    }

    const item = finding();
    const evidence = item.evidence[0];
    expect(evidence).toBeDefined();
    if (evidence === undefined) return;
    const canonicalEvidence = [
      { ...evidence, path: 'src/\uE000.ts' },
      { ...evidence, path: 'src/\u{10000}.ts' },
    ];
    expect(
      Exit.isSuccess(
        decodeExit(FindingSchema)({ ...item, evidence: canonicalEvidence }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(FindingSchema)({
          ...item,
          evidence: [...canonicalEvidence].reverse(),
        }),
      ),
    ).toBe(true);

    const atLimit = Array.from(
      { length: ContractLimits.semanticAnalyzerInventoryEntries },
      (_, index) => `src/path-${index.toString().padStart(4, '0')}.ts`,
    );
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(CanonicalRepositoryPathSet)(atLimit)),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(CanonicalRepositoryPathSet)([
          ...atLimit,
          'src/path-over-limit.ts',
        ]),
      ),
    ).toBe(true);

    const utf8 = new TextEncoder();
    const atByteLimit = Array.from(
      { length: ContractLimits.semanticAnalyzerInventoryEntries },
      (_, index) => `src/byte-${index.toString().padStart(4, '0')}${index === 0 ? '-λ' : ''}.ts`,
    );
    let remaining =
      ContractLimits.semanticAnalyzerRequestBytes -
      utf8.encode(JSON.stringify(atByteLimit)).byteLength;
    expect(remaining).toBeGreaterThan(0);
    for (let index = 0; index < atByteLimit.length && remaining > 0; index += 1) {
      const path = atByteLimit[index];
      expect(path).toBeDefined();
      if (path === undefined) continue;
      const capacity = ContractLimits.pathCharacters - path.length;
      const added = Math.min(capacity, remaining);
      atByteLimit[index] = `${path.slice(0, -3)}${'x'.repeat(added)}.ts`;
      remaining -= added;
    }
    expect(remaining).toBe(0);
    expect(utf8.encode(JSON.stringify(atByteLimit)).byteLength).toBe(
      ContractLimits.semanticAnalyzerRequestBytes,
    );
    expect(
      Exit.isSuccess(Schema.decodeUnknownExit(CanonicalRepositoryPathSet)(atByteLimit)),
    ).toBe(true);
    const overByteLimit = [...atByteLimit];
    const expandableIndex = overByteLimit.findIndex(
      path => path.length < ContractLimits.pathCharacters,
    );
    expect(expandableIndex).toBeGreaterThanOrEqual(0);
    const expandable = overByteLimit[expandableIndex];
    expect(expandable).toBeDefined();
    if (expandable === undefined) return;
    overByteLimit[expandableIndex] = `${expandable.slice(0, -3)}x.ts`;
    expect(utf8.encode(JSON.stringify(overByteLimit)).byteLength).toBe(
      ContractLimits.semanticAnalyzerRequestBytes + 1,
    );
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(CanonicalRepositoryPathSet)(overByteLimit)),
    ).toBe(true);
  });

  it('requires canonical path-set digests for complete and not-applicable runs', () => {
    const run = analyzerRuns()[0];
    expect(run).toBeDefined();
    if (run === undefined) return;
    const wrongDigest = `sha256:${'b'.repeat(64)}`;
    expect(Exit.isSuccess(decodeExit(RepositoryPathSetDigest)(singlePathSetDigest))).toBe(
      true,
    );
    for (const invalid of [
      `SHA256:${'a'.repeat(64)}`,
      `sha256:${'A'.repeat(64)}`,
      'sha256:short',
    ]) {
      expect(Exit.isFailure(decodeExit(RepositoryPathSetDigest)(invalid))).toBe(true);
    }
    expect(
      Exit.isFailure(
        decodeExit(CompleteAnalyzerRunSchema)({
          ...run,
          coverage: {
            ...run.coverage,
            analyzedPathSetDigest: wrongDigest,
          },
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(CompleteAnalyzerRunSchema)({
          ...run,
          coverage: {
            ...run.coverage,
            eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
            analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
          },
        }),
      ),
    ).toBe(true);
    const resultWithEmptyCompleteDigest = {
      ...successfulResult(),
      analyzerRuns: [
        {
          ...run,
          coverage: {
            ...run.coverage,
            eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
            analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
          },
        },
        ...analyzerRuns().slice(1),
      ],
    };
    expect(
      Exit.isFailure(
        Effect.runSync(Effect.exit(encodeScanResult(resultWithEmptyCompleteDigest))),
      ),
    ).toBe(true);
    const partialCoverage = {
      ...run.coverage,
      eligibleFiles: 1,
      analyzedFiles: 0,
      eligiblePathSetDigest: singlePathSetDigest,
      analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
    };
    expect(Exit.isSuccess(decodeExit(AnalyzerCoverageSchema)(partialCoverage))).toBe(
      true,
    );
    for (const inconsistentCoverage of [
      {
        ...run.coverage,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
      },
      {
        ...partialCoverage,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
      },
      {
        ...partialCoverage,
        analyzedPathSetDigest: singlePathSetDigest,
      },
      {
        ...run.coverage,
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: singlePathSetDigest,
        analyzedPathSetDigest: singlePathSetDigest,
      },
    ]) {
      expect(Exit.isFailure(decodeExit(AnalyzerCoverageSchema)(inconsistentCoverage))).toBe(
        true,
      );
    }
    const notApplicable = {
      ...run,
      _tag: 'NotApplicableAnalyzerRun',
      status: 'not_applicable',
      reason: { code: 'no-eligible-input', message: 'No eligible source files.' },
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      },
      observationCount: 0,
    };
    expect(Exit.isSuccess(decodeExit(NotApplicableAnalyzerRunSchema)(notApplicable))).toBe(
      true,
    );
    for (const coverage of [
      { ...notApplicable.coverage, omittedCapabilities: ['unsupported-mode'] },
      { ...notApplicable.coverage, analyzedPathSetDigest: wrongDigest },
    ]) {
      expect(
        Exit.isFailure(
          decodeExit(NotApplicableAnalyzerRunSchema)({ ...notApplicable, coverage }),
        ),
      ).toBe(true);
    }
  });

  it('round-trips one complete result with stable fingerprints', () => {
    const original = successfulResult();
    const encoded = Schema.encodeSync(ScanResult)(original);
    const decoded = Schema.decodeSync(ScanResult)(encoded);
    expect(decoded).toEqual(original);
    expect(decoded.findings.map(item => item.fingerprint)).toEqual([
      'fingerprint-one',
    ]);
    expect(ScanResultSchemaVersion).toBe('codebase-radar.scan-result/v2');
    expect(ScanResultV2).toBe(SuccessfulScanResultSchema);
    expect(Object.isFrozen(RequiredAnalyzerIds)).toBe(true);
    expect(Reflect.set(RequiredAnalyzerIds, '0', 'TraceDecay')).toBe(false);
    expect(RequiredAnalyzerIds).toHaveLength(7);
  });

  it('enforces mechanism, safe reference URLs, and complete coverage', () => {
    const item = finding();
    expect(
      Exit.isFailure(
        decodeExit(FindingSchema)({
          ...item,
          mechanism: undefined,
        }),
      ),
    ).toBe(true);
    const ambiguousUrls = [
      'https://example.com/reference\n',
      'https://example.com/ref\terence',
      'https://example.com/ref\u007ferance',
      'https://example.com:443/reference',
      'https://example.com',
      'HTTPS://EXAMPLE.COM/reference',
      'https://example.com/reference?access_token=credential',
      'https://example.com/reference#authorization=credential',
      'https://example.com/reference?pass=credential',
      'https://example.com/reference?pwd=credential',
      'https://example.com/reference?p%61ss=credential',
      `https://example.com/reference#${'prefix'.repeat(40)}access_token=credential`,
      'https://user:password@example.com/reference',
      'https:user:password@example.com/reference',
      'https://example.com/%00reference',
      'https://example.com/%C2%80reference',
    ];
    for (const url of ambiguousUrls) {
      expect(
        Exit.isFailure(
          decodeExit(ExternalReference)({
            label: 'unsafe',
            url,
            relationship: 'background',
            applicability: 'unverified',
          }),
        ),
      ).toBe(true);
    }
    expect(
      Exit.isFailure(
        decodeExit(EvidenceSchema)({
          analyzer: 'TraceDecay',
          kind: 'direct',
          message: 'Line without a repository path.',
          line: 1,
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ExternalReference)({
          label: 'unsafe',
          url: 'file:///private/report',
          relationship: 'background',
          applicability: 'unverified',
        }),
      ),
    ).toBe(true);
    const run = analyzerRuns()[0];
    expect(run).toBeDefined();
    if (!run) return;
    expect(
      Exit.isFailure(
        decodeExit(CompleteAnalyzerRunSchema)({
          ...run,
          coverage: {
            ...run.coverage,
            eligibleFiles: 0,
            analyzedFiles: 0,
          },
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(CompleteAnalyzerRunSchema)({
          ...run,
          coverage: {
            ...run.coverage,
            omittedCapabilities: ['unsupported-mode'],
          },
        }),
      ),
    ).toBe(true);
  });

  it('requires a structured reason for zero-input analyzer runs', () => {
    const run = analyzerRuns()[0];
    expect(run).toBeDefined();
    if (!run) return;
    const notApplicable = {
      ...run,
      _tag: 'NotApplicableAnalyzerRun',
      status: 'not_applicable',
      reason: {
        code: 'no-eligible-input',
        message: 'No supported files were present.',
      },
      coverage: {
        eligibleFiles: 0,
        analyzedFiles: 0,
        eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
        analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      },
      observationCount: 0,
    };
    expect(
      Exit.isSuccess(decodeExit(NotApplicableAnalyzerRunSchema)(notApplicable)),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(NotApplicableAnalyzerRunSchema)({
          ...notApplicable,
          reason: undefined,
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(NotApplicableAnalyzerRunSchema)({
          ...notApplicable,
          observationCount: 1,
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(NotApplicableAnalyzerRunSchema)({
          ...notApplicable,
          profileVersion: 'alternate-policy/v1',
        }),
      ),
    ).toBe(true);
  });

  it('keeps successful and attempted analyzer runs disjoint', () => {
    const complete = analyzerRuns()[0];
    expect(complete).toBeDefined();
    if (!complete) return;
    const attempted = {
      ...complete,
      _tag: 'AttemptedAnalyzerRun',
      status: 'failed',
      diagnostic: 'Analyzer exited before producing complete output.',
    };
    expect(Exit.isSuccess(decodeExit(SuccessfulAnalyzerRun)(complete))).toBe(true);
    expect(Exit.isFailure(decodeExit(AttemptedAnalyzerRun)(complete))).toBe(true);
    expect(Exit.isSuccess(decodeExit(AttemptedAnalyzerRun)(attempted))).toBe(true);
    expect(Exit.isFailure(decodeExit(SuccessfulAnalyzerRun)(attempted))).toBe(true);
  });

  it('rejects local path material throughout canonical output', () => {
    const result = successfulResult();
    const item = finding();
    const baseEvidence = item.evidence[0];
    const baseRun = result.analyzerRuns[0];
    expect(baseEvidence).toBeDefined();
    expect(baseRun).toBeDefined();
    if (!baseEvidence || !baseRun) return;
    const attackedResults = [
      {
        ...result,
        summary: {
          ...result.summary,
          headline: 'Failure found at /Users/alice/private.ts',
        },
      },
      {
        ...result,
        findings: [
          {
            ...item,
            technicalSummary: 'Read C:\\Users\\alice\\private.ts during analysis.',
          },
        ],
      },
      {
        ...result,
        findings: [
          {
            ...item,
            evidence: [
              {
                ...baseEvidence,
                message: 'Read \\\\server\\share\\private.ts during analysis.',
              },
            ],
          },
        ],
      },
      {
        ...result,
        profile: {
          ...result.profile,
          limitations: ['Temporary file at /private/var/folders/xy/output.txt'],
        },
      },
      {
        ...result,
        analyzerRuns: [
          {
            ...baseRun,
            coverage: {
              ...baseRun.coverage,
              warnings: ['Workspace under ~/private/repository'],
            },
          },
          ...result.analyzerRuns.slice(1),
        ],
      },
    ];
    for (const attacked of attackedResults) {
      expect(
        Exit.isFailure(decodeExit(SuccessfulScanResultSchema)(attacked)),
      ).toBe(true);
    }
    expect(
      Exit.isFailure(
        decodeExit(EvidenceSchema)({
          ...baseEvidence,
          path: 'C:/Users/alice/private.ts',
        }),
      ),
    ).toBe(true);
  });

  it('rejects every C1 control in canonical prose, paths, and URLs', () => {
    const baseEvidence = finding().evidence[0];
    expect(baseEvidence).toBeDefined();
    if (baseEvidence === undefined) return;
    for (let codePoint = 0x80; codePoint <= 0x9f; codePoint += 1) {
      const control = String.fromCodePoint(codePoint);
      expect(
        Exit.isFailure(
          decodeExit(EvidenceSchema)({
            ...baseEvidence,
            message: `unsafe${control}prose`,
          }),
        ),
      ).toBe(true);
      expect(
        Exit.isFailure(
          decodeExit(EvidenceSchema)({
            ...baseEvidence,
            path: `src/${control}unsafe.ts`,
          }),
        ),
      ).toBe(true);
      expect(
        Exit.isFailure(
          decodeExit(ExternalReference)({
            label: 'unsafe control',
            url: `https://example.test/${control}reference`,
            relationship: 'background',
            applicability: 'unverified',
          }),
        ),
      ).toBe(true);
    }
  });

  it('rejects control-bearing comparison identities', () => {
    const result = successfulResult();
    const item = finding();
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...result,
          findings: [{ ...item, fingerprint: 'a\0b' }],
          comparison: {
            ...result.comparison,
            newFingerprints: ['a\0b'],
          },
        }),
      ),
    ).toBe(true);
  });

  it('rejects nondeterministic nested ordering and invalid first comparisons', () => {
    const result = successfulResult();
    const item = finding();
    const invalidFinding = {
      ...item,
      tags: ['zeta', 'alpha'],
    };
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...result,
          findings: [invalidFinding],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...result,
          comparison: {
            ...result.comparison,
            newFingerprints: [],
            persistentFingerprints: ['fingerprint-one'],
          },
        }),
      ),
    ).toBe(true);
  });

  it('rejects duplicate values in every canonical repeated field', () => {
    const result = successfulResult();
    const item = finding();
    const evidence = item.evidence[0];
    expect(evidence).toBeDefined();
    if (!evidence) return;
    const reference = new ExternalReference({
      label: 'Reference',
      url: 'https://example.com/reference',
      relationship: 'background',
      applicability: 'unverified',
    });
    const duplicateFindings = [
      { ...item, evidence: [evidence, evidence] },
      { ...item, externalReferences: [reference, reference] },
      { ...item, tags: ['architecture', 'architecture'] },
    ];
    for (const duplicate of duplicateFindings) {
      expect(Exit.isFailure(decodeExit(FindingSchema)(duplicate))).toBe(true);
    }
    const duplicateProfiles = [
      { ...result.profile, frameworks: ['react', 'react'] },
      {
        ...result.profile,
        languageCoverage: ['TypeScript', 'TypeScript'],
      },
      { ...result.profile, limitations: ['same', 'same'] },
    ];
    for (const profile of duplicateProfiles) {
      expect(
        Exit.isFailure(
          decodeExit(SuccessfulScanResultSchema)({ ...result, profile }),
        ),
      ).toBe(true);
    }
    const coverage = analyzerRuns()[0]?.coverage;
    expect(coverage).toBeDefined();
    if (!coverage) return;
    expect(
      Exit.isFailure(
        decodeExit(AnalyzerCoverageSchema)({
          ...coverage,
          warnings: ['same', 'same'],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(AnalyzerCoverageSchema)({
          ...coverage,
          omittedCapabilities: ['same', 'same'],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ScanComparisonSchema)({
          ...result.comparison,
          newFingerprints: ['same', 'same'],
        }),
      ),
    ).toBe(true);
  });

  it('orders every repeated report field deterministically', () => {
    const result = successfulResult();
    const item = finding();
    const baseEvidence = item.evidence[0];
    expect(baseEvidence).toBeDefined();
    if (!baseEvidence) return;
    const invalidFindings = [
      {
        ...item,
        evidence: [
          { ...baseEvidence, excerpt: 'zeta' },
          { ...baseEvidence, excerpt: 'alpha' },
        ],
      },
      {
        ...item,
        externalReferences: [
          {
            label: 'Second',
            url: 'https://example.com/zeta',
            relationship: 'background',
            applicability: 'unverified',
          },
          {
            label: 'First',
            url: 'https://example.com/alpha',
            relationship: 'background',
            applicability: 'unverified',
          },
        ],
      },
    ];
    for (const invalid of invalidFindings) {
      expect(Exit.isFailure(decodeExit(FindingSchema)(invalid))).toBe(true);
    }

    const invalidProfiles = [
      { ...result.profile, frameworks: ['vue', 'react'] },
      { ...result.profile, languageCoverage: ['TypeScript', 'JavaScript'] },
      { ...result.profile, limitations: ['zeta', 'alpha'] },
    ];
    for (const profile of invalidProfiles) {
      expect(
        Exit.isFailure(
          decodeExit(SuccessfulScanResultSchema)({ ...result, profile }),
        ),
      ).toBe(true);
    }
  });

  it('rejects comparison identities that do not reference the current result', () => {
    const result = successfulResult();
    const invalidComparisons = [
      { ...result.comparison, basisCodebaseId: 'github:other/repository' },
      { ...result.comparison, previousScanId: result.scanId },
      { ...result.comparison, priorityDelta: 1 },
    ];
    for (const comparison of invalidComparisons) {
      expect(
        Exit.isFailure(
          decodeExit(SuccessfulScanResultSchema)({ ...result, comparison }),
        ),
      ).toBe(true);
    }
  });

  it('requires finding evidence to reference an observed complete run', () => {
    const result = successfulResult();
    const traceDecayIndex = result.analyzerRuns.findIndex(
      run => run.analyzer === 'TraceDecay',
    );
    expect(traceDecayIndex).toBeGreaterThanOrEqual(0);
    const zeroObservationRuns = result.analyzerRuns.map((run, index) =>
      index === traceDecayIndex ? { ...run, observationCount: 0 } : run,
    );
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...result,
          analyzerRuns: zeroObservationRuns,
        }),
      ),
    ).toBe(true);
  });

  it('requires the exact immutable analyzer manifest', () => {
    const result = successfulResult();
    const runs = analyzerRuns();
    const first = runs[0];
    expect(first).toBeDefined();
    if (!first) return;
    const invalidRunSets = [
      runs.slice(1),
      [...runs].reverse(),
      [...runs.slice(0, -1), first],
      [...runs, first],
    ];
    for (const analyzerRunSet of invalidRunSets) {
      expect(
        Exit.isFailure(
          decodeExit(SuccessfulScanResultSchema)({
            ...result,
            analyzerRuns: analyzerRunSet,
          }),
        ),
      ).toBe(true);
    }
  });

  it('binds every analyzer run to the canonical result policy', () => {
    const result = successfulResult();
    for (const [runIndex] of result.analyzerRuns.entries()) {
      expect(
        Exit.isFailure(
          decodeExit(SuccessfulScanResultSchema)({
            ...result,
            analyzerRuns: result.analyzerRuns.map((run, index) =>
              index === runIndex
                ? { ...run, profileVersion: 'alternate-policy/v1' }
                : run,
            ),
          }),
        ),
      ).toBe(true);
    }
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...result,
          analysisPolicy: 'alternate-policy/v1',
          analyzerRuns: result.analyzerRuns.map(run => ({
            ...run,
            profileVersion: 'alternate-policy/v1',
          })),
        }),
      ),
    ).toBe(true);
  });

  it('rejects duplicate finding identities and fingerprints', () => {
    const result = successfulResult();
    const item = finding();
    const second = {
      ...item,
      id: 'finding-two',
      fingerprint: 'fingerprint-two',
    };
    const base = {
      ...result,
      summary: { ...result.summary, investigate: 2 },
      findings: [item, second],
      comparison: {
        ...result.comparison,
        newFingerprints: ['fingerprint-one', 'fingerprint-two'],
      },
    };
    const attackedResults = [
      {
        ...base,
        findings: [item, { ...second, id: item.id }],
      },
      {
        ...base,
        findings: [item, { ...second, fingerprint: item.fingerprint }],
        comparison: {
          ...base.comparison,
          newFingerprints: [item.fingerprint, item.fingerprint],
        },
      },
    ];
    for (const attacked of attackedResults) {
      expect(
        Exit.isFailure(decodeExit(SuccessfulScanResultSchema)(attacked)),
      ).toBe(true);
    }
  });

  it('rejects excess properties at every external decode depth', () => {
    const result = successfulResult();
    const item = finding();
    const attackedResults = [
      { ...result, unexpectedRootField: true },
      { ...result, findings: [{ ...item, unexpectedFindingField: true }] },
      {
        ...result,
        findings: [
          {
            ...item,
            evidence: [
              { ...item.evidence[0], unexpectedEvidenceField: true },
            ],
          },
        ],
      },
    ];
    for (const attacked of attackedResults) {
      const exit = Effect.runSync(Effect.exit(decodeScanResult(attacked)));
      expect(Exit.isFailure(exit)).toBe(true);
    }
  });
});

describe('v1 migration', () => {
  it('retains even nominally complete v1 evidence as noncanonical without path-set proof', () => {
    const legacy = v1Result();
    const migrated = Schema.decodeUnknownSync(ScanResultFromV1)({
      ...legacy,
      comparison: { ...legacy.comparison, previousScanId: 'scan-before' },
    });
    expect(migrated.resultKind).toBe('legacy-noncanonical');
    expect(migrated.schemaVersion).toBe('codebase-radar.scan-result/v2');
    expect(migrated.source.codebaseId).toBe(codebaseId);
    expect(migrated.findings[0]?.fingerprint).toBe('fingerprint-one');
    expect(migrated.comparison.previousScanId).toBeUndefined();
  });

  it('keeps weak history explicit and preserves every evidence entry', () => {
    const legacy = v1Result();
    const first = legacy.findings[0];
    expect(first).toBeDefined();
    if (!first) return;
    const input = {
      ...legacy,
      createdAt: 'historical-time',
      profile: { ...legacy.profile, version: '2026-08-09' },
      findings: [
        {
          ...first,
          mechanism: undefined,
          evidence: [
            ...first.evidence,
            {
              ...first.evidence[0],
              excerpt: 'Distinct bytes at an otherwise identical location.',
            },
            {
              analyzer: 'TraceDecay',
              kind: 'context',
              message: 'Distinct evidence with the same location.',
              path: '/legacy/absolute/path.ts',
              line: -1,
            },
          ],
          externalReferences: [
            {
              label: 'first label',
              url: 'legacy-reference',
              relationship: 'background',
              applicability: 'unverified',
            },
            {
              label: 'second label',
              url: 'legacy-reference',
              relationship: 'similar_case',
              applicability: 'unverified',
            },
          ],
        },
      ],
    };

    const migrated = Schema.decodeUnknownSync(ScanResultFromV1)(input);
    expect(migrated.resultKind).toBe('legacy-noncanonical');
    expect(migrated.findings[0]?.evidence).toHaveLength(3);
    expect(migrated.findings[0]?.externalReferences).toHaveLength(2);
    expect(migrated.findings[0]?.mechanism).toBeUndefined();
    const encoded = Schema.encodeSync(ScanResultFromV1)(migrated);
    expect(encoded.schemaVersion).toBe('codebase-radar.scan-result/v2');
  });

  it('does not promote incomplete runs into successful results', () => {
    const legacy = v1Result();
    const run = legacy.analyzerRuns[0];
    expect(run).toBeDefined();
    if (!run) return;
    const migrated = Schema.decodeUnknownSync(ScanResultFromV1)({
      ...legacy,
      analyzerRuns: [
        {
          ...run,
          status: 'partial',
          diagnostic: 'bounded output ended early',
        },
        ...legacy.analyzerRuns.slice(1),
      ],
    });
    expect(migrated.resultKind).toBe('legacy-noncanonical');
    const missingRuns = Schema.decodeUnknownSync(ScanResultFromV1)({
      ...legacy,
      analyzerRuns: [],
    });
    expect(missingRuns.resultKind).toBe('legacy-noncanonical');
  });

  it('does not discard diagnostics from nominally complete history', () => {
    const legacy = v1Result();
    const run = legacy.analyzerRuns[0];
    expect(run).toBeDefined();
    if (!run) return;
    const migrated = Schema.decodeUnknownSync(ScanResultFromV1)({
      ...legacy,
      analyzerRuns: [
        {
          ...run,
          diagnostic: 'Historical run retained an important diagnostic.',
        },
        ...legacy.analyzerRuns.slice(1),
      ],
    });
    expect(migrated.resultKind).toBe('legacy-noncanonical');
    if (migrated.resultKind !== 'legacy-noncanonical') return;
    expect(migrated.analyzerRuns[0]?.diagnostic).toBe(
      'Historical run retained an important diagnostic.',
    );
  });

  it('keeps omission-bearing analyzer history noncanonical and lossless', () => {
    const legacy = v1Result();
    const run = legacy.analyzerRuns[0];
    expect(run).toBeDefined();
    if (!run) return;
    const migrated = Schema.decodeUnknownSync(ScanResultFromV1)({
      ...legacy,
      analyzerRuns: [
        {
          ...run,
          coverage: {
            ...run.coverage,
            omittedCapabilities: ['unsupported-mode'],
          },
        },
        ...legacy.analyzerRuns.slice(1),
      ],
    });
    expect(migrated.resultKind).toBe('legacy-noncanonical');
    if (migrated.resultKind !== 'legacy-noncanonical') return;
    expect(migrated.analyzerRuns[0]?.coverage.omittedCapabilities).toEqual([
      'unsupported-mode',
    ]);
  });

  it('exposes one strict external decoder', () => {
    const decoded = Schema.decodeUnknownSync(ScanResultFromV1)(v1Result());
    expect(Exit.isSuccess(Schema.decodeUnknownExit(ScanResult)(decoded))).toBe(true);
    expect(decodeScanResult).toBeTypeOf('function');
  });

  it('round-trips every public result kind through strict wire and JSON encoders', () => {
    const canonical = successfulResult();
    const v1Legacy = Schema.decodeUnknownSync(ScanResultFromV1)(v1Result());
    const weakV1 = v1Result();
    weakV1.profile.version = '2026-08-09';
    const legacy = Schema.decodeUnknownSync(ScanResultFromV1)(weakV1);
    expect(v1Legacy.resultKind).toBe('legacy-noncanonical');
    expect(legacy.resultKind).toBe('legacy-noncanonical');

    for (const result of [canonical, v1Legacy, legacy]) {
      const wireExit = Effect.runSync(Effect.exit(encodeScanResult(result)));
      expect(Exit.isSuccess(wireExit)).toBe(true);
      if (Exit.isFailure(wireExit)) continue;
      const wireDecoded = Effect.runSync(
        Effect.exit(decodeScanResult(wireExit.value)),
      );
      expect(Exit.isSuccess(wireDecoded)).toBe(true);
      if (Exit.isSuccess(wireDecoded)) {
        expect(wireDecoded.value.resultKind).toBe(result.resultKind);
      }

      const jsonExit = Effect.runSync(Effect.exit(encodeScanResultJson(result)));
      expect(Exit.isSuccess(jsonExit)).toBe(true);
      if (Exit.isFailure(jsonExit)) continue;
      const jsonDecoded = Effect.runSync(
        Effect.exit(decodeScanResultJson(jsonExit.value)),
      );
      expect(Exit.isSuccess(jsonDecoded)).toBe(true);
      if (Exit.isSuccess(jsonDecoded)) {
        expect(jsonDecoded.value.resultKind).toBe(result.resultKind);
      }
      expect(
        Exit.isSuccess(Schema.encodeUnknownExit(ScanResultJson)(result)),
      ).toBe(true);
    }

    const v1LegacyJson = Effect.runSync(
      Effect.exit(decodeScanResultJson(JSON.stringify(v1Result()))),
    );
    expect(Exit.isSuccess(v1LegacyJson)).toBe(true);
    if (Exit.isSuccess(v1LegacyJson)) {
      expect(v1LegacyJson.value.resultKind).toBe('legacy-noncanonical');
    }
  });

  it('keeps JSON boundaries strict during decoding and encoding', () => {
    const result = successfulResult();
    const attacked = {
      ...result,
      source: { ...result.source, unexpectedSourceField: true },
    };
    const decoded = Effect.runSync(
      Effect.exit(decodeScanResultJson(JSON.stringify(attacked))),
    );
    const encoded = Effect.runSync(Effect.exit(encodeScanResultJson(attacked)));
    expect(Exit.isFailure(decoded)).toBe(true);
    expect(Exit.isFailure(encoded)).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(ScanResultJson)(JSON.stringify(attacked)),
      ),
    ).toBe(true);
  });

  it('enforces the exact UTF-8 scan-result byte boundary on every codec', () => {
    const weakV1 = v1Result();
    weakV1.profile.version = 'legacy/v1';
    const legacy = Schema.decodeUnknownSync(ScanResultFromV1)(weakV1);
    expect(legacy.resultKind).toBe('legacy-noncanonical');
    if (legacy.resultKind !== 'legacy-noncanonical') return;

    const withHeadline = (headline: string) =>
      new LegacyScanResult({
        ...legacy,
        summary: { ...legacy.summary, headline },
      });
    const baseline = withHeadline(legacy.summary.headline);
    const utf8 = new TextEncoder();
    const remaining =
      ContractLimits.encodedResultBytes -
      utf8.encode(JSON.stringify(baseline)).byteLength;
    expect(remaining).toBeGreaterThan(0);

    const atLimit = withHeadline(
      `${legacy.summary.headline}${'x'.repeat(remaining)}`,
    );
    const atLimitJson = JSON.stringify(atLimit);
    expect(utf8.encode(atLimitJson).byteLength).toBe(
      ContractLimits.encodedResultBytes,
    );
    const wireAtLimit = Effect.runSync(Effect.exit(encodeScanResult(atLimit)));
    const jsonAtLimit = Effect.runSync(
      Effect.exit(encodeScanResultJson(atLimit)),
    );
    expect(Exit.isSuccess(wireAtLimit)).toBe(true);
    expect(Exit.isSuccess(jsonAtLimit)).toBe(true);
    if (Exit.isSuccess(jsonAtLimit)) {
      expect(utf8.encode(jsonAtLimit.value).byteLength).toBe(
        ContractLimits.encodedResultBytes,
      );
    }
    expect(
      Exit.isSuccess(
        Effect.runSync(Effect.exit(decodeScanResultJson(atLimitJson))),
      ),
    ).toBe(true);

    const overLimit = withHeadline(`${atLimit.summary.headline}x`);
    const overLimitJson = JSON.stringify(overLimit);
    expect(utf8.encode(overLimitJson).byteLength).toBe(
      ContractLimits.encodedResultBytes + 1,
    );
    expect(
      Exit.isFailure(Effect.runSync(Effect.exit(encodeScanResult(overLimit)))),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Effect.runSync(Effect.exit(encodeScanResultJson(overLimit))),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Effect.runSync(Effect.exit(decodeScanResultJson(overLimitJson))),
      ),
    ).toBe(true);
  });
});
