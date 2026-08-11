import { Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  AnalysisIncomplete,
  AnalysisProgressStream,
  AnalyzerCoverageSchema,
  BoundedTag,
  ContractLimits,
  EvidenceSchema,
  ExternalReference,
  FindingSchema,
  RequiredAnalyzerIds,
  ScanComparisonSchema,
  ScanProfileSchema,
  SuccessfulScanResultSchema,
} from '../src/index.js';
import {
  analyzerRuns,
  finding,
  singlePathSetDigest,
  successfulResult,
} from './fixtures.js';

const decodeExit = Schema.decodeUnknownExit;
const padded = (prefix: string, index: number) =>
  `${prefix}${String(index).padStart(5, '0')}`;

const findings = (count: number) => {
  const item = finding();
  return Array.from({ length: count }, (_, index) => ({
    ...item,
    id: padded('finding-', index),
    fingerprint: padded('fingerprint-', index),
  }));
};

const resultWithFindings = (count: number) => {
  const result = successfulResult();
  const items = findings(count);
  return {
    ...result,
    summary: {
      ...result.summary,
      investigate: count,
    },
    findings: items,
    comparison: {
      ...result.comparison,
      newFingerprints: items.map(item => item.fingerprint),
    },
  };
};

describe('contract collection and payload bounds', () => {
  it('bounds repository paths, web URLs, and tags at their exact limits', () => {
    const item = finding();
    const evidence = item.evidence[0];
    expect(evidence).toBeDefined();
    if (!evidence) return;
    const exactPath = `src/${'x'.repeat(ContractLimits.pathCharacters - 7)}.ts`;
    expect(exactPath).toHaveLength(ContractLimits.pathCharacters);
    expect(
      Exit.isSuccess(decodeExit(EvidenceSchema)({ ...evidence, path: exactPath })),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(EvidenceSchema)({ ...evidence, path: `x${exactPath}` }),
      ),
    ).toBe(true);

    const urlPrefix = 'https://example.com/';
    const exactUrl = `${urlPrefix}${'x'.repeat(
      ContractLimits.webUrlCharacters - urlPrefix.length,
    )}`;
    const reference = {
      label: 'Reference',
      url: exactUrl,
      relationship: 'background',
      applicability: 'unverified',
    };
    expect(Exit.isSuccess(decodeExit(ExternalReference)(reference))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ExternalReference)({ ...reference, url: `${exactUrl}x` }),
      ),
    ).toBe(true);

    const exactTag = `t${'x'.repeat(ContractLimits.tagCharacters - 1)}`;
    expect(Exit.isSuccess(decodeExit(BoundedTag)(exactTag))).toBe(true);
    expect(Exit.isFailure(decodeExit(BoundedTag)(`${exactTag}x`))).toBe(true);
  });

  it('bounds warnings and all repeated finding evidence', () => {
    const item = finding();
    const evidence = item.evidence[0];
    expect(evidence).toBeDefined();
    if (!evidence) return;
    const warnings = Array.from(
      { length: ContractLimits.warningsPerAnalyzer },
      (_, index) => padded('warning-', index),
    );
    const coverage = {
      eligibleFiles: 1,
      analyzedFiles: 1,
      eligiblePathSetDigest: singlePathSetDigest,
      analyzedPathSetDigest: singlePathSetDigest,
      omittedCapabilities: [],
      warnings,
    };
    expect(Exit.isSuccess(decodeExit(AnalyzerCoverageSchema)(coverage))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(AnalyzerCoverageSchema)({
          ...coverage,
          warnings: [...warnings, 'warning-over-limit'],
        }),
      ),
    ).toBe(true);

    const evidenceItems = Array.from(
      { length: ContractLimits.evidencePerFinding },
      (_, index) => ({ ...evidence, message: padded('evidence-', index) }),
    );
    const references = Array.from(
      { length: ContractLimits.externalReferencesPerFinding },
      (_, index) => ({
        label: padded('reference-', index),
        url: `https://example.com/${padded('reference-', index)}`,
        relationship: 'background',
        applicability: 'unverified',
      }),
    );
    const tags = Array.from(
      { length: ContractLimits.tagsPerFinding },
      (_, index) => padded('tag-', index),
    );
    const exact = {
      ...item,
      evidence: evidenceItems,
      externalReferences: references,
      tags,
    };
    expect(Exit.isSuccess(decodeExit(FindingSchema)(exact))).toBe(true);
    const invalid = [
      { ...exact, evidence: [...evidenceItems, { ...evidence, message: 'overflow' }] },
      {
        ...exact,
        externalReferences: [
          ...references,
          {
            label: 'Overflow',
            url: 'https://example.com/overflow',
            relationship: 'background',
            applicability: 'unverified',
          },
        ],
      },
      { ...exact, tags: [...tags, 'tag-over-limit'] },
    ];
    for (const candidate of invalid) {
      expect(Exit.isFailure(decodeExit(FindingSchema)(candidate))).toBe(true);
    }
  });

  it('bounds profile and comparison collections', () => {
    const result = successfulResult();
    const languageCoverage = Array.from(
      { length: ContractLimits.languageCoverageEntries },
      (_, index) => padded('language-', index),
    );
    const limitations = Array.from(
      { length: ContractLimits.limitations },
      (_, index) => padded('limitation-', index),
    );
    const profile = {
      frameworks: ['react'],
      languageCoverage,
      limitations,
    };
    expect(Exit.isSuccess(decodeExit(ScanProfileSchema)(profile))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ScanProfileSchema)({
          ...profile,
          languageCoverage: [...languageCoverage, 'language-over-limit'],
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ScanProfileSchema)({
          ...profile,
          limitations: [...limitations, 'limitation-over-limit'],
        }),
      ),
    ).toBe(true);

    const fingerprints = Array.from(
      { length: ContractLimits.referencesPerComparisonSet },
      (_, index) => padded('fingerprint-', index),
    );
    const comparison = {
      ...result.comparison,
      newFingerprints: fingerprints,
    };
    expect(Exit.isSuccess(decodeExit(ScanComparisonSchema)(comparison))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(ScanComparisonSchema)({
          ...comparison,
          newFingerprints: [...fingerprints, 'fingerprint-over-limit'],
        }),
      ),
    ).toBe(true);
  });

  it('bounds the exact analyzer manifest and finding inventory', () => {
    const exact = resultWithFindings(ContractLimits.findings);
    expect(Exit.isSuccess(decodeExit(SuccessfulScanResultSchema)(exact))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)(
          resultWithFindings(ContractLimits.findings + 1),
        ),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...successfulResult(),
          analyzerRuns: [...analyzerRuns(), analyzerRuns()[0]],
        }),
      ),
    ).toBe(true);

    const attempts = analyzerRuns().map(run => ({
      ...run,
      _tag: 'AttemptedAnalyzerRun',
    }));
    expect(
      Exit.isSuccess(
        decodeExit(AnalysisIncomplete)({
          _tag: 'AnalysisIncomplete',
          violations: [{ code: 'finding_inventory_exceeded' }],
          analyzerRuns: attempts,
        }),
      ),
    ).toBe(true);
    expect(attempts.map(run => run.analyzer)).toEqual(RequiredAnalyzerIds);
  });

  it('bounds progress history and correlated violation evidence', () => {
    const progress = (eventCount: number) => {
      const totalWork = eventCount + 1;
      const updates = Array.from({ length: eventCount - 1 }, (_, index) => ({
        _tag: 'AnalysisProgressUpdate',
        scanId: 'scan-bounded-progress',
        sequence: index,
        timestamp: new Date(Date.UTC(2026, 7, 11) + index).toISOString(),
        stage: 'analyzing',
        completedWork: index,
        totalWork,
        percent: Math.floor((index / totalWork) * 100),
        terminal: false,
      }));
      return [
        ...updates,
        {
          _tag: 'AnalysisProgressTerminal',
          scanId: 'scan-bounded-progress',
          sequence: eventCount - 1,
          timestamp: new Date(
            Date.UTC(2026, 7, 11) + eventCount - 1,
          ).toISOString(),
          stage: 'terminal',
          completedWork: eventCount - 1,
          totalWork,
          percent: Math.floor(((eventCount - 1) / totalWork) * 100),
          terminal: true,
          outcome: 'failed',
        },
      ];
    };
    expect(
      Exit.isSuccess(
        decodeExit(AnalysisProgressStream)(
          progress(ContractLimits.progressEvents),
        ),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(AnalysisProgressStream)(
          progress(ContractLimits.progressEvents + 1),
        ),
      ),
    ).toBe(true);

    const attempts = analyzerRuns().map((run, index) => ({
      ...run,
      _tag: 'AttemptedAnalyzerRun',
      profileVersion: index === 0 ? 'alternate-policy' : run.profileVersion,
      coverage: {
        ...run.coverage,
        eligibleFiles: 10,
        analyzedFiles: 9,
      },
    }));
    const globalViolations = [
      { code: 'inventory_truncated' },
      { code: 'finding_inventory_exceeded' },
      { code: 'runtime_mismatch' },
    ];
    const attributedViolations = attempts.flatMap(run => [
      { code: 'analyzer_duplicate', analyzer: run.analyzer },
      { code: 'coverage_incomplete', analyzer: run.analyzer },
    ]);
    const violations = [...globalViolations, ...attributedViolations];
    expect(violations).toHaveLength(ContractLimits.violations);
    const incomplete = {
      _tag: 'AnalysisIncomplete',
      violations,
      analyzerRuns: attempts,
    };
    expect(Exit.isSuccess(decodeExit(AnalysisIncomplete)(incomplete))).toBe(true);
    expect(
      Exit.isFailure(
        decodeExit(AnalysisIncomplete)({
          ...incomplete,
          violations: [...violations, { code: 'runtime_mismatch' }],
        }),
      ),
    ).toBe(true);
  });

  it('accepts the encoded byte limit and rejects one extra byte', () => {
    const encoder = new TextEncoder();
    const base = resultWithFindings(ContractLimits.findings);
    const baseBytes = encoder.encode(JSON.stringify(base)).byteLength;
    let remaining = ContractLimits.encodedResultBytes - baseBytes;
    expect(remaining).toBeGreaterThan(0);
    const filledFindings = base.findings.map(item => {
      const capacity = ContractLimits.proseCharacters - item.technicalSummary.length;
      const added = Math.min(capacity, remaining);
      remaining -= added;
      return {
        ...item,
        technicalSummary: `${item.technicalSummary}${'x'.repeat(added)}`,
      };
    });
    expect(remaining).toBe(0);
    const exact = { ...base, findings: filledFindings };
    expect(encoder.encode(JSON.stringify(exact)).byteLength).toBe(
      ContractLimits.encodedResultBytes,
    );
    expect(Exit.isSuccess(decodeExit(SuccessfulScanResultSchema)(exact))).toBe(true);
    const first = filledFindings[0];
    expect(first).toBeDefined();
    if (!first) return;
    expect(
      Exit.isFailure(
        decodeExit(SuccessfulScanResultSchema)({
          ...exact,
          findings: [
            { ...first, mechanism: `${first.mechanism}x` },
            ...filledFindings.slice(1),
          ],
        }),
      ),
    ).toBe(true);
  });
});
