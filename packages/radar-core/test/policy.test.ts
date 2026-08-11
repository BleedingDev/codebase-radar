import {
  AnalyzerCoverage,
  AttemptedAnalyzerRunValue,
  NotApplicableReason,
  RequiredAnalyzerIds,
  SemanticAnalyzerInventoryEntry,
  SemanticAnalyzerInventoryValue,
} from '@codebase-radar/contracts';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AnalyzerExecution } from '../src/internal/analyzers/index.js';
import { RepositoryInventory } from '../src/internal/inventory/index.js';
import { evaluatePolicy } from '../src/internal/policy/index.js';

const analyzerInventory = new SemanticAnalyzerInventoryValue({
  entries: [
    new SemanticAnalyzerInventoryEntry({
      path: 'package-lock.json',
      byteLength: 1,
      analyzers: ['OSV-Scanner'],
    }),
    new SemanticAnalyzerInventoryEntry({
      path: 'src/first.ts',
      byteLength: 1,
      analyzers: ['Oxlint + Ultracite', 'JSCPD', 'Calldiff', 'TraceDecay'],
    }),
    new SemanticAnalyzerInventoryEntry({
      path: 'src/second.ts',
      byteLength: 1,
      analyzers: ['Oxlint + Ultracite', 'JSCPD', 'Calldiff', 'TraceDecay'],
    }),
    new SemanticAnalyzerInventoryEntry({
      path: 'tsconfig.json',
      byteLength: 1,
      analyzers: ['strictest-comparator'],
    }),
  ],
  frameworks: [],
  truncated: false,
});

const inventory = new RepositoryInventory({
  files: ['package-lock.json', 'src/first.ts', 'src/second.ts', 'tsconfig.json'],
  sourceFiles: ['src/first.ts', 'src/second.ts'],
  lockfiles: ['package-lock.json'],
  tsconfigs: ['tsconfig.json'],
  workflowFiles: [],
  packageNames: [],
  frameworks: [],
  sourceBytes: 4,
  truncated: false,
  analyzerInventory,
});

const pathSetDigest = (paths: ReadonlyArray<string>) =>
  `sha256:${createHash('sha256').update(new TextEncoder().encode(JSON.stringify(paths))).digest('hex')}`;

const auditedPaths = (analyzer: typeof RequiredAnalyzerIds[number]) => {
  if (analyzer === 'strictest-comparator') return ['tsconfig.json'];
  if (analyzer === 'OSV-Scanner') return ['package-lock.json'];
  if (analyzer === 'zizmor') return [];
  return ['src/first.ts', 'src/second.ts'];
};

const execution = (
  analyzer: typeof RequiredAnalyzerIds[number],
  eligibleFiles: number,
  coveragePaths = auditedPaths(analyzer).slice(0, eligibleFiles),
) => new AnalyzerExecution({
  run: new AttemptedAnalyzerRunValue({
    analyzer,
    analyzerVersion: 'test-runtime-v1',
    profileVersion: 'dogfood:max/v1',
    status: eligibleFiles === 0 ? 'not_applicable' : 'complete',
    durationMs: 1,
    coverage: new AnalyzerCoverage({
      eligibleFiles,
      analyzedFiles: eligibleFiles,
      eligiblePathSetDigest: pathSetDigest(coveragePaths),
      analyzedPathSetDigest: pathSetDigest(coveragePaths),
      omittedCapabilities: [],
      warnings: [],
    }),
    observationCount: 0,
    ...(eligibleFiles === 0
      ? { reason: new NotApplicableReason({
          code: 'no-eligible-input',
          message: 'No eligible input.',
        }) }
      : {}),
  }),
  candidates: [],
});

const reportedEligibleFiles = (analyzer: typeof RequiredAnalyzerIds[number]) => {
  if (analyzer === 'strictest-comparator' || analyzer === 'OSV-Scanner') return 1;
  if (analyzer === 'zizmor') return 0;
  // Calldiff has two audited inputs, but a compromised runtime claims only
  // one eligible/analyzed file. Its own 1/1 denominator is not complete.
  if (analyzer === 'Calldiff') return 1;
  return 2;
};

describe('analysis policy coverage accounting', () => {
  it('rejects a self-consistent runtime denominator below the audited inventory count', () => {
    const decision = evaluatePolicy({
      inventory,
      executions: RequiredAnalyzerIds.map(analyzer =>
        execution(analyzer, reportedEligibleFiles(analyzer))),
    });
    expect(decision._tag).toBe('PolicyIncomplete');
    if (decision._tag === 'PolicyIncomplete') {
      expect(decision.failure.violations).toContainEqual({
        code: 'coverage_incomplete',
        analyzer: 'Calldiff',
      });
    }
  });
});

describe('analysis policy path-set evidence', () => {
  it('rejects an equal-count coverage digest for the wrong eligible paths', () => {
    const decision = evaluatePolicy({
      inventory,
      executions: RequiredAnalyzerIds.map(analyzer => execution(
        analyzer,
        analyzer === 'strictest-comparator' || analyzer === 'OSV-Scanner'
          ? 1
          : analyzer === 'zizmor'
            ? 0
            : 2,
        analyzer === 'Calldiff'
          ? ['src/first.ts', 'src/wrong.ts']
          : auditedPaths(analyzer),
      )),
    });
    expect(decision._tag).toBe('PolicyIncomplete');
    if (decision._tag === 'PolicyIncomplete') {
      expect(decision.failure.violations).toContainEqual({
        code: 'coverage_incomplete',
        analyzer: 'Calldiff',
      });
    }
  });

  it('uses UTF-8 byte order rather than UTF-16 code-unit order for path proof', () => {
    const paths = ['src/\uE000.ts', 'src/\u{10000}.ts'];
    const unicodeInventory = new RepositoryInventory({
      files: paths,
      sourceFiles: paths,
      lockfiles: [],
      tsconfigs: [],
      workflowFiles: [],
      packageNames: [],
      frameworks: [],
      sourceBytes: 2,
      truncated: false,
      analyzerInventory: new SemanticAnalyzerInventoryValue({
        entries: paths.map(path => new SemanticAnalyzerInventoryEntry({
          path,
          byteLength: 1,
          analyzers: [...RequiredAnalyzerIds],
        })),
        frameworks: [],
        truncated: false,
      }),
    });
    const decision = evaluatePolicy({
      inventory: unicodeInventory,
      executions: RequiredAnalyzerIds.map(analyzer => execution(analyzer, 2, paths)),
    });
    expect(decision._tag).toBe('PolicyComplete');
  });
});
