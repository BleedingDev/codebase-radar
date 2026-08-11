import { createHash } from 'node:crypto';
import {
  Clock,
  Effect,
  FileSystem,
  Option,
  Path,
  Schema,
} from 'effect';
import {
  CanonicalRepositoryPathSet,
  ContractLimits,
  EmptyRepositoryPathSetDigest,
  encodeCanonicalRepositoryPathSet,
  Evidence,
  RepositoryPath,
  RepositoryPathSetDigest,
} from '@codebase-radar/contracts';
import {
  completeAnalyzerOutput,
  FindingCandidate,
  incompleteAnalyzerOutput,
  notApplicableAnalyzerOutput,
  unprovenPathSetProof,
} from './analyzers';
import type { AnalyzerPathSetProof } from './analyzers';
import { canonicalRepositoryPathSet } from './analyzer-input';
import { RepositoryInventory } from './inventory';
import { boundedDiagnostic, runCommand } from './process';

const CalldiffNonNegativeInteger = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
  Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
);
const CalldiffPositiveInteger = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(Number.MAX_SAFE_INTEGER),
);
const CalldiffText = Schema.String.check(
  Schema.isMaxLength(ContractLimits.proseCharacters),
  Schema.isPattern(/^[^\u0000-\u001f\u007f-\u009f]*$/u),
);
const CalldiffPathSetDigest = RepositoryPathSetDigest;
const CalldiffCanonicalPathSet = CanonicalRepositoryPathSet.check(
  Schema.isMaxLength(ContractLimits.semanticAnalyzerInventoryEntries),
);
const CalldiffInventoryRows = <S extends Schema.Constraint>(schema: S) =>
  Schema.Array(schema).check(
    Schema.isMaxLength(ContractLimits.semanticAnalyzerInventoryEntries),
  );
const CalldiffWarningRows = <S extends Schema.Constraint>(schema: S) =>
  Schema.Array(schema).check(
    Schema.isMaxLength(ContractLimits.warningsPerAnalyzer),
  );

class CalldiffDefinition extends Schema.Class<CalldiffDefinition>(
  'CalldiffDefinition',
)({
  path: RepositoryPath,
  line: CalldiffPositiveInteger,
}) {}

class CalldiffFailedFile extends Schema.Class<CalldiffFailedFile>(
  'CalldiffFailedFile',
)({
  path: RepositoryPath,
  diagnostic: CalldiffText,
}) {}

class CalldiffInputTruncation extends Schema.Class<CalldiffInputTruncation>(
  'CalldiffInputTruncation',
)({
  path: RepositoryPath,
  reason: Schema.Literals(['file_count', 'file_bytes', 'total_bytes']),
}) {}

class CalldiffDirectoryTraversalFailure extends Schema.Class<CalldiffDirectoryTraversalFailure>(
  'CalldiffDirectoryTraversalFailure',
)({
  path: RepositoryPath,
  diagnostic: CalldiffText,
}) {}

class CalldiffTruncatedDirectory extends Schema.Class<CalldiffTruncatedDirectory>(
  'CalldiffTruncatedDirectory',
)({
  path: RepositoryPath,
  reason: Schema.Literals(['depth', 'directory_budget', 'entry_budget']),
}) {}

class CalldiffEntrypoint extends Schema.Class<CalldiffEntrypoint>(
  'CalldiffEntrypoint',
)({
  key: CalldiffText,
  path: Schema.optional(RepositoryPath),
  line: Schema.optional(CalldiffPositiveInteger),
  occurrenceCount: CalldiffPositiveInteger,
  pathSamples: CalldiffWarningRows(CalldiffText),
}) {}

class CalldiffDuplicate extends Schema.Class<CalldiffDuplicate>(
  'CalldiffDuplicate',
)({
  signatureId: CalldiffText,
  key: CalldiffText,
  label: CalldiffText,
  local: Schema.Boolean,
  subtreeNodes: CalldiffPositiveInteger,
  maximumOccurrences: CalldiffPositiveInteger,
  definition: Schema.optional(CalldiffDefinition),
  entrypointCount: CalldiffPositiveInteger,
  entrypointsTruncated: Schema.Boolean,
  entrypoints: CalldiffInventoryRows(CalldiffEntrypoint),
}) {}

class CalldiffCollisionDefinition extends Schema.Class<CalldiffCollisionDefinition>(
  'CalldiffCollisionDefinition',
)({
  key: CalldiffText,
  path: RepositoryPath,
  line: CalldiffPositiveInteger,
  exported: Schema.Boolean,
}) {}

class CalldiffAmbiguousCaller extends Schema.Class<CalldiffAmbiguousCaller>(
  'CalldiffAmbiguousCaller',
)({
  key: CalldiffText,
  path: RepositoryPath,
  line: CalldiffPositiveInteger,
}) {}

class CalldiffCollision extends Schema.Class<CalldiffCollision>(
  'CalldiffCollision',
)({
  key: CalldiffText,
  definitionCount: CalldiffPositiveInteger,
  definitionsTruncated: Schema.Boolean,
  definitions: CalldiffInventoryRows(CalldiffCollisionDefinition),
  ambiguousCallerCount: CalldiffNonNegativeInteger,
  ambiguousCallersTruncated: Schema.Boolean,
  ambiguousCallers: CalldiffInventoryRows(CalldiffAmbiguousCaller),
}) {}

class CalldiffUnmodeledCrossFileCall extends Schema.Class<CalldiffUnmodeledCrossFileCall>(
  'CalldiffUnmodeledCrossFileCall',
)({
  key: CalldiffText,
  callerKey: CalldiffText,
  path: RepositoryPath,
  line: CalldiffPositiveInteger,
  localDefinitionCount: CalldiffPositiveInteger,
}) {}

class CalldiffRewriteTruncatedDefinition extends Schema.Class<CalldiffRewriteTruncatedDefinition>(
  'CalldiffRewriteTruncatedDefinition',
)({
  key: CalldiffText,
  path: RepositoryPath,
  line: CalldiffPositiveInteger,
}) {}

class CalldiffReport extends Schema.Class<CalldiffReport>('CalldiffReport')({
  schemaVersion: Schema.Literal('codebase-radar.calldiff-report/v1'),
  calldiffVersion: Schema.Literal('0.4.1'),
  maximumDepth: CalldiffPositiveInteger,
  maximumExpandedNodes: CalldiffPositiveInteger,
  expandedNodes: CalldiffNonNegativeInteger,
  indexedStepLimit: CalldiffPositiveInteger,
  indexedSteps: CalldiffNonNegativeInteger,
  eligibleFiles: CalldiffNonNegativeInteger,
  analyzedFiles: CalldiffNonNegativeInteger,
  requestedPaths: CalldiffCanonicalPathSet,
  requestedPathSetDigest: CalldiffPathSetDigest,
  analyzedPaths: CalldiffCanonicalPathSet,
  analyzedPathSetDigest: CalldiffPathSetDigest,
  functionCount: CalldiffNonNegativeInteger,
  entrypointCount: CalldiffNonNegativeInteger,
  maximumInputFiles: CalldiffPositiveInteger,
  maximumInputFileBytes: CalldiffPositiveInteger,
  maximumInputBytes: CalldiffPositiveInteger,
  inputFileCount: CalldiffNonNegativeInteger,
  inputBytes: CalldiffNonNegativeInteger,
  inputTruncated: Schema.Boolean,
  truncatedInputFileCount: CalldiffNonNegativeInteger,
  truncatedInputFiles: CalldiffWarningRows(CalldiffInputTruncation),
  maximumDirectoryTraversalDepth: CalldiffPositiveInteger,
  maximumDirectoryTraversalDirectories: CalldiffPositiveInteger,
  maximumDirectoryTraversalEntries: CalldiffPositiveInteger,
  traversedDirectoryCount: CalldiffNonNegativeInteger,
  traversedDirectoryEntryCount: CalldiffNonNegativeInteger,
  directoryTraversalFailureCount: CalldiffNonNegativeInteger,
  directoryTraversalFailuresTruncated: Schema.Boolean,
  directoryTraversalFailures: CalldiffWarningRows(
    CalldiffDirectoryTraversalFailure,
  ),
  directoryTraversalTruncated: Schema.Boolean,
  truncatedDirectoryCount: CalldiffNonNegativeInteger,
  truncatedDirectories: CalldiffWarningRows(CalldiffTruncatedDirectory),
  failedFileCount: CalldiffNonNegativeInteger,
  failedFilesTruncated: Schema.Boolean,
  failedFiles: CalldiffWarningRows(CalldiffFailedFile),
  collisionCount: CalldiffNonNegativeInteger,
  collisionsTruncated: Schema.Boolean,
  collisions: Schema.Array(CalldiffCollision).check(
    Schema.isMaxLength(ContractLimits.findings),
  ),
  unmodeledCrossFileCallCount: CalldiffNonNegativeInteger,
  unmodeledCrossFileCallsTruncated: Schema.Boolean,
  unmodeledCrossFileCalls: CalldiffWarningRows(
    CalldiffUnmodeledCrossFileCall,
  ),
  rewriteTruncatedDefinitionCount: CalldiffNonNegativeInteger,
  rewriteTruncatedDefinitionsTruncated: Schema.Boolean,
  rewriteTruncatedDefinitions: CalldiffWarningRows(
    CalldiffRewriteTruncatedDefinition,
  ),
  maximumEvidenceBytes: CalldiffPositiveInteger,
  evidenceBytes: CalldiffNonNegativeInteger,
  evidenceTruncated: Schema.Boolean,
  depthCutCount: CalldiffNonNegativeInteger,
  depthTruncatedEntrypointCount: CalldiffNonNegativeInteger,
  depthTruncatedEntrypointsTruncated: Schema.Boolean,
  depthTruncatedEntrypoints: CalldiffWarningRows(CalldiffText),
  truncatedEntrypointCount: CalldiffNonNegativeInteger,
  truncatedEntrypoints: CalldiffWarningRows(CalldiffText),
  duplicateCount: CalldiffNonNegativeInteger,
  duplicatesTruncated: Schema.Boolean,
  duplicates: Schema.Array(CalldiffDuplicate).check(
    Schema.isMaxLength(ContractLimits.findings),
  ),
}) {}

const decodeReport = (text: string) =>
  Schema.decodeEffect(Schema.fromJsonString(CalldiffReport), {
    onExcessProperty: 'error',
  })(text);

const pathSetDigest = (paths: typeof CanonicalRepositoryPathSet.Type) =>
  Schema.decodeUnknownSync(RepositoryPathSetDigest)(
    `sha256:${createHash('sha256')
      .update(encodeCanonicalRepositoryPathSet(paths))
      .digest('hex')}`,
  );

const samePathSet = (
  left: ReadonlyArray<string>,
  right: ReadonlyArray<string>,
) =>
  left.length === right.length &&
  left.every((path, index) => path === right[index]);

export const calldiffCandidates = (report: CalldiffReport) =>
  report.duplicates.flatMap(duplicate => {
    const affectedTrees = duplicate.entrypointCount;
    const extraOccurrences = Math.max(1, duplicate.maximumOccurrences - 1);
    const entrypoints = duplicate.entrypoints.slice(
      0,
      ContractLimits.evidencePerFinding,
    );
    if (entrypoints.length === 0) return [];
    const evidence = entrypoints.map(
      entry =>
        new Evidence({
          analyzer: 'Calldiff',
          kind: 'direct',
          message: `${duplicate.key} occurs ${entry.occurrenceCount} times below ${entry.key}`,
          ruleId: 'repeated-call-tree-node',
          path: entry.path,
          line: entry.line,
          excerpt: boundedDiagnostic(
            entry.pathSamples
              .map(sample => sample.replace(/[\r\n\t]/gu, ' '))
              .join(' | '),
            ContractLimits.proseCharacters,
          ),
        }),
    );
    return new FindingCandidate({
      fingerprintSeed: `calldiff:${duplicate.key}:${duplicate.signatureId}`,
      mechanism: 'Repeated local call-tree node',
      title: `${duplicate.key} repeats in ${affectedTrees} call ${affectedTrees === 1 ? 'tree' : 'trees'}`,
      category: 'maintainability',
      summary:
        'The same local callable or expandable call-site node appears more than once below a supported call-tree root. This can signal repeated work or duplicated orchestration, but it still needs semantic review.',
      technicalSummary: `Calldiff expanded ${report.entrypointCount} roots to depth ${report.maximumDepth}. ${duplicate.key} appears up to ${duplicate.maximumOccurrences} times and expands to at most ${duplicate.subtreeNodes} nodes across ${affectedTrees} roots; ${evidence.length} bounded root samples are attached.`,
      recommendation:
        'Inspect the repeated paths, then remove repeated work at their narrowest shared owner only when the calls have the same responsibility and lifetime.',
      evidence,
      externalReferences: [],
      tags: [
        'calldiff',
        'call-tree-duplication',
        duplicate.local ? 'local-callable' : 'repeated-subtree',
      ],
      consequence: Math.min(
        76,
        (duplicate.local ? 24 : 14) +
          extraOccurrences * 9 +
          Math.min(18, duplicate.subtreeNodes * 2),
      ),
      blastRadius: Math.min(
        82,
        (duplicate.local ? 28 : 22) +
          affectedTrees * 6 +
          Math.min(18, duplicate.subtreeNodes * 2),
      ),
      confidence: duplicate.local ? 88 : 60,
      effort: Math.min(
        82,
        (duplicate.local ? 30 : 45) +
          duplicate.subtreeNodes * 3 +
          affectedTrees * 2,
      ),
      changeExposure: Math.min(
        86,
        34 + affectedTrees * 6 + duplicate.subtreeNodes * 2,
      ),
    });
  });

const emptyPathSetProof = {
  eligiblePathSetDigest: EmptyRepositoryPathSetDigest,
  analyzedPathSetDigest: EmptyRepositoryPathSetDigest,
} satisfies AnalyzerPathSetProof;

const emptyOutput = (
  inventory: RepositoryInventory,
  status: 'partial' | 'failed' | 'timed_out' | 'truncated',
  diagnostic: string,
  durationMs: number,
  pathSetProof: AnalyzerPathSetProof,
) =>
  incompleteAnalyzerOutput({
    analyzer: 'Calldiff',
    analyzerVersion: '0.4.1',
    status,
    durationMs,
    eligibleFiles: inventory.sourceFiles.length,
    analyzedFiles: 0,
    observationCount: 0,
    diagnostic,
    warnings: [diagnostic],
    pathSetProof,
  });

export const runCalldiff = Effect.fn('runCalldiff')(function* (
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  if (inventory.sourceFiles.length === 0) {
    return notApplicableAnalyzerOutput({
      analyzer: 'Calldiff',
      analyzerVersion: '0.4.1',
      durationMs: 0,
      code: 'no-eligible-input',
      message: 'No supported source files were found.',
    });
  }
  const canonicalSourceFiles = yield* canonicalRepositoryPathSet(
    inventory.sourceFiles,
  ).pipe(Effect.option);
  if (Option.isNone(canonicalSourceFiles)) {
    return emptyOutput(
      inventory,
      'partial',
      'The Calldiff source inventory was not uniquely ordered by canonical UTF-8 bytes.',
      0,
      emptyPathSetProof,
    );
  }
  const auditedSourceFiles = canonicalSourceFiles.value;
  const canonicalPathSetDigest = pathSetDigest(auditedSourceFiles);
  const unprovenCoverageProof = unprovenPathSetProof(
    inventory,
    auditedSourceFiles,
  );
  const script = pathService.resolve(root, 'calldiff-analyzer.mjs');
  const packageEntry = pathService.resolve(
    root,
    'node_modules/calldiff/dist/index.js',
  );
  if (!(yield* fs.exists(script)) || !(yield* fs.exists(packageEntry))) {
    return emptyOutput(
      inventory,
      'partial',
      'Pinned Calldiff runtime was not found.',
      0,
      unprovenCoverageProof,
    );
  }
  const startedAt = yield* Clock.currentTimeMillis;
  const scratchRoot =
    process.env['RADAR_SCRATCH_FD'] ?? pathService.dirname(repoRoot);
  const environment = {
    PATH: process.env['PATH'],
    HOME: scratchRoot,
    LANG: 'C.UTF-8',
    NO_COLOR: '1',
    CALLDIFF_GRAMMAR_CACHE: pathService.resolve(
      scratchRoot,
      'calldiff-grammars',
    ),
  };
  const auditedPathInput = JSON.stringify({
    sourceFiles: auditedSourceFiles,
  });
  if (
    new TextEncoder().encode(auditedPathInput).byteLength >
    ContractLimits.semanticAnalyzerRequestBytes
  ) {
    return emptyOutput(
      inventory,
      'partial',
      'The canonical Calldiff source-path input exceeded its bounded envelope.',
      0,
      unprovenCoverageProof,
    );
  }
  const result = yield* runCommand({
    command: process.execPath,
    args: [script, repoRoot, '--audited-source-files-stdin'],
    cwd: repoRoot,
    env: environment,
    stdin: auditedPathInput,
    timeoutMs: 120_000,
    maxOutputBytes: 32 * 1024 * 1024,
  });
  const durationMs = (yield* Clock.currentTimeMillis) - startedAt;
  if (result.timedOut) {
    return emptyOutput(
      inventory,
      'timed_out',
      'Calldiff exceeded the 120 second analysis envelope.',
      durationMs,
      unprovenCoverageProof,
    );
  }
  if (result.truncated) {
    return emptyOutput(
      inventory,
      'truncated',
      'Calldiff report exceeded the 32 MiB output envelope.',
      durationMs,
      unprovenCoverageProof,
    );
  }
  if (result.exitCode !== 0) {
    return emptyOutput(
      inventory,
      'failed',
      'Calldiff failed before producing a valid bounded report.',
      durationMs,
      unprovenCoverageProof,
    );
  }
  return yield* decodeReport(result.stdout).pipe(
    Effect.map(report => {
      const canonicalEligibleFiles = auditedSourceFiles.length;
      const inventoryEligiblePathSetMismatch =
        inventory.eligiblePathSetDigest !== undefined &&
        inventory.eligiblePathSetDigest !== canonicalPathSetDigest;
      const adapterEligibleCountMismatch =
        report.eligibleFiles !== canonicalEligibleFiles;
      const requestedPathCountMismatch =
        report.eligibleFiles !== report.requestedPaths.length;
      const analyzedPathCountMismatch =
        report.analyzedFiles !== report.analyzedPaths.length;
      const requestedPathSetDigest = pathSetDigest(report.requestedPaths);
      const analyzedPathSetDigest = pathSetDigest(report.analyzedPaths);
      const requestedDigestMismatch =
        report.requestedPathSetDigest !== requestedPathSetDigest;
      const analyzedDigestMismatch =
        report.analyzedPathSetDigest !== analyzedPathSetDigest;
      const requestedPathSetMismatch =
        !samePathSet(report.requestedPaths, auditedSourceFiles) ||
        requestedPathSetDigest !== canonicalPathSetDigest;
      const analyzedPathSetMismatch =
        !samePathSet(report.analyzedPaths, auditedSourceFiles) ||
        analyzedPathSetDigest !== canonicalPathSetDigest;
      const reportPathSetProof: AnalyzerPathSetProof =
        unprovenCoverageProof.eligiblePathSetDigest ===
        EmptyRepositoryPathSetDigest
          ? unprovenCoverageProof
          : {
              eligiblePathSetDigest:
                unprovenCoverageProof.eligiblePathSetDigest,
              analyzedPathSetDigest:
                report.analyzedPaths.length === 0
                  ? EmptyRepositoryPathSetDigest
                  : analyzedPathSetDigest,
            };
      const candidates = calldiffCandidates(report);
      const ambiguousCallers = report.collisions.reduce(
        (total, collision) => total + collision.ambiguousCallerCount,
        0,
      );
      const duplicateEntrypointEvidenceTruncations = report.duplicates.filter(
        duplicate =>
          duplicate.entrypointsTruncated ||
          duplicate.entrypoints.length < duplicate.entrypointCount ||
          duplicate.entrypointCount > ContractLimits.evidencePerFinding,
      ).length;
      const coverageSummaryWarnings = [
        'Static call-tree analysis does not include dynamic dispatch or runtime-only edges.',
        'Vue and Svelte single-file component callables are not included.',
        'Call-tree samples are capped at 32 paths per root.',
        ...(adapterEligibleCountMismatch
          ? [`Calldiff reported ${report.eligibleFiles} eligible source files, but the canonical audited inventory contains ${canonicalEligibleFiles}; coverage is partial.`]
          : []),
        ...(inventoryEligiblePathSetMismatch
          ? ['Calldiff source-path input did not match the semantic runner\'s audited staged-path digest; coverage is partial.']
          : []),
        ...(requestedPathCountMismatch
          ? [`Calldiff reported ${report.requestedPaths.length} requested source paths for ${report.eligibleFiles} eligible files; coverage is partial.`]
          : []),
        ...(analyzedPathCountMismatch
          ? [`Calldiff reported ${report.analyzedPaths.length} analyzed source paths for ${report.analyzedFiles} analyzed files; coverage is partial.`]
          : []),
        ...(requestedDigestMismatch
          ? ['Calldiff requested-path evidence did not match its reported digest; coverage is partial.']
          : []),
        ...(analyzedDigestMismatch
          ? ['Calldiff analyzed-path evidence did not match its reported digest; coverage is partial.']
          : []),
        ...(requestedPathSetMismatch
          ? ['Calldiff did not acknowledge the exact canonical audited source-path set; coverage is partial.']
          : []),
        ...(analyzedPathSetMismatch
          ? ['Calldiff analyzed a source-path set different from the canonical audited inventory; coverage is partial.']
          : []),
        ...(ambiguousCallers === 0
          ? []
          : [`${ambiguousCallers} call sites were not linked because textual names had multiple possible local definitions.`]),
        ...(report.unmodeledCrossFileCallCount === 0
          ? []
          : [`${report.unmodeledCrossFileCallCount} call sites had local definitions only in other files, but no same-file binding could be proven.`]),
        ...(report.unmodeledCrossFileCallsTruncated
          ? ['Calldiff unmodeled cross-file coverage evidence exceeded its bounded output envelope.']
          : []),
        ...(report.inputTruncated || report.truncatedInputFileCount > 0
          ? [`${report.truncatedInputFileCount} source files were skipped before parser allocation because Calldiff input limits were reached (${report.inputFileCount}/${report.maximumInputFiles} files, ${report.inputBytes}/${report.maximumInputBytes} bytes).`]
          : []),
        ...(report.directoryTraversalFailureCount === 0
          ? []
          : [`Calldiff could not inspect ${report.directoryTraversalFailureCount} source directories.`]),
        ...(report.directoryTraversalFailuresTruncated ||
        report.directoryTraversalFailures.length <
          report.directoryTraversalFailureCount
          ? [`Calldiff retained ${report.directoryTraversalFailures.length} of ${report.directoryTraversalFailureCount} directory-traversal diagnostics in its bounded report.`]
          : []),
        ...(report.directoryTraversalTruncated ||
        report.truncatedDirectoryCount > 0
          ? [`${report.truncatedDirectoryCount} source directories were skipped at Calldiff's traversal depth or budget boundary.`]
          : []),
        ...(report.failedFileCount === 0
          ? []
          : [`Calldiff could not read or parse ${report.failedFileCount} source files.`]),
        ...(report.failedFilesTruncated ||
        report.failedFiles.length < report.failedFileCount
          ? [`Calldiff retained ${report.failedFiles.length} of ${report.failedFileCount} file-failure diagnostics in its bounded report.`]
          : []),
        ...(report.depthCutCount === 0
          ? []
          : [`${report.depthCutCount} call-tree branches were cut at depth ${report.maximumDepth} across ${report.depthTruncatedEntrypointCount} roots.`]),
        ...(report.depthTruncatedEntrypointsTruncated
          ? ['Calldiff depth-cut root evidence exceeded its bounded output envelope.']
          : []),
        ...(report.rewriteTruncatedDefinitionCount === 0
          ? []
          : [`${report.rewriteTruncatedDefinitionCount} definitions were discarded before call-tree indexing because Calldiff's graph budget was reached.`]),
        ...(report.rewriteTruncatedDefinitionsTruncated
          ? ['Calldiff rewrite-truncation evidence exceeded its bounded output envelope.']
          : []),
        ...(report.evidenceTruncated
          ? [`Calldiff duplicate and collision evidence exceeded its ${report.maximumEvidenceBytes}-byte output envelope.`]
          : []),
        ...(report.truncatedEntrypointCount === 0
          ? []
          : [`${report.truncatedEntrypointCount} call-tree roots exceeded the bounded expansion budget.`]),
        ...(report.collisionsTruncated
          ? ['Calldiff collision evidence exceeded its bounded output envelope.']
          : []),
        ...(report.duplicatesTruncated
          ? ['Calldiff duplicate findings exceeded the canonical 1,000-finding envelope.']
          : []),
        ...(duplicateEntrypointEvidenceTruncations === 0
          ? []
          : [`${duplicateEntrypointEvidenceTruncations} duplicate findings have call-root evidence reduced to the consumer envelope.`]),
      ];
      const coverageWarnings = coverageSummaryWarnings.slice(
        0,
        ContractLimits.warningsPerAnalyzer,
      );
      if (
        report.failedFileCount > 0 ||
        report.failedFilesTruncated ||
        adapterEligibleCountMismatch ||
        inventoryEligiblePathSetMismatch ||
        requestedPathCountMismatch ||
        analyzedPathCountMismatch ||
        requestedDigestMismatch ||
        analyzedDigestMismatch ||
        requestedPathSetMismatch ||
        analyzedPathSetMismatch ||
        report.analyzedFiles !== report.eligibleFiles ||
        ambiguousCallers > 0 ||
        report.unmodeledCrossFileCallCount > 0 ||
        report.unmodeledCrossFileCallsTruncated ||
        report.inputTruncated ||
        report.truncatedInputFileCount > 0 ||
        report.directoryTraversalFailureCount > 0 ||
        report.directoryTraversalFailuresTruncated ||
        report.directoryTraversalTruncated ||
        report.truncatedDirectoryCount > 0 ||
        report.rewriteTruncatedDefinitionCount > 0 ||
        report.rewriteTruncatedDefinitionsTruncated ||
        report.evidenceTruncated ||
        report.depthCutCount > 0 ||
        report.depthTruncatedEntrypointsTruncated ||
        report.truncatedEntrypointCount > 0 ||
        report.collisionsTruncated ||
        report.duplicatesTruncated ||
        duplicateEntrypointEvidenceTruncations > 0
      ) {
        return incompleteAnalyzerOutput({
          analyzer: 'Calldiff',
          analyzerVersion: report.calldiffVersion,
          status: 'partial',
          durationMs,
          eligibleFiles: canonicalEligibleFiles,
          analyzedFiles: report.analyzedPaths.length,
          observationCount: report.duplicateCount,
          diagnostic:
            'Calldiff completed with bounded, ambiguous, or unmodeled call-graph coverage.',
          candidates,
          warnings: coverageWarnings,
          pathSetProof: reportPathSetProof,
        });
      }
      return completeAnalyzerOutput({
        analyzer: 'Calldiff',
        analyzerVersion: report.calldiffVersion,
        durationMs,
        eligibleFiles: canonicalEligibleFiles,
        analyzedFiles: report.analyzedPaths.length,
        observationCount: report.duplicateCount,
        candidates,
        warnings: coverageWarnings,
        pathSetProof: reportPathSetProof,
      });
    }),
    Effect.catch(() =>
      Effect.succeed(
        emptyOutput(
          inventory,
          'failed',
          'Calldiff produced an invalid bounded report.',
          durationMs,
          unprovenCoverageProof,
        ),
      ),
    ),
  );
});
