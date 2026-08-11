import {
  CanonicalAnalysisPolicy,
  ContractLimits,
  RequiredAnalyzer,
  SemanticAnalyzerInventory,
  SemanticAnalyzerProcessRequest,
} from '@codebase-radar/contracts';
import { Context, Effect, Layer, Schema, Scope } from 'effect';
import type {
  AnalyzerScratchHandle,
  SourceWorkspaceHandle,
} from '../workspace.js';

const MaximumDiagnosticCharacters = 500;
const PositiveInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
);
const BoundedTimeoutMilliseconds = PositiveInteger.check(
  Schema.isLessThanOrEqualTo(120_000),
);
const BoundedOutputBytes = PositiveInteger.check(
  Schema.isLessThanOrEqualTo(8 * 1024 * 1024),
);

const credentialMaterial = /(?:https?|ssh):\/\/[^\s/@:]+(?::[^\s/@]+)?@/giu;
const posixPathMaterial = /(?:^|[\s,;:=([{<'"`])\/(?:[^\s/]+\/)*[^\s/]+/gu;
const windowsPathMaterial = /(?:^|[\s,;:=([{<'"`])[a-z]:\\(?:[^\s\\]+\\)*[^\s\\]+/giu;
const uncPathMaterial = /(?:^|[\s,;:=([{<'"`])\\\\[^\s\\]+\\[^\s\\]+/gu;

export const boundedDiagnostic = (value: string) =>
  value
    .replace(credentialMaterial, '<redacted-credential>')
    .replace(posixPathMaterial, ' <redacted-path>')
    .replace(windowsPathMaterial, ' <redacted-path>')
    .replace(uncPathMaterial, ' <redacted-path>')
    .replace(/\s+/gu, ' ')
    .trim()
    .slice(0, MaximumDiagnosticCharacters) || 'Analyzer execution failed without a diagnostic.';

export const safeEnvironment = (): Readonly<Record<string, string>> => ({
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  GIT_TERMINAL_PROMPT: '0',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_LFS_SKIP_SMUDGE: '1',
  GIT_SSH_COMMAND: 'false',
});

export class ProcessRequest extends Schema.Class<ProcessRequest>('ProcessRequest')({
  /** A semantic operation is resolved by the verified host, never by a caller path. */
  analyzer: RequiredAnalyzer,
  /** The audited per-analyzer path assignment; never a runner-side inventory. */
  inventory: SemanticAnalyzerInventory,
  timeoutMs: BoundedTimeoutMilliseconds,
  maxOutputBytes: BoundedOutputBytes,
}) {}

const decodeSemanticAnalyzerProcessRequest = Schema.decodeUnknownEffect(
  SemanticAnalyzerProcessRequest,
  { onExcessProperty: 'error' },
);

const processUnavailable = (message: string) => new ProcessUnavailable({ message });

/**
 * Constructs and bounds the one shared runner protocol payload. This keeps the
 * process host from accepting raw JSON, file paths, or a caller-selected policy.
 */
export const encodeSemanticAnalyzerRequest = (
  request: ProcessRequest,
): Effect.Effect<Uint8Array, ProcessUnavailable> => decodeSemanticAnalyzerProcessRequest(
  new SemanticAnalyzerProcessRequest({
    schemaVersion: 'codebase-radar.semantic-analyzer-request/v1',
    analysisPolicy: CanonicalAnalysisPolicy,
    analyzer: request.analyzer,
    inventory: request.inventory,
  }),
).pipe(
  Effect.mapError(() => processUnavailable('The semantic analyzer request was invalid.')),
  Effect.flatMap(decoded => Effect.try({
    try: () => new TextEncoder().encode(JSON.stringify(decoded)),
    catch: () => {
      throw processUnavailable('The semantic analyzer request could not be encoded.');
    },
  }).pipe(
    Effect.mapError(() => processUnavailable('The semantic analyzer request could not be encoded.')),
    Effect.flatMap(bytes => bytes.byteLength <= ContractLimits.semanticAnalyzerRequestBytes
      ? Effect.succeed(bytes)
      : Effect.fail(processUnavailable('The semantic analyzer request exceeded its bounded transport size.'))),
  )),
);

export class ProcessOutput extends Schema.Class<ProcessOutput>('ProcessOutput')({
  exitCode: Schema.Int,
  stdout: Schema.String,
  stderr: Schema.String,
  durationMs: Schema.Natural,
  timedOut: Schema.Boolean,
  truncated: Schema.Boolean,
}) {}

export class ProcessUnavailable extends Schema.TaggedErrorClass<ProcessUnavailable>()(
  'ProcessUnavailable',
  { message: Schema.NonEmptyString },
) {}

export class WorkspaceProcess extends Context.Service<WorkspaceProcess, {
  readonly execute: (
    request: ProcessRequest,
    workspace: SourceWorkspaceHandle,
    scratch: AnalyzerScratchHandle,
  ) => Effect.Effect<ProcessOutput, ProcessUnavailable, Scope.Scope>;
}>()('@codebase-radar/core/internal/WorkspaceProcess') {}

export const WorkspaceProcessUnavailableLive = Layer.succeed(
  WorkspaceProcess,
  WorkspaceProcess.of({
    execute: () =>
      Effect.fail(
        new ProcessUnavailable({
          message: 'No scoped process executor has been supplied.',
        }),
      ),
  }),
);
