import {
  AnalyzerCoverage,
  AnalysisRuntimeUnavailable,
  AttemptedAnalyzerRun,
  ContractLimits,
  EvidenceSchema,
  ExternalReference,
  FindingCategory,
  RequiredAnalyzer,
} from '@codebase-radar/contracts';
import { Context, Effect, Layer, Schema } from 'effect';
import type { RepositoryInventory } from '../inventory/index.js';
import type {
  AnalyzerScratchHandle,
  SourceWorkspaceHandle,
} from '../workspace.js';

const CandidateText = Schema.NonEmptyString.check(Schema.isMaxLength(4_000));
const CandidateTag = Schema.NonEmptyString.check(Schema.isMaxLength(100));

export class FindingCandidate extends Schema.Class<FindingCandidate>('FindingCandidate')({
  fingerprintSeed: CandidateText,
  mechanism: CandidateText,
  title: CandidateText,
  category: FindingCategory,
  summary: CandidateText,
  technicalSummary: CandidateText,
  recommendation: CandidateText,
  evidence: Schema.Array(EvidenceSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(200),
  ),
  externalReferences: Schema.Array(ExternalReference).check(Schema.isMaxLength(100)),
  tags: Schema.Array(CandidateTag).check(Schema.isMaxLength(50)),
  consequence: Schema.Finite,
  blastRadius: Schema.Finite,
  confidence: Schema.Finite,
  effort: Schema.Finite,
  changeExposure: Schema.Finite,
}) {}

export class AnalyzerExecution extends Schema.Class<AnalyzerExecution>('AnalyzerExecution')({
  run: AttemptedAnalyzerRun,
  candidates: Schema.Array(FindingCandidate).check(
    Schema.isMaxLength(ContractLimits.findings),
  ),
}) {}

export interface AnalyzerExecutionRequest {
  readonly scanId: string;
  readonly analyzer: typeof RequiredAnalyzer.Type;
  readonly workspace: SourceWorkspaceHandle;
  readonly scratch: AnalyzerScratchHandle;
  readonly inventory: RepositoryInventory;
}

export class AnalyzerRuntime extends Context.Service<AnalyzerRuntime, {
  readonly run: (
    request: AnalyzerExecutionRequest,
  ) => Effect.Effect<AnalyzerExecution, AnalysisRuntimeUnavailable>;
}>()('@codebase-radar/core/internal/AnalyzerRuntime') {}

export const AnalyzerRuntimeUnavailableLive = Layer.succeed(
  AnalyzerRuntime,
  AnalyzerRuntime.of({
    run: () =>
      Effect.fail(
        new AnalysisRuntimeUnavailable({
          message: 'No verified analyzer runtime has been supplied.',
        }),
      ),
  }),
);
