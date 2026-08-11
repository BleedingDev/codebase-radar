import { Schema } from 'effect';
import { ContractLimits } from './primitives.js';
import {
  AnalysisPolicyIdentity,
  CanonicalAnalysisPolicy,
  compareCanonicalRepositoryPaths,
  Framework,
  RepositoryPath,
  RequiredAnalyzer,
  RequiredAnalyzerIds,
} from './report.js';

const NonNegativeInteger = Schema.Finite.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
  Schema.makeFilter(value =>
    Number.isSafeInteger(value) ? undefined : 'number must be a safe integer',
  ),
);

const FrameworkIds: ReadonlyArray<typeof Framework.Type> = Object.freeze([
  'react',
  'angular',
  'vue',
  'svelte',
  'solid',
]);

const isCanonicalSubset = <A>(
  values: ReadonlyArray<A>,
  canonical: ReadonlyArray<A>,
) =>
  values.length > 0 &&
  values.every((value, index) => canonical.indexOf(value) >= 0 &&
    (index === 0 || canonical.indexOf(values[index - 1] ?? value) < canonical.indexOf(value)));

export class SemanticAnalyzerInventoryEntry extends Schema.Class<SemanticAnalyzerInventoryEntry>(
  'SemanticAnalyzerInventoryEntry',
)({
  path: RepositoryPath,
  byteLength: NonNegativeInteger.check(
    Schema.isLessThanOrEqualTo(ContractLimits.semanticAnalyzerFileBytes),
  ),
  analyzers: Schema.Array(RequiredAnalyzer).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(RequiredAnalyzerIds.length),
  ),
}) {}

export const SemanticAnalyzerInventoryEntrySchema = SemanticAnalyzerInventoryEntry.check(
  Schema.makeFilter(entry =>
    isCanonicalSubset(entry.analyzers, RequiredAnalyzerIds)
      ? undefined
      : 'eligible analyzers must be unique and in canonical dogfood:max order',
  ),
);

export class SemanticAnalyzerInventoryValue extends Schema.Class<SemanticAnalyzerInventoryValue>(
  'SemanticAnalyzerInventoryValue',
)({
  entries: Schema.Array(SemanticAnalyzerInventoryEntrySchema).check(
    Schema.isMaxLength(ContractLimits.semanticAnalyzerInventoryEntries),
  ),
  frameworks: Schema.Array(Framework).check(Schema.isMaxLength(FrameworkIds.length)),
  truncated: Schema.Boolean,
}) {}

export const SemanticAnalyzerInventory = SemanticAnalyzerInventoryValue.check(
  Schema.makeFilter(inventory => {
    const canonicalEntries = inventory.entries.every((entry, index) => {
      const previous = inventory.entries[index - 1];
      return previous === undefined ||
        compareCanonicalRepositoryPaths(previous.path, entry.path) < 0;
    });
    if (!canonicalEntries) {
      return 'inventory entries must have unique paths in canonical byte order';
    }
    const sourceBytes = inventory.entries.reduce(
      (total, entry) => total + entry.byteLength,
      0,
    );
    if (
      !Number.isSafeInteger(sourceBytes) ||
      sourceBytes > ContractLimits.semanticAnalyzerSourceBytes
    ) {
      return 'inventory source bytes exceed the canonical semantic analyzer limit';
    }
    return inventory.frameworks.length === 0 ||
      isCanonicalSubset(inventory.frameworks, FrameworkIds)
      ? undefined
      : 'frameworks must be unique and in canonical order';
  }),
);

const encodedRequestExceedsLimit = <A>(value: A) => {
  try {
    const serialized = JSON.stringify(value);
    return serialized === undefined ||
      new TextEncoder().encode(serialized).byteLength >
        ContractLimits.semanticAnalyzerRequestBytes;
  } catch {
    return true;
  }
};

const SemanticAnalyzerProcessRequestFields = Schema.Struct({
  schemaVersion: Schema.Literal('codebase-radar.semantic-analyzer-request/v1'),
  analysisPolicy: AnalysisPolicyIdentity,
  analyzer: RequiredAnalyzer,
  inventory: SemanticAnalyzerInventory,
}).check(
  Schema.makeFilter(request =>
    encodedRequestExceedsLimit(request)
      ? {
          path: [],
          issue: 'semantic analyzer request exceeds the contract byte limit',
        }
      : undefined,
  ),
);

export class SemanticAnalyzerProcessRequest extends Schema.Class<SemanticAnalyzerProcessRequest>(
  'SemanticAnalyzerProcessRequest',
)(SemanticAnalyzerProcessRequestFields) {
  static readonly canonicalPolicy = CanonicalAnalysisPolicy;
}
