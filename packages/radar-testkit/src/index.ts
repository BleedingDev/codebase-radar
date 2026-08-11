/**
 * Test-only deterministic helpers for Codebase Radar.
 *
 * Contract integration intentionally lives outside this package: once the
 * public Scan Result, CLI, HTTP, and progress schemas stabilize, their owning
 * test modules should declare `NormalizationSchema` rule sets and pass typed
 * progress events into `createProgressCapture`. This package must remain free
 * of production-contract imports so production packages cannot depend on it.
 */
export {
  createDeterministicClock,
  decodeDeterministicClockOptions,
  type Clock,
  type DeterministicClock,
  DeterministicClockError,
  DeterministicClockFailureReason,
  DeterministicClockInstant,
  DeterministicClockOperation,
  type DeterministicClockOptions,
  DeterministicClockOptionsSchema,
} from "./clock.js";
export {
  createDeterministicRunIds,
  decodeDeterministicRunIdOptions,
  DeterministicRunIdError,
  DeterministicRunIdFailureReason,
  DeterministicRunIdOperation,
  type DeterministicRunIdOptions,
  DeterministicRunIdOptionsSchema,
  type DeterministicRunIds,
} from "./ids.js";
export {
  createSchemaNormalizer,
  defineNormalizationSchema,
  normalizeForComparison,
  stableStringify,
  type JsonValue,
  NormalizationError,
  type NormalizationContext,
  type NormalizationPathSegment,
  type NormalizationRule,
  type NormalizationSchema,
} from "./normalize.js";
export {
  createProgressCapture,
  type CapturedProgress,
  type ProgressCapture,
  ProgressCaptureError,
  ProgressCaptureFailureReason,
  ProgressCaptureOperation,
  type ProgressCaptureOptions,
  type ProgressValue,
  decodeProgressValue,
} from "./progress.js";
export {
  createTemporaryWorkspace,
  TemporaryWorkspaceCapabilityError,
  TemporaryWorkspaceCapabilityReason,
  TemporaryWorkspaceError,
  TemporaryWorkspaceOperation,
  withTemporaryWorkspace,
  type DescriptorRelativeWorkspace,
  type TemporaryWorkspace,
  type TemporaryWorkspaceFailure,
  type TemporaryWorkspaceFilesystem,
  type TemporaryWorkspaceOptions,
  type TemporaryWorkspaceRequest,
} from "./temp.js";
