import { Effect } from 'effect';
import { encodeScanResultJson } from '@codebase-radar/contracts';
import type { Finding, SuccessfulScanResult } from '@codebase-radar/contracts';
import { CliAnalysisError, CliFailOnError } from './errors.js';
import { renderHumanScanResult } from './render.js';

export type OutputFormat = 'human' | 'json';

export type FailOn = 'never' | 'fix-now' | 'investigate' | 'monitor' | 'any';

export const encodeScanOutput = (
  result: SuccessfulScanResult,
  format: OutputFormat,
) => {
  if (format === 'human') {
    return renderHumanScanResult(result).pipe(
      Effect.mapError(() => new CliAnalysisError({
        message: 'Analysis returned a scan result that cannot be rendered from the strict contract document.',
      })),
    );
  }
  return encodeScanResultJson(result).pipe(
    Effect.map(contents => `${contents}\n`),
    Effect.mapError(() => new CliAnalysisError({
      message: 'Analysis returned a scan result that cannot be encoded as the strict contract document.',
    })),
  );
};

const actionRank = (finding: Finding) => {
  if (finding.action === 'fix now') return 0;
  if (finding.action === 'investigate') return 1;
  if (finding.action === 'monitor') return 2;
  return 3;
};

const failRank = (failOn: FailOn) => {
  if (failOn === 'fix-now') return 0;
  if (failOn === 'investigate') return 1;
  if (failOn === 'monitor') return 2;
  return undefined;
};

const failsGate = (result: SuccessfulScanResult, failOn: FailOn) => {
  if (failOn === 'never') return false;
  if (failOn === 'any') return result.findings.length > 0;
  const rank = failRank(failOn);
  return rank === undefined
    ? false
    : result.findings.some(finding => actionRank(finding) <= rank);
};

export const applyFailOn = (result: SuccessfulScanResult, failOn: FailOn) =>
  failsGate(result, failOn)
    ? Effect.fail(new CliFailOnError({
      message: `Scan completed, but --fail-on ${failOn} matched the presentation result.`,
    }))
    : Effect.void;
