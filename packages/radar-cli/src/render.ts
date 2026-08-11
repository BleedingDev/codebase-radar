import { Effect, Schema } from 'effect';
import { encodeScanResult } from '@codebase-radar/contracts';
import type { SuccessfulScanResult } from '@codebase-radar/contracts';
import type { RadarRuntimeReport } from '@codebase-radar/core';
import { safeHumanText } from './text.js';

export { safeHumanText } from './text.js';

const JsonArray = Schema.Array(Schema.Json);
const JsonObject = Schema.Record(Schema.String, Schema.Json);
const decodeJson = Schema.decodeUnknownEffect(Schema.Json);

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const indent = (depth: number) => ' '.repeat(depth);

const controlCharacter = /[\u0000-\u001f\u007f-\u009f]/gu;
const stableJsonString = (value: string) =>
  JSON.stringify(value).replace(controlCharacter, character => {
    const codePoint = character.codePointAt(0);
    return codePoint === undefined
      ? ''
      : `\\u${codePoint.toString(16).padStart(4, '0')}`;
  });

const stablePrettyJson = (value: Schema.Json, depth = 0): string => {
  if (Schema.is(JsonArray)(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map(item => (
      `${indent(depth + 2)}${stablePrettyJson(item, depth + 2)}`
    )).join(',\n')}\n${indent(depth)}]`;
  }
  if (Schema.is(JsonObject)(value)) {
    const entries = Object.entries(value).sort(([left], [right]) => compareText(left, right));
    if (entries.length === 0) return '{}';
    return `{\n${entries.map(([key, item]) => (
      `${indent(depth + 2)}${stableJsonString(key)}: ${stablePrettyJson(item, depth + 2)}`
    )).join(',\n')}\n${indent(depth)}}`;
  }
  if (typeof value === 'string') return stableJsonString(value);
  return String(JSON.stringify(value));
};

const sourceSummary = (result: SuccessfulScanResult) =>
  result.source._tag === 'GitHubSourceIdentity'
    ? `${result.source.url} @ ${result.source.commitSha}`
    : `${result.source.repository} @ ${result.source.snapshotDigest}`;

/**
 * The ranked backlog is deliberately followed by the complete encoded record:
 * the compact view remains readable while no canonical finding metadata is lost.
 */
export const renderHumanScanResult = (result: SuccessfulScanResult) =>
  encodeScanResult(result).pipe(
    Effect.flatMap(decodeJson),
    Effect.map(record => [
      '# Codebase Radar Improvement Backlog',
      '',
      `Scan: ${safeHumanText(result.scanId)}`,
      `Policy: ${safeHumanText(result.analysisPolicy)}`,
      `Repository: ${safeHumanText(sourceSummary(result))}`,
      `Health: ${result.summary.healthScore}`,
      `Findings: ${result.findings.length} (fix now ${result.summary.fixNow}, investigate ${result.summary.investigate}, monitor ${result.summary.monitor}, do not fix ${result.summary.doNotFix})`,
      '',
      '## Ranked findings',
      '',
      ...result.findings.map((finding, index) => (
        `${index + 1}. ${finding.scores.priority} | ${safeHumanText(finding.action)} | ${safeHumanText(finding.mechanism)} | ${safeHumanText(finding.title)} | ${safeHumanText(finding.id)}`
      )),
      '',
      '## Complete canonical record',
      '',
      stablePrettyJson(record),
      '',
    ].join('\n')),
  );

const renderDoctorEvidence = (
  evidence: RadarRuntimeReport['evidence'][number],
) => {
  const lines = [
    `- ${safeHumanText(evidence.analyzer)}: ${safeHumanText(evidence.status)}`,
  ];
  return lines;
};

export const renderHumanDoctorReport = (report: RadarRuntimeReport) =>
  [
    'Codebase Radar doctor',
    `Status: ${safeHumanText(report.status)}`,
    `Runtime build: ${safeHumanText(report.manifest.buildIdentity)}`,
    `Policy digest: ${safeHumanText(report.manifest.policyDigest)}`,
    'Evidence:',
    ...report.evidence.flatMap(renderDoctorEvidence),
    '',
  ].join('\n');
