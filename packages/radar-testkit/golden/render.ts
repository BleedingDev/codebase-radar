import { Effect, Schema } from "effect";
import {
  encodeScanResult,
  type SuccessfulScanResult,
} from "../../radar-contracts/src/index.js";
import { stableStringify } from "../src/index.js";

const decodeJson = Schema.decodeUnknownEffect(Schema.Json);

const sourceSummary = (result: SuccessfulScanResult) =>
  result.source._tag === "GitHubSourceIdentity"
    ? `${result.source.url} @ ${result.source.commitSha}`
    : `${result.source.repository} @ ${result.source.snapshotDigest}`;

/**
 * The human golden intentionally carries the complete canonical record after
 * its ranked summary. This prevents a presentation layer from truncating
 * findings or silently dropping evidence, comparison, or analyzer metadata.
 */
export const renderHumanBacklog = (result: SuccessfulScanResult) =>
  encodeScanResult(result).pipe(
    Effect.flatMap(decodeJson),
    Effect.flatMap(stableStringify),
    Effect.map(record => [
      "# Codebase Radar Improvement Backlog",
      "",
      `Scan: ${result.scanId}`,
      `Policy: ${result.analysisPolicy}`,
      `Repository: ${sourceSummary(result)}`,
      `Health: ${result.summary.healthScore}`,
      `Findings: ${result.findings.length} (fix now ${result.summary.fixNow}, investigate ${result.summary.investigate}, monitor ${result.summary.monitor}, do not fix ${result.summary.doNotFix})`,
      "",
      "## Ranked findings",
      "",
      ...result.findings.map((finding, index) =>
        `${index + 1}. ${finding.scores.priority} | ${finding.action} | ${finding.mechanism} | ${finding.title} | ${finding.id}`),
      "",
      "## Complete canonical record",
      "",
      record,
      "",
    ].join("\n")),
  );
