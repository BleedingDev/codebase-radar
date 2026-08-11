import {
  ExternalReference,
  Finding,
  FindingScores,
  compareEvidence,
  compareExternalReferences,
  compareFindings,
} from '@codebase-radar/contracts';
import { Effect } from 'effect';
import { FindingCandidate } from '../analyzers/index.js';

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const priorityCap = (tags: ReadonlyArray<string>) => {
  if (tags.includes('heuristic-only')) return 24;
  if (tags.includes('structural-similarity')) return 58;
  if (tags.includes('style-policy')) return 20;
  if (tags.includes('generated-or-test')) return 28;
  return 100;
};

const actionFor = (priority: number, confidence: number, tags: ReadonlyArray<string>) => {
  if (tags.includes('generated-or-test') || tags.includes('style-policy')) {
    return 'do not fix';
  }
  if (priority >= 72 && confidence >= 70) return 'fix now';
  if (priority >= 50) return 'investigate';
  if (priority >= 30) return 'monitor';
  return 'do not fix';
};

const orderedStrings = (values: ReadonlyArray<string>) =>
  [...new Set(values)].sort(compareText);

const evidenceKey = (value: {
  readonly analyzer: string;
  readonly kind: string;
  readonly path?: string;
  readonly line?: number;
  readonly ruleId?: string;
  readonly message: string;
  readonly excerpt?: string;
}) =>
  `${value.analyzer}\u0000${value.kind}\u0000${value.path ?? ''}\u0000${String(value.line ?? 0).padStart(12, '0')}\u0000${value.ruleId ?? ''}\u0000${value.message}\u0000${value.excerpt ?? ''}`;

const referenceKey = (value: {
  readonly label: string;
  readonly url: string;
  readonly relationship: string;
  readonly applicability: string;
}) =>
  `${value.url}\u0000${value.label}\u0000${value.relationship}\u0000${value.applicability}`;

const orderedEvidence = (values: ReadonlyArray<FindingCandidate['evidence'][number]>) => {
  const byKey = new Map<string, FindingCandidate['evidence'][number]>();
  for (const value of [...values].sort(compareEvidence)) {
    byKey.set(evidenceKey(value), value);
  }
  return [...byKey.values()].sort(compareEvidence);
};

const orderedReferences = (
  values: ReadonlyArray<FindingCandidate['externalReferences'][number]>,
) => {
  const byKey = new Map<string, FindingCandidate['externalReferences'][number]>();
  for (const value of [...values].sort(compareExternalReferences)) {
    byKey.set(referenceKey(value), value);
  }
  return [...byKey.values()].sort(compareExternalReferences);
};

const candidateKey = (candidate: FindingCandidate) =>
  `${candidate.mechanism}\u0000${candidate.title}\u0000${candidate.category}\u0000${candidate.summary}\u0000${candidate.technicalSummary}\u0000${candidate.recommendation}`;

const fingerprintFor = (seed: string) => {
  let value = 0xcbf29ce484222325n;
  for (let index = 0; index < seed.length; index += 1) {
    value ^= BigInt(seed.charCodeAt(index));
    value = BigInt.asUintN(64, value * 0x100000001b3n);
  }
  return `fp_${value.toString(16).padStart(16, '0')}`;
};

const mergeCandidates = (candidates: ReadonlyArray<FindingCandidate>) => {
  const grouped = new Map<string, Array<FindingCandidate>>();
  for (const candidate of [...candidates].sort((left, right) =>
    compareText(left.fingerprintSeed.toLowerCase(), right.fingerprintSeed.toLowerCase()) ||
    compareText(candidateKey(left), candidateKey(right)),
  )) {
    const key = candidate.fingerprintSeed.toLowerCase();
    const group = grouped.get(key);
    if (group === undefined) {
      grouped.set(key, [candidate]);
    } else {
      group.push(candidate);
    }
  }

  const merged = new Array<{ readonly fingerprint: string; readonly candidate: FindingCandidate }>();
  for (const [seed, group] of [...grouped.entries()].sort((left, right) =>
    compareText(left[0], right[0]),
  )) {
    const orderedGroup = [...group].sort((left, right) =>
      compareText(candidateKey(left), candidateKey(right)),
    );
    const representative = orderedGroup[0];
    if (representative === undefined) continue;
    merged.push({
      fingerprint: fingerprintFor(seed),
      candidate: new FindingCandidate({
        fingerprintSeed: seed,
        mechanism: representative.mechanism,
        title: representative.title,
        category: representative.category,
        summary: representative.summary,
        technicalSummary: representative.technicalSummary,
        recommendation: representative.recommendation,
        evidence: orderedEvidence(orderedGroup.flatMap(candidate => candidate.evidence)),
        externalReferences: orderedReferences(
          orderedGroup.flatMap(candidate => candidate.externalReferences),
        ),
        tags: orderedStrings(orderedGroup.flatMap(candidate => candidate.tags)),
        consequence: Math.max(...orderedGroup.map(candidate => candidate.consequence)),
        blastRadius: Math.max(...orderedGroup.map(candidate => candidate.blastRadius)),
        confidence: Math.min(
          98,
          Math.max(...orderedGroup.map(candidate => candidate.confidence)) +
            Math.min(9, (orderedGroup.length - 1) * 3),
        ),
        effort: Math.max(...orderedGroup.map(candidate => candidate.effort)),
        changeExposure: Math.max(
          ...orderedGroup.map(candidate => candidate.changeExposure),
        ),
      }),
    });
  }
  return merged;
};

export const prioritize = Effect.fn('prioritize')(function* (
  candidates: ReadonlyArray<FindingCandidate>,
) {
  const findings = mergeCandidates(candidates).map(({ fingerprint, candidate }) => {
    const priority = Math.min(
      priorityCap(candidate.tags),
      clamp(
        candidate.consequence * 0.4 +
          candidate.blastRadius * 0.25 +
          candidate.confidence * 0.25 +
          (100 - candidate.effort) * 0.1,
      ),
    );
    return new Finding({
      id: `finding_${fingerprint}`,
      fingerprint,
      mechanism: candidate.mechanism,
      title: candidate.title,
      category: candidate.category,
      action: actionFor(priority, candidate.confidence, candidate.tags),
      summary: candidate.summary,
      technicalSummary: candidate.technicalSummary,
      recommendation: candidate.recommendation,
      scores: new FindingScores({
        consequence: clamp(candidate.consequence),
        blastRadius: clamp(candidate.blastRadius),
        confidence: clamp(candidate.confidence),
        effort: clamp(candidate.effort),
        changeExposure: clamp(candidate.changeExposure),
        priority,
      }),
      evidence: orderedEvidence(candidate.evidence),
      externalReferences: orderedReferences(candidate.externalReferences).map(
        reference => new ExternalReference({ ...reference }),
      ),
      tags: orderedStrings(candidate.tags),
      statusComparedToPrevious: 'new',
    });
  });
  return [...findings].sort(compareFindings);
});
