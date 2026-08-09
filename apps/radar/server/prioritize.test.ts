import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Effect, Layer } from 'effect';
import { describe, expect, it } from 'vitest';
import { Evidence } from '../shared/domain';
import { FindingCandidate } from './analyzers';
import { prioritize } from './prioritize';

const TestServices = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);

describe('priority policy', () => {
  it('keeps style-only volume out of the action queue', () =>
    Effect.runPromise(
      prioritize([
        new FindingCandidate({
          fingerprintSeed: 'style-policy',
          title: 'Repository formatting preference',
          category: 'maintainability',
          summary: 'Consistency preference.',
          technicalSummary: 'A style rule matched many files.',
          recommendation: 'Apply during nearby work.',
          evidence: [
            new Evidence({
              analyzer: 'Oxlint + Ultracite',
              kind: 'direct',
              message: 'Style rule matched.',
            }),
          ],
          tags: ['style-policy'],
          consequence: 14,
          blastRadius: 18,
          confidence: 86,
          effort: 78,
          changeExposure: 16,
        }),
      ]).pipe(Effect.provide(TestServices)),
    ).then(findings => {
      expect(findings).toHaveLength(1);
      expect(findings[0]?.action).toBe('do not fix');
    }));

  it('ranks corroborated consequential evidence above low-value observations', () =>
    Effect.runPromise(
      prioritize([
        new FindingCandidate({
          fingerprintSeed: 'high-value',
          title: 'Published advisory match',
          category: 'security',
          summary: 'Locked package version matches an advisory.',
          technicalSummary: 'Direct package and version match.',
          recommendation: 'Validate reachability, then upgrade.',
          evidence: [
            new Evidence({
              analyzer: 'OSV-Scanner',
              kind: 'direct',
              message: 'Package and version matched.',
            }),
          ],
          tags: ['dependency', 'advisory'],
          consequence: 88,
          blastRadius: 64,
          confidence: 94,
          effort: 42,
          changeExposure: 76,
        }),
        new FindingCandidate({
          fingerprintSeed: 'low-value',
          title: 'Small duplicate',
          category: 'maintainability',
          summary: 'A generated fixture repeats code.',
          technicalSummary: 'Small static clone.',
          recommendation: 'Leave it alone.',
          evidence: [
            new Evidence({
              analyzer: 'JSCPD',
              kind: 'direct',
              message: 'Eight lines matched.',
            }),
          ],
          tags: ['generated-or-test'],
          consequence: 18,
          blastRadius: 15,
          confidence: 82,
          effort: 55,
          changeExposure: 20,
        }),
      ]).pipe(Effect.provide(TestServices)),
    ).then(findings => {
      expect(findings[0]?.title).toBe('Published advisory match');
      expect(findings[0]?.action).toBe('fix now');
      expect(findings[1]?.action).toBe('do not fix');
    }));
});
