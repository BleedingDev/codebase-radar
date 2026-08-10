import { NodeHttpClient, NodeServices } from '@effect/platform-node';
import { Effect, Layer } from 'effect';
import { describe, expect, it } from 'vitest';
import { Evidence } from '../shared/domain';
import { classifyOxlintRule, FindingCandidate } from './analyzers';
import { prioritize } from './prioritize';

const TestServices = Layer.mergeAll(NodeServices.layer, NodeHttpClient.layerUndici);

describe('priority policy', () => {
  it('normalizes production Oxlint rule IDs and keeps policy-only findings below defect evidence', () => {
    const preferenceRules = [
      'typescript(no-useless-undefined)',
      'typescript(func-style)',
      'react/function-component-definition',
      'unicorn/escape-case',
    ];
    const defectRules = [
      'eslint(no-eval)',
      'eslint/no-unreachable',
    ];
    expect(preferenceRules.map(classifyOxlintRule)).toEqual(
      preferenceRules.map(() => ({
        category: 'maintainability',
        policyOnly: true,
      })),
    );
    expect(defectRules.every(rule => !classifyOxlintRule(rule).policyOnly)).toBe(
      true,
    );
    expect(classifyOxlintRule('eslint(no-eval)')).toEqual(
      classifyOxlintRule('eslint/no-eval'),
    );
    expect(classifyOxlintRule('eslint(no-unreachable)')).toEqual(
      classifyOxlintRule('eslint/no-unreachable'),
    );
    const candidates = [...defectRules, ...preferenceRules].map(rule => {
      const disposition = classifyOxlintRule(rule);
      return new FindingCandidate({
        fingerprintSeed: rule,
        title: rule,
        category: disposition.category,
        summary: disposition.policyOnly
          ? 'Consistency preference.'
          : 'Behavior-bearing lint evidence.',
        technicalSummary: disposition.policyOnly
          ? 'A preference-only lint rule matched.'
          : 'A positively allowlisted rule matched.',
        recommendation: disposition.policyOnly
          ? 'Apply during nearby work.'
          : 'Validate the behavior before changing it.',
        evidence: [
          new Evidence({
            analyzer: 'Oxlint + Ultracite',
            kind: 'direct',
            message: rule,
            ruleId: rule,
          }),
        ],
        tags: [
          'oxlint',
          rule,
          ...(disposition.policyOnly ? ['style-policy'] : []),
        ],
        consequence: disposition.policyOnly ? 100 : 45,
        blastRadius: disposition.policyOnly ? 100 : 35,
        confidence: disposition.policyOnly ? 100 : 80,
        effort: disposition.policyOnly ? 0 : 65,
        changeExposure: disposition.policyOnly ? 100 : 20,
      });
    });

    return Effect.runPromise(
      prioritize(candidates).pipe(Effect.provide(TestServices)),
    ).then(findings => {
      expect(findings.map(finding => finding.title).sort()).toEqual(
        [...defectRules, ...preferenceRules].sort(),
      );
      expect(findings.slice(0, defectRules.length).every(finding =>
        !finding.tags.includes('style-policy'),
      )).toBe(true);
      expect(findings.filter(finding => finding.tags.includes('style-policy')))
        .toEqual(expect.arrayContaining([
          expect.objectContaining({ action: 'do not fix' }),
        ]));
    });
  });

  it('does not increase urgency when only change exposure rises', () => {
    const candidateWithExposure = (changeExposure: number) =>
      new FindingCandidate({
        fingerprintSeed: 'change-exposure',
        title: 'Bounded reliability concern',
        category: 'reliability',
        summary: 'The evidence is identical across both candidates.',
        technicalSummary: 'Only delivery change exposure differs.',
        recommendation: 'Validate the behavior before changing it.',
        evidence: [
          new Evidence({
            analyzer: 'test',
            kind: 'direct',
            message: 'Same evidence.',
          }),
        ],
        tags: ['reliability'],
        consequence: 68,
        blastRadius: 62,
        confidence: 75,
        effort: 55,
        changeExposure,
      });

    return Effect.runPromise(
      Effect.all([
        prioritize([candidateWithExposure(0)]),
        prioritize([candidateWithExposure(100)]),
      ]).pipe(Effect.provide(TestServices)),
    ).then(([lowExposure, highExposure]) => {
      expect(highExposure[0]?.scores.priority).toBe(
        lowExposure[0]?.scores.priority,
      );
      expect(highExposure[0]?.action).toBe(lowExposure[0]?.action);
    });
  });

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
