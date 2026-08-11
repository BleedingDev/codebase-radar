import { Effect, Exit } from 'effect';
import { Schema } from '@modern-js/plugin-bff/effect-client';
import { RadarRuntimePreflight } from '@codebase-radar/core';
import { describe, expect, it } from 'vitest';
import {
  approvedGithubRepository,
  isMcpOriginAllowed,
  isMcpRequestPath,
  productionRuntimeLayerFromEnvironment,
  productionRuntimeOptionsFromEnvironment,
  reportAgentPriorityCapability,
} from './index';
import { ReadyResponse } from '../shared/api';

describe('HTTP GitHub source boundary', () => {
  it('accepts one credential-free GitHub identity and canonicalizes its URL', () =>
    Effect.runPromise(
      approvedGithubRepository('https://github.com/Acme/Radar.git').pipe(
        Effect.tap(repository =>
          Effect.sync(() => {
            expect(repository).toEqual({
              owner: 'acme',
              repository: 'radar',
              url: 'https://github.com/acme/radar',
            });
          }),
        ),
      ),
    ));

  it('rejects local paths, alternate hosts, credentials, refs, and URL smuggling', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          '/private/repository',
          '../repository',
          'owner/..',
          'C:\\workspace\\repository',
          '\\\\server\\share\\repository',
          'https://github.com/acme/radar\n',
          'https://github.com/acme/radar\u0000',
          'https:////github.com/acme/radar',
          'https://github.com:443/acme/radar',
          'https://github.com./acme/radar',
          'file:///private/repository',
          'ssh://github.com/acme/radar',
          'https://github.com@attacker.example/acme/radar',
          'https://token@github.com/acme/radar',
          'https://github.com/acme/radar.git/',
          'https://github.com/acme/radar?',
          'https://github.com/acme/radar#',
          'https://github.com/acme/radar?ref=main',
          'https://github.com/acme/radar#main',
          'https://github.com//acme/radar',
          'https://github.com/acme/radar/tree/main',
          'https://github.com/acme/radar%2Ftree%2Fmain',
          'https://github.com/acme%2Fradar',
        ],
        input => Effect.exit(approvedGithubRepository(input)),
      ).pipe(
        Effect.tap(exits =>
          Effect.sync(() => {
            expect(exits.every(Exit.isFailure)).toBe(true);
          }),
        ),
      ),
    ));

  it('guards every MCP query form and never derives trust from Host headers', () => {
    expect(isMcpRequestPath('/mcp')).toBe(true);
    expect(isMcpRequestPath('/mcp?transport=sse')).toBe(true);
    expect(isMcpRequestPath('/mcp#fragment')).toBe(true);
    expect(isMcpRequestPath('/mcp-tools')).toBe(false);
    expect(isMcpOriginAllowed(
      '/mcp?transport=sse',
      'https://radar.example',
      'https://radar.example',
    )).toBe(true);
    expect(isMcpOriginAllowed(
      'https://edge.invalid/mcp?transport=sse',
      'https://radar.example',
      'https://RADAR.example:443/',
    )).toBe(true);
    expect(isMcpOriginAllowed(
      '/mcp?transport=sse',
      'https://attacker.example',
      'https://radar.example',
    )).toBe(false);
    expect(isMcpOriginAllowed('/mcp', 'https://radar.example', undefined)).toBe(false);
    expect(isMcpOriginAllowed('/mcp', undefined, 'https://radar.example')).toBe(false);
    expect(isMcpOriginAllowed(
      '/mcp',
      'https://radar.example',
      'https://radar.example/path',
    )).toBe(false);
    expect(isMcpOriginAllowed(
      '/health',
      undefined,
      undefined,
    )).toBe(true);
  });
});

describe('HTTP optional capability readiness', () => {
  it('makes unavailable Agent Priority explicit while preserving core readiness', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const unavailable = yield* reportAgentPriorityCapability(
          Effect.fail('provider runtime deliberately unavailable'),
        );
        const ready = yield* reportAgentPriorityCapability(Effect.void);
        const omittedCapability = yield* Effect.exit(
          Schema.decodeUnknownEffect(ReadyResponse, {
            onExcessProperty: 'error',
          })({
            status: 'ready',
            storage: 'postgres',
          }),
        );
        const response = new ReadyResponse({
          status: 'ready',
          storage: 'postgres',
          agentPriority: unavailable,
        });

        expect(unavailable.status).toBe('unavailable');
        expect(ready.status).toBe('ready');
        expect(Exit.isFailure(omittedCapability)).toBe(true);
        expect(response.agentPriority.status).toBe('unavailable');
      }),
    ));
});

describe('production analyzer-root boundary', () => {
  const validEnvironment = {
    runtimeRoot: '/var/www/.zerops/analyzer-runtime',
    workspaceParent: '/var/www/.radar-workspaces',
    resourceCgroupRoot: '/sys/fs/cgroup/radar',
    analyzerControlRoot: '/var/www/.zerops/analyzer-control',
  };

  it('requires independently configured host-owned roots', () => {
    expect(productionRuntimeOptionsFromEnvironment(validEnvironment)).toEqual(
      validEnvironment,
    );

    for (const environment of [
      { ...validEnvironment, runtimeRoot: undefined },
      { ...validEnvironment, workspaceParent: undefined },
      { ...validEnvironment, resourceCgroupRoot: undefined },
      { ...validEnvironment, analyzerControlRoot: undefined },
    ]) {
      expect(productionRuntimeOptionsFromEnvironment(environment)).toBeUndefined();
    }

    expect(productionRuntimeOptionsFromEnvironment({
      ...validEnvironment,
      analyzerControlRoot: validEnvironment.runtimeRoot,
    })).toBeUndefined();
  });

  it('fails closed for absent or malformed control-root configuration', () => {
    for (const analyzerControlRoot of [
      undefined,
      '',
      '/',
      'var/www/.zerops/analyzer-control',
      ' /var/www/.zerops/analyzer-control',
      '/var/www/.zerops/analyzer-control\n',
    ]) {
      expect(productionRuntimeOptionsFromEnvironment({
        ...validEnvironment,
        analyzerControlRoot,
      })).toBeUndefined();
    }
  });

  it('keeps readiness canonically unavailable for a missing or malformed control root', () =>
    Effect.runPromise(
      Effect.forEach(
        [
          undefined,
          'relative/analyzer-control',
          '/var/www/.zerops/analyzer-control\n',
        ],
        analyzerControlRoot =>
          Effect.gen(function* () {
            const result = yield* Effect.gen(function* () {
              const preflight = yield* RadarRuntimePreflight;
              return {
                report: yield* preflight.report(),
                check: yield* Effect.exit(preflight.check()),
              };
            }).pipe(
              Effect.provide(productionRuntimeLayerFromEnvironment({
                ...validEnvironment,
                analyzerControlRoot,
              })),
            );

            yield* Effect.sync(() => {
              expect(result.report.status).toBe('unavailable');
              expect(result.report.evidence).toHaveLength(7);
              expect(result.report.evidence.every(evidence => evidence.status === 'unavailable'))
                .toBe(true);
              expect(Exit.isFailure(result.check)).toBe(true);
            });
          }),
      ),
    ));
});
