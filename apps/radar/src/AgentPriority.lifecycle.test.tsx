// @vitest-environment happy-dom
import React, { act } from 'react';
import type { ReactElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AnalyzerCoverage,
  AgentProfile,
  CompleteAnalyzerRun,
  GitHubSourceIdentity,
  RequiredAnalyzerIds,
  ScanComparison,
  ScanProfile,
  ScanRecord,
  ScanSummary,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  agentPriorityRequests,
  clearAgentPriorityRequests,
  resetAgentPriorityClient,
  setAgentLoginBeginFailure,
  setAgentPriorityPollHeld,
} from './AgentPriority.test-client';

vi.mock('./radar-client', () => import('./AgentPriority.test-client'));

import { AgentPriority } from './AgentPriority';

type MountedView = {
  readonly container: HTMLDivElement;
  readonly unmount: () => void;
};

const source = new GitHubSourceIdentity({
  codebaseId: 'github:octo/radar',
  owner: 'octo',
  repository: 'radar',
  url: 'https://github.com/octo/radar',
  commitSha: 'a'.repeat(40),
  defaultBranch: 'main',
  snapshotDigest: `git:${'a'.repeat(40)}`,
});
const analyzedPathSetDigest = `sha256:${'d'.repeat(64)}`;
const completeAnalyzerRuns = () =>
  RequiredAnalyzerIds.map(analyzer =>
    new CompleteAnalyzerRun({
      analyzer,
      analyzerVersion: 'test',
      profileVersion: 'dogfood:max/v1',
      status: 'complete',
      durationMs: 1,
      coverage: new AnalyzerCoverage({
        eligibleFiles: 1,
        analyzedFiles: 1,
        eligiblePathSetDigest: analyzedPathSetDigest,
        analyzedPathSetDigest,
        omittedCapabilities: [],
        warnings: [],
      }),
      observationCount: 0,
    }),
  );
const result = new SuccessfulScanResult({
  schemaVersion: 'codebase-radar.scan-result/v2',
  resultKind: 'complete',
  analysisPolicy: 'dogfood:max/v1',
  scanId: 'scan-1',
  source,
  createdAt: '2026-08-11T00:00:00.000Z',
  completedAt: '2026-08-11T00:00:01.000Z',
  profile: new ScanProfile({ frameworks: [], languageCoverage: [], limitations: [] }),
  summary: new ScanSummary({
    headline: 'No canonical findings were returned.',
    healthScore: 100,
    fixNow: 0,
    investigate: 0,
    monitor: 0,
    doNotFix: 0,
  }),
  findings: [],
  analyzerRuns: completeAnalyzerRuns(),
  comparison: new ScanComparison({
    basisCodebaseId: source.codebaseId,
    basisPolicyId: 'dogfood:max/v1',
    newFingerprints: [],
    resolvedFingerprints: [],
    persistentFingerprints: [],
    priorityDelta: 0,
  }),
});
const scan = new ScanRecord({
  id: result.scanId,
  githubUrl: source.url,
  owner: source.owner,
  repository: source.repository,
  audience: 'technical',
  status: 'completed',
  progress: 100,
  stage: 'completed',
  createdAt: result.createdAt,
  updatedAt: result.completedAt,
  result,
});

const settle = (milliseconds = 0) =>
  Promise.resolve(
    act(
      () =>
        new Promise<void>(resolve => {
          window.setTimeout(resolve, milliseconds);
        }),
    ),
  );

const mount = (content: ReactElement): MountedView => {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  act(() => {
    root.render(content);
  });
  return {
    container,
    unmount: () => {
      act(() => {
        root.unmount();
      });
      container.remove();
    },
  };
};

let mounted: MountedView | undefined;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  resetAgentPriorityClient();
});

afterEach(() => {
  mounted?.unmount();
  mounted = undefined;
  document.body.replaceChildren();
});

describe('Agent Priority lifecycle', () => {
  it('upserts a created profile, blocks unrelated controls, polls, and keeps cancellation available', () => {
    setAgentPriorityPollHeld(true);
    mounted = mount(<AgentPriority result={result} scan={scan} />);

    return settle()
      .then(() => {
        const connect = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="connect Codex"]',
        );
        expect(connect).not.toBeNull();
        act(() => {
          connect?.click();
        });
        return settle();
      })
      .then(() => {
        const requests = agentPriorityRequests();
        expect(requests.map(request => request.operation)).toContain('createAgentProfile');
        expect(requests.map(request => request.operation)).toContain('beginAgentLogin');
        const section = mounted?.container.querySelector('.account-priority');
        const profile = mounted?.container.querySelector(
          '[data-provider="codex"]',
        );
        const refresh = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Refresh connected account status"]',
        );
        const disconnect = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Disconnect Codex"]',
        );
        const cancel = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Cancel secure sign-in"]',
        );
        expect(section?.getAttribute('aria-busy')).toBe('true');
        expect(profile?.getAttribute('data-profile-state')).toBe('connecting');
        expect(profile?.textContent).toContain('codex@example.test');
        expect(profile?.textContent).toContain('Account created; secure sign-in is pending.');
        expect(refresh?.disabled).toBe(true);
        expect(disconnect?.disabled).toBe(true);
        expect(cancel?.textContent).toContain('CANCEL SIGN-IN');
        expect(cancel?.disabled).toBe(false);
        return settle(1250);
      })
      .then(() => {
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'pollAgentLogin',
        );
        const cancel = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Cancel secure sign-in"]',
        );
        expect(cancel?.textContent).toContain('CANCEL SIGN-IN');
        expect(cancel?.disabled).toBe(false);
        act(() => {
          cancel?.click();
        });
        return settle();
      })
      .then(() => {
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'cancelAgentLogin',
        );
        const section = mounted?.container.querySelector('.account-priority');
        const refresh = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Refresh connected account status"]',
        );
        expect(section?.getAttribute('aria-busy')).toBe('false');
        expect(refresh?.disabled).toBe(false);
      });
  });

  it('retains the created profile when secure sign-in cannot begin', () => {
    setAgentLoginBeginFailure(true);
    mounted = mount(<AgentPriority result={result} scan={scan} />);

    return settle()
      .then(() => {
        const connect = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="connect Codex"]',
        );
        act(() => {
          connect?.click();
        });
        return settle();
      })
      .then(() => {
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'createAgentProfile',
        );
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'beginAgentLogin',
        );
        const profile = mounted?.container.querySelector(
          '[data-provider="codex"]',
        );
        expect(profile?.getAttribute('data-profile-state')).toBe('disconnected');
        expect(profile?.textContent).toContain('codex@example.test');
        expect(profile?.textContent).toContain(
          'Account created; secure sign-in is pending.',
        );
        expect(mounted?.container.textContent).toContain(
          'Simulated secure sign-in startup failure',
        );
      });
  });

  it('executes refresh and disconnect from rendered controls', () => {
    resetAgentPriorityClient([
      new AgentProfile({
        id: 'profile-codex',
        provider: 'codex',
        state: 'connected',
        accountLabel: 'team@example.test',
        diagnostic: 'Connected to the team workspace.',
        createdAt: '2026-08-11T00:00:00.000Z',
        updatedAt: '2026-08-11T00:00:00.000Z',
      }),
    ]);
    mounted = mount(<AgentPriority result={result} scan={scan} />);

    return settle()
      .then(() => {
        const refresh = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Refresh connected account status"]',
        );
        expect(refresh?.disabled).toBe(false);
        act(() => {
          refresh?.click();
        });
        return settle();
      })
      .then(() => {
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'refreshAgentProfile',
        );
        const disconnect = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Disconnect Codex"]',
        );
        expect(disconnect?.disabled).toBe(false);
        act(() => {
          disconnect?.click();
        });
        return settle();
      })
      .then(() => {
        expect(agentPriorityRequests().map(request => request.operation)).toContain(
          'disconnectAgentProfile',
        );
      });
  });

  it('refreshes the selected profile before starting a priority review', () => {
    resetAgentPriorityClient([
      new AgentProfile({
        id: 'profile-codex',
        provider: 'codex',
        state: 'connected',
        accountLabel: 'team@example.test',
        diagnostic: 'Connected to the team workspace.',
        createdAt: '2026-08-11T00:00:00.000Z',
        updatedAt: '2026-08-11T00:00:00.000Z',
      }),
    ]);
    mounted = mount(<AgentPriority result={result} scan={scan} />);

    return settle()
      .then(() => {
        clearAgentPriorityRequests();
        const prioritize = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="prioritize Codex"]',
        );
        expect(prioritize?.disabled).toBe(false);
        act(() => {
          prioritize?.click();
        });
        return settle();
      })
      .then(() => {
        const operations = agentPriorityRequests().map(request => request.operation);
        expect(operations).toEqual([
          'refreshAgentProfile',
          'createPriorityReview',
        ]);
      });
  });
});
