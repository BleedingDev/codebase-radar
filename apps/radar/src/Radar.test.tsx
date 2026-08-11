// @vitest-environment happy-dom
import React, { act } from 'react';
import type { ReactElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AnalyzerCoverage,
  CompleteAnalyzerRun,
  Evidence,
  Finding,
  FindingScores,
  GitHubSourceIdentity,
  LegacyScanResult,
  LocalSourceIdentity,
  RequiredAnalyzerIds,
  ScanComparison,
  ScanProfile,
  ScanRecord,
  ScanResult,
  ScanSummary,
  SourceIdentity,
  SuccessfulScanResult,
} from '../shared/domain';
import {
  radarRequests,
  resetRadarClient,
  setRadarCreateFailure,
  setRadarRepositoryLoadHeld,
  setRadarTestScans,
} from './Radar.test-client';
import {
  radarRouteHref,
  radarRouterCalls,
  resetRadarRouter,
  setRadarMatch,
  setRadarOutlet,
  setRadarRoute,
} from './Radar.test-router';

vi.mock('./radar-client', () => import('./Radar.test-client'));
vi.mock('@modern-js/plugin-tanstack/runtime', () => import('./Radar.test-router'));

import { HomePage, NewReviewPage, RepositoryReviewPage } from './Radar';
import Layout from './routes/layout';

type MountedView = {
  readonly container: HTMLDivElement;
  readonly unmount: () => void;
};

const gitHubSource = new GitHubSourceIdentity({
  codebaseId: 'github:octo/radar',
  owner: 'octo',
  repository: 'radar',
  url: 'https://github.com/octo/radar',
  commitSha: 'a'.repeat(40),
  defaultBranch: 'main',
  snapshotDigest: `git:${'a'.repeat(40)}`,
});

const localSource = new LocalSourceIdentity({
  codebaseId: 'local:radar-worktree',
  repository: 'radar-worktree',
  snapshotDigest: `sha256:${'b'.repeat(64)}`,
  commitSha: 'b'.repeat(40),
  branch: 'feature/local-review',
  dirty: true,
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
      observationCount: analyzer === 'TraceDecay' ? 2 : 0,
    }),
  );

const completeResult = (
  source: typeof SourceIdentity.Type = gitHubSource,
  scanId = 'scan-current',
) => {
  const firstFinding = new Finding({
    id: 'finding-one',
    fingerprint: 'fingerprint-one',
    action: 'fix now',
    mechanism: 'unsafe deserialization',
    category: 'security',
    statusComparedToPrevious: 'new',
    tags: [],
    title: 'Untrusted payload reaches a decoder',
    summary: 'A hostile payload can cross the boundary.',
    technicalSummary: 'The decoder trusts an unvalidated payload.',
    recommendation: 'Validate before decoding.',
    scores: new FindingScores({
      priority: 91,
      consequence: 82,
      blastRadius: 73,
      confidence: 64,
      effort: 55,
      changeExposure: 46,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: 'Decoder accepts the payload.',
        path: 'src/decoder.ts',
        line: 42,
      }),
    ],
    externalReferences: [],
  });
  const secondFinding = new Finding({
    id: 'finding-two',
    fingerprint: 'fingerprint-two',
    action: 'investigate',
    mechanism: 'unbounded retry loop',
    category: 'reliability',
    statusComparedToPrevious: 'persistent',
    tags: [],
    title: 'Retry loop can outlive its request',
    summary: 'A failed call retries without a bounded stop.',
    technicalSummary: 'The retry loop has no terminal limit.',
    recommendation: 'Add a bounded retry policy.',
    scores: new FindingScores({
      priority: 71,
      consequence: 62,
      blastRadius: 53,
      confidence: 44,
      effort: 35,
      changeExposure: 26,
    }),
    evidence: [
      new Evidence({
        analyzer: 'TraceDecay',
        kind: 'direct',
        message: 'Retry stays active.',
        path: 'src/retry.ts',
        line: 17,
      }),
    ],
    externalReferences: [],
  });

  return new SuccessfulScanResult({
    schemaVersion: 'codebase-radar.scan-result/v2',
    resultKind: 'complete',
    analysisPolicy: 'dogfood:max/v1',
    scanId,
    source,
    createdAt: '2026-08-11T00:00:00.000Z',
    completedAt: '2026-08-11T00:00:01.000Z',
    profile: new ScanProfile({
      frameworks: [],
      languageCoverage: [],
      limitations: ['Public snapshot only.'],
    }),
    summary: new ScanSummary({
      headline: 'Canonical backlog ready.',
      healthScore: 72,
      fixNow: 1,
      investigate: 1,
      monitor: 0,
      doNotFix: 0,
    }),
    findings: [firstFinding, secondFinding],
    analyzerRuns: completeAnalyzerRuns(),
    comparison: new ScanComparison({
      basisCodebaseId: source.codebaseId,
      basisPolicyId: 'dogfood:max/v1',
      previousScanId: scanId === 'scan-earlier' ? 'scan-baseline' : 'scan-earlier',
      newFingerprints: ['fingerprint-one'],
      resolvedFingerprints: [],
      persistentFingerprints: ['fingerprint-two'],
      priorityDelta: 7,
    }),
  });
};

const scanFor = (
  id: string,
  result: typeof ScanResult.Type,
  createdAt: string,
) =>
  new ScanRecord({
    id,
    owner: 'octo',
    repository: 'radar',
    githubUrl: 'https://github.com/octo/radar',
    audience: 'technical',
    status: 'completed',
    progress: 100,
    stage: 'completed',
    createdAt,
    updatedAt: createdAt,
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

const setInputValue = (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value',
  )?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
};

let mounted: MountedView | undefined;
let showModalCalls = 0;
let closeModalCalls = 0;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  resetRadarClient();
  resetRadarRouter();
  showModalCalls = 0;
  closeModalCalls = 0;
  vi.spyOn(HTMLDialogElement.prototype, 'showModal').mockImplementation(
    function (this: HTMLDialogElement) {
      showModalCalls += 1;
      this.open = true;
    },
  );
  vi.spyOn(HTMLDialogElement.prototype, 'close').mockImplementation(
    function (this: HTMLDialogElement) {
      closeModalCalls += 1;
      this.open = false;
    },
  );
  vi.spyOn(window, 'requestAnimationFrame').mockImplementation(callback =>
    window.setTimeout(() => callback(Date.now()), 0),
  );
});

afterEach(() => {
  mounted?.unmount();
  mounted = undefined;
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

describe('Radar routed review UI', () => {
  it('loads a bookmarkable GitHub review through the client and renders history, mechanisms, and every score', () => {
    const current = scanFor(
      'scan-current',
      completeResult(gitHubSource, 'scan-current'),
      '2026-08-11T00:00:00.000Z',
    );
    const earlier = scanFor(
      'scan-earlier',
      completeResult(gitHubSource, 'scan-earlier'),
      '2026-08-10T00:00:00.000Z',
    );
    setRadarMatch({
      provider: 'github.com',
      owner: 'octo',
      repository: 'radar',
      scanId: current.id,
    });
    setRadarTestScans([current, earlier], [current]);
    mounted = mount(<RepositoryReviewPage />);

    return settle().then(() => {
      const text = mounted?.container.textContent;
      expect(radarRequests().map(request => request.operation)).toContain(
        'listRepositoryScans',
      );
      expect(text).toContain('GitHub review aaaaaaaa');
      expect(text).toContain('octo/radar');
      expect(text).toContain('default branch main');
      expect(text).toContain('Repository history');
      expect(text).toContain('All 2 findings, scored.');
      for (const value of [
        'unsafe deserialization',
        'unbounded retry loop',
        'Priority',
        'Consequence',
        'Reach',
        'Confidence',
        'Effort',
        'Change risk',
        '91',
        '26',
        'Decoder accepts the payload.',
        'Retry stays active.',
      ]) {
        expect(text).toContain(value);
      }
      const hrefs = [...(mounted?.container.querySelectorAll('a') ?? [])].map(
        link => link.getAttribute('href'),
      );
      expect(hrefs).toContain('/github.com/octo/radar/reviews/scan-current');
      expect(hrefs).toContain('/github.com/octo/radar/reviews/scan-earlier');
    });
  });

  it('renders local and legacy results explicitly through routed client state', () => {
    const local = scanFor(
      'scan-local',
      completeResult(localSource, 'scan-local'),
      '2026-08-11T00:00:00.000Z',
    );
    setRadarMatch({
      provider: 'github.com',
      owner: 'octo',
      repository: 'radar',
      scanId: local.id,
    });
    setRadarTestScans([local]);
    mounted = mount(<RepositoryReviewPage />);

    return settle()
      .then(() => {
        const text = mounted?.container.textContent;
        expect(text).toContain('Local review bbbbbbbb');
        expect(text).toContain('radar-worktree');
        expect(text).toContain('feature/local-review');
        expect(text).toContain('uncommitted changes');
        expect(text).toContain(
          'Agent prioritization is available only for hosted GitHub source snapshots.',
        );
        mounted?.unmount();
        mounted = undefined;

        const legacy = scanFor(
          'scan-legacy',
          new LegacyScanResult({
            schemaVersion: 'codebase-radar.scan-result/v2',
            resultKind: 'legacy-noncanonical',
            legacyProfileVersion: 'dogfood:v1',
            legacyReason: 'Canonical evidence was not retained for this historical review.',
            scanId: 'scan-legacy',
            source: {
              _tag: 'LegacyGitHubSourceIdentity',
              codebaseId: 'github:legacy-owner/legacy-repository',
              owner: 'legacy-owner',
              repository: 'legacy-repository',
              url: 'https://github.com/legacy-owner/legacy-repository',
              commitSha: 'c'.repeat(40),
              defaultBranch: 'main',
              snapshotDigest: `git:${'c'.repeat(40)}`,
            },
            createdAt: '2026-08-09T00:00:00.000Z',
            completedAt: '2026-08-09T00:00:01.000Z',
            profile: {
              version: 'dogfood:v1',
              frameworks: [],
              languageCoverage: [],
              limitations: [],
            },
            summary: {
              headline: 'Historical review',
              healthScore: 0,
              fixNow: 0,
              investigate: 0,
              monitor: 0,
              doNotFix: 0,
            },
            findings: [],
            analyzerRuns: [],
            comparison: {
              newFindingIds: [],
              resolvedFingerprints: [],
              persistentFindingIds: [],
              priorityDelta: 0,
            },
          }),
          '2026-08-09T00:00:00.000Z',
        );
        setRadarMatch({
          provider: 'github.com',
          owner: 'octo',
          repository: 'radar',
          scanId: legacy.id,
        });
        setRadarTestScans([legacy]);
        mounted = mount(<RepositoryReviewPage />);
        return settle();
      })
      .then(() => {
        const text = mounted?.container.textContent;
        expect(text).toContain('LEGACY REVIEW');
        expect(text).toContain('legacy-owner/legacy-repository');
        expect(text).toContain(
          'Canonical evidence was not retained for this historical review.',
        );
        expect(text).not.toContain('All 2 findings, scored.');
      });
  });

  it('announces loading, running progress, and a submission failure to assistive technology', () => {
    const queued = new ScanRecord({
      id: 'scan-queued',
      owner: 'octo',
      repository: 'radar',
      githubUrl: 'https://github.com/octo/radar',
      audience: 'technical',
      status: 'running',
      progress: 47,
      stage: 'analyzing dependency paths',
      error: 'The latest progress update could not be delivered.',
      createdAt: '2026-08-11T00:00:00.000Z',
      updatedAt: '2026-08-11T00:00:00.000Z',
    });
    setRadarMatch({
      provider: 'github.com',
      owner: 'octo',
      repository: 'radar',
      scanId: queued.id,
    });
    setRadarTestScans([queued]);
    setRadarRepositoryLoadHeld(true);
    mounted = mount(<RepositoryReviewPage />);

    return settle()
      .then(() => {
        const loading = mounted?.container.querySelector(
          '.running-state[role="status"]',
        );
        expect(loading?.getAttribute('aria-busy')).toBe('true');
        expect(loading?.getAttribute('aria-live')).toBe('polite');
        mounted?.unmount();
        mounted = undefined;
        resetRadarClient();
        resetRadarRouter();
        setRadarMatch({
          provider: 'github.com',
          owner: 'octo',
          repository: 'radar',
          scanId: queued.id,
        });
        setRadarTestScans([queued]);
        mounted = mount(<RepositoryReviewPage />);
        return settle();
      })
      .then(() => {
        const progress = mounted?.container.querySelector('[role="progressbar"]');
        expect(progress?.getAttribute('aria-valuemin')).toBe('0');
        expect(progress?.getAttribute('aria-valuemax')).toBe('100');
        expect(progress?.getAttribute('aria-valuenow')).toBe('47');
        expect(mounted?.container.querySelector('[role="status"]')?.textContent).toContain(
          '47% complete',
        );
        expect(mounted?.container.querySelector('[role="alert"]')?.textContent).toContain(
          'The latest progress update could not be delivered.',
        );
        mounted?.unmount();
        mounted = undefined;
        resetRadarClient();
        resetRadarRouter();
        setRadarCreateFailure(true);
        mounted = mount(<NewReviewPage />);
        return settle();
      })
      .then(() => {
        const input = mounted?.container.querySelector<HTMLInputElement>(
          '#repository-url',
        );
        act(() => {
          if (input) setInputValue(input, 'octo/radar');
        });
        const form = mounted?.container.querySelector('form.scan-console');
        act(() => {
          form?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        });
        return settle();
      })
      .then(() => {
        const form = mounted?.container.querySelector('form.scan-console');
        const error = mounted?.container.querySelector('.scan-console [role="alert"]');
        expect(form?.getAttribute('aria-busy')).toBe('false');
        expect(error?.textContent).toContain(
          'The review could not be started. Check the repository and try again.',
        );
      });
  });

  it('opens a native modal and submits only the current scan payload', () => {
    mounted = mount(<NewReviewPage />);

    return settle()
      .then(() => {
        const dialog = mounted?.container.querySelector('dialog');
        const input = mounted?.container.querySelector<HTMLInputElement>(
          '#repository-url',
        );
        expect(showModalCalls).toBe(1);
        expect(dialog?.open).toBe(true);
        act(() => {
          if (input) {
            setInputValue(input, 'octo/radar');
          }
        });
        const form = mounted?.container.querySelector('form.scan-console');
        act(() => {
          form?.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        });
        return settle();
      })
      .then(() => {
        const create = radarRequests().find(
          request => request.operation === 'createScan',
        );
        expect(create?.payload).toEqual({
          repository: 'octo/radar',
          audience: 'technical',
        });
        expect(create?.payload).not.toHaveProperty('profileId');
      });
  });

  it('restores focus in the persistent layout after Escape commits the destination route', () => {
    const RoutedReview = () =>
      radarRouteHref() === '/reviews/new' ? <NewReviewPage /> : <HomePage />;

    setRadarRoute('/reviews/new', { newReviewOrigin: true });
    setRadarOutlet(RoutedReview);
    mounted = mount(<Layout />);

    return settle()
      .then(() => {
        const dialog = mounted?.container.querySelector('dialog');
        const input = mounted?.container.querySelector<HTMLInputElement>(
          '#repository-url',
        );
        expect(dialog?.open).toBe(true);
        act(() => {
          input?.focus();
        });
        expect(document.activeElement).toBe(input);
        act(() => {
          dialog?.dispatchEvent(
            new Event('cancel', { bubbles: true, cancelable: true }),
          );
        });
        expect(radarRouterCalls().map(call => call.operation)).toContain('back');
        return settle();
      })
      .then(() => {
        const routeShell = mounted?.container.querySelector<HTMLDivElement>(
          '#radar-route-shell',
        );
        expect(radarRouteHref()).toBe('/');
        expect(mounted?.container.textContent).toContain('START A REVIEW');
        expect(mounted?.container.querySelector('dialog')).toBeNull();
        expect(document.activeElement).toBe(routeShell);
      });
  });

  it('closes the native dialog before restoring destination focus from the Close control', () => {
    const RoutedReview = () =>
      radarRouteHref() === '/reviews/new' ? <NewReviewPage /> : <HomePage />;

    setRadarRoute('/reviews/new');
    setRadarOutlet(RoutedReview);
    mounted = mount(<Layout />);

    return settle()
      .then(() => {
        const close = mounted?.container.querySelector<HTMLButtonElement>(
          '[aria-label="Close new review"]',
        );
        const input = mounted?.container.querySelector<HTMLInputElement>(
          '#repository-url',
        );
        act(() => {
          input?.focus();
          close?.click();
        });
        expect(closeModalCalls).toBe(1);
        expect(radarRouterCalls()).toContainEqual({ operation: 'replace', to: '/' });
        return settle();
      })
      .then(() => {
        const routeShell = mounted?.container.querySelector<HTMLDivElement>(
          '#radar-route-shell',
        );
        expect(radarRouteHref()).toBe('/');
        expect(document.activeElement).toBe(routeShell);
      });
  });
});
