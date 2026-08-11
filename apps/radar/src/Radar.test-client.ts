import { Effect } from '@modern-js/plugin-bff/effect-client';
import { AgentPriorityCapability, ReadyResponse, ScanListResponse } from '../shared/api';
import { Audience, ScanRecord } from '../shared/domain';

type ScanClientCall = {
  readonly operation: string;
  readonly payload?: {
    readonly audience: typeof Audience.Type;
    readonly repository: string;
  };
  readonly scanId?: string;
};

type ScanPayload = {
  readonly payload: {
    readonly audience: typeof Audience.Type;
    readonly repository: string;
  };
};

type ScanParameters = {
  readonly params: { readonly scanId: string };
};

const requests: ScanClientCall[] = [];
let repositories: ReadonlyArray<ScanRecord> = [];
let scans: ReadonlyArray<ScanRecord> = [];
let createdScan: ScanRecord | undefined;
let createScanFails = false;
let holdRepositoryLoad = false;

const createdAt = '2026-08-11T00:00:00.000Z';

const selectScan = (scanId: string) =>
  scans.find(scan => scan.id === scanId) ?? createdScan ?? scans[0];

export const resetRadarClient = () => {
  requests.splice(0, requests.length);
  repositories = [];
  scans = [];
  createdScan = undefined;
  createScanFails = false;
  holdRepositoryLoad = false;
};

export const setRadarTestScans = (
  nextScans: ReadonlyArray<ScanRecord>,
  nextRepositories: ReadonlyArray<ScanRecord> = nextScans,
) => {
  scans = nextScans;
  repositories = nextRepositories;
};

export const radarRequests = () => [...requests];

export const setRadarCreateFailure = (fails: boolean) => {
  createScanFails = fails;
};

export const setRadarRepositoryLoadHeld = (held: boolean) => {
  holdRepositoryLoad = held;
};

export const RadarClient = Effect.succeed({
  radar: {
    ready: () =>
      Effect.sync(() => {
        requests.push({ operation: 'ready' });
        return new ReadyResponse({
          status: 'ready',
          storage: 'memory',
          agentPriority: new AgentPriorityCapability({ status: 'unavailable' }),
        });
      }),
    listRepositories: () =>
      Effect.sync(() => {
        requests.push({ operation: 'listRepositories' });
        return new ScanListResponse({ items: repositories });
      }),
    listRepositoryScans: () =>
      Effect.sync(() => {
        requests.push({ operation: 'listRepositoryScans' });
        return holdRepositoryLoad;
      }).pipe(
        Effect.flatMap(held =>
          held
            ? Effect.never
            : Effect.succeed(new ScanListResponse({ items: scans })),
        ),
      ),
    getScan: ({ params }: ScanParameters) =>
      Effect.sync(() => {
        requests.push({ operation: 'getScan', scanId: params.scanId });
        return selectScan(params.scanId);
      }),
    createScan: ({ payload }: ScanPayload) =>
      Effect.sync(() => {
        requests.push({ operation: 'createScan', payload });
        return createScanFails;
      }).pipe(
        Effect.flatMap(fails => {
          if (fails) return Effect.fail('Simulated scan submission failure');
          const [owner, repository] = payload.repository.split('/');
          createdScan = new ScanRecord({
            id: 'scan-created',
            githubUrl: `https://github.com/${payload.repository}`,
            owner: owner ?? 'octo',
            repository: repository ?? 'radar',
            audience: payload.audience,
            status: 'queued',
            progress: 0,
            stage: 'queued',
            createdAt,
            updatedAt: createdAt,
          });
          scans = [createdScan, ...scans];
          repositories = [createdScan, ...repositories];
          return Effect.succeed(createdScan);
        }),
      ),
  },
});
