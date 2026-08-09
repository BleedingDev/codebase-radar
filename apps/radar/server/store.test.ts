import { NodeServices } from '@effect/platform-node';
import { Effect, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import { MemoryStoreLive, RadarStore } from './store';

describe('repository scan history', () => {
  it('deduplicates repositories and retains every case-insensitive scan', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        const first = yield* store.createScan({
          githubUrl: 'https://github.com/Acme/Radar',
          owner: 'Acme',
          repository: 'Radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const other = yield* store.createScan({
          githubUrl: 'https://github.com/Elsewhere/App',
          owner: 'Elsewhere',
          repository: 'App',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const newest = yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });

        const repositories = yield* store.listRecentRepositories();
        const history = yield* store.listRepositoryScans('ACME', 'RADAR');
        const historicalSnapshot = yield* store.getScan(first.id);

        expect(repositories.map(scan => scan.id)).toEqual([newest.id, other.id]);
        expect(repositories[0]?.owner).toBe('acme');
        expect(repositories[0]?.repository).toBe('radar');
        expect(history.map(scan => scan.id)).toEqual([newest.id, first.id]);
        expect(Option.getOrUndefined(historicalSnapshot)?.id).toBe(first.id);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(NodeServices.layer),
      ),
    ));

  it('applies the repository limit after deduplication', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* RadarStore;
        yield* store.createScan({
          githubUrl: 'https://github.com/acme/radar',
          owner: 'acme',
          repository: 'radar',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        yield* store.createScan({
          githubUrl: 'https://github.com/ACME/RADAR',
          owner: 'ACME',
          repository: 'RADAR',
          audience: 'technical',
        });
        yield* Effect.sleep('2 millis');
        const other = yield* store.createScan({
          githubUrl: 'https://github.com/elsewhere/app',
          owner: 'elsewhere',
          repository: 'app',
          audience: 'technical',
        });

        const repositories = yield* store.listRecentRepositories(1.9);

        expect(repositories.map(scan => scan.id)).toEqual([other.id]);
      }).pipe(
        Effect.provide(MemoryStoreLive),
        Effect.provide(NodeServices.layer),
      ),
    ));
});
