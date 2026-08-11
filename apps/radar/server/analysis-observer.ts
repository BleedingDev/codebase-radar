import { AnalysisObserver } from '@codebase-radar/core';
import { Effect, Layer, Option, Ref, Semaphore } from 'effect';
import {
  isMonotonicProgress,
  type AnalysisProgress,
} from '@codebase-radar/contracts';
import { RadarStore, ScanLease } from './store';

const stageLabel = (progress: AnalysisProgress) => {
  if (progress._tag === 'AnalysisProgressTerminal') {
    return progress.outcome === 'succeeded'
      ? 'Finalizing canonical scan result'
      : 'Analysis did not complete';
  }
  switch (progress.stage) {
    case 'preflight':
      return 'Validating the GitHub source';
    case 'materializing':
      return 'Resolving the approved GitHub revision';
    case 'inventory':
      return 'Reading the codebase';
    case 'analyzing':
      return 'Running the required analysis policy';
    case 'prioritizing':
      return 'Preparing the evidence-backed backlog';
    case 'comparing':
      return 'Comparing repository history';
  }
};

/**
 * The core invokes this observer from its single canonical analysis effect.
 * Store failures and malformed/out-of-order observations cannot alter that
 * analysis outcome, while accepted progress remains correlated and monotonic.
 */
export const RadarAnalysisObserverLive = (scanId: string, lease?: ScanLease) =>
  Layer.effect(
    AnalysisObserver,
    Effect.gen(function* () {
      const store = yield* RadarStore;
      const latest = yield* Ref.make<Option.Option<AnalysisProgress>>(
        Option.none(),
      );
      const observerLock = yield* Semaphore.make(1);
      const observe = (progress: AnalysisProgress) =>
        observerLock.withPermit(
          Effect.gen(function* () {
            if (progress.scanId !== scanId) return;
            const previous = yield* Ref.get(latest);
            const accepted =
              Option.isNone(previous)
                ? progress.sequence === 0
                : isMonotonicProgress(previous.value, progress);
            if (!accepted) return;
            const stage = stageLabel(progress);
            const updated = yield* store.updateScan(
              progress.scanId,
              {
                progress: progress.percent,
                stage,
              },
              lease,
            );
            if (
              (updated.status !== 'queued' && updated.status !== 'running') ||
              updated.progress !== progress.percent ||
              updated.stage !== stage
            ) {
              return;
            }
            yield* Ref.set(latest, Option.some(progress));
          }).pipe(Effect.catchCause(() => Effect.void)),
        );
      return AnalysisObserver.of({ observe });
    }),
  );
