import {
  Cause,
  Clock,
  Context,
  DateTime,
  Effect,
  Layer,
  Option,
  Queue,
  Ref,
} from 'effect';
import { AgentPriorityReview } from '../shared/domain';
import { AgentRuntime } from './agent-runtime';
import { AgentStore } from './agent-store';
import {
  isValidPriorityOutput,
  prioritizationBrief,
} from './prioritization-brief';
import { boundedDiagnostic } from './process';
import { RadarStore } from './store';

interface QueuedReview {
  readonly ownerId: string;
  readonly review: AgentPriorityReview;
}

const staleReviewAgeMs = 40 * 60_000;

export class AgentCoordinator extends Context.Service<AgentCoordinator, {
  readonly enqueue: (ownerId: string, review: AgentPriorityReview) => Effect.Effect<void>;
}>()('AgentCoordinator') {}

const performReview = Effect.fn('performAgentPriorityReview')(function* (
  item: QueuedReview,
) {
  const agentStore = yield* AgentStore;
  const radarStore = yield* RadarStore;
  const runtime = yield* AgentRuntime;
  const [scan, profile] = yield* Effect.all([
    radarStore.getScan(item.review.scanId),
    agentStore.getProfile(item.ownerId, item.review.profileId),
  ]);
  if (Option.isNone(scan) || !scan.value.result) {
    return yield* Effect.fail(new Error('The codebase review is not ready yet.'));
  }
  if (Option.isNone(profile) || profile.value.state !== 'connected') {
    return yield* Effect.fail(new Error('Sign in before requesting agent prioritization.'));
  }
  const startedAt = yield* DateTime.nowAsDate.pipe(
    Effect.map(date => date.toISOString()),
  );
  yield* agentStore.updateReview(
    item.ownerId,
    new AgentPriorityReview({
      ...item.review,
      status: 'running',
      updatedAt: startedAt,
    }),
  );
  const brief = prioritizationBrief(scan.value);
  if (!brief) {
    return yield* Effect.fail(new Error('The codebase review has no priority brief.'));
  }
  const output = yield* runtime.prioritize(item.ownerId, profile.value, brief);
  if (!isValidPriorityOutput(scan.value.result, output)) {
    return yield* Effect.fail(new Error('The provider returned an invalid finding reference.'));
  }
  const completedAt = yield* DateTime.nowAsDate.pipe(
    Effect.map(date => date.toISOString()),
  );
  yield* agentStore.updateReview(
    item.ownerId,
    new AgentPriorityReview({
      ...item.review,
      status: 'completed',
      output,
      updatedAt: completedAt,
    }),
  );
});

export const AgentCoordinatorLive = Layer.effect(
  AgentCoordinator,
  Effect.gen(function* () {
    const store = yield* AgentStore;
    const queue = yield* Queue.dropping<QueuedReview>(16);
    const owned = yield* Ref.make<ReadonlyMap<string, QueuedReview>>(new Map());
    const failStaleReviews = Clock.currentTimeMillis.pipe(
      Effect.flatMap(now =>
        store.failStaleReviews(
          new Date(now - staleReviewAgeMs).toISOString(),
          new Date(now).toISOString(),
        ),
      ),
      Effect.ignore,
    );
    yield* failStaleReviews;
    yield* Effect.forever(
      failStaleReviews.pipe(Effect.delay('1 minute')),
    ).pipe(Effect.forkScoped);
    yield* Effect.addFinalizer(() =>
      Ref.getAndSet(owned, new Map()).pipe(
        Effect.flatMap(current =>
          Effect.forEach(
            current.values(),
            item =>
              DateTime.nowAsDate.pipe(
                Effect.map(date => date.toISOString()),
                Effect.flatMap(updatedAt =>
                  store.failReviewIfActive(
                    item.ownerId,
                    item.review.id,
                    'The priority review was interrupted by a service restart. Retry it.',
                    updatedAt,
                  ),
                ),
                Effect.ignore,
              ),
            { concurrency: 'unbounded', discard: true },
          ),
        ),
      ),
    );
    yield* Effect.forever(
      Queue.take(queue).pipe(
        Effect.flatMap(item =>
          performReview(item).pipe(
            Effect.catchCause(cause =>
              DateTime.nowAsDate.pipe(
                Effect.map(date => date.toISOString()),
                Effect.flatMap(updatedAt =>
                  store.failReviewIfActive(
                    item.ownerId,
                    item.review.id,
                    boundedDiagnostic(Cause.pretty(cause), 360),
                    updatedAt,
                  ),
                ),
                Effect.ignore,
              ),
            ),
            Effect.ensuring(
              Ref.update(owned, current => {
                const updated = new Map(current);
                updated.delete(item.review.id);
                return updated;
              }),
            ),
          ),
        ),
      ),
    ).pipe(Effect.forkScoped);
    return AgentCoordinator.of({
      enqueue: (ownerId, review) =>
        Effect.uninterruptible(
          Ref.update(owned, current =>
            new Map(current).set(review.id, { ownerId, review }),
          ).pipe(
            Effect.andThen(Queue.offer(queue, { ownerId, review })),
            Effect.flatMap(accepted =>
              accepted
                ? Effect.void
                : Ref.update(owned, current => {
                    const updated = new Map(current);
                    updated.delete(review.id);
                    return updated;
                  }).pipe(
                    Effect.andThen(
                      DateTime.nowAsDate.pipe(
                        Effect.map(date => date.toISOString()),
                        Effect.flatMap(updatedAt =>
                          store.failReviewIfActive(
                            ownerId,
                            review.id,
                            'The priority review queue is full. Retry when current reviews finish.',
                            updatedAt,
                          ),
                        ),
                        Effect.asVoid,
                        Effect.ignore,
                      ),
                    ),
                  ),
            ),
          ),
        ),
    });
  }),
);
