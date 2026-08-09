import {
  Cause,
  Context,
  DateTime,
  Effect,
  Layer,
  Option,
  Queue,
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
    const queue = yield* Queue.bounded<QueuedReview>(16);
    yield* Effect.forever(
      Queue.take(queue).pipe(
        Effect.flatMap(item =>
          performReview(item).pipe(
            Effect.catchCause(cause =>
              DateTime.nowAsDate.pipe(
                Effect.map(date => date.toISOString()),
                Effect.flatMap(updatedAt =>
                  store.updateReview(
                    item.ownerId,
                    new AgentPriorityReview({
                      ...item.review,
                      status: 'failed',
                      diagnostic: boundedDiagnostic(Cause.pretty(cause), 360),
                      updatedAt,
                    }),
                  ),
                ),
                Effect.ignore,
              ),
            ),
          ),
        ),
      ),
    ).pipe(Effect.forkScoped);
    return AgentCoordinator.of({
      enqueue: (ownerId, review) =>
        Queue.offer(queue, { ownerId, review }).pipe(Effect.asVoid),
    });
  }),
);
