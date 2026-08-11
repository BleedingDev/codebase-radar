import {
  Clock,
  Context,
  DateTime,
  Effect,
  Fiber,
  Layer,
  Option,
  Ref,
  Schema,
} from 'effect';
import {
  AgentPriorityReview,
  AgentProfile,
  SuccessfulScanResult,
} from '../shared/domain';
import { AgentRuntime } from './agent-runtime';
import { AgentReviewLease, AgentStore, QueuedAgentReview } from './agent-store';
import { AgentScanVisibilityGate } from './agent-visibility-gate';
import {
  aggregateAgentPriorityTournament,
  buildAgentPriorityChunkRequests,
  buildAgentPriorityMergeRoundRequests,
  canonicalFindingInventoryDigest,
  canonicalResultDigest,
  isExactCanonicalSource,
  AgentPriorityMergeOutput,
  agentPriorityMergeRoundCount,
  legacyPriorityOutput,
  retryAgentPriorityChunk,
  retryAgentPriorityMerge,
} from './agent-priority-overlay';
import { requireCompleteScanResult } from './mcp-read-model';
import { RadarStore } from './store';

export const agentReviewLeaseMs = 5 * 60_000;
export const agentReviewHeartbeatMs = 60_000;
export const agentReviewDeadlineMs = 12 * 60 * 60_000;
export const agentReviewGlobalConcurrency = 4;
export const agentReviewPerOwnerQueueLimit = 4;
export const agentReviewGlobalQueueLimit = 32;

export class AgentCoordinatorError extends Schema.TaggedErrorClass<AgentCoordinatorError>()(
  'AgentCoordinatorError',
  { message: Schema.String },
) {}

export interface QueuedReview {
  readonly ownerId: string;
  readonly review: AgentPriorityReview;
}

interface SchedulerState {
  readonly pending: ReadonlyMap<string, ReadonlyArray<QueuedReview>>;
  readonly ownerOrder: ReadonlyArray<string>;
  readonly active: ReadonlyMap<string, QueuedReview>;
  readonly activeOwners: ReadonlySet<string>;
  readonly cancelled: ReadonlySet<string>;
}

export class AgentCoordinator extends Context.Service<AgentCoordinator, {
  readonly enqueue: (
    ownerId: string,
    review: AgentPriorityReview,
  ) => Effect.Effect<
    void,
    AgentCoordinatorError,
    AgentStore | RadarStore | AgentRuntime | AgentScanVisibilityGate
  >;
  readonly cancel: (
    ownerId: string,
    reviewId: string,
  ) => Effect.Effect<
    void,
    AgentCoordinatorError,
    AgentStore | RadarStore | AgentRuntime | AgentScanVisibilityGate
  >;
}>()('AgentCoordinator') {}

const now = Clock.currentTimeMillis.pipe(
  Effect.map(value => ({
    current: new Date(value).toISOString(),
    lease: new Date(value + agentReviewLeaseMs).toISOString(),
    deadline: new Date(value + agentReviewDeadlineMs).toISOString(),
  })),
);

const coordinatorError = (message: string) => new AgentCoordinatorError({ message });

const renewCurrentReviewLease = Effect.fn('renewCurrentAgentReviewLease')(function* (
  ownerId: string,
  reviewId: string,
  leaseRef: Ref.Ref<AgentReviewLease>,
) {
  const store = yield* AgentStore;
  const lease = yield* Ref.get(leaseRef);
  const currentTime = yield* Clock.currentTimeMillis;
  const currentTimestamp = new Date(currentTime).toISOString();
  const deadline = Date.parse(lease.deadlineAt);
  if (!Number.isFinite(deadline) || currentTime >= deadline) {
    return yield* coordinatorError('Priority review reached its review-wide deadline.');
  }
  const requestedExpiry = new Date(
    Math.min(currentTime + agentReviewLeaseMs, deadline),
  ).toISOString();
  const renewed = yield* store.renewReviewLease(
    ownerId,
    reviewId,
    lease,
    currentTimestamp,
    requestedExpiry,
  );
  yield* Ref.update(leaseRef, current =>
    renewed.expiresAt > current.expiresAt ? renewed : current,
  );
  return renewed;
});

const isCancelled = (
  state: Ref.Ref<SchedulerState>,
  reviewId: string,
) =>
  Ref.get(state).pipe(Effect.map(current => current.cancelled.has(reviewId)));

const requireNotCancelled = (
  state: Ref.Ref<SchedulerState>,
  reviewId: string,
) =>
  isCancelled(state, reviewId).pipe(
    Effect.flatMap(cancelled =>
      cancelled
        ? Effect.fail(coordinatorError('Priority review was cancelled.'))
        : Effect.void,
    ),
  );

export const verifyBoundAgentReviewScan = Effect.fn('verifyAgentReviewScanGrant')(function* (
  item: QueuedReview,
) {
  const store = yield* AgentStore;
  const radarStore = yield* RadarStore;
  const visibilityGate = yield* AgentScanVisibilityGate;
  const grant = yield* store.getReviewAccessGrant(item.ownerId, item.review.id);
  if (Option.isNone(grant)) {
    return yield* coordinatorError('The priority review has no valid scan access grant.');
  }
  if (
    grant.value.reviewOwnerId !== item.ownerId ||
    grant.value.scanId !== item.review.scanId
  ) {
    return yield* coordinatorError('The priority review scan access grant was rejected.');
  }
  const scan = yield* radarStore.getScan(item.review.scanId).pipe(
    Effect.mapError(() => coordinatorError('The codebase review is unavailable.')),
  );
  if (Option.isNone(scan) || scan.value.result === undefined) {
    return yield* coordinatorError('The codebase review is not ready yet.');
  }
  const result = yield* requireCompleteScanResult(scan.value.result).pipe(
    Effect.mapError(() => coordinatorError('The codebase review is not eligible for agent prioritization.')),
  );
  if (
    scan.value.id !== grant.value.scanId ||
    result.scanId !== grant.value.scanId ||
    canonicalResultDigest(result) !== grant.value.canonicalResultDigest ||
    !isExactCanonicalSource(result.source, grant.value.source) ||
    canonicalFindingInventoryDigest(result) !== grant.value.findingInventoryDigest
  ) {
    return yield* coordinatorError('The immutable scan bound to this review changed.');
  }
  yield* visibilityGate.verify(grant.value).pipe(
    Effect.mapError(() =>
      coordinatorError('The priority review scan is no longer publicly available.'),
    ),
  );
  return result;
});

const requireConnectedProfile = Effect.fn('requireAgentReviewProfile')(function* (
  item: QueuedReview,
) {
  const store = yield* AgentStore;
  const profile = yield* store.getProfile(item.ownerId, item.review.profileId);
  if (Option.isNone(profile) || profile.value.state !== 'connected') {
    return yield* coordinatorError('Sign in before requesting agent prioritization.');
  }
  if (profile.value.provider !== item.review.provider) {
    return yield* coordinatorError('The connected provider does not match this priority review.');
  }
  return profile.value;
});

const runPriorityProtocol = Effect.fn('runCompleteAgentPriorityProtocol')(function* (
  item: QueuedReview,
  profile: AgentProfile,
  leaseRef: Ref.Ref<AgentReviewLease>,
  scheduler: Ref.Ref<SchedulerState>,
  result: SuccessfulScanResult,
) {
  const runtime = yield* AgentRuntime;
  const immutableDigest = canonicalResultDigest(result);
  const revalidateBeforeProvider = () =>
    verifyBoundAgentReviewScan(item).pipe(
      Effect.flatMap(current =>
        canonicalResultDigest(current) === immutableDigest
          ? Effect.void
          : Effect.fail(
              coordinatorError('The immutable scan bound to this review changed.'),
            ),
      ),
    );
  const requests = yield* buildAgentPriorityChunkRequests(result).pipe(
    Effect.mapError(() => coordinatorError('The immutable scan cannot be prepared for agent review.')),
  );
  const outputs = yield* Effect.forEach(
    requests,
    request =>
      requireNotCancelled(scheduler, item.review.id).pipe(
        Effect.andThen(renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef)),
        Effect.andThen(
          retryAgentPriorityChunk(() =>
            requireNotCancelled(scheduler, item.review.id).pipe(
              Effect.andThen(
                renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef),
              ),
              Effect.andThen(revalidateBeforeProvider()),
              Effect.andThen(runtime.prioritizeChunk(item.ownerId, profile, request)),
            ),
          ).pipe(
            Effect.tap(() =>
              renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef),
            ),
          ),
        ),
      ),
    { concurrency: 1 },
  ).pipe(
    Effect.mapError(() => coordinatorError('The provider could not complete the priority protocol.')),
  );
  const mergeRounds = new Array<ReadonlyArray<AgentPriorityMergeOutput>>();
  for (let roundIndex = 0; roundIndex < agentPriorityMergeRoundCount; roundIndex += 1) {
    yield* requireNotCancelled(scheduler, item.review.id);
    const mergeRequests = yield* buildAgentPriorityMergeRoundRequests(
      result,
      requests,
      outputs,
      mergeRounds,
      roundIndex,
    ).pipe(
      Effect.mapError(() => coordinatorError('The priority tournament merge is invalid.')),
    );
    const mergeOutputs = yield* Effect.forEach(
      mergeRequests,
      request =>
        requireNotCancelled(scheduler, item.review.id).pipe(
          Effect.andThen(renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef)),
          Effect.andThen(
            retryAgentPriorityMerge(() =>
              requireNotCancelled(scheduler, item.review.id).pipe(
                Effect.andThen(
                  renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef),
                ),
                Effect.andThen(revalidateBeforeProvider()),
                Effect.andThen(runtime.prioritizeMerge(item.ownerId, profile, request)),
              ),
            ).pipe(
              Effect.tap(() =>
                renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef),
              ),
            ),
          ),
        ),
      { concurrency: 1 },
    ).pipe(
      Effect.mapError(() => coordinatorError('The provider could not complete the priority tournament.')),
    );
    mergeRounds.push(mergeOutputs);
  }
  return yield* aggregateAgentPriorityTournament(
    result,
    profile.provider,
    requests,
    outputs,
    mergeRounds,
  ).pipe(
    Effect.mapError(() => coordinatorError('The provider returned an invalid complete priority overlay.')),
  );
});

const performReview = Effect.fn('performAgentPriorityReview')(function* (
  item: QueuedReview,
  scheduler: Ref.Ref<SchedulerState>,
) {
  const store = yield* AgentStore;
  const times = yield* now;
  const lease = yield* store.claimReview(
    item.ownerId,
    item.review.id,
    times.deadline,
    times.lease,
  ).pipe(Effect.mapError(() => coordinatorError('Priority review is no longer queued.')));
  const leaseRef = yield* Ref.make(lease);
  const protocol = Effect.gen(function* () {
    yield* requireNotCancelled(scheduler, item.review.id);
    const result = yield* verifyBoundAgentReviewScan(item);
    const profile = yield* requireConnectedProfile(item);
    yield* requireNotCancelled(scheduler, item.review.id);
    const overlay = yield* runPriorityProtocol(
      item,
      profile,
      leaseRef,
      scheduler,
      result,
    );
    const presentation = yield* legacyPriorityOutput(overlay).pipe(
      Effect.mapError(() => coordinatorError('The priority overlay cannot be presented.')),
    );
    const completedAt = yield* DateTime.nowAsDate.pipe(
      Effect.map(value => value.toISOString()),
    );
    const completedLease = yield* Ref.get(leaseRef);
    yield* store.completeReviewWithOverlay(
      item.ownerId,
      item.review.id,
      completedLease,
      overlay,
      presentation,
      completedAt,
    ).pipe(Effect.mapError(() => coordinatorError('Priority review completion was rejected.')));
  });
  const heartbeat = Effect.forever(
    Effect.sleep(agentReviewHeartbeatMs).pipe(
      Effect.andThen(requireNotCancelled(scheduler, item.review.id)),
      Effect.andThen(renewCurrentReviewLease(item.ownerId, item.review.id, leaseRef)),
      Effect.asVoid,
    ),
  );
  return yield* Effect.raceFirst(protocol, heartbeat).pipe(
    Effect.mapError(() => coordinatorError('Priority review did not complete.')),
  );
});

const initialSchedulerState = (): SchedulerState => ({
  pending: new Map(),
  ownerOrder: [],
  active: new Map(),
  activeOwners: new Set(),
  cancelled: new Set(),
});

const pendingCount = (state: SchedulerState) =>
  [...state.pending.values()].reduce((count, items) => count + items.length, 0);

export const selectFairOwner = (
  ownerOrder: ReadonlyArray<string>,
  pendingCounts: ReadonlyMap<string, number>,
  activeOwners: ReadonlySet<string>,
) => {
  for (const ownerId of ownerOrder) {
    if ((pendingCounts.get(ownerId) ?? 0) > 0 && !activeOwners.has(ownerId)) {
      return ownerId;
    }
  }
  return undefined;
};

const dequeueFair = (state: Ref.Ref<SchedulerState>) =>
  Ref.modify(state, current => {
    if (current.active.size >= agentReviewGlobalConcurrency) {
      return [Option.none<QueuedReview>(), current];
    }
    const pending = new Map(current.pending);
    const ownerOrder = current.ownerOrder.filter(ownerId => {
      const items = pending.get(ownerId);
      return items !== undefined && items.length > 0;
    });
    const ownerId = selectFairOwner(
      ownerOrder,
      new Map(ownerOrder.map(owner => [owner, pending.get(owner)?.length ?? 0])),
      current.activeOwners,
    );
    if (ownerId === undefined) return [Option.none<QueuedReview>(), current];
    const items = pending.get(ownerId);
    const item = items?.[0];
    if (items === undefined || item === undefined) {
      return [Option.none<QueuedReview>(), current];
    }
    const rest = items.slice(1);
    if (rest.length === 0) {
      pending.delete(ownerId);
    } else {
      pending.set(ownerId, rest);
    }
    const nextOwnerOrder = ownerOrder.filter(owner => owner !== ownerId);
    if (rest.length > 0) nextOwnerOrder.push(ownerId);
    return [
      Option.some(item),
      {
        pending,
        ownerOrder: nextOwnerOrder,
        active: new Map(current.active).set(item.review.id, item),
        activeOwners: new Set(current.activeOwners).add(ownerId),
        cancelled: current.cancelled,
      },
    ];
  });

const releaseReview = (
  scheduler: Ref.Ref<SchedulerState>,
  fibers: Ref.Ref<ReadonlyMap<string, Fiber.Fiber<void>>>,
  item: QueuedReview,
) =>
  Ref.update(scheduler, current => {
    const active = new Map(current.active);
    active.delete(item.review.id);
    const activeOwners = new Set(current.activeOwners);
    activeOwners.delete(item.ownerId);
    const cancelled = new Set(current.cancelled);
    cancelled.delete(item.review.id);
    return { ...current, active, activeOwners, cancelled };
  }).pipe(
    Effect.andThen(
      Ref.update(fibers, current => {
        const updated = new Map(current);
        updated.delete(item.review.id);
        return updated;
      }),
    ),
  );

const enqueueRecoveredReview = (
  scheduler: Ref.Ref<SchedulerState>,
  recovered: QueuedAgentReview,
) =>
  Ref.update(scheduler, current => {
    const review = recovered.review;
    const ownerId = recovered.ownerId;
    const existing = current.active.has(review.id) ||
      [...current.pending.values()].some(items =>
        items.some(item => item.review.id === review.id),
      );
    if (existing || pendingCount(current) >= agentReviewGlobalQueueLimit) {
      return current;
    }
    const queued = current.pending.get(ownerId) ?? [];
    const pending = new Map(current.pending).set(ownerId, [
      ...queued,
      { ownerId, review },
    ]);
    const ownerOrder = current.ownerOrder.includes(ownerId)
      ? current.ownerOrder
      : [...current.ownerOrder, ownerId];
    return { ...current, pending, ownerOrder };
  });

export const AgentCoordinatorLive = Layer.effect(
  AgentCoordinator,
  Effect.gen(function* () {
    const store = yield* AgentStore;
    const scheduler = yield* Ref.make<SchedulerState>(initialSchedulerState());
    const fibers = yield* Ref.make<ReadonlyMap<string, Fiber.Fiber<void>>>(new Map());

    const dispatch: () => Effect.Effect<
      void,
      never,
      AgentStore | RadarStore | AgentRuntime | AgentScanVisibilityGate
    > = () =>
      Effect.gen(function* () {
        while (true) {
          const item = yield* dequeueFair(scheduler);
          if (Option.isNone(item)) return;
          const worker = performReview(item.value, scheduler).pipe(
            Effect.catchCause(() =>
              DateTime.nowAsDate.pipe(
                Effect.map(value => value.toISOString()),
                Effect.flatMap(failedAt =>
                  store.failReviewIfActive(
                    item.value.ownerId,
                    item.value.review.id,
                    failedAt,
                  ),
                ),
                Effect.ignore,
              ),
            ),
            Effect.ensuring(
              releaseReview(scheduler, fibers, item.value).pipe(
                Effect.andThen(dispatch()),
              ),
            ),
            Effect.asVoid,
          );
          const fiber = yield* Effect.forkDetach(worker);
          yield* Ref.update(fibers, current =>
            new Map(current).set(item.value.review.id, fiber),
          );
          const cancelled = yield* isCancelled(scheduler, item.value.review.id);
          if (cancelled) yield* Fiber.interrupt(fiber).pipe(Effect.asVoid);
        }
      });

    const failExpiredReviews = DateTime.nowAsDate.pipe(
      Effect.map(value => value.toISOString()),
      Effect.flatMap(current => store.failExpiredReviews(current, current)),
      Effect.ignore,
    );
    yield* failExpiredReviews;
    const expireReviews = Effect.forever(
      Effect.sleep(agentReviewHeartbeatMs).pipe(
        Effect.andThen(failExpiredReviews),
      ),
    );
    yield* expireReviews.pipe(Effect.forkScoped({ startImmediately: true }));
    const recoverQueuedReviews = Effect.forever(
      store.listQueuedReviews().pipe(
        Effect.flatMap(recovered =>
          Effect.forEach(
            recovered,
            item => enqueueRecoveredReview(scheduler, item),
            { concurrency: 1, discard: true },
          ),
        ),
        Effect.andThen(dispatch()),
        Effect.catchCause(() => Effect.void),
        Effect.andThen(Effect.sleep(agentReviewHeartbeatMs)),
      ),
    );
    yield* recoverQueuedReviews.pipe(Effect.forkScoped({ startImmediately: true }));
    yield* Effect.addFinalizer(() =>
      Ref.get(fibers).pipe(
        Effect.flatMap(active =>
          Effect.forEach(
            active.values(),
            fiber => Fiber.interrupt(fiber).pipe(Effect.asVoid),
            { concurrency: 'unbounded', discard: true },
          ),
        ),
        Effect.andThen(
          Ref.get(scheduler).pipe(
            Effect.flatMap(current =>
              DateTime.nowAsDate.pipe(
                Effect.map(value => value.toISOString()),
                Effect.flatMap(failedAt =>
                  Effect.forEach(
                    current.active.values(),
                    item =>
                      store.failReviewIfActive(
                        item.ownerId,
                        item.review.id,
                        failedAt,
                      ),
                    { concurrency: 'unbounded', discard: true },
                  ),
                ),
              ),
            ),
          ),
        ),
        Effect.ignore,
      ),
    );

    return AgentCoordinator.of({
      enqueue: (ownerId, review) =>
        Ref.modify(scheduler, current => {
          const existing = current.active.has(review.id) ||
            [...current.pending.values()].some(items =>
              items.some(item => item.review.id === review.id),
            );
          const queued = current.pending.get(ownerId) ?? [];
          if (existing) {
            return ['duplicate', current];
          }
          if (
            queued.length >= agentReviewPerOwnerQueueLimit ||
            pendingCount(current) >= agentReviewGlobalQueueLimit
          ) {
            return ['capacity', current];
          }
          const pending = new Map(current.pending).set(ownerId, [
            ...queued,
            { ownerId, review },
          ]);
          const ownerOrder = current.ownerOrder.includes(ownerId)
            ? current.ownerOrder
            : [...current.ownerOrder, ownerId];
          return ['accepted', { ...current, pending, ownerOrder }];
        }).pipe(
          Effect.flatMap(decision =>
            decision === 'accepted'
              ? dispatch()
              : decision === 'duplicate'
                ? Effect.fail(
                    coordinatorError('This priority review is already queued or running.'),
                  )
                : DateTime.nowAsDate.pipe(
                  Effect.map(value => value.toISOString()),
                  Effect.flatMap(failedAt =>
                    store.failReviewIfActive(ownerId, review.id, failedAt).pipe(
                      Effect.mapError(() =>
                        coordinatorError('The priority review could not be queued.'),
                      ),
                    ),
                  ),
                  Effect.andThen(
                    Effect.fail(
                      coordinatorError('The priority review queue is at capacity. Retry later.'),
                    ),
                  ),
                ),
          ),
        ),
      cancel: (ownerId, reviewId) =>
        Ref.modify(scheduler, current => {
          const pending = new Map<string, ReadonlyArray<QueuedReview>>();
          for (const [owner, items] of current.pending) {
            const rest = owner === ownerId
              ? items.filter(item => item.review.id !== reviewId)
              : items;
            if (rest.length > 0) pending.set(owner, rest);
          }
          const ownerOrder = current.ownerOrder.filter(owner => pending.has(owner));
          const cancelled = new Set(current.cancelled);
          const activeItem = current.active.get(reviewId);
          const active = activeItem !== undefined && activeItem.ownerId === ownerId;
          if (active) cancelled.add(reviewId);
          return [
            active,
            { ...current, pending, ownerOrder, cancelled },
          ];
        }).pipe(
          Effect.flatMap(active =>
            DateTime.nowAsDate.pipe(
              Effect.map(value => value.toISOString()),
              Effect.flatMap(cancelledAt =>
                store.cancelReview(ownerId, reviewId, cancelledAt),
              ),
              Effect.andThen(
                active
                  ? Ref.get(fibers).pipe(
                      Effect.flatMap(current => {
                        const fiber = current.get(reviewId);
                        return fiber === undefined
                          ? Effect.void
                          : Fiber.interrupt(fiber).pipe(Effect.asVoid);
                      }),
                    )
                  : Effect.void,
              ),
              Effect.andThen(dispatch()),
            ),
          ),
          Effect.mapError(() => coordinatorError('Priority review cancellation failed.')),
        ),
    });
  }),
);
