import { Machine } from '@typeonce/effect-machine';
import { Effect, Schema } from 'effect';
import { describe, expect, it } from 'vitest';

const CompatibilityState = Schema.TaggedUnion({
  Idle: {},
  Running: {},
});

const CompatibilityEvent = Schema.TaggedUnion({
  Start: {},
});

const CompatibilityStates = Machine.defineStates(CompatibilityState.cases);

const CompatibilityMachine = Machine.make({
  id: 'EffectMachineCompatibility',
  states: CompatibilityStates.states,
  events: [CompatibilityEvent.cases.Start],
  initial: () => CompatibilityStates.initial.Idle.from(),
}).handle({
  Idle: {
    on: {
      Start: ({ target }) => target.full.Running.from(),
    },
  },
  Running: {},
});

describe('effect-machine compatibility', () => {
  it('plans a transition on the supported Effect runtime', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const initial = yield* Machine.planInitial(CompatibilityMachine);
        expect(initial.state.path).toBe('Idle');

        const next = yield* Machine.plan(
          CompatibilityMachine,
          initial.state,
          CompatibilityEvent.cases.Start.make({}),
        );
        expect(next.next.path).toBe('Running');
      }),
    ));
});
