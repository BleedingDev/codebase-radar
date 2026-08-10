import {
  RegistryProvider,
  useAtomSet,
  useAtomValue,
} from '@effect/atom-react';
import { Machine } from '@typeonce/effect-machine';
import { AtomMachine } from '@typeonce/effect-machine/reactivity';
import { AsyncResult } from 'effect/unstable/reactivity';
import { Effect, Schema } from 'effect';
import { useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import {
  AgentLoginChallenge,
  AgentPriorityReview,
  AgentProfile,
  AgentProvider,
  ScanRecord,
  ScanResult,
} from '../shared/domain';
import { RadarClient } from './radar-client';

const Profiles = Schema.Array(AgentProfile);

const State = Schema.TaggedUnion({
  Loading: { scanId: Schema.String },
  Ready: { scanId: Schema.String, profiles: Profiles },
  Connecting: {
    scanId: Schema.String,
    profiles: Profiles,
    provider: AgentProvider,
  },
  LoginWaiting: {
    scanId: Schema.String,
    profiles: Profiles,
    challenge: AgentLoginChallenge,
  },
  LoginPolling: {
    scanId: Schema.String,
    profiles: Profiles,
    challenge: AgentLoginChallenge,
  },
  LoginSubmitting: {
    scanId: Schema.String,
    profiles: Profiles,
    challenge: AgentLoginChallenge,
    value: Schema.String,
  },
  PriorityStarting: {
    scanId: Schema.String,
    profiles: Profiles,
    profile: AgentProfile,
  },
  ReviewWaiting: {
    scanId: Schema.String,
    profiles: Profiles,
    review: AgentPriorityReview,
  },
  ReviewPolling: {
    scanId: Schema.String,
    profiles: Profiles,
    review: AgentPriorityReview,
  },
  Complete: {
    scanId: Schema.String,
    profiles: Profiles,
    review: AgentPriorityReview,
  },
  Failed: {
    scanId: Schema.String,
    profiles: Profiles,
    message: Schema.String,
  },
});

const Command = Schema.TaggedUnion({
  Connect: { provider: AgentProvider },
  SubmitLogin: { value: Schema.String },
  Prioritize: { profile: AgentProfile },
  Retry: {},
});

const Internal = Schema.TaggedUnion({
  ProfilesLoaded: { profiles: Profiles },
  LoginStarted: { challenge: AgentLoginChallenge },
  LoginPolled: { challenge: AgentLoginChallenge },
  LoginSubmitted: { challenge: AgentLoginChallenge },
  ReviewStarted: { review: AgentPriorityReview },
  ReviewPolled: { review: AgentPriorityReview },
  PollLogin: {},
  PollReview: {},
  RequestFailed: { message: Schema.String },
});

const States = Machine.defineStates(State.cases);

const AgentPriorityMachine = Machine.make({
  id: 'AgentPriority',
  states: States.states,
  events: [
    Command.cases.Connect,
    Command.cases.SubmitLogin,
    Command.cases.Prioritize,
    Command.cases.Retry,
  ],
  internalEvents: [
    Internal.cases.ProfilesLoaded,
    Internal.cases.LoginStarted,
    Internal.cases.LoginPolled,
    Internal.cases.LoginSubmitted,
    Internal.cases.ReviewStarted,
    Internal.cases.ReviewPolled,
    Internal.cases.PollLogin,
    Internal.cases.PollReview,
    Internal.cases.RequestFailed,
  ],
  input: Schema.Struct({ scanId: Schema.String }),
  initial: input => States.initial.Loading.from({ scanId: input.scanId }),
}).handle({
  Loading: {
    invoke: () =>
      Machine.invokeEffect({
        id: 'load-profiles',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.getSession({}).pipe(
              Effect.flatMap(() => client.radar.listAgentProfiles({})),
            ),
          ),
        ),
        onSuccess: response =>
          Internal.cases.ProfilesLoaded.make({ profiles: response.items }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'Your connected accounts could not be loaded. Try again.',
          }),
      }),
    on: {
      ProfilesLoaded: ({ event, state, target }) =>
        target.full.Ready.from({ scanId: state.scanId, profiles: event.profiles }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: [],
          message: event.message,
        }),
    },
  },
  Ready: {
    on: {
      Connect: ({ event, state, target }) =>
        target.full.Connecting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          provider: event.provider,
        }),
      Prioritize: ({ event, state, target }) =>
        target.full.PriorityStarting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
    },
  },
  Connecting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'begin-login',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.createAgentProfile({ payload: { provider: state.provider } }).pipe(
              Effect.flatMap(profile =>
                client.radar.beginAgentLogin({ params: { profileId: profile.id } }),
              ),
            ),
          ),
        ),
        onSuccess: challenge => Internal.cases.LoginStarted.make({ challenge }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'Sign-in could not be started. Try again.',
          }),
      }),
    on: {
      LoginStarted: ({ event, state, target }) =>
        target.full.LoginWaiting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: event.challenge,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
    },
  },
  LoginWaiting: {
    invoke: Machine.after('1200 millis', Internal.cases.PollLogin.make({})),
    on: {
      PollLogin: ({ state, target }) =>
        target.full.LoginPolling.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: state.challenge,
        }),
      SubmitLogin: ({ event, state, target }) =>
        target.full.LoginSubmitting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: state.challenge,
          value: event.value,
        }),
    },
  },
  LoginPolling: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'poll-login',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.pollAgentLogin({
              params: { challengeId: state.challenge.id },
            }),
          ),
        ),
        onSuccess: challenge => Internal.cases.LoginPolled.make({ challenge }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'Sign-in was interrupted. Start it again.',
          }),
      }),
    on: {
      LoginPolled: ({ event, state, target }) => {
        if (event.challenge.status === 'completed') {
          return target.full.Loading.from({ scanId: state.scanId });
        }
        if (event.challenge.status === 'failed') {
          return target.full.Failed.from({
            scanId: state.scanId,
            profiles: state.profiles,
            message: event.challenge.diagnostic ?? 'Sign-in failed. Start it again.',
          });
        }
        return target.full.LoginWaiting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: event.challenge,
        });
      },
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
    },
  },
  LoginSubmitting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'submit-login',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.submitAgentLoginInput({
              params: { challengeId: state.challenge.id },
              payload: { value: state.value },
            }),
          ),
        ),
        onSuccess: challenge => Internal.cases.LoginSubmitted.make({ challenge }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'That code was not accepted. Try again.',
          }),
      }),
    on: {
      LoginSubmitted: ({ event, state, target }) =>
        target.full.LoginWaiting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: event.challenge,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
    },
  },
  PriorityStarting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'start-review',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.createPriorityReview({
              params: { scanId: state.scanId },
              payload: { profileId: state.profile.id },
            }),
          ),
        ),
        onSuccess: review => Internal.cases.ReviewStarted.make({ review }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'The priority list could not be started. Try again.',
          }),
      }),
    on: {
      ReviewStarted: ({ event, state, target }) =>
        target.full.ReviewWaiting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          review: event.review,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
    },
  },
  ReviewWaiting: {
    invoke: Machine.after('1500 millis', Internal.cases.PollReview.make({})),
    on: {
      PollReview: ({ state, target }) =>
        target.full.ReviewPolling.from({
          scanId: state.scanId,
          profiles: state.profiles,
          review: state.review,
        }),
    },
  },
  ReviewPolling: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'poll-review',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.getPriorityReview({
              params: { reviewId: state.review.id },
            }),
          ),
        ),
        onSuccess: review => Internal.cases.ReviewPolled.make({ review }),
        onFailure: () =>
          Internal.cases.RequestFailed.make({
            message: 'The priority list could not be refreshed. Try again.',
          }),
      }),
    on: {
      ReviewPolled: ({ event, state, target }) => {
        if (event.review.status === 'completed') {
          return target.full.Complete.from({
            scanId: state.scanId,
            profiles: state.profiles,
            review: event.review,
          });
        }
        if (event.review.status === 'failed') {
          return target.full.Failed.from({
            scanId: state.scanId,
            profiles: state.profiles,
            message:
              event.review.diagnostic ?? 'The priority list could not be completed.',
          });
        }
        return target.full.ReviewWaiting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          review: event.review,
        });
      },
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
    },
  },
  Complete: {
    on: {
      Connect: ({ event, state, target }) =>
        target.full.Connecting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          provider: event.provider,
        }),
      Prioritize: ({ event, state, target }) =>
        target.full.PriorityStarting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
    },
  },
  Failed: {
    on: {
      Retry: ({ state, target }) =>
        target.full.Loading.from({ scanId: state.scanId }),
      Connect: ({ event, state, target }) =>
        target.full.Connecting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          provider: event.provider,
        }),
      Prioritize: ({ event, state, target }) =>
        target.full.PriorityStarting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
    },
  },
});

interface AgentPriorityProps {
  readonly scan: ScanRecord;
  readonly result: ScanResult;
}

export function AgentPriority(props: AgentPriorityProps) {
  return (
    <RegistryProvider>
      <AgentPriorityContent {...props} />
    </RegistryProvider>
  );
}

function AgentPriorityContent({ scan, result }: AgentPriorityProps) {
  const [loginInput, setLoginInput] = useState('');
  const machineAtom = useMemo(
    () => AtomMachine.make(AgentPriorityMachine, { scanId: scan.id }),
    [scan.id],
  );
  const machineResult = useAtomValue(machineAtom.result);
  const send = useAtomSet(machineAtom.send);

  if (!AsyncResult.isSuccess(machineResult)) {
    return <p className="priority-progress">Preparing account options…</p>;
  }

  const snapshot = machineResult.value;
  const profiles =
    'profiles' in snapshot.value &&
    snapshot.path !== 'Connecting' &&
    snapshot.path !== 'PriorityStarting'
      ? snapshot.value.profiles
      : [];
  const challenge =
    'challenge' in snapshot.value ? snapshot.value.challenge : undefined;
  const review = 'review' in snapshot.value ? snapshot.value.review : undefined;
  const complete = snapshot.path === 'Complete' ? snapshot.value : undefined;
  const failed = snapshot.path === 'Failed' ? snapshot.value : undefined;
  const busy =
    snapshot.path === 'Loading' ||
    snapshot.path === 'Connecting' ||
    snapshot.path === 'LoginPolling' ||
    snapshot.path === 'LoginSubmitting' ||
    snapshot.path === 'PriorityStarting' ||
    snapshot.path === 'ReviewWaiting' ||
    snapshot.path === 'ReviewPolling';
  const codex = profiles.find(profile => profile.provider === 'codex');
  const claude = profiles.find(profile => profile.provider === 'claude');

  const submitLogin = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    send(Command.cases.SubmitLogin.make({ value: loginInput }));
    setLoginInput('');
  };

  return (
    <section className="account-priority">
      <div className="account-priority-head">
        <div>
          <p className="eyebrow">A second opinion</p>
          <h3>Prioritize with your account.</h3>
        </div>
        <p>Use your own Codex or Claude account to rank this review.</p>
      </div>

      {complete?.review.output ? (
        <div className="priority-answer">
          <div className="priority-answer-title">
            <span>{complete.review.provider === 'codex' ? 'Codex' : 'Claude'}</span>
            <p>{complete.review.output.summary}</p>
          </div>
          <ol>
            {complete.review.output.orderedItems.map(item => {
              const finding = result.findings.find(candidate => candidate.id === item.findingId);
              return (
                <li key={item.findingId}>
                  <span>{item.action}</span>
                  <div>
                    <h4>{finding?.title ?? 'Selected finding'}</h4>
                    <p>{item.reason}</p>
                    <b>{item.nextMove}</b>
                  </div>
                </li>
              );
            })}
          </ol>
          <details>
            <summary>What was deliberately left out</summary>
            <p>{complete.review.output.notNowFindingIds.length} findings were held back.</p>
            {complete.review.output.unsupportedClaims.map(claim => (
              <p key={claim}>{claim}</p>
            ))}
          </details>
        </div>
      ) : (
        <>
          <div className="provider-actions">
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                codex?.state === 'connected'
                  ? send(Command.cases.Prioritize.make({ profile: codex }))
                  : send(Command.cases.Connect.make({ provider: 'codex' }))
              }
            >
              <span>Codex</span>
              <b>{codex?.state === 'connected' ? 'PRIORITIZE' : 'CONNECT'}</b>
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                claude?.state === 'connected'
                  ? send(Command.cases.Prioritize.make({ profile: claude }))
                  : send(Command.cases.Connect.make({ provider: 'claude' }))
              }
            >
              <span>Claude</span>
              <b>{claude?.state === 'connected' ? 'PRIORITIZE' : 'CONNECT'}</b>
            </button>
          </div>

          {challenge ? (
            <div className="login-challenge">
              {challenge.verificationUrl ? (
                <a href={challenge.verificationUrl} target="_blank" rel="noreferrer">
                  Open the secure sign-in page ↗
                </a>
              ) : (
                <p>Preparing the secure sign-in page…</p>
              )}
              {challenge.userCode ? (
                <p className="login-code">
                  One-time code <strong>{challenge.userCode}</strong>
                </p>
              ) : null}
              {challenge.prompt ? (
                <form onSubmit={submitLogin}>
                  <label htmlFor="provider-login-code">{challenge.prompt}</label>
                  <div>
                    <input
                      id="provider-login-code"
                      value={loginInput}
                      onChange={event => setLoginInput(event.currentTarget.value)}
                      minLength={8}
                      maxLength={2048}
                      required
                    />
                    <button type="submit">CONTINUE</button>
                  </div>
                </form>
              ) : null}
            </div>
          ) : null}

          {busy ? <p className="priority-progress">Working…</p> : null}
          {failed ? (
            <div>
              <p className="error-note">{failed.message}</p>
              <button
                type="button"
                disabled={busy}
                onClick={() => send(Command.cases.Retry.make({}))}
              >
                TRY AGAIN
              </button>
            </div>
          ) : null}
          {review?.status === 'failed' ? (
            <p className="error-note">
              {review.diagnostic ?? 'The second opinion could not be completed.'}
            </p>
          ) : null}
        </>
      )}
    </section>
  );
}
