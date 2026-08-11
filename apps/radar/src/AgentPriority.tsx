import {
  RegistryProvider,
  useAtomSet,
  useAtomValue,
} from '@effect/atom-react';
import { Machine } from '@typeonce/effect-machine';
import { AtomMachine } from '@typeonce/effect-machine/reactivity';
import { AsyncResult } from 'effect/unstable/reactivity';
import { Effect, Schema } from 'effect';
import React, { useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import {
  AgentLoginChallenge,
  AgentPriorityOutput,
  AgentPriorityReview,
  AgentProfile,
  AgentProvider,
  isAgentLoginVerificationUrl,
  ScanRecord,
  ScanResult,
} from '../shared/domain';
import { RadarClient } from './radar-client';

const Profiles = Schema.Array(AgentProfile);

const providerLabel = (provider: typeof AgentProvider.Type) =>
  provider === 'codex' ? 'Codex' : 'Claude';

const profileStateLabel = (profile: AgentProfile | undefined) => {
  if (!profile) return 'Not connected';

  switch (profile.state) {
    case 'connected':
      return 'Connected';
    case 'connecting':
      return 'Sign-in in progress';
    case 'failed':
      return 'Needs attention';
    case 'deleting':
      return 'Disconnecting';
    case 'disconnected':
      return 'Disconnected';
  }
};

const requestFailureMessage = (error: object, fallback: string) =>
  typeof error === 'object' &&
  error !== null &&
  'message' in error &&
  typeof error.message === 'string' &&
  error.message.trim().length > 0
    ? error.message
    : fallback;

const replaceProfile = (
  profiles: ReadonlyArray<AgentProfile>,
  profile: AgentProfile,
) => profiles.map(current => (current.id === profile.id ? profile : current));

const upsertProfile = (
  profiles: ReadonlyArray<AgentProfile>,
  profile: AgentProfile,
) =>
  profiles.some(current => current.id === profile.id)
    ? replaceProfile(profiles, profile)
    : [...profiles, profile];

const profileAwaitingLogin = (profile: AgentProfile) =>
  new AgentProfile({
    id: profile.id,
    provider: profile.provider,
    state: 'connecting',
    accountLabel: profile.accountLabel,
    diagnostic: profile.diagnostic,
    createdAt: profile.createdAt,
    updatedAt: profile.updatedAt,
  });

const agentPriorityUnavailableMessage =
  'Agent Priority is unavailable in this deployment because no secure, attested provider runner is active.';

const isAgentPriorityUnavailable = (
  error: object,
): error is {
  readonly _tag: 'CapabilityUnavailable';
  readonly capability: 'agent-priority';
  readonly message: string;
} =>
  typeof error === 'object' &&
  error !== null &&
  '_tag' in error &&
  error._tag === 'CapabilityUnavailable' &&
  'capability' in error &&
  error.capability === 'agent-priority' &&
  'message' in error &&
  typeof error.message === 'string';

const ProfileLoadResult = Schema.TaggedUnion({
  Unavailable: {},
  Profiles: { profiles: Profiles },
});

const loadProfiles = Effect.gen(function* () {
  const client = yield* RadarClient;
  const readiness = yield* client.radar.ready({});
  if (readiness.agentPriority.status === 'unavailable') {
    return ProfileLoadResult.cases.Unavailable.make({});
  }

  yield* client.radar.getSession({});
  const response = yield* client.radar.listAgentProfiles({});
  const profiles = yield* Effect.forEach(response.items, profile =>
    profile.state === 'deleting'
      ? Effect.succeed(profile)
      : client.radar.refreshAgentProfile({
          params: { profileId: profile.id },
        }),
  );
  return ProfileLoadResult.cases.Profiles.make({ profiles });
});

export const trustedVerificationUrl = (
  provider: typeof AgentProvider.Type,
  value: string | undefined,
) => (value && isAgentLoginVerificationUrl(provider, value) ? value : undefined);

const State = Schema.TaggedUnion({
  Loading: { scanId: Schema.String },
  Unavailable: { scanId: Schema.String, message: Schema.String },
  Ready: { scanId: Schema.String, profiles: Profiles },
  RefreshingProfiles: { scanId: Schema.String, profiles: Profiles },
  Connecting: {
    scanId: Schema.String,
    profiles: Profiles,
    provider: AgentProvider,
  },
  LoginStarting: {
    scanId: Schema.String,
    profiles: Profiles,
    profile: AgentProfile,
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
  LoginCancelling: {
    scanId: Schema.String,
    profiles: Profiles,
    challenge: AgentLoginChallenge,
  },
  PriorityRefreshing: {
    scanId: Schema.String,
    profiles: Profiles,
    profile: AgentProfile,
  },
  PriorityStarting: {
    scanId: Schema.String,
    profiles: Profiles,
    profile: AgentProfile,
  },
  Disconnecting: {
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
  RefreshProfiles: {},
  Disconnect: { profile: AgentProfile },
  CancelLogin: {},
  Retry: {},
});

const Internal = Schema.TaggedUnion({
  ProfilesLoaded: { profiles: Profiles },
  CapabilityUnavailable: { message: Schema.String },
  ProfileCreated: { profile: AgentProfile },
  LoginStarted: { challenge: AgentLoginChallenge },
  LoginPolled: { challenge: AgentLoginChallenge },
  LoginSubmitted: { challenge: AgentLoginChallenge },
  LoginCancelled: {},
  ProfileRefreshed: { profile: AgentProfile },
  ProfileDisconnected: {},
  ReviewStarted: { review: AgentPriorityReview },
  ReviewPolled: { review: AgentPriorityReview },
  PollLogin: {},
  PollReview: {},
  RequestFailed: { message: Schema.String },
});

const requestFailure = (error: object, fallback: string) =>
  isAgentPriorityUnavailable(error)
    ? Internal.cases.CapabilityUnavailable.make({ message: error.message })
    : Internal.cases.RequestFailed.make({
        message: requestFailureMessage(error, fallback),
      });

const States = Machine.defineStates(State.cases);

const AgentPriorityMachine = Machine.make({
  id: 'AgentPriority',
  states: States.states,
  events: [
    Command.cases.Connect,
    Command.cases.SubmitLogin,
    Command.cases.Prioritize,
    Command.cases.RefreshProfiles,
    Command.cases.Disconnect,
    Command.cases.CancelLogin,
    Command.cases.Retry,
  ],
  internalEvents: [
    Internal.cases.ProfilesLoaded,
    Internal.cases.CapabilityUnavailable,
    Internal.cases.ProfileCreated,
    Internal.cases.LoginStarted,
    Internal.cases.LoginPolled,
    Internal.cases.LoginSubmitted,
    Internal.cases.LoginCancelled,
    Internal.cases.ProfileRefreshed,
    Internal.cases.ProfileDisconnected,
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
        effect: loadProfiles,
        onSuccess: response =>
          response._tag === 'Unavailable'
            ? Internal.cases.CapabilityUnavailable.make({
                message: agentPriorityUnavailableMessage,
              })
            : Internal.cases.ProfilesLoaded.make({ profiles: response.profiles }),
        onFailure: error =>
          requestFailure(
            error,
            'Your connected accounts could not be loaded. Try again.',
          ),
      }),
    on: {
      ProfilesLoaded: ({ event, state, target }) =>
        target.full.Ready.from({ scanId: state.scanId, profiles: event.profiles }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: [],
          message: event.message,
        }),
    },
  },
  Unavailable: {
    on: {
      RefreshProfiles: ({ state, target }) =>
        target.full.Loading.from({ scanId: state.scanId }),
    },
  },
  RefreshingProfiles: {
    invoke: () =>
      Machine.invokeEffect({
        id: 'refresh-profiles',
        effect: loadProfiles,
        onSuccess: response =>
          response._tag === 'Unavailable'
            ? Internal.cases.CapabilityUnavailable.make({
                message: agentPriorityUnavailableMessage,
              })
            : Internal.cases.ProfilesLoaded.make({ profiles: response.profiles }),
        onFailure: error =>
          requestFailure(
            error,
            'Your connected accounts could not be refreshed. Try again.',
          ),
      }),
    on: {
      ProfilesLoaded: ({ event, state, target }) =>
        target.full.Ready.from({ scanId: state.scanId, profiles: event.profiles }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
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
        target.full.PriorityRefreshing.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
      RefreshProfiles: ({ state, target }) =>
        target.full.RefreshingProfiles.from({
          scanId: state.scanId,
          profiles: state.profiles,
        }),
      Disconnect: ({ event, state, target }) =>
        target.full.Disconnecting.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
    },
  },
  Connecting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'create-profile',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.createAgentProfile({ payload: { provider: state.provider } }),
          ),
        ),
        onSuccess: profile => Internal.cases.ProfileCreated.make({ profile }),
        onFailure: error =>
          requestFailure(error, 'Sign-in could not be started. Try again.'),
      }),
    on: {
      ProfileCreated: ({ event, state, target }) => {
        return target.full.LoginStarting.from({
          scanId: state.scanId,
          profiles: upsertProfile(state.profiles, event.profile),
          profile: event.profile,
        });
      },
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
    },
  },
  LoginStarting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'begin-login',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.beginAgentLogin({
              params: { profileId: state.profile.id },
            }),
          ),
        ),
        onSuccess: challenge => Internal.cases.LoginStarted.make({ challenge }),
        onFailure: error =>
          requestFailure(error, 'Sign-in could not be started. Try again.'),
      }),
    on: {
      LoginStarted: ({ event, state, target }) =>
        target.full.LoginWaiting.from({
          scanId: state.scanId,
          profiles: upsertProfile(
            state.profiles,
            profileAwaitingLogin(state.profile),
          ),
          challenge: event.challenge,
        }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
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
      CancelLogin: ({ state, target }) =>
        target.full.LoginCancelling.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: state.challenge,
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
        onFailure: error =>
          requestFailure(error, 'Sign-in was interrupted. Start it again.'),
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
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
      CancelLogin: ({ state, target }) =>
        target.full.LoginCancelling.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: state.challenge,
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
        onFailure: error =>
          requestFailure(error, 'That code was not accepted. Try again.'),
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
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
      CancelLogin: ({ state, target }) =>
        target.full.LoginCancelling.from({
          scanId: state.scanId,
          profiles: state.profiles,
          challenge: state.challenge,
        }),
    },
  },
  LoginCancelling: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'cancel-login',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.cancelAgentLogin({
              params: { challengeId: state.challenge.id },
            }),
          ),
        ),
        onSuccess: () => Internal.cases.LoginCancelled.make({}),
        onFailure: error =>
          requestFailure(error, 'The sign-in could not be cancelled. Try again.'),
      }),
    on: {
      LoginCancelled: ({ state, target }) =>
        target.full.Loading.from({ scanId: state.scanId }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
    },
  },
  PriorityRefreshing: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'refresh-priority-profile',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.refreshAgentProfile({
              params: { profileId: state.profile.id },
            }),
          ),
        ),
        onSuccess: profile =>
          Internal.cases.ProfileRefreshed.make({ profile }),
        onFailure: error =>
          requestFailure(
            error,
            'The connected account could not be refreshed. Try again.',
          ),
      }),
    on: {
      ProfileRefreshed: ({ event, state, target }) => {
        const profiles = replaceProfile(state.profiles, event.profile);
        return event.profile.state === 'connected'
          ? target.full.PriorityStarting.from({
              scanId: state.scanId,
              profiles,
              profile: event.profile,
            })
          : target.full.Ready.from({ scanId: state.scanId, profiles });
      },
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
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
        onFailure: error =>
          requestFailure(error, 'The priority list could not be started. Try again.'),
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
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
          message: event.message,
        }),
    },
  },
  Disconnecting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'disconnect-profile',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.disconnectAgentProfile({
              params: { profileId: state.profile.id },
            }),
          ),
        ),
        onSuccess: () => Internal.cases.ProfileDisconnected.make({}),
        onFailure: error =>
          requestFailure(
            error,
            'The connected account could not be disconnected. Try again.',
          ),
      }),
    on: {
      ProfileDisconnected: ({ state, target }) =>
        target.full.Loading.from({ scanId: state.scanId }),
      RequestFailed: ({ event, state, target }) =>
        target.full.Failed.from({
          scanId: state.scanId,
          profiles: state.profiles,
          message: event.message,
        }),
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
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
        onFailure: error =>
          requestFailure(error, 'The priority list could not be refreshed. Try again.'),
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
      CapabilityUnavailable: ({ event, state, target }) =>
        target.full.Unavailable.from({
          scanId: state.scanId,
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
        target.full.PriorityRefreshing.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
      RefreshProfiles: ({ state, target }) =>
        target.full.RefreshingProfiles.from({
          scanId: state.scanId,
          profiles: state.profiles,
        }),
      Disconnect: ({ event, state, target }) =>
        target.full.Disconnecting.from({
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
        target.full.PriorityRefreshing.from({
          scanId: state.scanId,
          profiles: state.profiles,
          profile: event.profile,
        }),
      RefreshProfiles: ({ state, target }) =>
        target.full.RefreshingProfiles.from({
          scanId: state.scanId,
          profiles: state.profiles,
        }),
      Disconnect: ({ event, state, target }) =>
        target.full.Disconnecting.from({
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

export function AgentOpinionMarker({
  opinionKind,
}: {
  readonly opinionKind: 'unverified-model-opinion';
}) {
  return (
    <p
      className="eyebrow priority-progress"
      data-opinion-kind={opinionKind}
      role="note"
    >
      <strong>{opinionKind.replaceAll('-', ' ')}</strong> — this is a model
      ordering opinion. It does not replace canonical findings, evidence, or scores.
    </p>
  );
}

export function AgentPriorityAnswer({
  provider,
  output,
  findingTitles,
}: {
  readonly provider: typeof AgentProvider.Type;
  readonly output: AgentPriorityOutput;
  readonly findingTitles: ReadonlyMap<string, string>;
}) {
  return (
    <div className="priority-answer">
      <AgentOpinionMarker opinionKind={output.opinionKind} />
      <div className="priority-answer-title">
        <span>{provider === 'codex' ? 'Codex' : 'Claude'}</span>
        <p>{output.summary}</p>
      </div>
      <p className="priority-progress">
        {output.orderedItems.length} findings are included in this agent overlay.
      </p>
      <ol>
        {output.orderedItems.map(item => (
          <li data-finding-id={item.findingId} key={item.findingId}>
            <span>{item.action}</span>
            <div>
              <p className="eyebrow" data-opinion-kind={item.opinionKind}>
                {item.opinionKind.replaceAll('-', ' ')}
              </p>
              <h4>{findingTitles.get(item.findingId) ?? 'Selected finding'}</h4>
              <p>{item.reason}</p>
              <b>{item.nextMove}</b>
            </div>
          </li>
        ))}
      </ol>
      <details>
        <summary>What was deliberately left out</summary>
        {output.notNowFindingIds.length === 0 ? (
          <p>No findings were held back.</p>
        ) : (
          <ol>
            {output.notNowFindingIds.map(findingId => (
              <li data-finding-id={findingId} key={findingId}>
                <p>{findingTitles.get(findingId) ?? findingId}</p>
              </li>
            ))}
          </ol>
        )}
        {output.unsupportedClaims.map(claim => (
          <p key={claim}>{claim}</p>
        ))}
      </details>
    </div>
  );
}

export function AgentProfileStatus({
  provider,
  profile,
}: {
  readonly provider: typeof AgentProvider.Type;
  readonly profile: AgentProfile | undefined;
}) {
  const label = providerLabel(provider);

  return (
    <div
      className="provider-profile"
      data-provider={provider}
      data-profile-state={profile?.state ?? 'missing'}
    >
      <strong>{label}</strong>
      <p aria-live="polite" role="status">
        {profileStateLabel(profile)}
      </p>
      {profile?.accountLabel ? (
        <p>
          Account <strong>{profile.accountLabel}</strong>
        </p>
      ) : (
        <p>No account is connected.</p>
      )}
      {profile?.diagnostic ? (
        <p className="error-note" role="alert">
          {profile.diagnostic}
        </p>
      ) : null}
    </div>
  );
}

export function AgentVerificationLink({
  provider,
  verificationUrl,
}: {
  readonly provider: typeof AgentProvider.Type;
  readonly verificationUrl: string | undefined;
}) {
  const trustedUrl = trustedVerificationUrl(provider, verificationUrl);

  if (trustedUrl) {
    return (
      <a href={trustedUrl} rel="noreferrer noopener" target="_blank">
        Open the secure sign-in page ↗
      </a>
    );
  }

  return verificationUrl ? (
    <p className="error-note" role="alert">
      The provider returned an untrusted sign-in address. Do not continue;
      cancel this sign-in and try again.
    </p>
  ) : (
    <p>Preparing the secure sign-in page…</p>
  );
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
    return (
      <p
        aria-busy="true"
        aria-live="polite"
        className="priority-progress"
        role="status"
      >
        Preparing account options…
      </p>
    );
  }

  const snapshot = machineResult.value;
  const profiles = 'profiles' in snapshot.value ? snapshot.value.profiles : [];
  const challenge =
    'challenge' in snapshot.value ? snapshot.value.challenge : undefined;
  const review = 'review' in snapshot.value ? snapshot.value.review : undefined;
  const complete = snapshot.path === 'Complete' ? snapshot.value : undefined;
  const failed = snapshot.path === 'Failed' ? snapshot.value : undefined;
  const unavailable = snapshot.path === 'Unavailable' ? snapshot.value : undefined;
  const loginPending =
    snapshot.path === 'LoginWaiting' ||
    snapshot.path === 'LoginPolling' ||
    snapshot.path === 'LoginSubmitting' ||
    snapshot.path === 'LoginCancelling';
  const loginInputEnabled = snapshot.path === 'LoginWaiting';
  const busy =
    snapshot.path === 'Loading' ||
    snapshot.path === 'RefreshingProfiles' ||
    snapshot.path === 'Connecting' ||
    snapshot.path === 'LoginStarting' ||
    loginPending ||
    snapshot.path === 'PriorityRefreshing' ||
    snapshot.path === 'PriorityStarting' ||
    snapshot.path === 'Disconnecting' ||
    snapshot.path === 'ReviewWaiting' ||
    snapshot.path === 'ReviewPolling';
  const providers = ['codex', 'claude'] satisfies ReadonlyArray<
    typeof AgentProvider.Type
  >;
  const statusMessage =
    snapshot.path === 'Loading'
      ? 'Checking connected account availability…'
      : snapshot.path === 'Unavailable'
        ? 'Agent Priority is unavailable in this deployment.'
      : snapshot.path === 'RefreshingProfiles'
        ? 'Refreshing account status…'
        : snapshot.path === 'Connecting'
          ? `Starting ${providerLabel(snapshot.value.provider)} sign-in…`
          : snapshot.path === 'LoginStarting'
            ? 'Opening secure sign-in…'
            : snapshot.path === 'LoginWaiting'
              ? 'Waiting for you to finish secure sign-in…'
              : snapshot.path === 'LoginPolling'
                ? 'Checking secure sign-in…'
                : snapshot.path === 'LoginSubmitting'
                  ? 'Submitting sign-in input…'
                  : snapshot.path === 'LoginCancelling'
                    ? 'Cancelling secure sign-in…'
                    : snapshot.path === 'PriorityRefreshing'
                      ? 'Refreshing the selected account…'
                      : snapshot.path === 'PriorityStarting'
                        ? 'Starting the model-priority overlay…'
                        : snapshot.path === 'Disconnecting'
                          ? 'Disconnecting the selected account…'
                          : snapshot.path === 'ReviewWaiting' ||
                              snapshot.path === 'ReviewPolling'
                            ? 'Building the model-priority overlay…'
                            : snapshot.path === 'Complete'
                              ? 'Model-priority overlay is ready.'
                              : 'Account actions are ready.';

  const submitLogin = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    send(Command.cases.SubmitLogin.make({ value: loginInput }));
    setLoginInput('');
  };

  return (
    <section
      aria-busy={busy}
      aria-labelledby="account-priority-title"
      className="account-priority"
    >
      <div className="account-priority-head">
        <div>
          <p className="eyebrow">A second opinion</p>
          <h3 id="account-priority-title">Prioritize with your account.</h3>
        </div>
        <p>Use your own Codex or Claude account to rank this review.</p>
      </div>

      <p
        aria-atomic="true"
        aria-live="polite"
        className="priority-progress"
        role="status"
      >
        {statusMessage}
      </p>

      {unavailable ? (
        <div className="empty-state" role="alert">
          <p>AGENT PRIORITY UNAVAILABLE</p>
          <h4>{unavailable.message}</h4>
          <p>
            Sign-in and model-priority actions are disabled until this deployment has
            a secure, attested provider runner. Your canonical findings, evidence,
            and scores remain available.
          </p>
          <button
            aria-label="Check whether Agent Priority is available"
            disabled={busy}
            onClick={() => send(Command.cases.RefreshProfiles.make({}))}
            type="button"
          >
            CHECK AGENT PRIORITY AGAIN
          </button>
        </div>
      ) : (
        <>
      <div aria-label="Connected agent accounts" className="provider-actions" role="group">
        {providers.map(provider => {
          const profile = profiles.find(item => item.provider === provider);
          const connected = profile?.state === 'connected';
          const actionLabel = profile?.state === 'connecting'
            ? 'SIGN-IN IN PROGRESS'
            : profile?.state === 'deleting'
              ? 'DISCONNECTING'
              : connected
                ? 'PRIORITIZE'
                : profile?.state === 'failed'
                  ? 'RECONNECT'
                  : 'CONNECT';
          const actionDisabled =
            busy ||
            profile?.state === 'connecting' ||
            profile?.state === 'deleting';

          return (
            <div className="provider-action" key={provider}>
              <AgentProfileStatus profile={profile} provider={provider} />
              <div className="provider-action-controls">
                <button
                  aria-label={`${actionLabel.toLowerCase()} ${providerLabel(provider)}`}
                  disabled={actionDisabled}
                  onClick={() =>
                    connected && profile
                      ? send(Command.cases.Prioritize.make({ profile }))
                      : send(Command.cases.Connect.make({ provider }))
                  }
                  type="button"
                >
                  <span>{providerLabel(provider)}</span>
                  <b>{actionLabel}</b>
                </button>
                {profile ? (
                  <button
                    aria-label={`Disconnect ${providerLabel(provider)}`}
                    disabled={busy || profile.state === 'deleting'}
                    onClick={() => send(Command.cases.Disconnect.make({ profile }))}
                    type="button"
                  >
                    DISCONNECT
                  </button>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>

      <button
        aria-label="Refresh connected account status"
        disabled={busy}
        onClick={() => send(Command.cases.RefreshProfiles.make({}))}
        type="button"
      >
        REFRESH ACCOUNTS
      </button>

      {complete?.review.output ? (
        <AgentPriorityAnswer
          findingTitles={new Map(
            result.findings.map(finding => [finding.id, finding.title]),
          )}
          output={complete.review.output}
          provider={complete.review.provider}
        />
      ) : (
        <>
          {challenge ? (
            <div
              aria-atomic="true"
              aria-live="polite"
              className="login-challenge"
              id="login-challenge-status"
              role="status"
            >
              <p>Continue the secure {providerLabel(challenge.provider)} sign-in.</p>
              <AgentVerificationLink
                provider={challenge.provider}
                verificationUrl={challenge.verificationUrl}
              />
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
                      aria-describedby="login-challenge-status"
                      disabled={!loginInputEnabled}
                      id="provider-login-code"
                      value={loginInput}
                      onChange={event => setLoginInput(event.currentTarget.value)}
                      minLength={8}
                      maxLength={2048}
                      required
                    />
                    <button disabled={!loginInputEnabled} type="submit">CONTINUE</button>
                  </div>
                </form>
              ) : null}
              {challenge.diagnostic ? (
                <p className="error-note" role="alert">
                  {challenge.diagnostic}
                </p>
              ) : null}
              <button
                aria-label="Cancel secure sign-in"
                disabled={snapshot.path === 'LoginCancelling'}
                onClick={() => send(Command.cases.CancelLogin.make({}))}
                type="button"
              >
                CANCEL SIGN-IN
              </button>
            </div>
          ) : null}

          {failed ? (
            <div>
              <p className="error-note" role="alert">{failed.message}</p>
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
            <p className="error-note" role="alert">
              {review.diagnostic ?? 'The second opinion could not be completed.'}
            </p>
          ) : null}
        </>
      )}
        </>
      )}
    </section>
  );
}
