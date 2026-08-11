import { Effect } from 'effect';
import {
  AgentLoginChallenge,
  AgentPriorityReview,
  AgentProfile,
  AgentProfileList,
  AgentProvider,
  BrowserSession,
} from '../shared/domain';
import { AgentPriorityCapability, ReadyResponse } from '../shared/api';

type AgentClientCall = {
  readonly operation: string;
  readonly profileId?: string;
  readonly provider?: typeof AgentProvider.Type;
};

type ProviderPayload = {
  readonly payload: { readonly provider: typeof AgentProvider.Type };
};

type ProfileParameters = {
  readonly params: { readonly profileId: string };
};

type ChallengeParameters = {
  readonly params: { readonly challengeId: string };
};

type SubmitLoginInput = ChallengeParameters & {
  readonly payload: { readonly value: string };
};

type PriorityReviewRequest = {
  readonly params: { readonly scanId: string };
  readonly payload: { readonly profileId: string };
};

const requests: AgentClientCall[] = [];
let profiles: ReadonlyArray<AgentProfile> = [];
let holdLoginPoll = false;
let failLoginBegin = false;

const timestamp = '2026-08-11T00:00:00.000Z';
const fallbackProfile = () =>
  new AgentProfile({
    id: 'profile-codex',
    provider: 'codex',
    state: 'disconnected',
    createdAt: timestamp,
    updatedAt: timestamp,
  });

const challengeFor = (profileId: string) =>
  new AgentLoginChallenge({
    id: `challenge-${profileId}`,
    profileId,
    provider: 'codex',
    status: 'waiting',
    verificationUrl: 'https://auth.openai.com/codex/device',
    userCode: 'ABCD-EFGH',
    prompt: 'Enter the code after approving access.',
    diagnostic: 'Keep this window open while approval completes.',
    expiresAt: '2026-08-11T00:10:00.000Z',
  });

const record = <A>(call: AgentClientCall, value: A) =>
  Effect.sync(() => {
    requests.push(call);
    return value;
  });

const withState = (
  profile: AgentProfile,
  state: AgentProfile['state'],
) =>
  new AgentProfile({
    id: profile.id,
    provider: profile.provider,
    state,
    accountLabel: profile.accountLabel,
    diagnostic: profile.diagnostic,
    createdAt: profile.createdAt,
    updatedAt: timestamp,
  });

const profileById = (profileId: string) =>
  profiles.find(profile => profile.id === profileId) ?? fallbackProfile();

export const resetAgentPriorityClient = (
  nextProfiles: ReadonlyArray<AgentProfile> = [],
) => {
  requests.splice(0, requests.length);
  profiles = nextProfiles;
  holdLoginPoll = false;
  failLoginBegin = false;
};

export const setAgentPriorityPollHeld = (held: boolean) => {
  holdLoginPoll = held;
};

export const setAgentLoginBeginFailure = (fails: boolean) => {
  failLoginBegin = fails;
};

export const agentPriorityRequests = () => [...requests];

export const clearAgentPriorityRequests = () => {
  requests.splice(0, requests.length);
};

export const RadarClient = Effect.succeed({
  radar: {
    ready: () =>
      record(
        { operation: 'ready' },
        new ReadyResponse({
          status: 'ready',
          storage: 'memory',
          agentPriority: new AgentPriorityCapability({ status: 'ready' }),
        }),
      ),
    getSession: () =>
      record({ operation: 'getSession' }, new BrowserSession({ status: 'ready' })),
    listAgentProfiles: () =>
      record(
        { operation: 'listAgentProfiles' },
        new AgentProfileList({ items: profiles }),
      ),
    refreshAgentProfile: ({ params }: ProfileParameters) =>
      record(
        { operation: 'refreshAgentProfile', profileId: params.profileId },
        profileById(params.profileId),
      ),
    createAgentProfile: ({ payload }: ProviderPayload) =>
      Effect.sync(() => {
        const profile = new AgentProfile({
          id: `profile-${payload.provider}`,
          provider: payload.provider,
          state: 'disconnected',
          accountLabel: `${payload.provider}@example.test`,
          diagnostic: 'Account created; secure sign-in is pending.',
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        profiles = profiles.some(current => current.id === profile.id)
          ? profiles.map(current => current.id === profile.id ? profile : current)
          : [...profiles, profile];
        requests.push({
          operation: 'createAgentProfile',
          provider: payload.provider,
        });
        return profile;
      }),
    beginAgentLogin: ({ params }: ProfileParameters) =>
      Effect.sync(() => {
        requests.push({ operation: 'beginAgentLogin', profileId: params.profileId });
        return failLoginBegin;
      }).pipe(
        Effect.flatMap(fails => {
          if (fails) {
            return Effect.fail({
              message: 'Simulated secure sign-in startup failure',
            });
          }
          profiles = profiles.map(profile =>
            profile.id === params.profileId ? withState(profile, 'connecting') : profile,
          );
          return Effect.succeed(challengeFor(params.profileId));
        }),
      ),
    pollAgentLogin: ({ params }: ChallengeParameters) =>
      record(
        { operation: 'pollAgentLogin', profileId: params.challengeId },
        holdLoginPoll,
      ).pipe(
        Effect.flatMap(held =>
          held
            ? Effect.never
            : Effect.succeed(challengeFor(params.challengeId.replace('challenge-', ''))),
        ),
      ),
    submitAgentLoginInput: ({ params, payload }: SubmitLoginInput) =>
      record(
        { operation: `submitAgentLoginInput:${payload.value}`, profileId: params.challengeId },
        challengeFor(params.challengeId.replace('challenge-', '')),
      ),
    cancelAgentLogin: ({ params }: ChallengeParameters) =>
      Effect.sync(() => {
        const profileId = params.challengeId.replace('challenge-', '');
        profiles = profiles.map(profile =>
          profile.id === profileId ? withState(profile, 'disconnected') : profile,
        );
        requests.push({ operation: 'cancelAgentLogin', profileId: params.challengeId });
      }),
    disconnectAgentProfile: ({ params }: ProfileParameters) =>
      Effect.sync(() => {
        profiles = profiles.filter(profile => profile.id !== params.profileId);
        requests.push({ operation: 'disconnectAgentProfile', profileId: params.profileId });
      }),
    createPriorityReview: ({ params, payload }: PriorityReviewRequest) =>
      record(
        { operation: 'createPriorityReview', profileId: payload.profileId },
        new AgentPriorityReview({
          schemaVersion: 'codebase-radar.priority-review/v1',
          id: `priority-${params.scanId}`,
          scanId: params.scanId,
          profileId: payload.profileId,
          provider: profileById(payload.profileId).provider,
          status: 'queued',
          createdAt: timestamp,
          updatedAt: timestamp,
        }),
      ),
  },
});
