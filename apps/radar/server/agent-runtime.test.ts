import { Deferred, Effect, Exit, Fiber, Ref, Schema } from 'effect';
import { TestClock } from 'effect/testing';
import { describe, expect, it } from 'vitest';
import {
  AgentLoginChallenge,
  isAgentLoginVerificationUrl,
} from '../shared/domain';
import {
  type AgentLoginTerminal,
  releaseAgentLoginSlot,
  redactAgentDiagnostic,
  reserveAgentLoginSlot,
  providerSandboxGovernanceReady,
  sandboxCommand,
  superviseAgentLoginLifetime,
} from './agent-runtime';

describe('agent login admission', () => {
  it('allows only one active login for an owner and profile', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const reservations = yield* Ref.make<ReadonlySet<string>>(new Set());
        yield* reserveAgentLoginSlot(reservations, 'owner:profile', 4);
        const duplicate = yield* Effect.exit(
          reserveAgentLoginSlot(reservations, 'owner:profile', 4),
        );
        expect(Exit.isFailure(duplicate)).toBe(true);
        expect((yield* Ref.get(reservations)).size).toBe(1);
      }),
    ));

  it('enforces global capacity and releases slots for retry', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const reservations = yield* Ref.make<ReadonlySet<string>>(new Set());
        yield* reserveAgentLoginSlot(reservations, 'first', 1);
        const full = yield* Effect.exit(
          reserveAgentLoginSlot(reservations, 'second', 1),
        );
        expect(Exit.isFailure(full)).toBe(true);
        yield* releaseAgentLoginSlot(reservations, 'first');
        yield* reserveAgentLoginSlot(reservations, 'second', 1);
        expect(yield* Ref.get(reservations)).toEqual(new Set(['second']));
      }),
    ));
});

describe('agent diagnostic redaction', () => {
  it('redacts credential material before provider output can become a review diagnostic', () => {
    const diagnostic = redactAgentDiagnostic(
      'access_token=codex-private Bearer claude-private-token api_key="third-secret" Authorization: Bearer fourth-secret-token',
    );

    expect(diagnostic).toContain('<redacted>');
    expect(diagnostic).not.toContain('codex-private');
    expect(diagnostic).not.toContain('claude-private-token');
    expect(diagnostic).not.toContain('third-secret');
    expect(diagnostic).not.toContain('fourth-secret-token');
  });

  it('removes provider filesystem locations from surfaced diagnostics', () => {
    const diagnostic = redactAgentDiagnostic(
      'provider wrote /private/radar/home/.codex/auth.json after a failure',
    );

    expect(diagnostic).toContain('<path>');
    expect(diagnostic).not.toContain('/private/radar/home/.codex/auth.json');
  });
});

describe('agent login verification URLs', () => {
  const claudeAuthorizationUrl = [
    'https://claude.com/cai/oauth/authorize?',
    'code=true',
    '&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e',
    '&response_type=code',
    '&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback',
    '&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code+user%3Amcp_servers+user%3Afile_upload',
    `&code_challenge=${'a'.repeat(43)}`,
    '&code_challenge_method=S256',
    `&state=${'b'.repeat(32)}`,
  ].join('');

  it('accepts only canonical, provider-owned HTTPS device pages', () => {
    expect(
      isAgentLoginVerificationUrl('codex', 'https://auth.openai.com/codex/device'),
    ).toBe(true);
    expect(isAgentLoginVerificationUrl('claude', claudeAuthorizationUrl)).toBe(true);
    expect(isAgentLoginVerificationUrl('codex', claudeAuthorizationUrl)).toBe(false);
    expect(
      isAgentLoginVerificationUrl('claude', 'https://auth.openai.com/codex/device'),
    ).toBe(false);
  });

  it('rejects schemes, userinfo, host suffixes, fragments, and redirect-like URLs', () => {
    const hostile = [
      'http://auth.openai.com/codex/device',
      'https://auth.openai.com.evil.example/codex/device',
      'https://auth.openai.com@evil.example/codex/device',
      'https://auth.openai.com/codex/device?redirect_uri=https%3A%2F%2Fevil.example',
      'https://auth.openai.com/codex/device#evil',
      claudeAuthorizationUrl.replace(
        'platform.claude.com%2Foauth%2Fcode%2Fcallback',
        'evil.example%2Fcallback',
      ),
      claudeAuthorizationUrl.replace(
        '9d1c250a-e61b-44d9-88ed-5944d1962f5e',
        '00000000-0000-0000-0000-000000000000',
      ),
      claudeAuthorizationUrl.replace(
        'org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code+user%3Amcp_servers+user%3Afile_upload',
        'admin%3Aeverything',
      ),
      `${claudeAuthorizationUrl}&redirect=https%3A%2F%2Fevil.example`,
      claudeAuthorizationUrl.replace('https://claude.com', 'https://claude.com@evil.example'),
    ];

    expect(
      hostile.every(url =>
        !isAgentLoginVerificationUrl('codex', url) &&
        !isAgentLoginVerificationUrl('claude', url),
      ),
    ).toBe(true);
  });

  it('rejects a hostile verification URL during public challenge decoding', () => {
    const base = {
      id: 'challenge-one',
      profileId: 'profile-one',
      provider: 'codex',
      status: 'waiting',
      expiresAt: '2026-08-11T12:00:00.000Z',
    };
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(AgentLoginChallenge)({
          ...base,
          verificationUrl: 'https://auth.openai.com/codex/device',
        }),
      ),
    ).toBe(true);
    expect(
      Exit.isFailure(
        Schema.decodeUnknownExit(AgentLoginChallenge)({
          ...base,
          verificationUrl: 'https://auth.openai.com@evil.example/codex/device',
        }),
      ),
    ).toBe(true);
  });
});

describe('provider sandbox admission', () => {
  it('fails closed when destination allowlisting and resource governance are not attested', () => {
    const exit = Effect.runSyncExit(providerSandboxGovernanceReady());

    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('does not transfer Codex auth.json into a model-tool sandbox', () => {
    const command = sandboxCommand(
      '/opt/radar-agent',
      process.execPath,
      '/private/home',
      '/private/work',
      { provider: 'codex' },
      ['exec', '-'],
      false,
      [],
      undefined,
      'run',
      'model',
    );
    const payload = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Struct({
      homeInputs: Schema.Array(Schema.Json),
      homeOutputs: Schema.Array(Schema.Json),
    })))(command.args.at(-1) ?? 'null');

    expect(payload.homeInputs).toEqual([]);
    expect(payload.homeOutputs).toEqual([]);
    expect(command.args).toContain('--unshare-net');
  });
});

describe('agent login lifetime', () => {
  it('cancels the expiry watcher after process completion and finalizes once', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitCode = yield* Deferred.make<number>();
        const expiryWatcherStarted = yield* Deferred.make<void>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const expiryWatcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Deferred.await(exitCode),
          Deferred.succeed(expiryWatcherStarted, undefined).pipe(
            Effect.andThen(Effect.sleep('1 minute')),
            Effect.ensuring(
              Ref.update(expiryWatcherFinalizations, count => count + 1),
            ),
          ),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* Deferred.await(expiryWatcherStarted);
        yield* Deferred.succeed(exitCode, 0);
        yield* Fiber.join(lifetime);
        yield* TestClock.adjust('2 minutes');

        expect(yield* Ref.get(handled)).toEqual(['Finished']);
        expect(yield* Ref.get(expiryWatcherFinalizations)).toBe(1);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('expires once and cancels the process watcher', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const processWatcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Effect.never.pipe(
            Effect.ensuring(
              Ref.update(processWatcherFinalizations, count => count + 1),
            ),
          ),
          Effect.sleep('1 minute'),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* TestClock.adjust('1 minute');
        yield* Fiber.join(lifetime);

        expect(yield* Ref.get(handled)).toEqual(['Expired']);
        expect(yield* Ref.get(processWatcherFinalizations)).toBe(1);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('lets cancellation atomically win against later process completion', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitCode = yield* Deferred.make<number>();
        const handled = yield* Ref.make<ReadonlyArray<string>>([]);
        const finalizations = yield* Ref.make(0);
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          Deferred.await(exitCode),
          Effect.sleep('1 minute'),
          event => Ref.update(handled, events => [...events, event._tag]),
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        const claimed = yield* Deferred.succeed(terminal, {
          _tag: 'Cancelled',
        });
        yield* Deferred.succeed(exitCode, 0);
        yield* Fiber.join(lifetime);
        yield* TestClock.adjust('2 minutes');

        expect(claimed).toBe(true);
        expect(yield* Ref.get(handled)).toEqual(['Cancelled']);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }).pipe(Effect.provide(TestClock.layer())),
    ));

  it('cancels watchers and finalizes when the owning scope interrupts the lifetime', () =>
    Effect.runPromise(
      Effect.gen(function* () {
        const terminal = yield* Deferred.make<AgentLoginTerminal>();
        const exitWatcherStarted = yield* Deferred.make<void>();
        const expiryWatcherStarted = yield* Deferred.make<void>();
        const watcherFinalizations = yield* Ref.make(0);
        const finalizations = yield* Ref.make(0);
        const watcher = (started: Deferred.Deferred<void>) =>
          Deferred.succeed(started, undefined).pipe(
            Effect.andThen(Effect.never),
            Effect.ensuring(
              Ref.update(watcherFinalizations, count => count + 1),
            ),
          );
        const lifetime = yield* superviseAgentLoginLifetime(
          terminal,
          watcher(exitWatcherStarted),
          watcher(expiryWatcherStarted),
          () => Effect.void,
          Ref.update(finalizations, count => count + 1),
        ).pipe(Effect.forkChild);

        yield* Deferred.await(exitWatcherStarted);
        yield* Deferred.await(expiryWatcherStarted);
        yield* Fiber.interrupt(lifetime);

        expect(yield* Ref.get(watcherFinalizations)).toBe(2);
        expect(yield* Ref.get(finalizations)).toBe(1);
      }),
    ));
});
