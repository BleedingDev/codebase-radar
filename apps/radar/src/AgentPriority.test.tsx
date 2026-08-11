// @vitest-environment happy-dom
import React from 'react';
import type { ReactElement } from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { Schema } from 'effect';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentPriorityOutput, AgentProfile } from '../shared/domain';
import {
  AgentPriorityAnswer,
  AgentProfileStatus,
  AgentVerificationLink,
  trustedVerificationUrl,
} from './AgentPriority';

type MountedView = {
  readonly container: HTMLDivElement;
  readonly unmount: () => void;
};

const profileStates = [
  'disconnected',
  'connecting',
  'connected',
  'failed',
  'deleting',
] satisfies ReadonlyArray<AgentProfile['state']>;

const claudeAuthorizationUrl = [
  'https://claude.com/cai/oauth/authorize?',
  'code=true',
  '&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e',
  '&response_type=code',
  '&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback',
  '&scope=org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload',
  `&code_challenge=${'A'.repeat(43)}`,
  '&code_challenge_method=S256',
  `&state=${'B'.repeat(32)}`,
].join('');

const mount = (content: ReactElement): MountedView => {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  act(() => {
    root.render(content);
  });
  return {
    container,
    unmount: () => {
      act(() => {
        root.unmount();
      });
      container.remove();
    },
  };
};

let mounted: MountedView | undefined;

beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
});

afterEach(() => {
  mounted?.unmount();
  mounted = undefined;
  document.body.replaceChildren();
});

describe('Agent Priority UI', () => {
  it('renders the complete overlay, every item field, and one opinion marker per item plus the overlay', () => {
    const output = Schema.decodeUnknownSync(AgentPriorityOutput)({
      opinionKind: 'unverified-model-opinion',
      summary: 'Review the first two findings before the deferred one.',
      orderedItems: [
        {
          findingId: 'finding-one',
          action: 'fix now',
          opinionKind: 'unverified-model-opinion',
          reason: 'It has the strongest bounded rationale.',
          nextMove: 'Make the smallest safe change.',
        },
        {
          findingId: 'finding-two',
          action: 'investigate',
          opinionKind: 'unverified-model-opinion',
          reason: 'Confirm the representative evidence.',
          nextMove: 'Inspect the linked evidence.',
        },
      ],
      notNowFindingIds: ['finding-three'],
      unsupportedClaims: [
        'No unsupported claim may alter the canonical backlog.',
        '<img src=x onerror=alert(1)>',
      ],
    });

    mounted = mount(
      <AgentPriorityAnswer
        findingTitles={new Map([
          ['finding-one', 'First finding'],
          ['finding-two', 'Second finding'],
          ['finding-three', 'Deferred finding'],
        ])}
        output={output}
        provider="codex"
      />,
    );

    const text = mounted.container.textContent;
    expect(
      mounted.container.querySelectorAll(
        '[data-opinion-kind="unverified-model-opinion"]',
      ),
    ).toHaveLength(output.orderedItems.length + 1);
    expect(mounted.container.querySelectorAll('[data-finding-id]')).toHaveLength(3);
    expect(text).toContain('unverified model opinion');
    expect(text).toContain('2 findings are included in this agent overlay.');
    for (const value of [
      'fix now',
      'First finding',
      'It has the strongest bounded rationale.',
      'Make the smallest safe change.',
      'investigate',
      'Second finding',
      'Confirm the representative evidence.',
      'Inspect the linked evidence.',
      'Deferred finding',
      'No unsupported claim may alter the canonical backlog.',
      '<img src=x onerror=alert(1)>',
    ]) {
      expect(text).toContain(value);
    }
    expect(mounted.container.querySelector('img')).toBeNull();
  });

  it('renders every account state with account, diagnostic, and live-status semantics', () => {
    mounted = mount(
      <div>
        {profileStates.map(state => (
          <AgentProfileStatus
            key={state}
            profile={new AgentProfile({
              id: `profile-${state}`,
              provider: 'claude',
              state,
              accountLabel: '<personal-account>',
              diagnostic: `${state} diagnostic`,
              createdAt: '2026-08-11T00:00:00.000Z',
              updatedAt: '2026-08-11T00:00:00.000Z',
            })}
            provider="claude"
          />
        ))}
      </div>,
    );

    const labels = new Map([
      ['disconnected', 'Disconnected'],
      ['connecting', 'Sign-in in progress'],
      ['connected', 'Connected'],
      ['failed', 'Needs attention'],
      ['deleting', 'Disconnecting'],
    ]);
    for (const state of profileStates) {
      const profile = mounted.container.querySelector(
        `[data-profile-state="${state}"]`,
      );
      expect(profile?.textContent).toContain(labels.get(state));
      expect(profile?.textContent).toContain('<personal-account>');
      expect(profile?.textContent).toContain(`${state} diagnostic`);
      expect(profile?.querySelector('[role="status"]')).not.toBeNull();
      expect(profile?.querySelector('[role="alert"]')).not.toBeNull();
    }
  });

  it('only renders provider-owned canonical HTTPS verification URLs', () => {
    const reorderedScopeUrl = claudeAuthorizationUrl.replace(
      'org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload',
      'user%3Ainference%20org%3Acreate_api_key%20user%3Aprofile%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload',
    );
    const codexHostileUrls = [
      'javascript:alert(1)',
      'data:text/html,unsafe',
      'http://auth.openai.com/codex/device',
      'https://auth.openai.com.evil.test/codex/device',
      'https://auth.openai.com@evil.test/codex/device',
      'https://auth.openai.com/codex/device?redirect=https://evil.test',
    ];
    const claudeHostileUrls = [
      'https://claude.com/cai/oauth/authorize?redirect_uri=https%3A%2F%2Fevil.test',
      claudeAuthorizationUrl.replace(
        '9d1c250a-e61b-44d9-88ed-5944d1962f5e',
        '00000000-0000-0000-0000-000000000000',
      ),
      claudeAuthorizationUrl.replace(
        'org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload',
        'user%3Ainference',
      ),
      claudeAuthorizationUrl.replace(
        'org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload',
        'admin%3Aeverything',
      ),
      reorderedScopeUrl,
    ];

    expect(
      trustedVerificationUrl('codex', 'https://auth.openai.com/codex/device'),
    ).toBe('https://auth.openai.com/codex/device');
    expect(trustedVerificationUrl('claude', claudeAuthorizationUrl)).toBe(
      claudeAuthorizationUrl,
    );
    for (const hostileUrl of codexHostileUrls) {
      expect(trustedVerificationUrl('codex', hostileUrl)).toBeUndefined();
    }
    for (const hostileUrl of claudeHostileUrls) {
      expect(trustedVerificationUrl('claude', hostileUrl)).toBeUndefined();
    }

    mounted = mount(
      <div>
        <AgentVerificationLink
          provider="claude"
          verificationUrl={claudeAuthorizationUrl}
        />
        {codexHostileUrls.map(url => (
          <AgentVerificationLink key={url} provider="codex" verificationUrl={url} />
        ))}
        {claudeHostileUrls.map(url => (
          <AgentVerificationLink key={url} provider="claude" verificationUrl={url} />
        ))}
      </div>,
    );

    const secureLink = mounted.container.querySelector<HTMLAnchorElement>('a');
    expect(secureLink?.getAttribute('href')).toBe(claudeAuthorizationUrl);
    expect(secureLink?.getAttribute('rel')).toBe('noreferrer noopener');
    expect(secureLink?.getAttribute('target')).toBe('_blank');
    expect(mounted.container.querySelectorAll('[role="alert"]')).toHaveLength(
      codexHostileUrls.length + claudeHostileUrls.length,
    );
    expect(mounted.container.textContent).not.toContain('javascript:alert(1)');
  });
});
