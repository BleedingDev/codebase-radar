import { useAtomSet, useAtomValue } from '@effect/atom-react';
import {
  Link,
  Navigate,
  useMatch,
} from '@modern-js/plugin-tanstack/runtime';
import { Effect } from '@modern-js/plugin-bff/effect-client';
import { Machine } from '@typeonce/effect-machine';
import { AtomMachine } from '@typeonce/effect-machine/reactivity';
import { Option, Schema } from 'effect';
import { AsyncResult } from 'effect/unstable/reactivity';
import { useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import {
  audienceCopy,
  audienceLabel,
  decisionHeadline,
} from '../shared/audience';
import { Audience, ScanRecord } from '../shared/domain';
import { AgentPriority } from './AgentPriority';
import { RadarClient } from './radar-client';
import './styles.css';

const audienceOptions = Audience.literals;

const analyzerTitle = {
  security: 'Risky code pattern',
  reliability: 'Reliability concern',
  maintainability: 'Maintainability concern',
  performance: 'Performance concern',
  architecture: 'Dependency concern',
  configuration: 'Configuration concern',
};

const ReviewRoute = Schema.TaggedUnion({
  Home: {},
  NewReview: {},
  Review: { scanId: Schema.String },
});

const scanIsPending = (scan: ScanRecord) =>
  scan.status === 'queued' || scan.status === 'running';

const ScanWorkflowState = Schema.TaggedUnion({
  Loading: { route: ReviewRoute },
  Ready: {
    route: ReviewRoute,
    scans: Schema.Array(ScanRecord),
    selected: Schema.NullOr(ScanRecord),
    error: Schema.String,
  },
  Submitting: {
    scans: Schema.Array(ScanRecord),
    repositoryUrl: Schema.String,
    displayName: Schema.String,
    audience: Audience,
  },
  Waiting: {
    route: ReviewRoute,
    scans: Schema.Array(ScanRecord),
    selected: ScanRecord,
  },
  Refreshing: {
    route: ReviewRoute,
    scans: Schema.Array(ScanRecord),
    selected: ScanRecord,
  },
});

const ScanWorkflowEvent = Schema.TaggedUnion({
  Submit: {
    repositoryUrl: Schema.String,
    displayName: Schema.String,
    audience: Audience,
  },
});

const ScanWorkflowResult = Schema.TaggedUnion({
  Loaded: {
    route: ReviewRoute,
    scans: Schema.Array(ScanRecord),
    selected: Schema.NullOr(ScanRecord),
  },
  LoadFailed: { route: ReviewRoute },
  ScanCreated: { scan: ScanRecord },
  SubmitFailed: {},
  Refresh: {},
  PollComplete: { scan: ScanRecord },
  PollFailed: {},
});

const ScanWorkflowStates = Machine.defineStates(ScanWorkflowState.cases);

const ScanWorkflow = Machine.make({
  id: 'ScanWorkflow',
  states: ScanWorkflowStates.states,
  events: [ScanWorkflowEvent.cases.Submit],
  internalEvents: [
    ScanWorkflowResult.cases.Loaded,
    ScanWorkflowResult.cases.LoadFailed,
    ScanWorkflowResult.cases.ScanCreated,
    ScanWorkflowResult.cases.SubmitFailed,
    ScanWorkflowResult.cases.Refresh,
    ScanWorkflowResult.cases.PollComplete,
    ScanWorkflowResult.cases.PollFailed,
  ],
  input: ReviewRoute,
  initial: route => ScanWorkflowStates.initial.Loading.from({ route }),
}).handle({
  Loading: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'load-reviews',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.listScans({ query: { limit: 8 } }).pipe(
              Effect.flatMap(response => {
                if (state.route._tag !== 'Review') {
                  return Effect.succeed(
                    ScanWorkflowResult.cases.Loaded.make({
                      route: state.route,
                      scans: response.items,
                      selected: null,
                    }),
                  );
                }
                return client.radar.getScan({
                  params: { scanId: state.route.scanId },
                }).pipe(
                  Effect.map(scan =>
                    ScanWorkflowResult.cases.Loaded.make({
                      route: state.route,
                      scans: [
                        scan,
                        ...response.items.filter(item => item.id !== scan.id),
                      ],
                      selected: scan,
                    }),
                  ),
                );
              }),
            ),
          ),
        ),
        onSuccess: event => event,
        onFailure: () =>
          ScanWorkflowResult.cases.LoadFailed.make({ route: state.route }),
      }),
    on: {
      Loaded: ({ event, target }) => {
        if (event.selected && scanIsPending(event.selected)) {
          return target.full.Waiting.from({
            route: event.route,
            scans: event.scans,
            selected: event.selected,
          });
        }
        return target.full.Ready.from({
          route: event.route,
          scans: event.scans,
          selected: event.selected,
          error: '',
        });
      },
      LoadFailed: ({ event, target }) =>
        target.full.Ready.from({
          route: event.route,
          scans: [],
          selected: null,
          error: event.route._tag === 'Review'
            ? 'This review could not be loaded.'
            : 'Reviews could not be loaded. Refresh and try again.',
        }),
    },
  },
  Ready: {
    on: {
      Submit: ({ event, state, target }) =>
        target.full.Submitting.from({
          scans: state.scans,
          repositoryUrl: event.repositoryUrl,
          displayName: event.displayName,
          audience: event.audience,
        }),
    },
  },
  Waiting: {
    invoke: Machine.after('1800 millis', ScanWorkflowResult.cases.Refresh.make({})),
    on: {
      Refresh: ({ state, target }) =>
        target.full.Refreshing.from({
          route: state.route,
          scans: state.scans,
          selected: state.selected,
        }),
    },
  },
  Refreshing: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'refresh-review',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.getScan({ params: { scanId: state.selected.id } }),
          ),
        ),
        onSuccess: scan =>
          ScanWorkflowResult.cases.PollComplete.make({ scan }),
        onFailure: () => ScanWorkflowResult.cases.PollFailed.make({}),
      }),
    on: {
      PollComplete: ({ event, state, target }) => {
        const scans = state.scans.map(item =>
            item.id === event.scan.id ? event.scan : item,
          );
        if (scanIsPending(event.scan)) {
          return target.full.Waiting.from({
            route: state.route,
            scans,
            selected: event.scan,
          });
        }
        return target.full.Ready.from({
          route: state.route,
          scans,
          selected: event.scan,
          error: '',
        });
      },
      PollFailed: ({ state, target }) =>
        target.full.Waiting.from({
          route: state.route,
          scans: state.scans,
          selected: state.selected,
        }),
    },
  },
  Submitting: {
    invoke: ({ state }) =>
      Machine.invokeEffect({
        id: 'submit-review',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar
              .createProfile({
                payload: {
                  audience: state.audience,
                  ...(state.displayName.trim()
                    ? { displayName: state.displayName.trim() }
                    : {}),
                },
              })
              .pipe(
                Effect.flatMap(profile =>
                  client.radar.createScan({
                    payload: {
                      githubUrl: state.repositoryUrl,
                      audience: state.audience,
                      profileId: profile.id,
                    },
                  }),
                ),
              ),
          ),
        ),
        onSuccess: scan =>
          ScanWorkflowResult.cases.ScanCreated.make({ scan }),
        onFailure: () => ScanWorkflowResult.cases.SubmitFailed.make({}),
      }),
    on: {
      ScanCreated: ({ event, state, target }) =>
        target.full.Waiting.from({
          route: ReviewRoute.cases.Review.make({ scanId: event.scan.id }),
          scans: [
            event.scan,
            ...state.scans.filter(item => item.id !== event.scan.id),
          ],
          selected: event.scan,
        }),
      SubmitFailed: ({ state, target }) =>
        target.full.Ready.from({
          route: ReviewRoute.cases.NewReview.make({}),
          scans: state.scans,
          selected: null,
          error: 'The review could not be started. Check the link and try again.',
        }),
    },
  },
});

function Radar({ route }: { readonly route: typeof ReviewRoute.Type }) {
  const [repositoryUrl, setRepositoryUrl] = useState(
    'https://github.com/realworld-apps/angular-realworld-example-app',
  );
  const [displayName, setDisplayName] = useState('');
  const [audience, setAudience] = useState<ScanRecord['audience']>('technical');
  const machineAtom = useMemo(
    () => AtomMachine.make(ScanWorkflow, route),
    [route],
  );
  const machineResult = useAtomValue(machineAtom.result);
  const send = useAtomSet(machineAtom.send);
  const snapshot = AsyncResult.isSuccess(machineResult)
    ? machineResult.value
    : undefined;
  const loadingState = snapshot
    ? Option.getOrUndefined(ScanWorkflowStates.get(snapshot, 'Loading'))
    : undefined;
  const ready = snapshot
    ? Option.getOrUndefined(ScanWorkflowStates.get(snapshot, 'Ready'))
    : undefined;
  const submittingState = snapshot
    ? Option.getOrUndefined(ScanWorkflowStates.get(snapshot, 'Submitting'))
    : undefined;
  const waiting = snapshot
    ? Option.getOrUndefined(ScanWorkflowStates.get(snapshot, 'Waiting'))
    : undefined;
  const refreshing = snapshot
    ? Option.getOrUndefined(ScanWorkflowStates.get(snapshot, 'Refreshing'))
    : undefined;
  const scans =
    ready?.scans ??
    submittingState?.scans ??
    waiting?.scans ??
    refreshing?.scans ??
    [];
  const selected = ready?.selected ?? waiting?.selected ?? refreshing?.selected;
  const submitting = Boolean(submittingState);
  const error = ready?.error ?? '';
  const createdReview = waiting?.route._tag === 'Review'
    ? waiting.route
    : refreshing?.route._tag === 'Review'
      ? refreshing.route
      : undefined;

  const submitScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    send(
      ScanWorkflowEvent.cases.Submit.make({
        repositoryUrl,
        displayName,
        audience,
      }),
    );
  };

  const result = selected?.result;
  const resultAudience = selected?.audience ?? audience;
  const visibleFindings = result?.findings.slice(0, 5) ?? [];
  const presentedHeadline = result
    ? decisionHeadline(
        result.summary.fixNow,
        result.summary.investigate,
        result.summary.monitor,
      )
    : '';
  let presentedChange = 'First';
  if (result?.comparison.previousScanId) {
    if (result.comparison.priorityDelta < -4) {
      presentedChange = 'Improved';
    } else if (result.comparison.priorityDelta > 4) {
      presentedChange = 'More work';
    } else {
      presentedChange = 'Stable';
    }
  }

  if (
    route._tag === 'NewReview' &&
    createdReview
  ) {
    return (
      <Navigate
        to="/reviews/$scanId"
        params={{ scanId: createdReview.scanId }}
        replace
      />
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" to="/" aria-label="Codebase Radar home">
          <span className="brand-mark" aria-hidden="true">
            <span />
          </span>
          <span>CODEBASE RADAR</span>
        </Link>
        {route._tag !== 'NewReview' ? (
          <Link className="new-review-button" to="/reviews/new">
            NEW REVIEW
          </Link>
        ) : null}
      </header>

      <main id="top">
        {route._tag !== 'Review' ? (
          <section className="hero-grid">
            <div className="hero-copy">
              <p className="eyebrow">Your codebase, in priority order</p>
              <h1>
                Fix the right <em>things.</em>
              </h1>
              <p className="lede">
                Paste a public GitHub link. Get the few changes worth doing first—and
                the noise you can safely leave alone.
              </p>
              <Link className="scan-button hero-action" to="/reviews/new">
                <span>START A REVIEW</span>
                <span aria-hidden="true">↗</span>
              </Link>
            </div>
          </section>
        ) : null}

        <section className="workspace">
          <aside className="scan-rail">
            <div className="section-heading">
              <span>RECENT REVIEWS</span>
              <span>{String(scans.length).padStart(2, '0')}</span>
            </div>
            {scans.length === 0 ? (
              <div className="empty-rail">Your first review starts here.</div>
            ) : (
              <div className="scan-list">
                {scans.map(scan => (
                  <Link
                    className={scan.id === selected?.id ? 'scan-item active' : 'scan-item'}
                    key={scan.id}
                    to="/reviews/$scanId"
                    params={{ scanId: scan.id }}
                  >
                    <span className={`status-mark ${scan.status}`} />
                    <span>
                      <strong>{scan.owner}/{scan.repository}</strong>
                      <small>{scan.stage}</small>
                    </span>
                    <b>{scan.progress}%</b>
                  </Link>
                ))}
              </div>
            )}
          </aside>

          <div className="results-panel">
            {route._tag === 'Review' && (!snapshot || loadingState) ? (
              <div className="running-state">
                <div className="scan-visual" aria-hidden="true">
                  <span className="sweep" />
                </div>
                <h2>Loading this review…</h2>
              </div>
            ) : route._tag === 'Review' && !selected && error ? (
              <div className="empty-state">
                <p>REVIEW NOT AVAILABLE</p>
                <h2>{error}</h2>
                <Link className="scan-button empty-action" to="/">
                  RETURN HOME
                </Link>
              </div>
            ) : !selected ? (
              <div className="empty-state">
                <span className="radar-orbit" aria-hidden="true"><i /></span>
                <p>NO REVIEW YET</p>
                <h2>Start with one clear list.</h2>
                <p className="empty-promise">What to do now, what to check, and what to leave alone.</p>
              </div>
            ) : !result ? (
              <div className="running-state">
                <div className="running-meta">
                  <span>{selected.owner}/{selected.repository}</span>
                  <span>{selected.status.toUpperCase()}</span>
                </div>
                <div className="scan-visual" aria-hidden="true">
                  <span className="sweep" />
                  <i className="ping one" />
                  <i className="ping two" />
                </div>
                <h2>{selected.stage}</h2>
                <div className="progress-track">
                  <span style={{ width: `${selected.progress}%` }} />
                </div>
                <p>{selected.progress}% complete</p>
                {selected.error ? <p className="error-note">{selected.error}</p> : null}
              </div>
            ) : (
              <>
                <div className="result-header">
                  <p className="eyebrow">Review {result.repository.commitSha.slice(0, 8)}</p>
                  <h2>{result.repository.owner}/{result.repository.name}</h2>
                  <p>{presentedHeadline}</p>
                </div>

                <div className="metric-row">
                  <div className="metric critical"><span>FIX NOW</span><b>{result.summary.fixNow}</b></div>
                  <div><span>CHECK</span><b>{result.summary.investigate}</b></div>
                  <div><span>WATCH</span><b>{result.summary.monitor}</b></div>
                  <div><span>LEAVE ALONE</span><b>{result.summary.doNotFix}</b></div>
                  <div><span>CHANGE</span><b>{presentedChange}</b></div>
                </div>

                <AgentPriority scan={selected} result={result} />

                <div className="backlog-head">
                  <div>
                    <p className="eyebrow">Your priority list</p>
                    <h3>What deserves attention.</h3>
                  </div>
                  <span>{audienceLabel[resultAudience]}</span>
                </div>

                <div className="finding-list">
                  {visibleFindings.map((finding, index) => {
                    const copy = audienceCopy(finding, resultAudience);
                    const analyzerFinding = finding.tags.includes('oxlint');
                    const consistencyPreference = finding.tags.includes('style-policy');
                    const presentedTitle = analyzerFinding
                      ? consistencyPreference
                        ? 'Consistency preference'
                        : analyzerTitle[finding.category]
                      : finding.title;
                    const presentedRecommendation = analyzerFinding
                      ? consistencyPreference
                        ? 'Apply this preference only while editing nearby code; do not schedule a repository-wide cleanup.'
                        : finding.category === 'security'
                          ? 'Inspect representative locations, confirm whether inputs can reach them, then fix the smallest proven risk.'
                          : 'Inspect representative locations, confirm the pattern matters, then address it within one bounded change.'
                      : copy.recommendation;
                    return (
                      <article className={`finding ${finding.action.replaceAll(' ', '-')}`} key={finding.id}>
                        <div className="finding-rank">{String(index + 1).padStart(2, '0')}</div>
                        <div className="finding-body">
                          <div className="finding-topline">
                            <span className="action-chip">{finding.action}</span>
                            <span>{finding.category}</span>
                            <span>{finding.statusComparedToPrevious}</span>
                          </div>
                          <h4>{presentedTitle}</h4>
                          <p>{copy.summary}</p>
                          <div className="recommendation">
                            <b>NEXT MOVE</b>
                            <span>{presentedRecommendation}</span>
                          </div>
                          <details className="finding-details">
                            <summary>Why this is ranked here</summary>
                            <div className="score-list">
                              <div><span>Consequence</span><b>{finding.scores.consequence}</b></div>
                              <div><span>Reach</span><b>{finding.scores.blastRadius}</b></div>
                              <div><span>Confidence</span><b>{finding.scores.confidence}</b></div>
                              <div><span>Effort</span><b>{finding.scores.effort}</b></div>
                              <div><span>Change risk</span><b>{finding.scores.changeExposure}</b></div>
                            </div>
                            <div className="evidence-list">
                              {finding.evidence.map((evidence, evidenceIndex) => (
                                <p key={`${finding.id}-${evidenceIndex}`}>
                                  <span>{evidence.message}</span>
                                  {evidence.path ? <code>{evidence.path}{evidence.line ? `:${evidence.line}` : ''}</code> : null}
                                </p>
                              ))}
                            </div>
                          </details>
                        </div>
                      </article>
                    );
                  })}
                </div>

                <details className="review-details">
                  <summary>Review details</summary>
                  <p>{result.analyzerRuns.filter(run => run.status === 'complete').length} of {result.analyzerRuns.length} checks completed.</p>
                  <p>{result.profile.limitations.join(' ')}</p>
                </details>
              </>
            )}
          </div>
        </section>
      </main>

      {route._tag === 'NewReview' ? (
        <>
          <Link
            className="dialog-backdrop"
            to="/"
            replace
            aria-label="Close new review"
          />
          <dialog className="review-dialog" open aria-labelledby="new-review-title">
            <form className="scan-console" onSubmit={submitScan}>
              <div className="console-head dialog-head">
                <span id="new-review-title">START A REVIEW</span>
                <Link to="/" replace aria-label="Close new review">CLOSE</Link>
              </div>
              <label className="field-label" htmlFor="repository-url">
                GitHub repository
              </label>
              <div className="url-input-wrap">
                <span aria-hidden="true">GH/</span>
                <input
                  id="repository-url"
                  type="url"
                  value={repositoryUrl}
                  onChange={event => setRepositoryUrl(event.currentTarget.value)}
                  placeholder="https://github.com/owner/repository"
                  required
                />
              </div>

              <fieldset>
                <legend>Explain this for</legend>
                <div className="audience-grid">
                  {audienceOptions.map(option => (
                    <label
                      className={option === audience ? 'audience active' : 'audience'}
                      key={option}
                    >
                      <input
                        type="radio"
                        name="audience"
                        value={option}
                        checked={option === audience}
                        onChange={() => setAudience(option)}
                      />
                      <span>{audienceLabel[option]}</span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <details className="profile-options">
                <summary>Personalize this view</summary>
                <label className="field-label" htmlFor="display-name">
                  Profile name <span>optional</span>
                </label>
                <input
                  className="name-input"
                  id="display-name"
                  value={displayName}
                  onChange={event => setDisplayName(event.currentTarget.value)}
                  placeholder="Ada / Platform team"
                  maxLength={80}
                />
              </details>

              <button className="scan-button" disabled={submitting} type="submit">
                <span>{submitting ? 'STARTING REVIEW' : 'SHOW ME WHAT MATTERS'}</span>
                <span aria-hidden="true">↗</span>
              </button>
              <p className="boundary-note">
                Read-only review. We never run your code.
              </p>
              {error ? <p className="error-note">{error}</p> : null}
            </form>
          </dialog>
        </>
      ) : null}

    </div>
  );
}

export function HomePage() {
  return <Radar route={ReviewRoute.cases.Home.make({})} />;
}

export function NewReviewPage() {
  return <Radar route={ReviewRoute.cases.NewReview.make({})} />;
}

export function ReviewPage() {
  const match = useMatch({ from: '/reviews/$scanId' });
  return (
    <Radar
      route={ReviewRoute.cases.Review.make({ scanId: match.params.scanId })}
    />
  );
}
