import { Effect } from '@modern-js/plugin-bff/effect-client';
import { Machine } from '@typeonce/effect-machine';
import { Fiber, Schema, Stream } from 'effect';
import { useEffect, useRef, useState } from 'react';
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

const ScanWorkflowState = Schema.TaggedUnion({
  Loading: {},
  Ready: {
    scans: Schema.Array(ScanRecord),
    selected: Schema.NullOr(ScanRecord),
    showScanner: Schema.Boolean,
    error: Schema.String,
  },
  Submitting: {
    scans: Schema.Array(ScanRecord),
    selected: Schema.NullOr(ScanRecord),
    repositoryUrl: Schema.String,
    displayName: Schema.String,
    audience: Audience,
  },
  Refreshing: {
    scans: Schema.Array(ScanRecord),
    selected: ScanRecord,
    showScanner: Schema.Boolean,
  },
});

const ScanWorkflowEvent = Schema.TaggedUnion({
  Select: { scan: ScanRecord },
  ToggleScanner: {},
  Refresh: {},
  Submit: {
    repositoryUrl: Schema.String,
    displayName: Schema.String,
    audience: Audience,
  },
});

const ScanWorkflowResult = Schema.TaggedUnion({
  Loaded: { scans: Schema.Array(ScanRecord) },
  LoadFailed: {},
  ScanCreated: { scan: ScanRecord },
  SubmitFailed: {},
  PollComplete: { scan: ScanRecord },
  PollFailed: {},
});

const ScanWorkflowStates = Machine.defineStates(ScanWorkflowState.cases);

const ScanWorkflow = Machine.make({
  id: 'ScanWorkflow',
  states: ScanWorkflowStates.states,
  events: [
    ScanWorkflowEvent.cases.Select,
    ScanWorkflowEvent.cases.ToggleScanner,
    ScanWorkflowEvent.cases.Refresh,
    ScanWorkflowEvent.cases.Submit,
  ],
  internalEvents: [
    ScanWorkflowResult.cases.Loaded,
    ScanWorkflowResult.cases.LoadFailed,
    ScanWorkflowResult.cases.ScanCreated,
    ScanWorkflowResult.cases.SubmitFailed,
    ScanWorkflowResult.cases.PollComplete,
    ScanWorkflowResult.cases.PollFailed,
  ],
  initial: () => ScanWorkflowStates.initial.Loading.from(),
}).handle({
  Loading: {
    invoke: () =>
      Machine.invokeEffect({
        id: 'load-reviews',
        effect: RadarClient.pipe(
          Effect.flatMap(client =>
            client.radar.listScans({ query: { limit: 8 } }),
          ),
        ),
        onSuccess: response =>
          ScanWorkflowResult.cases.Loaded.make({ scans: response.items }),
        onFailure: () => ScanWorkflowResult.cases.LoadFailed.make({}),
      }),
    on: {
      Loaded: ({ event, target }) =>
        target.full.Ready.from({
          scans: event.scans,
          selected: event.scans[0] ?? null,
          showScanner: false,
          error: '',
        }),
      LoadFailed: ({ target }) =>
        target.full.Ready.from({
          scans: [],
          selected: null,
          showScanner: true,
          error: 'Reviews could not be loaded. Refresh and try again.',
        }),
    },
  },
  Ready: {
    on: {
      Select: ({ event, state, target }) =>
        target.full.Ready.from({
          ...state,
          selected: event.scan,
          error: '',
        }),
      ToggleScanner: ({ state, target }) =>
        target.full.Ready.from({
          ...state,
          showScanner: !state.showScanner,
        }),
      Submit: ({ event, state, target }) =>
        target.full.Submitting.from({
          scans: state.scans,
          selected: state.selected,
          repositoryUrl: event.repositoryUrl,
          displayName: event.displayName,
          audience: event.audience,
        }),
      Refresh: ({ state, target }) =>
        state.selected
          ? target.full.Refreshing.from({
              scans: state.scans,
              selected: state.selected,
              showScanner: state.showScanner,
            })
          : undefined,
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
      PollComplete: ({ event, state, target }) =>
        target.full.Ready.from({
          scans: state.scans.map(item =>
            item.id === event.scan.id ? event.scan : item,
          ),
          selected: event.scan,
          showScanner: state.showScanner,
          error: '',
        }),
      PollFailed: ({ state, target }) =>
        target.full.Ready.from({
          scans: state.scans,
          selected: state.selected,
          showScanner: state.showScanner,
          error: 'This review could not be refreshed. Trying again.',
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
        target.full.Ready.from({
          scans: [
            event.scan,
            ...state.scans.filter(item => item.id !== event.scan.id),
          ],
          selected: event.scan,
          showScanner: false,
          error: '',
        }),
      SubmitFailed: ({ state, target }) =>
        target.full.Ready.from({
          scans: state.scans,
          selected: state.selected,
          showScanner: true,
          error: 'The review could not be started. Check the link and try again.',
        }),
    },
  },
});

const ScanWorkflowStart = Machine.start(ScanWorkflow);

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState(
    'https://github.com/realworld-apps/angular-realworld-example-app',
  );
  const [displayName, setDisplayName] = useState('');
  const [audience, setAudience] = useState<ScanRecord['audience']>('technical');
  const workflowRef = useRef<Effect.Success<typeof ScanWorkflowStart> | undefined>(
    undefined,
  );
  const [workflow, setWorkflow] = useState<
    Machine.Machine.Snapshot<Machine.Machine.States<typeof ScanWorkflow>>
  >();

  useEffect(() => {
    const fiber = Effect.runFork(
      Effect.scoped(
        Effect.gen(function* () {
          const ref = yield* ScanWorkflowStart;
          workflowRef.current = ref;
          yield* ref.state.pipe(
            Effect.tap(snapshot => Effect.sync(() => setWorkflow(snapshot))),
          );
          yield* ref.changes.pipe(
            Stream.runForEach(snapshot =>
              Effect.sync(() => setWorkflow(snapshot.state)),
            ),
          );
        }),
      ),
    );
    return () => {
      workflowRef.current = undefined;
      Effect.runFork(Fiber.interrupt(fiber));
    };
  }, []);

  const send = (event: Machine.Machine.InputEvent<typeof ScanWorkflow>) => {
    const ref = workflowRef.current;
    if (ref) Effect.runFork(ref.send(event));
  };

  const workflowValue = workflow?.value;
  const settled =
    workflowValue?._tag === 'Ready' ||
    workflowValue?._tag === 'Submitting' ||
    workflowValue?._tag === 'Refreshing'
      ? workflowValue
      : undefined;
  const scans = settled?.scans ?? [];
  const selected = settled?.selected ?? undefined;
  const showScanner =
    workflowValue?._tag === 'Ready' || workflowValue?._tag === 'Refreshing'
      ? workflowValue.showScanner
      : false;
  const submitting = workflowValue?._tag === 'Submitting';
  const error = workflowValue?._tag === 'Ready' ? workflowValue.error : '';

  useEffect(() => {
    if (
      workflowValue?._tag !== 'Ready' ||
      !selected ||
      (selected.status !== 'queued' && selected.status !== 'running')
    ) return;
    const timeout = window.setTimeout(
      () => send(ScanWorkflowEvent.cases.Refresh.make({})),
      1_800,
    );
    return () => window.clearTimeout(timeout);
  }, [selected, workflowValue?._tag]);

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

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Codebase Radar home">
          <span className="brand-mark" aria-hidden="true">
            <span />
          </span>
          <span>CODEBASE RADAR</span>
        </a>
        {selected ? (
          <button
            className="new-review-button"
            type="button"
            onClick={() => send(ScanWorkflowEvent.cases.ToggleScanner.make({}))}
          >
            {showScanner ? 'CLOSE' : 'NEW REVIEW'}
          </button>
        ) : null}
      </header>

      <main id="top">
        <section
          className={selected ? 'hero-grid repeat' : 'hero-grid'}
          hidden={selected ? !showScanner : false}
        >
          <div className="hero-copy">
            <p className="eyebrow">Your codebase, in priority order</p>
            <h1>
              Fix the right <em>things.</em>
            </h1>
            <p className="lede">
              Paste a public GitHub link. Get the few changes worth doing first—and
              the noise you can safely leave alone.
            </p>
          </div>

          <form className="scan-console" onSubmit={submitScan}>
            <div className="console-head">
              <span>START A REVIEW</span>
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
        </section>

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
                  <button
                    type="button"
                    className={scan.id === selected?.id ? 'scan-item active' : 'scan-item'}
                    key={scan.id}
                    onClick={() =>
                      send(ScanWorkflowEvent.cases.Select.make({ scan }))
                    }
                  >
                    <span className={`status-mark ${scan.status}`} />
                    <span>
                      <strong>{scan.owner}/{scan.repository}</strong>
                      <small>{scan.stage}</small>
                    </span>
                    <b>{scan.progress}%</b>
                  </button>
                ))}
              </div>
            )}
          </aside>

          <div className="results-panel">
            {!selected ? (
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

    </div>
  );
}
