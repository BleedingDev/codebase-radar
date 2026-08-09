import { Effect } from '@modern-js/plugin-bff/effect-client';
import { makeEffectHttpApiClient } from '@modern-js/plugin-bff/effect-client';
import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { RadarApi } from '../shared/api';
import { audienceCopy, audienceLabel } from '../shared/audience';
import { Audience, ScanRecord } from '../shared/domain';
import './styles.css';

const RadarClient = makeEffectHttpApiClient(RadarApi, { baseUrl: '/api' });

const audienceOptions = Audience.literals;
const frameworkProfiles = ['React', 'Angular', 'Vue', 'Svelte', 'Solid'];

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState(
    'https://github.com/realworld-apps/angular-realworld-example-app',
  );
  const [displayName, setDisplayName] = useState('');
  const [audience, setAudience] = useState<ScanRecord['audience']>('technical');
  const [scans, setScans] = useState<ReadonlyArray<ScanRecord>>([]);
  const [selected, setSelected] = useState<ScanRecord>();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const loadScans = useCallback(() => {
    Effect.runFork(
      RadarClient.pipe(
        Effect.flatMap(client =>
          client.radar.listScans({ query: { limit: 8 } }),
        ),
        Effect.tap(response =>
          Effect.sync(() => {
            setScans(response.items);
            setSelected(current => current ?? response.items[0]);
          }),
        ),
        Effect.catch(errorValue =>
          Effect.sync(() => setError(String(errorValue))),
        ),
      ),
    );
  }, []);

  const loadScan = useCallback((scanId: string) => {
    Effect.runFork(
      RadarClient.pipe(
        Effect.flatMap(client =>
          client.radar.getScan({ params: { scanId } }),
        ),
        Effect.tap(scan =>
          Effect.sync(() => {
            setSelected(scan);
            setScans(current =>
              current.map(item => (item.id === scan.id ? scan : item)),
            );
          }),
        ),
        Effect.catch(errorValue =>
          Effect.sync(() => setError(String(errorValue))),
        ),
      ),
    );
  }, []);

  useEffect(loadScans, [loadScans]);

  useEffect(() => {
    if (!selected || !['queued', 'running'].includes(selected.status)) return;
    const interval = window.setInterval(() => loadScan(selected.id), 1_800);
    return () => window.clearInterval(interval);
  }, [loadScan, selected]);

  const submitScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    Effect.runFork(
      RadarClient.pipe(
        Effect.flatMap(client =>
          client.radar
            .createProfile({
              payload: {
                audience,
                ...(displayName.trim()
                  ? { displayName: displayName.trim() }
                  : {}),
              },
            })
            .pipe(
              Effect.flatMap(profile =>
                client.radar.createScan({
                  payload: {
                    githubUrl: repositoryUrl,
                    audience,
                    profileId: profile.id,
                  },
                }),
              ),
            ),
        ),
        Effect.tap(scan =>
          Effect.sync(() => {
            setSelected(scan);
            setScans(current => [
              scan,
              ...current.filter(item => item.id !== scan.id),
            ]);
            setSubmitting(false);
          }),
        ),
        Effect.catch(errorValue =>
          Effect.sync(() => {
            setError(String(errorValue));
            setSubmitting(false);
          }),
        ),
      ),
    );
  };

  const result = selected?.result;
  const visibleFindings = result?.findings.slice(0, 5) ?? [];

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Codebase Radar home">
          <span className="brand-mark" aria-hidden="true">
            <span />
          </span>
          <span>CODEBASE RADAR</span>
        </a>
        <div className="runtime-chip">
          <span className="live-dot" /> UltraModern · Effect · TraceDecay
        </div>
      </header>

      <main id="top">
        <section className="hero-grid">
          <div className="hero-copy">
            <p className="eyebrow">Static code intelligence, ranked for action</p>
            <h1>
              Know what to fix <em>next.</em>
            </h1>
            <p className="lede">
              Give Radar a public GitHub repository. Get one short, evidence-backed
              improvement queue with consequence, confidence, effort, and blast
              radius kept separate.
            </p>
            <div className="framework-strip" aria-label="Supported frameworks">
              {frameworkProfiles.map(framework => (
                <span key={framework}>{framework}</span>
              ))}
            </div>
          </div>

          <form className="scan-console" onSubmit={submitScan}>
            <div className="console-head">
              <span>NEW SNAPSHOT</span>
              <span className="console-index">01</span>
            </div>
            <label className="field-label" htmlFor="repository-url">
              Public GitHub repository
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
              <legend>Communication profile</legend>
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
                    <small>
                      {option === 'technical'
                        ? 'Mechanism + remediation'
                        : option === 'security'
                          ? 'Exposure + evidence limits'
                          : 'Consequence + decision'}
                    </small>
                  </label>
                ))}
              </div>
            </fieldset>

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

            <button className="scan-button" disabled={submitting} type="submit">
              <span>{submitting ? 'QUEUING SNAPSHOT' : 'SCAN & PRIORITIZE'}</span>
              <span aria-hidden="true">↗</span>
            </button>
            <p className="boundary-note">
              No installs, builds, tests, hooks, submodules, or repository code.
            </p>
            {error ? <p className="error-note">{error}</p> : null}
          </form>
        </section>

        <section className="workspace">
          <aside className="scan-rail">
            <div className="section-heading">
              <span>SNAPSHOTS</span>
              <span>{String(scans.length).padStart(2, '0')}</span>
            </div>
            {scans.length === 0 ? (
              <div className="empty-rail">Your first repository snapshot starts here.</div>
            ) : (
              <div className="scan-list">
                {scans.map(scan => (
                  <button
                    type="button"
                    className={scan.id === selected?.id ? 'scan-item active' : 'scan-item'}
                    key={scan.id}
                    onClick={() => setSelected(scan)}
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
            <div className="rail-foot">
              <span>MCP</span>
              <code>/api/mcp</code>
              <small>Read-only agent taskpacks</small>
            </div>
          </aside>

          <div className="results-panel">
            {!selected ? (
              <div className="empty-state">
                <span className="radar-orbit" aria-hidden="true"><i /></span>
                <p>NO SNAPSHOT SELECTED</p>
                <h2>One queue. Multiple signals. Explicit uncertainty.</h2>
                <div className="method-grid">
                  <div><b>01</b><span>Bounded repository inventory</span></div>
                  <div><b>02</b><span>Independent static analyzers</span></div>
                  <div><b>03</b><span>TraceDecay structural evidence</span></div>
                  <div><b>04</b><span>Deterministic priority model</span></div>
                </div>
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
                <p>{selected.progress}% · the HTTP service stays responsive during bounded child processes.</p>
                {selected.error ? <p className="error-note">{selected.error}</p> : null}
              </div>
            ) : (
              <>
                <div className="result-header">
                  <div>
                    <p className="eyebrow">Snapshot {result.repository.commitSha.slice(0, 8)}</p>
                    <h2>{result.repository.owner}/{result.repository.name}</h2>
                    <p>{result.summary.headline}</p>
                  </div>
                  <div className="health-dial">
                    <span>HEALTH</span>
                    <strong>{result.summary.healthScore}</strong>
                    <small>/ 100</small>
                  </div>
                </div>

                <div className="metric-row">
                  <div className="metric critical"><span>FIX NOW</span><b>{result.summary.fixNow}</b></div>
                  <div><span>INVESTIGATE</span><b>{result.summary.investigate}</b></div>
                  <div><span>MONITOR</span><b>{result.summary.monitor}</b></div>
                  <div><span>DO NOT FIX</span><b>{result.summary.doNotFix}</b></div>
                  <div><span>PRIORITY Δ</span><b>{result.comparison.priorityDelta > 0 ? '+' : ''}{result.comparison.priorityDelta}</b></div>
                </div>

                <div className="backlog-head">
                  <div>
                    <p className="eyebrow">Prioritized improvement backlog</p>
                    <h3>Signal over volume.</h3>
                  </div>
                  <span>{audienceLabel[audience]}</span>
                </div>

                <div className="finding-list">
                  {visibleFindings.map((finding, index) => {
                    const copy = audienceCopy(finding, audience);
                    return (
                      <article className={`finding ${finding.action.replaceAll(' ', '-')}`} key={finding.id}>
                        <div className="finding-rank">{String(index + 1).padStart(2, '0')}</div>
                        <div className="finding-body">
                          <div className="finding-topline">
                            <span className="action-chip">{finding.action}</span>
                            <span>{finding.category}</span>
                            <span>{finding.statusComparedToPrevious}</span>
                          </div>
                          <h4>{finding.title}</h4>
                          <p>{copy.summary}</p>
                          <div className="recommendation">
                            <b>NEXT MOVE</b>
                            <span>{copy.recommendation}</span>
                          </div>
                          <details>
                            <summary>Evidence & limits · {finding.evidence.length}</summary>
                            <div className="evidence-list">
                              {finding.evidence.map((evidence, evidenceIndex) => (
                                <p key={`${finding.id}-${evidenceIndex}`}>
                                  <b>{evidence.analyzer}</b>
                                  <span>{evidence.message}</span>
                                  {evidence.path ? <code>{evidence.path}{evidence.line ? `:${evidence.line}` : ''}</code> : null}
                                </p>
                              ))}
                            </div>
                          </details>
                        </div>
                        <div className="score-stack">
                          <strong>{finding.scores.priority}</strong>
                          <span>PRIORITY</span>
                          <dl>
                            <div><dt>Consequence</dt><dd>{finding.scores.consequence}</dd></div>
                            <div><dt>Blast radius</dt><dd>{finding.scores.blastRadius}</dd></div>
                            <div><dt>Confidence</dt><dd>{finding.scores.confidence}</dd></div>
                            <div><dt>Effort</dt><dd>{finding.scores.effort}</dd></div>
                            <div><dt>Exposure</dt><dd>{finding.scores.changeExposure}</dd></div>
                          </dl>
                        </div>
                      </article>
                    );
                  })}
                </div>

                <section className="coverage-section">
                  <div className="section-heading">
                    <span>ANALYZER COVERAGE</span>
                    <span>{result.analyzerRuns.length} SOURCES</span>
                  </div>
                  <div className="coverage-table">
                    {result.analyzerRuns.map(run => (
                      <div className="coverage-row" key={run.analyzer}>
                        <div><span className={`status-mark ${run.status}`} /><b>{run.analyzer}</b></div>
                        <span>{run.status.replaceAll('_', ' ')}</span>
                        <span>{run.coverage.analyzedFiles}/{run.coverage.eligibleFiles} files</span>
                        <span>{run.observationCount} signals</span>
                        <span>{Math.round(run.durationMs / 100) / 10}s</span>
                      </div>
                    ))}
                  </div>
                  <p className="coverage-limit">{result.profile.limitations.join(' · ')}</p>
                </section>
              </>
            )}
          </div>
        </section>
      </main>

      <footer>
        <span>CODEBASE RADAR / MVP 0.1</span>
        <span>Evidence is not runtime truth.</span>
        <a href="https://github.com/BleedingDev/codebase-radar">SOURCE ↗</a>
      </footer>
    </div>
  );
}
