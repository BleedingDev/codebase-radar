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

const analyzerTitle = {
  security: 'Risky code pattern',
  reliability: 'Reliability concern',
  maintainability: 'Maintainability concern',
  performance: 'Performance concern',
  architecture: 'Dependency concern',
  configuration: 'Configuration concern',
};

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState(
    'https://github.com/realworld-apps/angular-realworld-example-app',
  );
  const [displayName, setDisplayName] = useState('');
  const [audience, setAudience] = useState<ScanRecord['audience']>('technical');
  const [scans, setScans] = useState<ReadonlyArray<ScanRecord>>([]);
  const [selected, setSelected] = useState<ScanRecord>();
  const [showScanner, setShowScanner] = useState(false);
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
            setShowScanner(false);
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
  const resultAudience = selected?.audience ?? audience;
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
        {selected ? (
          <button
            className="new-review-button"
            type="button"
            onClick={() => setShowScanner(current => !current)}
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
                  <div>
                    <p className="eyebrow">Review {result.repository.commitSha.slice(0, 8)}</p>
                    <h2>{result.repository.owner}/{result.repository.name}</h2>
                    <p>{result.summary.headline}</p>
                  </div>
                  <div className="health-dial">
                    <span>OVERALL</span>
                    <strong>{result.summary.healthScore}</strong>
                    <small>/ 100</small>
                  </div>
                </div>

                <div className="metric-row">
                  <div className="metric critical"><span>FIX NOW</span><b>{result.summary.fixNow}</b></div>
                  <div><span>CHECK</span><b>{result.summary.investigate}</b></div>
                  <div><span>WATCH</span><b>{result.summary.monitor}</b></div>
                  <div><span>LEAVE ALONE</span><b>{result.summary.doNotFix}</b></div>
                  <div><span>SINCE LAST</span><b>{result.comparison.previousScanId ? `${result.comparison.priorityDelta > 0 ? '+' : ''}${result.comparison.priorityDelta}` : '—'}</b></div>
                </div>

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
