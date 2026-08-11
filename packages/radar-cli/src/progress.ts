import { Effect } from 'effect';
import type { AnalysisProgress } from '@codebase-radar/contracts';
import { writeStderr } from './io.js';
import { safeHumanText } from './render.js';

export interface ProgressPresentation {
  readonly quiet: boolean;
  readonly isTty: boolean;
}

const progressLabel = (progress: AnalysisProgress) =>
  progress._tag === 'AnalysisProgressTerminal'
    ? `terminal ${progress.outcome}`
    : progress.stage;

export const renderProgress = (progress: AnalysisProgress) =>
  `${safeHumanText(progressLabel(progress))} ${progress.completedWork}/${progress.totalWork} (${progress.percent}%)`;

export const presentProgress = (
  presentation: ProgressPresentation,
  progress: AnalysisProgress,
) => {
  if (presentation.quiet) return Effect.void;
  const line = renderProgress(progress);
  const suffix = presentation.isTty && !progress.terminal ? '\r' : '\n';
  return writeStderr(`${presentation.isTty && !progress.terminal ? '\r' : ''}${line}${suffix}`);
};
