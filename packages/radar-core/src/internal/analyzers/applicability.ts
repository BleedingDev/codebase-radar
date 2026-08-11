import { RequiredAnalyzerIds } from '@codebase-radar/contracts';
import type { RepositoryInventory } from '../inventory/index.js';

/**
 * Computes applicability from the audited inventory rather than trusting a
 * runtime's self-description. A `not_applicable` run is valid only when this
 * count is zero.
 */
export const eligiblePathsForAnalyzer = (
  analyzer: typeof RequiredAnalyzerIds[number],
  inventory: RepositoryInventory,
): ReadonlyArray<string> => inventory.analyzerInventory.entries
  .filter(entry => entry.analyzers.includes(analyzer))
  .map(entry => entry.path);

export const eligibleFilesForAnalyzer = (
  analyzer: typeof RequiredAnalyzerIds[number],
  inventory: RepositoryInventory,
): number => eligiblePathsForAnalyzer(analyzer, inventory).length;

export const isAnalyzerApplicable = (
  analyzer: typeof RequiredAnalyzerIds[number],
  inventory: RepositoryInventory,
): boolean => eligibleFilesForAnalyzer(analyzer, inventory) > 0;
