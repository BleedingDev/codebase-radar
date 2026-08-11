import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import * as publicApi from '../src/index.js';

const packageDirectory = resolve(import.meta.dirname, '..');
const typeScriptCompiler = resolve(packageDirectory, 'node_modules/.bin/tsc');

describe('public core boundary', () => {
  it('exports the supported analysis, strict preflight, and trusted production composition', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'AnalysisObserver',
      'AnalysisObserverNoop',
      'RadarAnalysis',
      'RadarAnalysisLive',
      'RadarRuntimeEvidence',
      'RadarRuntimeEvidenceStatus',
      'RadarRuntimeManifest',
      'RadarRuntimePreflight',
      'RadarRuntimeReport',
      'RadarRuntimeReportSchema',
      'RadarRuntimeStatus',
      'decodeRadarRuntimeReport',
      'makeProductionRadarRuntimePreflight',
      'makeRadarProductionLayer',
      'makeUnavailableRadarRuntimePreflight',
      'verifyTrustedRadarAnalyzerRuntime',
    ]);
  });

  it('emits declarations without private source or analyzer tags', () => {
    const declarationDirectory = mkdtempSync(
      join(tmpdir(), 'radar-core-public-api-'),
    );
    try {
      execFileSync(
        typeScriptCompiler,
        [
          '--project',
          'tsconfig.json',
          '--declaration',
          '--emitDeclarationOnly',
          '--noEmit',
          'false',
          '--outDir',
          declarationDirectory,
          '--rootDir',
          '.',
        ],
        { cwd: packageDirectory },
      );
      const scannerDeclaration = readFileSync(
        join(declarationDirectory, 'src/scanner.d.ts'),
        'utf8',
      );
      expect(scannerDeclaration).not.toMatch(
        /AnalyzerRuntime|IsolatedWorkspace|ProcessExecutor|SourceMaterializer|WorkspaceAllocator|internal\/(?:analyzers|source|workspace)/u,
      );
      const productionDeclaration = readFileSync(
        join(declarationDirectory, 'src/production.d.ts'),
        'utf8',
      );
      expect(productionDeclaration).not.toMatch(/internal\//u);
    } finally {
      rmSync(declarationDirectory, { force: true, recursive: true });
    }
  });
});
