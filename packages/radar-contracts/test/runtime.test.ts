import { describe, expect, it } from 'vitest';
import { Effect, Schema } from 'effect';
import { ContractLimits } from '../src/primitives.js';
import {
  SemanticAnalyzerInventoryEntry,
  SemanticAnalyzerInventoryValue,
  SemanticAnalyzerProcessRequest,
} from '../src/runtime.js';

const decodeRequest = Schema.decodeUnknownEffect(SemanticAnalyzerProcessRequest, {
  onExcessProperty: 'error',
});

const inventoryEntry = () => new SemanticAnalyzerInventoryEntry({
  path: 'src/main.ts',
  byteLength: 120,
  analyzers: [
    'Oxlint + Ultracite',
    'JSCPD',
    'Calldiff',
    'TraceDecay',
  ],
});

const inventory = () =>
  new SemanticAnalyzerInventoryValue({
    entries: [inventoryEntry()],
    frameworks: ['react'],
    truncated: false,
  });

const request = () =>
  new SemanticAnalyzerProcessRequest({
    schemaVersion: 'codebase-radar.semantic-analyzer-request/v1',
    analysisPolicy: SemanticAnalyzerProcessRequest.canonicalPolicy,
    analyzer: 'Calldiff',
    inventory: inventory(),
  });

describe('semantic analyzer process request', () => {
  it('accepts one canonical bounded inventory shared by core and runtime', () => {
    expect(Effect.runSync(decodeRequest(request()))).toEqual(request());
  });

  it('rejects duplicate, reversed, empty, and excess analyzer evidence', () => {
    const baseline = request();
    const invalidAnalyzers = [
      [],
      ['Calldiff', 'JSCPD'],
      ['Calldiff', 'Calldiff'],
    ];
    for (const analyzers of invalidAnalyzers) {
      const value = {
        ...baseline,
        inventory: {
          ...baseline.inventory,
          entries: [{ ...inventoryEntry(), analyzers }],
        },
      };
      expect(Effect.runSyncExit(decodeRequest(value))._tag).toBe('Failure');
    }
    expect(Effect.runSyncExit(decodeRequest({ ...baseline, extra: true }))._tag).toBe(
      'Failure',
    );
  });

  it('rejects duplicate or reversed paths and framework ordering', () => {
    const baseline = request();
    const first = inventoryEntry();
    const invalidInventories = [
      { ...baseline.inventory, entries: [first, first] },
      {
        ...baseline.inventory,
        entries: [
          { ...first, path: 'src/z.ts' },
          { ...first, path: 'src/a.ts' },
        ],
      },
      { ...baseline.inventory, frameworks: ['vue', 'react'] },
    ];
    for (const invalidInventory of invalidInventories) {
      expect(
        Effect.runSyncExit(decodeRequest({ ...baseline, inventory: invalidInventory }))._tag,
      ).toBe('Failure');
    }
  });

  it('uses UTF-8 byte order rather than JavaScript UTF-16 order for inventory paths', () => {
    const baseline = request();
    const bmp = { ...inventoryEntry(), path: 'src/\uE000.ts' };
    const supplementary = { ...inventoryEntry(), path: 'src/\u{10000}.ts' };
    const canonical = {
      ...baseline,
      inventory: {
        ...baseline.inventory,
        entries: [bmp, supplementary],
      },
    };
    expect(Effect.runSyncExit(decodeRequest(canonical))._tag).toBe('Success');
    expect(
      Effect.runSyncExit(
        decodeRequest({
          ...canonical,
          inventory: { ...canonical.inventory, entries: [supplementary, bmp] },
        }),
      )._tag,
    ).toBe('Failure');
  });

  it('enforces exact inventory boundaries', () => {
    const entries = Array.from(
      { length: ContractLimits.semanticAnalyzerInventoryEntries },
      (_, index) =>
        new SemanticAnalyzerInventoryEntry({
          path: `src/file-${index.toString().padStart(4, '0')}.ts`,
          byteLength: 1,
          analyzers: ['Calldiff'],
        }),
    );
    const boundary = {
      ...request(),
      inventory: {
        ...inventory(),
        entries,
      },
    };
    expect(Effect.runSyncExit(decodeRequest(boundary))._tag).toBe('Success');
    const excess = {
      ...boundary,
      inventory: {
        ...boundary.inventory,
        entries: [
          ...entries,
          new SemanticAnalyzerInventoryEntry({
            path: 'src/file-excess.ts',
            byteLength: 1,
            analyzers: ['Calldiff'],
          }),
        ],
      },
    };
    expect(Effect.runSyncExit(decodeRequest(excess))._tag).toBe('Failure');
    expect(
      Effect.runSyncExit(
        decodeRequest({
          ...request(),
          inventory: {
            ...inventory(),
            entries: [{ ...inventoryEntry(), byteLength: Number.MAX_SAFE_INTEGER }],
          },
        }),
      )._tag,
    ).toBe('Failure');
  });

  it('enforces actual UTF-8 JSON request bytes at exact, +1, and wide boundaries', () => {
    const entries = Array.from(
      { length: ContractLimits.semanticAnalyzerInventoryEntries },
      (_, index) => ({
        path: `src/file-${index.toString().padStart(4, '0')}${index === 0 ? '-λ' : ''}.ts`,
        byteLength: 1,
        analyzers: ['Calldiff'],
      }),
    );
    const atLimit = {
      ...request(),
      inventory: {
        ...inventory(),
        entries,
      },
    };
    const utf8 = new TextEncoder();
    let remaining =
      ContractLimits.semanticAnalyzerRequestBytes - utf8.encode(JSON.stringify(atLimit)).byteLength;
    expect(remaining).toBeGreaterThan(0);
    for (let index = 0; index < entries.length && remaining > 0; index += 1) {
      const entry = entries[index];
      expect(entry).toBeDefined();
      if (entry === undefined) continue;
      const extension = '.ts';
      const capacity = ContractLimits.pathCharacters - entry.path.length;
      const added = Math.min(capacity, remaining);
      entries[index] = {
        ...entry,
        path: `${entry.path.slice(0, -extension.length)}${'x'.repeat(added)}${extension}`,
      };
      remaining -= added;
    }
    expect(remaining).toBe(0);
    expect(utf8.encode(JSON.stringify(atLimit)).byteLength).toBe(
      ContractLimits.semanticAnalyzerRequestBytes,
    );
    expect(Effect.runSyncExit(decodeRequest(atLimit))._tag).toBe('Success');

    const overLimitEntries = atLimit.inventory.entries.map(entry => ({ ...entry }));
    const expandableIndex = overLimitEntries.findIndex(
      entry => entry.path.length < ContractLimits.pathCharacters,
    );
    expect(expandableIndex).toBeGreaterThanOrEqual(0);
    const expandable = overLimitEntries[expandableIndex];
    expect(expandable).toBeDefined();
    if (expandable === undefined) return;
    overLimitEntries[expandableIndex] = {
      ...expandable,
      path: `${expandable.path.slice(0, -3)}x.ts`,
    };
    const overLimit = {
      ...atLimit,
      inventory: {
        ...atLimit.inventory,
        entries: overLimitEntries,
      },
    };
    expect(utf8.encode(JSON.stringify(overLimit)).byteLength).toBe(
      ContractLimits.semanticAnalyzerRequestBytes + 1,
    );
    expect(Effect.runSyncExit(decodeRequest(overLimit))._tag).toBe('Failure');

    const wideEntries = Array.from(
      { length: ContractLimits.semanticAnalyzerInventoryEntries },
      (_, index) => {
        const prefix = `src/wide-${index.toString().padStart(4, '0')}-`;
        return {
          path: `${prefix}${'x'.repeat(ContractLimits.pathCharacters - prefix.length - 3)}.ts`,
          byteLength: 1,
          analyzers: ['Calldiff'],
        };
      },
    );
    const wide = {
      ...request(),
      inventory: {
        ...inventory(),
        entries: wideEntries,
      },
    };
    expect(utf8.encode(JSON.stringify(wide)).byteLength).toBeGreaterThan(8_600_000);
    expect(Effect.runSyncExit(decodeRequest(wide))._tag).toBe('Failure');
  });
});
