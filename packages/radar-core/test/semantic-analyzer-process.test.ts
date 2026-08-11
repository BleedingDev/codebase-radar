import {
  RequiredAnalyzerIds,
  SemanticAnalyzerInventoryEntry,
  SemanticAnalyzerInventoryValue,
  SemanticAnalyzerProcessRequest,
} from '@codebase-radar/contracts';
import { Effect, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  ProcessRequest,
  encodeSemanticAnalyzerRequest,
} from '../src/internal/process/index.js';

const inventory = new SemanticAnalyzerInventoryValue({
  entries: [
    new SemanticAnalyzerInventoryEntry({
      path: 'src/index.ts',
      byteLength: 42,
      analyzers: [
        'Oxlint + Ultracite',
        'JSCPD',
        'Calldiff',
        'TraceDecay',
      ],
    }),
    new SemanticAnalyzerInventoryEntry({
      path: 'tsconfig.json',
      byteLength: 64,
      analyzers: ['strictest-comparator'],
    }),
  ],
  frameworks: [],
  truncated: false,
});

const decodeRequest = Schema.decodeUnknownSync(
  Schema.fromJsonString(SemanticAnalyzerProcessRequest),
  { onExcessProperty: 'error' },
);

describe('semantic analyzer process protocol', () => {
  it('strictly encodes the canonical audited inventory and selected analyzer', () => {
    const bytes = Effect.runSync(encodeSemanticAnalyzerRequest(new ProcessRequest({
      analyzer: 'Calldiff',
      inventory,
      timeoutMs: 120_000,
      maxOutputBytes: 8 * 1024 * 1024,
    })));
    const decoded = decodeRequest(new TextDecoder().decode(bytes));
    expect(decoded.analysisPolicy).toBe('dogfood:max/v1');
    expect(decoded.analyzer).toBe('Calldiff');
    expect(decoded.inventory.entries).toEqual(inventory.entries);
  });

  it('rejects a noncanonical inventory before the host can spawn a runner', () => {
    const invalid = new SemanticAnalyzerInventoryValue({
      entries: [
        new SemanticAnalyzerInventoryEntry({
          path: 'tsconfig.json',
          byteLength: 64,
          analyzers: ['strictest-comparator'],
        }),
        new SemanticAnalyzerInventoryEntry({
          path: 'src/index.ts',
          byteLength: 42,
          analyzers: ['Calldiff'],
        }),
      ],
      frameworks: [],
      truncated: false,
    });
    expect(() => new ProcessRequest({
        analyzer: RequiredAnalyzerIds[0] ?? 'strictest-comparator',
        inventory: invalid,
        timeoutMs: 120_000,
        maxOutputBytes: 8 * 1024 * 1024,
      })).toThrow(/canonical/u);
  });
});
