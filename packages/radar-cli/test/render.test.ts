import { readFileSync } from 'node:fs';
import { Effect } from 'effect';
import { describe, expect, it } from 'vitest';
import { decodeScanResultJson } from '@codebase-radar/contracts';
import { encodeScanOutput } from '../src/result.js';
import { renderHumanScanResult } from '../src/render.js';

const artifact = (name: string) =>
  readFileSync(
    new URL(`../../radar-testkit/golden/artifacts/${name}`, import.meta.url),
    'utf8',
  );

describe('canonical scan rendering', () => {
  it('matches the shared strict JSON and complete human backlog artifacts byte-for-byte', () => {
    const decoded = Effect.runSync(decodeScanResultJson(artifact('complete-scan-result.json')));
    expect(decoded.resultKind).toBe('complete');
    if (decoded.resultKind !== 'complete') return;

    const json = Effect.runSync(encodeScanOutput(decoded, 'json'));
    expect(json).toBe(artifact('cli-json.json'));
    expect(json.endsWith('\n\n')).toBe(false);
    expect(Effect.runSync(renderHumanScanResult(decoded))).toBe(artifact('human-backlog.txt'));
  });
});
