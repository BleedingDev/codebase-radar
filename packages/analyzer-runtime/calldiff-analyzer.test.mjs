import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const adapter = join(packageRoot, 'calldiff-analyzer.mjs');

const pathSetDigest = paths =>
  `sha256:${createHash('sha256').update(JSON.stringify(paths)).digest('hex')}`;

const runAdapter = (root, auditedSourceFiles) => {
  const result = spawnSync(
    process.execPath,
    [
      adapter,
      root,
      ...(auditedSourceFiles === undefined
        ? []
        : ['--audited-source-files-stdin']),
    ],
    {
      encoding: 'utf8',
      ...(auditedSourceFiles === undefined
        ? {}
        : { input: JSON.stringify({ sourceFiles: auditedSourceFiles }) }),
      env: {
        HOME: '/nonexistent',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        NO_COLOR: '1',
        PATH: process.env.PATH ?? '',
      },
      maxBuffer: 40 * 1024 * 1024,
      timeout: 20_000,
    },
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
};

test('uses the audited source allowlist and reports identities from files it analyzed', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-audited-paths-'));
  try {
    writeFileSync(
      join(root, 'audited.ts'),
      'export function audited() { repeated(); repeated(); }\nfunction repeated() {}\n',
    );
    writeFileSync(
      join(root, 'wrong.ts'),
      'export function wrong() { foreign(); foreign(); }\nfunction foreign() {}\n',
    );
    const auditedPaths = ['audited.ts'];

    const report = runAdapter(root, auditedPaths);

    assert.equal(report.eligibleFiles, 1);
    assert.equal(report.analyzedFiles, 1);
    assert.deepEqual(report.requestedPaths, auditedPaths);
    assert.deepEqual(report.analyzedPaths, auditedPaths);
    assert.equal(report.requestedPathSetDigest, pathSetDigest(auditedPaths));
    assert.equal(report.analyzedPathSetDigest, pathSetDigest(auditedPaths));
    assert.ok(
      report.duplicates.every(item => !item.key.startsWith('wrong.ts::')),
      'a same-count unapproved file must not be silently substituted for an audited path',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('preserves the canonical UTF-8 audited source order in path-set identities', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-utf8-path-order-'));
  try {
    const auditedPaths = ['\uE000.ts', '\u{10000}.ts'];
    for (const path of auditedPaths) {
      writeFileSync(join(root, path), 'export function source() {}\n');
    }

    const report = runAdapter(root, auditedPaths);

    assert.deepEqual(report.requestedPaths, auditedPaths);
    assert.deepEqual(report.analyzedPaths, auditedPaths);
    assert.equal(report.requestedPathSetDigest, pathSetDigest(auditedPaths));
    assert.equal(report.analyzedPathSetDigest, pathSetDigest(auditedPaths));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('never resolves duplicate unqualified definitions by traversal order', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-collision-'));
  try {
    writeFileSync(join(root, 'one.ts'), [
      'function shared() { leafOne(); }',
      'function leafOne() {}',
      'export function fromOne() { shared(); }',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'two.ts'), [
      'function shared() { leafTwo(); }',
      'function leafTwo() {}',
      'export function fromTwo() { shared(); }',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'three.ts'), [
      'export function ambiguousCaller() { shared(); }',
      '',
    ].join('\n'));

    const first = runAdapter(root);
    const second = runAdapter(root);
    assert.deepEqual(second, first, 'collision handling must be deterministic');

    const collision = first.collisions.find(item => item.key === 'shared');
    assert.ok(collision, 'the duplicate definition must be evidence, not silently chosen');
    assert.deepEqual(
      collision.definitions.map(item => item.key),
      ['one.ts::shared', 'two.ts::shared'],
    );
    assert.deepEqual(
      collision.ambiguousCallers.map(item => item.key),
      ['three.ts::ambiguousCaller'],
    );
    assert.equal(
      first.duplicates.some(item => item.key.endsWith('::shared')),
      false,
      'separate local shared functions must never be merged into one duplicate node',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('keeps constructor aliases scoped to the defining file', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-constructor-'));
  try {
    writeFileSync(join(root, 'left.ts'), [
      'class Local { constructor() { leftLeaf(); } }',
      'function leftLeaf() {}',
      'export function fromLeft() { new Local(); }',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'right.ts'), [
      'class Local { constructor() { rightLeaf(); } }',
      'function rightLeaf() {}',
      'export function fromRight() { new Local(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    const aliases = report.collisions.find(item => item.key === 'new Local');
    assert.ok(aliases, 'constructor aliases must retain all candidate definitions');
    assert.deepEqual(
      aliases.definitions.map(item => item.key),
      ['left.ts::new Local', 'right.ts::new Local'],
    );
    assert.deepEqual(
      aliases.ambiguousCallers,
      [],
      'same-file constructor calls must be resolved without cross-file guessing',
    );
    assert.equal(
      report.duplicates.some(item => item.key.endsWith('::new Local')),
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('never infers cross-file bindings from exported or globally unique names', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-export-collision-'));
  try {
    writeFileSync(join(root, 'exported.ts'), [
      'export function shared() { exportedLeaf(); }',
      'function exportedLeaf() {}',
      'export function uniqueRemote() { exportedLeaf(); }',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'private.ts'), [
      'function shared() { privateLeaf(); }',
      'function privateLeaf() {}',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'caller.ts'), [
      'export function caller() { shared(); uniqueRemote(); uniqueRemote(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    const collision = report.collisions.find(item => item.key === 'shared');
    assert.ok(collision);
    assert.deepEqual(
      collision.ambiguousCallers.map(item => item.key),
      ['caller.ts::caller'],
      'an exported candidate is not an import-binding proof',
    );
    assert.equal(
      report.duplicates.some(item => item.key === 'exported.ts::uniqueRemote'),
      false,
      'a globally unique textual name is not a cross-file import-binding proof',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('counts a constructor body once through its canonical new-expression alias', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-constructor-count-'));
  try {
    writeFileSync(join(root, 'constructor.ts'), [
      'class Worker { constructor() { repeated(); repeated(); } }',
      'function repeated() {}',
      'export function create() { new Worker(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    const repeated = report.duplicates.find(item => item.key === 'constructor.ts::repeated');
    assert.ok(repeated);
    assert.equal(repeated.entrypoints.length, 1);
    assert.equal(repeated.entrypoints[0].key, 'constructor.ts::create');
    assert.equal(repeated.entrypoints[0].occurrenceCount, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('resolves same-file constructor member calls through the canonical new-expression alias', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-constructor-member-'));
  try {
    writeFileSync(join(root, 'constructor-member.ts'), [
      'class Worker {',
      '  constructor() { leaf(); leaf(); }',
      '  static invoke() { this.constructor(); }',
      '}',
      'function leaf() {}',
      'export function root() { new Worker(); Worker.invoke(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root, ['constructor-member.ts']);
    const leaf = report.duplicates.find(
      item => item.key === 'constructor-member.ts::leaf',
    );

    assert.equal(report.functionCount, 4);
    assert.equal(report.collisionCount, 0);
    assert.equal(report.unmodeledCrossFileCallCount, 0);
    assert.ok(leaf);
    assert.equal(
      leaf.maximumOccurrences,
      4,
      'the member call must expand the existing constructor body instead of becoming an invisible external edge',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('bounds adversarial exponential call-tree expansion', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-expansion-'));
  try {
    const functions = Array.from({ length: 22 }, (_, index) =>
      index === 21
        ? `function f${index}() {}`
        : `function f${index}() { f${index + 1}(); f${index + 1}(); }`,
    );
    writeFileSync(
      join(root, 'expansion.ts'),
      [...functions, 'export function root() { f0(); }', ''].join('\n'),
    );

    const report = runAdapter(root);
    assert.ok(report.truncatedEntrypointCount > 0);
    assert.ok(report.expandedNodes <= report.maximumExpandedNodes);
    assert.ok(report.truncatedEntrypoints.length <= 32);
    assert.ok(
      JSON.stringify(report).length < 4 * 1024 * 1024,
      'bounded expansion must also bound the serialized report',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports unmodeled single-candidate cross-file calls without calling them ambiguous', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-unmodeled-'));
  try {
    writeFileSync(join(root, 'remote.ts'), 'export function remote() {}\n');
    writeFileSync(
      join(root, 'caller.ts'),
      'export function caller() { remote(); }\n',
    );

    const report = runAdapter(root);
    assert.equal(report.unmodeledCrossFileCallCount, 1);
    assert.equal(report.unmodeledCrossFileCallsTruncated, false);
    assert.deepEqual(report.unmodeledCrossFileCalls, [
      {
        key: 'remote',
        callerKey: 'caller.ts::caller',
        path: 'caller.ts',
        line: 1,
        localDefinitionCount: 1,
      },
    ]);
    assert.equal(report.collisions.length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('analyzes approved hidden source directories and out while excluding canonical unsafe directories', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-hidden-source-'));
  try {
    const sources = new Map([
      ['.github/actions/check.ts', 'export function githubAction() {}\n'],
      ['.storybook/preview.ts', 'export function storybookPreview() {}\n'],
      ['out/retained.ts', 'export function outputSource() {}\n'],
      ['types.d.ts', 'export declare function declaration(): void;\n'],
      ['.git/ignored.ts', 'export function gitMetadata() {}\n'],
      ['.hg/ignored.ts', 'export function mercurialMetadata() {}\n'],
      ['.svn/ignored.ts', 'export function svnMetadata() {}\n'],
      ['.cache/ignored.ts', 'export function cachedBuild() {}\n'],
    ]);
    for (const [path, source] of sources) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), source);
    }

    const report = runAdapter(root);
    assert.equal(report.eligibleFiles, 4);
    assert.equal(report.analyzedFiles, 4);
    assert.ok(report.functionCount >= 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('skips oversized source input before parser allocation and reports bounded coverage evidence', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-input-budget-'));
  try {
    writeFileSync(
      join(root, 'oversized.ts'),
      `export function oversized() {}\n${' '.repeat(2_097_152)}`,
    );

    const report = runAdapter(root);
    assert.equal(report.eligibleFiles, 1);
    assert.equal(report.analyzedFiles, 0);
    assert.equal(report.inputFileCount, 0);
    assert.equal(report.inputBytes, 0);
    assert.equal(report.inputTruncated, true);
    assert.equal(report.truncatedInputFileCount, 1);
    assert.deepEqual(report.truncatedInputFiles, [
      { path: 'oversized.ts', reason: 'file_bytes' },
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('does not count Tree-sitter recovery parses as analyzed source coverage', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-syntax-error-'));
  try {
    writeFileSync(
      join(root, 'malformed.ts'),
      'export function malformed( { return 1; }\n',
    );

    const report = runAdapter(root, ['malformed.ts']);

    assert.equal(report.eligibleFiles, 1);
    assert.equal(report.analyzedFiles, 0);
    assert.equal(report.failedFileCount, 1);
    assert.deepEqual(report.requestedPaths, ['malformed.ts']);
    assert.deepEqual(report.analyzedPaths, []);
    assert.equal(report.analyzedPathSetDigest, pathSetDigest([]));
    assert.match(report.failedFiles[0]?.diagnostic ?? '', /syntax errors/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rejects malformed UTF-8 instead of silently replacing source bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-invalid-utf8-'));
  try {
    writeFileSync(
      join(root, 'invalid.ts'),
      Buffer.from([0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x20, 0xff]),
    );

    const report = runAdapter(root, ['invalid.ts']);

    assert.equal(report.eligibleFiles, 1);
    assert.equal(report.analyzedFiles, 0);
    assert.equal(report.failedFileCount, 1);
    assert.deepEqual(report.requestedPaths, ['invalid.ts']);
    assert.deepEqual(report.analyzedPaths, []);
    assert.equal(report.analyzedPathSetDigest, pathSetDigest([]));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('caps failure evidence at the warning envelope without dropping valid findings', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-failure-cap-'));
  const unreadableFiles = [];
  try {
    writeFileSync(join(root, 'good.ts'), [
      'function repeated() {}',
      'export function good() { repeated(); repeated(); }',
      '',
    ].join('\n'));
    for (let index = 0; index < 101; index += 1) {
      const file = join(root, `unreadable-${index}.ts`);
      unreadableFiles.push(file);
      writeFileSync(file, `export function unreadable${index}() {}\n`);
      chmodSync(file, 0o000);
    }

    const report = runAdapter(root);
    assert.equal(report.failedFileCount, 101);
    assert.equal(report.failedFilesTruncated, true);
    assert.equal(report.failedFiles.length, 100);
    assert.ok(
      report.duplicates.some(item => item.key === 'good.ts::repeated'),
      'a bounded failure report must retain findings from readable files',
    );
  } finally {
    for (const file of unreadableFiles) chmodSync(file, 0o600);
    rmSync(root, { recursive: true, force: true });
  }
});

test('caps each duplicate root inventory at 8,000 entries while retaining its total', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-entrypoint-cap-'));
  try {
    const rootCount = 8_001;
    const roots = Array.from(
      { length: rootCount },
      (_, index) =>
        `export function root${index}() { repeated(); repeated(); }`,
    );
    writeFileSync(join(root, 'entrypoints.ts'), [
      'function repeated() {}',
      ...roots,
      '',
    ].join('\n'));

    const report = runAdapter(root);
    const duplicate = report.duplicates.find(
      item => item.key === 'entrypoints.ts::repeated',
    );
    assert.ok(duplicate);
    assert.equal(duplicate.entrypointCount, rootCount);
    assert.equal(duplicate.entrypointsTruncated, true);
    assert.equal(duplicate.entrypoints.length, 8_000);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports depth cuts while retaining duplicates discovered before the cutoff', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-depth-cut-'));
  try {
    const chain = Array.from({ length: 36 }, (_, index) => {
      const next = index === 35 ? '' : ` f${index + 1}();`;
      return index === 0
        ? `function f0() { repeated(); repeated();${next} }`
        : `function f${index}() {${next} }`;
    });
    writeFileSync(join(root, 'depth.ts'), [
      'function repeated() {}',
      ...chain,
      'export function root() { f0(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    assert.ok(report.depthCutCount > 0);
    assert.equal(report.depthTruncatedEntrypointCount, 1);
    assert.deepEqual(report.depthTruncatedEntrypoints, ['depth.ts::root']);
    assert.ok(
      report.duplicates.some(item => item.key === 'depth.ts::repeated'),
      'duplicates before a bounded depth cut must remain observable',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('walks a call chain deeper than the JavaScript stack without recursion', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-deep-chain-'));
  try {
    const functionCount = 16_000;
    const chain = Array.from({ length: functionCount }, (_, index) =>
      index === functionCount - 1
        ? `function f${index}() {}`
        : `function f${index}() { f${index + 1}(); }`,
    );
    writeFileSync(join(root, 'deep.ts'), [
      ...chain,
      'export function root() { f0(); }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    assert.equal(report.entrypointCount, 1);
    assert.ok(report.depthCutCount > 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('loads JavaScript and JSX grammars through the packaged runtime dependency', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-jsx-'));
  try {
    writeFileSync(join(root, 'script.js'), [
      'function jsLeaf() {}',
      'export function jsRoot() { jsLeaf(); jsLeaf(); }',
      '',
    ].join('\n'));
    writeFileSync(join(root, 'view.jsx'), [
      'function label() { return "label"; }',
      'export function View() { return <div>{label()}</div>; }',
      '',
    ].join('\n'));

    const report = runAdapter(root);
    assert.equal(report.analyzedFiles, 2);
    assert.equal(report.failedFileCount, 0);
    assert.ok(report.functionCount >= 4);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports inaccessible source subtrees instead of silently excluding them', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-directory-failure-'));
  const blocked = join(root, 'blocked');
  try {
    writeFileSync(join(root, 'readable.ts'), 'export function readable() {}\n');
    mkdirSync(blocked);
    writeFileSync(join(blocked, 'hidden.ts'), 'export function hidden() {}\n');
    chmodSync(blocked, 0o000);

    const report = runAdapter(root);
    assert.equal(report.analyzedFiles, 1);
    assert.equal(report.directoryTraversalFailureCount, 1);
    assert.equal(report.directoryTraversalFailures.length, 1);
    assert.equal(report.directoryTraversalFailures[0].path, 'blocked');
  } finally {
    chmodSync(blocked, 0o700);
    rmSync(root, { recursive: true, force: true });
  }
});

test('bounds deep source-directory traversal without recursion', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-directory-depth-'));
  try {
    let directory = root;
    for (let index = 0; index < 140; index += 1) {
      directory = join(directory, 'd');
      mkdirSync(directory);
    }
    writeFileSync(join(directory, 'deep.ts'), 'export function deep() {}\n');

    const report = runAdapter(root);
    assert.equal(report.directoryTraversalTruncated, true);
    assert.ok(report.truncatedDirectoryCount > 0);
    assert.ok(
      report.truncatedDirectories.some(item => item.reason === 'depth'),
    );
    assert.equal(report.eligibleFiles, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('bounds high-flat step rewrites before cloning the full step forest', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-rewrite-budget-'));
  try {
    const callCount = 100_001;
    writeFileSync(join(root, 'flat.ts'), [
      'function f() {}',
      `export function root() {${'f();'.repeat(callCount)}}`,
      '',
    ].join('\n'));

    const report = runAdapter(root);
    assert.ok(report.rewriteTruncatedDefinitionCount > 0);
    assert.equal(report.indexedSteps, report.indexedStepLimit);
    assert.ok(report.rewriteTruncatedDefinitions.length <= 100);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rewrites deeply nested branch steps iteratively and reports their bounded depth', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-nested-steps-'));
  try {
    const depth = 1_000;
    writeFileSync(join(root, 'nested.ts'), [
      'function leaf() {}',
      `export function root() {${'if (true) {'.repeat(depth)}leaf();${'}'.repeat(depth)}}`,
      '',
    ].join('\n'));

    const report = runAdapter(root);
    assert.equal(report.failedFileCount, 0);
    assert.ok(report.depthCutCount > 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('caps many duplicate groups and long root evidence below the process envelope', () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-calldiff-evidence-budget-'));
  try {
    const groupCount = 12;
    const rootCount = 40;
    const label = 'x'.repeat(60);
    const groups = Array.from({ length: groupCount }, (_, group) => {
      const functions = Array.from({ length: 10 }, (_, index) => {
        const name = `group${group}Step${index}${label}`;
        const next = index === 9
          ? `group${group}Leaf${label}`
          : `group${group}Step${index + 1}${label}`;
        return `function ${name}() { ${next}(); }`;
      });
      return [
        `function group${group}Leaf${label}() {}`,
        ...functions,
      ];
    }).flat();
    const roots = Array.from({ length: rootCount }, (_, index) => {
      const calls = Array.from(
        { length: groupCount },
        (_, group) => `group${group}Step0${label}(); group${group}Step0${label}();`,
      );
      return `export function root${index}() { ${calls.join(' ')} }`;
    });
    writeFileSync(join(root, 'evidence.ts'), [...groups, ...roots, ''].join('\n'));

    const report = runAdapter(root);
    assert.equal(report.evidenceTruncated, true);
    assert.ok(report.evidenceBytes <= report.maximumEvidenceBytes);
    assert.ok(report.duplicates.length > 0);
    assert.ok(
      Buffer.byteLength(JSON.stringify(report), 'utf8') < 32 * 1024 * 1024,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
