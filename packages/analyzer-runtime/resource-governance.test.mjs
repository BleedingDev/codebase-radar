import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  rmdirSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  buildResourceSeccompPolicy,
  buildResourceGovernedCommand,
  buildMaterializedAnalyzerBwrapArguments,
  buildPrlimitedAnalyzerCommand,
  launchResourceGovernedAnalyzerForTest,
  parseChildLimits,
  requiredOfflineOsvDatabase,
  requiredPrlimitArguments,
  resourceSeccompPolicySha256,
  verifyResourceGovernance,
  verifyResourceGovernanceForTest,
} from './resource-governance.mjs';

const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex');

const firstLine = path => {
  const result = spawnSync(path, ['--version'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.replace(/\r\n?/gu, '\n').split('\n', 1)[0];
};

const linuxHarnessRoot = process.env.RADAR_CGROUP_TEST_ROOT;
const launcherNode = '/usr/local/lib/radar-node-v24.18.1/bin/node';
const testLauncherPath = fileURLToPath(new URL('./resource-governance-launcher.mjs', import.meta.url));
const canRunLinuxHarness =
  process.platform === 'linux' &&
  process.arch === 'x64' &&
  typeof linuxHarnessRoot === 'string' &&
  linuxHarnessRoot.startsWith('/sys/fs/cgroup/') &&
  existsSync(launcherNode) &&
  existsSync('/usr/bin/bwrap') &&
  existsSync('/usr/bin/prlimit');

const testTools = () => ({
  bwrap: {
    path: '/usr/bin/bwrap',
    sha256: sha256('/usr/bin/bwrap'),
    versionFirstLine: firstLine('/usr/bin/bwrap'),
  },
  prlimit: {
    path: '/usr/bin/prlimit',
    sha256: sha256('/usr/bin/prlimit'),
    versionFirstLine: firstLine('/usr/bin/prlimit'),
  },
  node: {
    path: launcherNode,
    sha256: sha256(launcherNode),
    versionFirstLine: firstLine(launcherNode),
  },
});

const childEnvironment = Object.freeze({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  PATH: '/usr/bin:/bin',
});

const makeRawSeccompSyscallProbe = () => {
  const directory = mkdtempSync(join(tmpdir(), 'radar-seccomp-syscall-probe-'));
  const source = join(directory, 'probe.c');
  const executable = join(directory, 'probe');
  writeFileSync(source, [
    '#define _GNU_SOURCE',
    '#include <errno.h>',
    '#include <sched.h>',
    '#include <signal.h>',
    '#include <stdio.h>',
    '#include <sys/syscall.h>',
    '#include <unistd.h>',
    '#ifndef SYS_clone3',
    '#define SYS_clone3 435',
    '#endif',
    'int main(void) {',
    '  errno = 0;',
    '  long clone3_result = syscall(SYS_clone3, NULL, 0);',
    '  int clone3_errno = errno;',
    '  errno = 0;',
    '  long clone_result = syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);',
    '  int clone_errno = errno;',
    '  if (clone_result == 0) _exit(99);',
    '  printf("%d %d\\n", clone3_errno, clone_errno);',
    '  return clone3_result == -1 && clone3_errno == ENOSYS && clone_result == -1 && clone_errno == EPERM ? 0 : 1;',
    '}',
    '',
  ].join('\n'));
  const compilation = spawnSync('/usr/bin/cc', ['-O2', '-o', executable, source], {
    cwd: '/',
    encoding: 'utf8',
    env: childEnvironment,
    timeout: 10_000,
  });
  assert.equal(compilation.error, undefined);
  assert.equal(compilation.signal, null);
  assert.equal(compilation.status, 0, compilation.stderr);
  return {
    executable,
    release: () => rmSync(directory, { recursive: true, force: true }),
  };
};

const childArguments = (program, extraBwrapArguments = []) => [
  '--die-with-parent',
  '--new-session',
  '--clearenv',
  '--proc', '/proc',
  '--dev', '/dev',
  '--ro-bind', '/usr', '/usr',
  '--ro-bind-try', '/bin', '/bin',
  '--ro-bind-try', '/lib', '/lib',
  '--ro-bind-try', '/lib64', '/lib64',
  '--ro-bind', '/usr/local/lib/radar-node-v24.18.1', '/usr/local/lib/radar-node-v24.18.1',
  '--tmpfs', '/tmp',
  ...extraBwrapArguments,
  '--setenv', 'PATH', '/usr/bin:/bin',
  launcherNode, '-e', program,
];

const makeSnapshotFixture = () => {
  const directory = mkdtempSync(join(tmpdir(), 'radar-governance-test-'));
  const path = join(directory, 'snapshot');
  writeFileSync(path, 'sealed-test-fixture', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  const snapshotFd = openSync(path, 'r');
  return {
    snapshotFd,
    release: () => {
      closeSync(snapshotFd);
      rmSync(directory, { recursive: true, force: true });
    },
  };
};

const makeSealedDatabaseFixture = () => {
  const require = createRequire(import.meta.url);
  const bridge = require('./runtime-memfd-addon.node');
  const snapshotFd = bridge.createData();
  const bytes = 32 * 1024 * 1024;
  ftruncateSync(snapshotFd, bytes);
  writeSync(snapshotFd, Buffer.from('radar-osv-start'), 0, 15, 0);
  writeSync(snapshotFd, Buffer.from('radar-osv-end'), 0, 13, bytes - 13);
  bridge.seal(snapshotFd);
  return { snapshotFd, release: () => closeSync(snapshotFd) };
};

const makeMaterializedOsvRootFixture = () => {
  const root = mkdtempSync(join(tmpdir(), 'radar-materialized-runtime-'));
  const databaseDirectory = join(root, 'databases', 'osv', 'osv-scalibr', 'npm');
  const databasePath = join(databaseDirectory, 'all.zip');
  mkdirSync(databaseDirectory, { recursive: true });
  writeFileSync(databasePath, Buffer.alloc(0), { mode: 0o444, flag: 'wx' });
  const directories = [
    join(root, 'databases'),
    join(root, 'databases', 'osv'),
    join(root, 'databases', 'osv', 'osv-scalibr'),
    databaseDirectory,
  ];
  for (const directory of directories) chmodSync(directory, 0o555);
  chmodSync(root, 0o555);
  const runtimeRootFd = openSync(root, 'r');
  return {
    runtimeRootFd,
    release: () => {
      closeSync(runtimeRootFd);
      chmodSync(root, 0o755);
      for (const directory of directories) chmodSync(directory, 0o755);
      rmSync(root, { recursive: true, force: true });
    },
  };
};

const launchTestAnalyzer = async ({
  program,
  timeoutMs = 10_000,
  tools = testTools(),
  signal,
  bwrapArguments,
  snapshot: suppliedSnapshot,
  databaseFd,
}) => {
  const snapshot = suppliedSnapshot ?? makeSnapshotFixture();
  try {
    const session = await launchResourceGovernedAnalyzerForTest({
      analyzerId: 'Calldiff',
      cgroupRoot: linuxHarnessRoot,
      tools,
      bwrapArguments: bwrapArguments ?? childArguments(program),
      environment: childEnvironment,
      snapshotFd: snapshot.snapshotFd,
      launcherPath: testLauncherPath,
      timeoutMs,
      ...(databaseFd === undefined ? {} : { databaseFd }),
      ...(signal === undefined ? {} : { signal }),
    });
    return { session, snapshot };
  } catch (error) {
    snapshot.release();
    throw error;
  }
};

const residualAnalysisCgroups = () =>
  readdirSync(linuxHarnessRoot).filter(name => name.startsWith('radar-analysis-'));

test('pins exactly the per-child prlimit arguments and intentionally omits NPROC', () => {
  assert.deepEqual(requiredPrlimitArguments, [
    '--core=0:0',
    '--fsize=16777216:16777216',
    '--nofile=256:256',
    '--cpu=130:130',
    '--as=8589934592:8589934592',
  ]);
  assert.equal(requiredPrlimitArguments.some(argument => argument.includes('nproc')), false);
});

test('wraps the materialized analyzer sandbox in exact prlimit and rejects network sharing', () => {
  assert.deepEqual(
    buildPrlimitedAnalyzerCommand('/runtime/bin/node', ['/runtime/bin/runner.mjs']),
    {
      executable: '/usr/bin/prlimit',
      arguments: [
        '--core=0:0',
        '--fsize=16777216:16777216',
        '--nofile=256:256',
        '--cpu=130:130',
        '--as=8589934592:8589934592',
        '/runtime/bin/node',
        '/runtime/bin/runner.mjs',
      ],
    },
  );
  assert.deepEqual(
    buildResourceGovernedCommand(['/usr/bin/true']),
    {
      executable: '/usr/bin/prlimit',
      arguments: [
        '--core=0:0',
        '--fsize=16777216:16777216',
        '--nofile=256:256',
        '--cpu=130:130',
        '--as=8589934592:8589934592',
        '/usr/bin/bwrap',
        '--unshare-all',
        '--unshare-net',
        '--seccomp',
        '4',
        '/usr/bin/true',
      ],
    },
  );
  assert.throws(
    () => buildResourceGovernedCommand(['--share-net', '/usr/bin/true']),
    error => error?.code === 'network-policy-rejected',
  );
  for (const argument of ['--unshare-all', '--unshare-net', '--seccomp', '--seccomp=9']) {
    assert.throws(
      () => buildResourceGovernedCommand([argument, '/usr/bin/true']),
      error => error?.code === 'protocol-invalid',
    );
  }
});

test('builds the exact descriptor-only materialized runtime, request, and offline OSV mounts', () => {
  assert.equal(
    requiredOfflineOsvDatabase.runtimeRelativePath,
    'databases/osv/osv-scalibr/npm/all.zip',
  );
  assert.equal(
    requiredOfflineOsvDatabase.sandboxPath,
    '/runtime/databases/osv/osv-scalibr/npm/all.zip',
  );
  const typescript = buildMaterializedAnalyzerBwrapArguments('Calldiff');
  assert.deepEqual(
    typescript.slice(-6),
    [
      '--chdir',
      '/workspace',
      '/runtime/bin/node',
      '/runtime/bin/radar-semantic-analyzer.mjs',
      '--analyzer',
      'Calldiff',
    ],
  );
  assert.equal(typescript.includes('--unshare-all'), false);
  assert.equal(typescript.includes('--unshare-net'), false);
  assert.equal(typescript.includes('--share-net'), false);
  assert.equal(typescript.includes('/run/radar/runtime.snapshot'), false);
  assert.equal(typescript.includes('runtime-snapshot-loader.mjs'), false);
  assert.equal(typescript.includes('/proc/self/fd/5'), false);
  const runtimeBind = typescript.indexOf('/proc/self/fd/3');
  assert.deepEqual(
    typescript.slice(runtimeBind - 1, runtimeBind + 2),
    ['--ro-bind', '/proc/self/fd/3', '/runtime'],
  );
  const requestBind = typescript.indexOf('/run/radar/analyzer-request.json');
  assert.equal(typescript[requestBind - 2], '--ro-bind');
  assert.equal(typescript[requestBind - 1], '/proc/self/fd/7');
  const requestEnvironment = typescript.findIndex((value, index) =>
    value === 'RADAR_ANALYZER_REQUEST' && typescript[index - 1] === '--setenv');
  assert.equal(typescript[requestEnvironment + 1], '/run/radar/analyzer-request.json');

  const osv = buildMaterializedAnalyzerBwrapArguments('OSV-Scanner');
  const database = osv.indexOf('/runtime/databases/osv/osv-scalibr/npm/all.zip');
  assert.equal(osv[database - 2], '--ro-bind');
  assert.equal(osv[database - 1], '/proc/self/fd/5');
  const osvEnvironment = osv.findIndex((value, index) =>
    value === 'OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY' && osv[index - 1] === '--setenv');
  assert.equal(osv[osvEnvironment + 1], '/runtime/databases/osv');
});

test('accepts exactly the seven production analyzer identifiers', () => {
  const analyzerIds = [
    'strictest-comparator',
    'Oxlint + Ultracite',
    'JSCPD',
    'Calldiff',
    'zizmor',
    'OSV-Scanner',
    'TraceDecay',
  ];
  for (const analyzerId of analyzerIds) {
    const arguments_ = buildMaterializedAnalyzerBwrapArguments(analyzerId);
    assert.deepEqual(arguments_.slice(-2), ['--analyzer', analyzerId]);
  }
  for (const legacyId of ['dependency-cruiser', 'ESLint', 'Madge', 'TypeScript']) {
    assert.throws(
      () => buildMaterializedAnalyzerBwrapArguments(legacyId),
      error => error?.code === 'analyzer-id-invalid',
    );
  }
});

test('uses one stable, byte-aligned seccomp policy', () => {
  const policy = buildResourceSeccompPolicy();
  assert.equal(policy.byteLength % 8, 0);
  assert.equal(
    createHash('sha256').update(policy).digest('hex'),
    resourceSeccompPolicySha256,
  );
  const instruction = index => ({
    code: policy.readUInt16LE(index * 8),
    jumpTrue: policy.readUInt8(index * 8 + 2),
    jumpFalse: policy.readUInt8(index * 8 + 3),
    value: policy.readUInt32LE(index * 8 + 4),
  });
  assert.deepEqual(
    [instruction(3), instruction(4), instruction(5), instruction(6), instruction(7)],
    [
      { code: 0x20, jumpTrue: 0, jumpFalse: 0, value: 0 },
      { code: 0x54, jumpTrue: 0, jumpFalse: 0, value: 0x4000_0000 },
      { code: 0x15, jumpTrue: 1, jumpFalse: 0, value: 0 },
      { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0x0005_0001 },
      { code: 0x20, jumpTrue: 0, jumpFalse: 0, value: 0 },
    ],
  );
  const instructions = Array.from(
    { length: policy.byteLength / 8 },
    (_, index) => instruction(index),
  );
  const clone3Comparison = instructions.findIndex(candidate =>
    candidate.code === 0x15 && candidate.value === 435);
  assert.notEqual(clone3Comparison, -1);
  assert.deepEqual(
    instructions[clone3Comparison + 1],
    { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0x0005_0026 },
  );
  assert.equal(
    instructions.filter(candidate => candidate.value === 0x0005_0026).length,
    1,
  );
  for (const syscallNumber of [41, 165, 272]) {
    const comparison = instructions.findIndex(candidate =>
      candidate.code === 0x15 && candidate.value === syscallNumber);
    assert.notEqual(comparison, -1);
    assert.equal(instructions[comparison + 1].value, 0x0005_0001);
  }
  assert.deepEqual(
    instructions.slice(-2),
    [
      { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0x0005_0001 },
      { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0x7fff_0000 },
    ],
  );
});

test('requires the actual bounded child limits and rejects shared-UID NPROC', () => {
  const limits = [
    'Max cpu time              130                  130                  seconds',
    'Max file size             16777216             16777216             bytes',
    'Max core file size        0                    0                    bytes',
    'Max open files            256                  256                  files',
    'Max address space         8589934592           8589934592           bytes',
    'Max processes             4096                 4096                 processes',
  ].join('\n');
  assert.equal(parseChildLimits(limits).nofile.soft, '256');
  assert.throws(
    () => parseChildLimits(limits.replace('4096                 4096', '128                  128')),
    error => error?.code === 'child-limits-invalid',
  );
});

test('Darwin explicitly reports Linux governance unavailable', { skip: process.platform !== 'darwin' }, () => {
  assert.throws(
    () => verifyResourceGovernance({ cgroupRoot: '/sys/fs/cgroup/radar' }),
    error => error?.code === 'linux-required',
  );
});

test(
  'Linux delegated probe attests cgroup configuration, prlimit inheritance, seccomp, and cleanup',
  { skip: !canRunLinuxHarness },
  () => {
    assert.deepEqual(residualAnalysisCgroups(), []);
    const evidence = verifyResourceGovernanceForTest({
      cgroupRoot: linuxHarnessRoot,
      tools: testTools(),
      launcherPath: testLauncherPath,
    });
    assert.equal(evidence.status, 'passed');
    assert.deepEqual(evidence.cgroupV2.controllers, ['cpu', 'memory', 'pids']);
    assert.equal(evidence.cgroupV2.pidsMax, '128');
    assert.equal(evidence.cgroupV2.memoryMax, '2147483648');
    assert.equal(evidence.cgroupV2.memorySwapMax, '0');
    assert.equal(evidence.cgroupV2.cpuMax, '200000 100000');
    assert.equal(evidence.child.nproc, 'not-set');
    assert.deepEqual(residualAnalysisCgroups(), []);
  },
);

test(
  'Linux seccomp returns ENOSYS only for raw clone3, blocks clone namespace flags, and permits a pinned Node Worker',
  { skip: !canRunLinuxHarness || !existsSync('/usr/bin/cc') },
  async () => {
    const probe = makeRawSeccompSyscallProbe();
    const sandboxProbe = '/run/radar/seccomp-syscall-probe';
    const program = [
      "const { spawnSync } = require('node:child_process');",
      "const { Worker } = require('node:worker_threads');",
      "const worker = new Worker('0', { eval: true });",
      'worker.once(\'error\', () => process.exit(95));',
      'worker.once(\'exit\', code => {',
      '  if (code !== 0) process.exit(96);',
      `  const raw = spawnSync(${JSON.stringify(sandboxProbe)}, [], { encoding: 'utf8' });`,
      "  if (raw.error || raw.signal !== null || raw.status !== 0 || raw.stdout !== '38 1\\n' || raw.stderr !== '') process.exit(97);",
      '});',
    ].join('');
    const { session, snapshot } = await launchTestAnalyzer({
      program,
      bwrapArguments: childArguments(program, [
        '--dir', '/run',
        '--dir', '/run/radar',
        '--ro-bind', probe.executable, sandboxProbe,
      ]),
    });
    try {
      const completion = await session.completion;
      assert.equal(completion.status, 'terminated');
      assert.equal(completion.exitCode, 0);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
      probe.release();
    }
  },
);

test(
  'Linux cancellation kills forked descendants and removes the operation-owned cgroup',
  { skip: !canRunLinuxHarness },
  async () => {
    assert.deepEqual(residualAnalysisCgroups(), []);
    const { session, snapshot } = await launchTestAnalyzer({
      program: `const { spawn } = require('node:child_process'); for (let index = 0; index < 32; index += 1) spawn('${launcherNode}', ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); setInterval(() => {}, 1000);`,
    });
    try {
      assert.equal(session.cancel(), true);
      const completion = await session.completion;
      assert.equal(completion.status, 'terminated');
      assert.equal(completion.reason, 'cancel');
      assert.equal(completion.exitCode, 130);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux launcher treats parent IPC loss as cancellation and removes its owned cgroup',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: `const { spawn } = require('node:child_process'); spawn('${launcherNode}', ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); setInterval(() => {}, 1000);`,
    });
    try {
      session.child.disconnect();
      const completion = await session.completion;
      assert.equal(completion.status, 'failed');
      assert.equal(completion.reason, 'launcher-exited-without-terminal');
      assert.equal(completion.cleanup, 'not-needed');
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux max-one admission queues a concurrent launch before cgroup allocation',
  { skip: !canRunLinuxHarness },
  async () => {
    const tools = testTools();
    const first = await launchTestAnalyzer({
      tools,
      program: 'setInterval(() => {}, 1000);',
    });
    const secondPromise = launchTestAnalyzer({
      tools,
      program: 'setTimeout(() => process.exit(0), 40);',
    });
    try {
      await new Promise(resolve => setTimeout(resolve, 75));
      assert.equal(residualAnalysisCgroups().length, 1);
      assert.equal(first.session.cancel(), true);
      const firstResult = await first.session.completion;
      assert.equal(firstResult.reason, 'cancel');
      const second = await secondPromise;
      try {
        assert.equal(residualAnalysisCgroups().length, 1);
        const secondResult = await second.session.completion;
        assert.equal(secondResult.exitCode, 0);
      } finally {
        second.snapshot.release();
      }
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      first.session.cancel();
      await first.session.completion;
      first.snapshot.release();
    }
  },
);

test(
  'Linux queued cancellation allocates no cgroup and does not leak the admission permit',
  { skip: !canRunLinuxHarness },
  async () => {
    const first = await launchTestAnalyzer({ program: 'setInterval(() => {}, 1000);' });
    const controller = new AbortController();
    const queued = launchTestAnalyzer({
      program: 'process.exit(99);',
      signal: controller.signal,
    });
    try {
      await new Promise(resolve => setTimeout(resolve, 75));
      assert.equal(residualAnalysisCgroups().length, 1);
      controller.abort();
      await assert.rejects(queued, error => error?.code === 'launch-cancelled');
      assert.equal(residualAnalysisCgroups().length, 1);
      first.session.cancel();
      await first.session.completion;
      const after = await launchTestAnalyzer({ program: 'process.exit(0);' });
      try {
        assert.equal((await after.session.completion).exitCode, 0);
      } finally {
        after.snapshot.release();
      }
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      controller.abort();
      first.session.cancel();
      await first.session.completion;
      first.snapshot.release();
    }
  },
);

test(
  'Linux terminal completion replays a fast analyzer exit without an event-listener race',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({ program: 'process.exit(0);' });
    try {
      const completion = await session.completion;
      assert.equal(completion.status, 'terminated');
      assert.equal(completion.reason, 'exit');
      assert.equal(completion.exitCode, 0);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux pids.max caps a fork storm inside one analysis without a shared-UID limit',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: `const { spawn } = require('node:child_process'); for (let index = 0; index < 256; index += 1) { const child = spawn('${launcherNode}', ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); child.on('error', () => {}); } setInterval(() => {}, 1000);`,
    });
    try {
      await new Promise(resolve => setTimeout(resolve, 250));
      const cgroups = residualAnalysisCgroups();
      assert.equal(cgroups.length, 1);
      const current = Number(readFileSync(join(linuxHarnessRoot, cgroups[0], 'pids.current'), 'utf8').trim());
      const events = readFileSync(join(linuxHarnessRoot, cgroups[0], 'pids.events'), 'utf8');
      assert.equal(current <= 128, true);
      assert.match(events, /^max\s+[1-9][0-9]*$/mu);
      session.cancel();
      await session.completion;
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux timeout kills the full cgroup and makes cleanup observable',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: 'setInterval(() => {}, 1000);',
      timeoutMs: 50,
    });
    try {
      const completion = await session.completion;
      assert.equal(completion.status, 'terminated');
      assert.equal(completion.reason, 'timeout');
      assert.equal(completion.exitCode, 124);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux parent supervision cleans descendants after the launcher is killed',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: `const { spawn } = require('node:child_process'); spawn('${launcherNode}', ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' }); setInterval(() => {}, 1000);`,
    });
    try {
      assert.equal(session.child.kill('SIGKILL'), true);
      const completion = await session.completion;
      assert.equal(completion.status, 'failed');
      assert.equal(completion.reason, 'launcher-exited-without-terminal');
      assert.equal(completion.cleanup, 'passed');
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux prlimit rejects a file larger than the exact output-file ceiling',
  { skip: !canRunLinuxHarness },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: "require('node:fs').writeFileSync('/tmp/oversized', Buffer.alloc(17 * 1024 * 1024));",
    });
    try {
      const completion = await session.completion;
      assert.notEqual(completion.exitCode, 0);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);

test(
  'Linux directly binds a sealed database FD without copying under FSIZE and closes the backing FD',
  { skip: !canRunLinuxHarness || !existsSync(new URL('./runtime-memfd-addon.node', import.meta.url)) },
  async () => {
    const database = makeSealedDatabaseFixture();
    assert.throws(
      () => writeSync(database.snapshotFd, Buffer.from('x'), 0, 1, 0),
      error => error?.code === 'EPERM',
    );
    const program = [
      "const fs = require('node:fs');",
      "const path = '/tmp/all.zip';",
      'const fd = fs.openSync(path, \'r\');',
      'const stat = fs.fstatSync(fd);',
      'const start = Buffer.alloc(15); const end = Buffer.alloc(13);',
      'fs.readSync(fd, start, 0, start.length, 0);',
      'fs.readSync(fd, end, 0, end.length, stat.size - end.length);',
      "if (stat.size !== 32 * 1024 * 1024 || start.toString() !== 'radar-osv-start' || end.toString() !== 'radar-osv-end') process.exit(91);",
      "const leaked = fs.readdirSync('/proc/self/fd').some(name => { try { return fs.readlinkSync('/proc/self/fd/' + name).includes('codebase-radar-runtime'); } catch { return false; } });",
      'if (leaked) process.exit(92);',
    ].join('');
    const { session, snapshot } = await launchTestAnalyzer({
      program,
      databaseFd: database.snapshotFd,
      bwrapArguments: childArguments(program, [
        '--ro-bind', '/proc/self/fd/5', '/tmp/all.zip',
      ]),
    });
    try {
      const completion = await session.completion;
      assert.equal(completion.exitCode, 0);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
      database.release();
    }
  },
);

test(
  'Linux bwrap 0.9 overlays sealed OSV bytes on the pre-materialized placeholder under a read-only runtime root',
  { skip: !canRunLinuxHarness || !existsSync(new URL('./runtime-memfd-addon.node', import.meta.url)) },
  () => {
    assert.equal(firstLine('/usr/bin/bwrap'), 'bubblewrap 0.9.0');
    const runtime = makeMaterializedOsvRootFixture();
    const database = makeSealedDatabaseFixture();
    const runtimeTarget = readlinkSync(`/proc/self/fd/${runtime.runtimeRootFd}`);
    const databaseTarget = readlinkSync(`/proc/self/fd/${database.snapshotFd}`);
    const program = [
      "const fs = require('node:fs');",
      "const path = '/runtime/databases/osv/osv-scalibr/npm/all.zip';",
      'const stat = fs.statSync(path);',
      'const fd = fs.openSync(path, \'r\');',
      'const start = Buffer.alloc(15); const end = Buffer.alloc(13);',
      'fs.readSync(fd, start, 0, start.length, 0);',
      'fs.readSync(fd, end, 0, end.length, stat.size - end.length);',
      "if (stat.size !== 32 * 1024 * 1024 || start.toString() !== 'radar-osv-start' || end.toString() !== 'radar-osv-end') process.exit(91);",
      `const backingTarget = ${JSON.stringify(databaseTarget)};`,
      `const runtimeTarget = ${JSON.stringify(runtimeTarget)};`,
      "const leaked = fs.readdirSync('/proc/self/fd').some(name => { try { const target = fs.readlinkSync('/proc/self/fd/' + name); return target === backingTarget || target === runtimeTarget; } catch { return false; } });",
      'if (leaked) process.exit(92);',
      "try { fs.writeFileSync(path, 'x'); process.exit(93); } catch (error) { if (error.code !== 'EROFS') process.exit(94); }",
    ].join('');
    const bwrapArguments = [
      '--die-with-parent',
      '--new-session',
      '--unshare-all',
      '--unshare-net',
      '--clearenv',
      '--proc', '/proc',
      '--dev', '/dev',
      '--ro-bind', '/usr', '/usr',
      '--ro-bind-try', '/bin', '/bin',
      '--ro-bind-try', '/lib', '/lib',
      '--ro-bind-try', '/lib64', '/lib64',
      '--ro-bind', '/usr/local/lib/radar-node-v24.18.1', '/usr/local/lib/radar-node-v24.18.1',
      '--dir', '/runtime',
      '--ro-bind', '/proc/self/fd/3', '/runtime',
      '--ro-bind', '/proc/self/fd/5', '/runtime/databases/osv/osv-scalibr/npm/all.zip',
      '--setenv', 'HOME', '/nonexistent',
      '--setenv', 'LANG', 'C.UTF-8',
      '--setenv', 'LC_ALL', 'C.UTF-8',
      '--setenv', 'PATH', '/usr/bin:/bin',
      launcherNode,
      '-e',
      program,
    ];
    const command = buildPrlimitedAnalyzerCommand('/usr/bin/bwrap', bwrapArguments);
    try {
      const result = spawnSync(command.executable, command.arguments, {
        cwd: '/',
        encoding: 'utf8',
        env: childEnvironment,
        stdio: ['ignore', 'pipe', 'pipe', runtime.runtimeRootFd, 'ignore', database.snapshotFd],
        timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.signal, null);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, '');
    } finally {
      runtime.release();
      database.release();
    }
  },
);

test(
  'Linux stale analysis cgroups are rejected without killing an unknown owner',
  { skip: !canRunLinuxHarness },
  () => {
    const stalePath = join(linuxHarnessRoot, 'radar-analysis-00000000-0000-4000-8000-000000000001');
    mkdirSync(stalePath, { mode: 0o700 });
    try {
      assert.throws(
        () => verifyResourceGovernanceForTest({
          cgroupRoot: linuxHarnessRoot,
          tools: testTools(),
          launcherPath: testLauncherPath,
        }),
        error => error?.code === 'stale-analysis-cgroup-detected',
      );
      assert.equal(existsSync(stalePath), true);
    } finally {
      rmdirSync(stalePath);
    }
  },
);

test(
  'Linux stress harness enforces the cgroup memory ceiling and still cleans up',
  { skip: !canRunLinuxHarness || process.env.RADAR_RUN_RESOURCE_STRESS_TESTS !== '1' },
  async () => {
    const { session, snapshot } = await launchTestAnalyzer({
      program: "const chunks = []; for (;;) chunks.push(Buffer.allocUnsafe(64 * 1024 * 1024).fill(1));",
      timeoutMs: 30_000,
    });
    try {
      const completion = await session.completion;
      assert.notEqual(completion.exitCode, 0);
      assert.deepEqual(residualAnalysisCgroups(), []);
    } finally {
      snapshot.release();
    }
  },
);
