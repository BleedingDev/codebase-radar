import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  closeSync,
  cpSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ControlEnvironment = 'RADAR_ANALYZER_CONTROL_ROOT';
const RuntimeEnvironment = 'RADAR_ANALYZER_ROOT';
const WorkspaceEnvironment = 'RADAR_WORKSPACE_PARENT';
const CgroupEnvironment = 'RADAR_ANALYSIS_CGROUP_ROOT';
const OutputEnvironment = 'RADAR_OUTPUT_ROOT';
const CliEnvironment = 'RADAR_CLI_BIN';
const ControlRootPrefix = '.radar-control-smoke-';
const MaximumOutputFiles = 256;
const DoctorTimeoutMs = 60_000;
const DoctorUnavailableExitCode = 69;
const StaticMode = '--static';
const ScriptDirectory = dirname(fileURLToPath(import.meta.url));
const WorkspaceRoot = realpathSync(resolve(ScriptDirectory, '../../..'));
const BuiltOutputRoot = resolve(ScriptDirectory, '../.output');

const fail = message => {
  throw new Error(`production-output-smoke: ${message}`);
};

const explicitAbsolutePath = name => {
  const value = process.env[name];
  if (
    value === undefined ||
    value === '/' ||
    value.trim() !== value ||
    !isAbsolute(value) ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail(`${name} must be an explicit non-root absolute path.`);
  }
  return value;
};

const sortedEntries = directory =>
  readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, 'en'));

const assertRegularDirectory = (path, label) => {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a non-symbolic directory.`);
  }
};

const collectJavaScriptFiles = (directory, files = []) => {
  assertRegularDirectory(directory, 'output directory');
  for (const entry of sortedEntries(directory)) {
    if (entry.name === 'node_modules') continue;
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      fail('the output bundle must not depend on a symbolic-link entry.');
    }
    if (entry.isDirectory()) {
      collectJavaScriptFiles(path, files);
      continue;
    }
    if (entry.isFile() && path.endsWith('.js')) {
      files.push(path);
      if (files.length > MaximumOutputFiles) {
        fail('the output bundle contains too many JavaScript entries to inspect.');
      }
    }
  }
  return files;
};

const assertOutputReadsExplicitControlRoot = outputRoot => {
  const files = collectJavaScriptFiles(outputRoot);
  if (!files.some(path => readFileSync(path, 'utf8').includes(ControlEnvironment))) {
    fail('the Modern output does not read the explicit analyzer-control root.');
  }
};

const assertOutputIsRelocatable = outputRoot => {
  assertRegularDirectory(outputRoot, 'Modern output root');
  const forbidden = [WorkspaceRoot, pathToFileURL(WorkspaceRoot).href];
  for (const path of collectJavaScriptFiles(outputRoot)) {
    const source = readFileSync(path, 'utf8');
    if (forbidden.some(value => source.includes(value))) {
      fail('the Modern output embeds its build-machine workspace path.');
    }
  }
  assertOutputReadsExplicitControlRoot(outputRoot);
};

const canonicalDoctorReport = (result, expectedStatus, expectedExit) => {
  if (result.error !== undefined || result.signal !== null || result.status !== expectedExit) {
    fail(`doctor did not exit with the expected ${String(expectedExit)} status.`);
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    fail('doctor did not emit a JSON runtime report.');
  }
  if (
    report?.schemaVersion !== 'codebase-radar.runtime-report/v1' ||
    report.status !== expectedStatus ||
    !Array.isArray(report.evidence) ||
    report.evidence.length !== 7 ||
    !report.evidence.every(evidence => evidence?.status === expectedStatus)
  ) {
    fail(`doctor did not emit canonical seven-row ${expectedStatus} evidence.`);
  }
};

const runDoctor = ({
  cli,
  runtimeRoot,
  workspaceParent,
  resourceCgroupRoot,
  analyzerControlRoot,
}) =>
  spawnSync(process.execPath, [cli, 'doctor', '--format', 'json'], {
    cwd: dirname(cli),
    encoding: 'utf8',
    env: {
      HOME: '/nonexistent',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      NO_COLOR: '1',
      PATH: '/usr/bin:/bin',
      [RuntimeEnvironment]: runtimeRoot,
      [WorkspaceEnvironment]: workspaceParent,
      [CgroupEnvironment]: resourceCgroupRoot,
      [ControlEnvironment]: analyzerControlRoot,
    },
    maxBuffer: 256 * 1024,
    timeout: DoctorTimeoutMs,
    windowsHide: true,
  });

const preserveMetadata = (source, destination) => {
  const sourceMetadata = lstatSync(source);
  if (sourceMetadata.isSymbolicLink()) {
    fail('the trusted control bundle must not contain symbolic links.');
  }
  if (sourceMetadata.isDirectory()) {
    for (const entry of sortedEntries(source)) {
      preserveMetadata(join(source, entry.name), join(destination, entry.name));
    }
  } else if (!sourceMetadata.isFile()) {
    fail('the trusted control bundle must contain only regular files.');
  }
  if (process.getuid?.() !== 0 && (
    sourceMetadata.uid !== process.getuid?.() ||
    sourceMetadata.gid !== process.getgid?.()
  )) {
    fail('a root-owned control bundle requires this hostile-mutation smoke to run as root.');
  }
  chownSync(destination, sourceMetadata.uid, sourceMetadata.gid);
  chmodSync(destination, sourceMetadata.mode & 0o7777);
};

const cloneControlRoot = controlRoot => {
  const parent = dirname(controlRoot);
  assertRegularDirectory(parent, 'control-root parent');
  const temporaryRoot = mkdtempSync(join(parent, ControlRootPrefix));
  const clonedControlRoot = join(temporaryRoot, 'control');
  try {
    cpSync(controlRoot, clonedControlRoot, {
      dereference: false,
      errorOnExist: true,
      preserveTimestamps: true,
      recursive: true,
      verbatimSymlinks: true,
    });
    preserveMetadata(controlRoot, clonedControlRoot);
    if (realpathSync(controlRoot) === realpathSync(clonedControlRoot)) {
      fail('the mutation control root must be independent from the trusted root.');
    }
    return { temporaryRoot, clonedControlRoot };
  } catch (error) {
    rmSync(temporaryRoot, { force: true, maxRetries: 3, recursive: true, retryDelay: 20 });
    throw error;
  }
};

const firstNonemptyRegularFile = directory => {
  for (const entry of sortedEntries(directory)) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) fail('the control clone contains a symbolic link.');
    if (entry.isDirectory()) {
      const nested = firstNonemptyRegularFile(path);
      if (nested !== undefined) return nested;
      continue;
    }
    if (entry.isFile() && lstatSync(path).size > 0) return path;
  }
  return undefined;
};

const mutateOneControlArtifact = controlRoot => {
  const artifact = firstNonemptyRegularFile(controlRoot);
  if (artifact === undefined) fail('the control clone has no mutable regular artifact.');
  const originalMode = lstatSync(artifact).mode & 0o7777;
  let descriptor;
  try {
    chmodSync(artifact, originalMode | 0o200);
    descriptor = openSync(artifact, 'r+');
    const byte = Buffer.alloc(1);
    readSync(descriptor, byte, 0, byte.length, 0);
    byte[0] ^= 0xff;
    writeSync(descriptor, byte, 0, byte.length, 0);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    chmodSync(artifact, originalMode);
  }
};

const main = () => {
  const runtimeRoot = explicitAbsolutePath(RuntimeEnvironment);
  const workspaceParent = explicitAbsolutePath(WorkspaceEnvironment);
  const resourceCgroupRoot = explicitAbsolutePath(CgroupEnvironment);
  const analyzerControlRoot = explicitAbsolutePath(ControlEnvironment);
  const outputRoot = explicitAbsolutePath(OutputEnvironment);
  const cli = explicitAbsolutePath(CliEnvironment);
  if (runtimeRoot === analyzerControlRoot) {
    fail('the analyzer-control root must not equal the analyzer target root.');
  }

  assertRegularDirectory(outputRoot, 'Modern output root');
  assertOutputReadsExplicitControlRoot(outputRoot);

  const doctorOptions = {
    cli,
    runtimeRoot,
    workspaceParent,
    resourceCgroupRoot,
    analyzerControlRoot,
  };
  canonicalDoctorReport(runDoctor(doctorOptions), 'ready', 0);
  canonicalDoctorReport(
    runDoctor({ ...doctorOptions, analyzerControlRoot: runtimeRoot }),
    'unavailable',
    DoctorUnavailableExitCode,
  );

  const { temporaryRoot, clonedControlRoot } = cloneControlRoot(analyzerControlRoot);
  try {
    canonicalDoctorReport(
      runDoctor({ ...doctorOptions, analyzerControlRoot: clonedControlRoot }),
      'ready',
      0,
    );
    mutateOneControlArtifact(clonedControlRoot);
    canonicalDoctorReport(
      runDoctor({ ...doctorOptions, analyzerControlRoot: clonedControlRoot }),
      'unavailable',
      DoctorUnavailableExitCode,
    );
  } finally {
    rmSync(temporaryRoot, { force: true, maxRetries: 3, recursive: true, retryDelay: 20 });
  }

  process.stdout.write('production-output-smoke: passed\n');
};

const run = () => {
  if (process.argv.length === 3 && process.argv[2] === StaticMode) {
    assertOutputIsRelocatable(BuiltOutputRoot);
    process.stdout.write('production-output-static-smoke: passed\n');
    return;
  }
  if (process.argv.length !== 2) {
    fail('unsupported arguments.');
  }
  main();
};

try {
  run();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'production-output-smoke: failed'}\n`);
  process.exitCode = 1;
}
