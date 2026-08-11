import {
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  writeSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const output = join(packageRoot, 'runtime-memfd-addon.node');
const source = join(packageRoot, 'runtime-memfd-addon.c');
const mode = process.argv[2] ?? '--check';
const require = createRequire(import.meta.url);
const RequiredMemfdSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;
const MaximumExecutableProbeBytes = 256 * 1024 * 1024;

if (mode !== '--check' && mode !== '--write') {
  throw new Error('Expected --check or --write.');
}

// The bridge is Linux-only by design. Darwin validation must honestly skip
// memfd sealing rather than pretending that an unlinked regular file is one.
if (process.platform !== 'linux') process.exit(0);

const nodePrefix = resolve(dirname(process.execPath), '..');
const includeCandidates = [
  join(nodePrefix, 'include', 'node'),
  '/usr/local/include/node',
  '/usr/include/node',
];
const include = includeCandidates.find(candidate => existsSync(join(candidate, 'node_api.h')));
if (include === undefined) throw new Error('No trusted Node N-API headers are available.');

const closeQuietly = fd => {
  if (!Number.isSafeInteger(fd) || fd < 0) return;
  try { closeSync(fd); } catch {}
};

const expectFailure = (action, label) => {
  try {
    action();
  } catch {
    return;
  }
  throw new Error(`The ${label} unexpectedly succeeded.`);
};

const assertMode = (fd, modeBits, label) => {
  const metadata = fstatSync(fd, { bigint: true });
  if (!metadata.isFile() || metadata.nlink !== 0n || (metadata.mode & 0o7777n) !== BigInt(modeBits)) {
    throw new Error(`The ${label} did not have its required anonymous mode.`);
  }
};

const writeAll = (fd, bytes) => {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = writeSync(fd, bytes, offset, bytes.byteLength - offset, null);
    if (written <= 0) throw new Error('The memfd write probe made no progress.');
    offset += written;
  }
};

const copyExecutableProbe = (source, destination) => {
  let sourceFd;
  try {
    sourceFd = openSync(source, 'r');
    const metadata = fstatSync(sourceFd, { bigint: true });
    if (!metadata.isFile() || metadata.size < 1n || metadata.size > BigInt(MaximumExecutableProbeBytes)) {
      throw new Error('The executable memfd probe source is outside its bounded regular-file policy.');
    }
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    const byteLength = Number(metadata.size);
    while (position < byteLength) {
      const read = readSync(sourceFd, buffer, 0, Math.min(buffer.byteLength, byteLength - position), position);
      if (read <= 0) throw new Error('The executable memfd probe source became truncated.');
      writeAll(destination, buffer.subarray(0, read));
      position += read;
    }
  } finally {
    closeQuietly(sourceFd);
  }
};

const proveBridge = () => {
  if (!existsSync(output)) throw new Error('The Linux runtime memfd bridge has not been built.');
  const addonMetadata = lstatSync(output, { bigint: true });
  if (
    !addonMetadata.isFile() ||
    addonMetadata.isSymbolicLink() ||
    addonMetadata.nlink !== 1n ||
    (addonMetadata.mode & 0o7777n) !== 0o555n
  ) {
    throw new Error('The Linux runtime memfd bridge must be an executable mode-0555 regular file.');
  }
  const bridge = require(output);
  if (
    typeof bridge?.createData !== 'function' ||
    typeof bridge?.createExecutable !== 'function' ||
    typeof bridge?.seal !== 'function' ||
    typeof bridge?.getSeals !== 'function'
  ) {
    throw new Error('The Linux runtime memfd bridge does not expose the required data/executable seal API.');
  }
  let dataFd;
  let executableFd;
  try {
    dataFd = bridge.createData();
    fchmodSync(dataFd, 0o444);
    assertMode(dataFd, 0o444, 'data memfd');
    writeAll(dataFd, Buffer.from('sealed-data-probe', 'ascii'));
    expectFailure(() => fchmodSync(dataFd, 0o555), 'MFD_NOEXEC_SEAL data chmod-to-exec probe');
    bridge.seal(dataFd);
    if ((bridge.getSeals(dataFd) & RequiredMemfdSeals) !== RequiredMemfdSeals) {
      throw new Error('The data memfd did not prove F_SEAL_WRITE|GROW|SHRINK|SEAL|EXEC.');
    }
    expectFailure(() => writeSync(dataFd, Buffer.from('x', 'ascii'), 0, 1, null), 'post-seal data write probe');

    executableFd = bridge.createExecutable();
    fchmodSync(executableFd, 0o555);
    assertMode(executableFd, 0o555, 'executable memfd');
    copyExecutableProbe(process.execPath, executableFd);
    bridge.seal(executableFd);
    if ((bridge.getSeals(executableFd) & RequiredMemfdSeals) !== RequiredMemfdSeals) {
      throw new Error('The executable memfd did not prove F_SEAL_WRITE|GROW|SHRINK|SEAL|EXEC.');
    }
    expectFailure(() => writeSync(executableFd, Buffer.from('x', 'ascii'), 0, 1, null), 'post-seal executable write probe');
    const exec = spawnSync(`/proc/self/fd/${executableFd}`, ['--version'], {
      cwd: '/',
      encoding: 'utf8',
      env: { HOME: '/nonexistent', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PATH: '/usr/bin:/bin' },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    if (exec.error !== undefined || exec.status !== 0 || !/^v[0-9]+\./u.test(exec.stdout ?? '')) {
      throw new Error('The executable MFD_EXEC memfd could not execute the bounded known ELF probe.');
    }
  } finally {
    closeQuietly(dataFd);
    closeQuietly(executableFd);
  }
};

if (mode === '--check') {
  proveBridge();
  process.exit(0);
}

const compiler = ['/usr/bin/cc', '/usr/bin/gcc'].find(candidate => existsSync(candidate));
if (compiler === undefined) throw new Error('A trusted C compiler is required to build the Linux memfd bridge.');
const result = spawnSync(
  compiler,
  ['-shared', '-fPIC', '-O2', '-std=c11', `-I${include}`, source, '-o', output],
  { cwd: packageRoot, encoding: 'utf8', shell: false, windowsHide: true },
);
if (result.status !== 0 || !existsSync(output)) {
  throw new Error('The Linux runtime memfd bridge could not be built.');
}
chmodSync(output, 0o555);
proveBridge();
