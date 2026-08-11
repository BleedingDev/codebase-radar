import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const cliRoot = '/build/source/.zerops/radar-cli';
const controlRoot = '/build/source/.zerops/analyzer-control';
const targetRoot = '/build/source/.zerops/analyzer-runtime';
const nodePath = '/usr/local/lib/radar-node-v24.18.1/bin/node';
const nodeSha256 =
  'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a';
const maximumNodeBytes = 256 * 1024 * 1024;
const requiredSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;
const expectedControl = [
  ['resource-governance-launcher.mjs', 0o444],
  ['runtime-memfd-addon.node', 0o555],
  ['runtime-snapshot-loader.mjs', 0o444],
];

const fail = message => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const inside = (root, candidate) =>
  candidate === root || candidate.startsWith(`${root}/`);

const actualControl = readdirSync(controlRoot).sort();
const expectedControlNames = expectedControl.map(([name]) => name).sort();
if (JSON.stringify(actualControl) !== JSON.stringify(expectedControlNames)) {
  fail('Analyzer control root has an unexpected inventory.');
}

for (const [name, expectedMode] of expectedControl) {
  const candidate = `${controlRoot}/${name}`;
  const metadata = lstatSync(candidate, { bigint: true });
  if (
    realpathSync(candidate) !== candidate ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1n ||
    (metadata.mode & 0o7777n) !== BigInt(expectedMode)
  ) {
    fail(`Analyzer control artifact ${name} has invalid containment or mode.`);
  }
}

const fromCli = createRequire(resolve(cliRoot, 'package.json'));
const coreEntry = realpathSync(fromCli.resolve('@codebase-radar/core'));
const fromCore = createRequire(resolve(coreEntry, '../../package.json'));
const verifier = realpathSync(
  fromCore.resolve('@codebase-radar/analyzer-runtime/runtime-verifier'),
);
const anchor = realpathSync(
  fromCore.resolve('@codebase-radar/analyzer-runtime/trust-anchor'),
);
const addon = realpathSync(resolve(verifier, '../runtime-memfd-addon.node'));
const addonMetadata = lstatSync(addon, { bigint: true });
if (
  !inside(cliRoot, coreEntry) ||
  !inside(cliRoot, verifier) ||
  !inside(cliRoot, anchor) ||
  !inside(cliRoot, addon) ||
  inside(targetRoot, verifier) ||
  inside(targetRoot, anchor) ||
  inside(targetRoot, addon) ||
  !addonMetadata.isFile() ||
  addonMetadata.isSymbolicLink() ||
  addonMetadata.nlink !== 1n
) {
  fail(
    'CLI verifier and native bridge must resolve only from its deployed dependency tree.',
  );
}

const nodeMetadata = lstatSync(nodePath, { bigint: true });
if (
  realpathSync(nodePath) !== nodePath ||
  !nodeMetadata.isFile() ||
  nodeMetadata.isSymbolicLink() ||
  nodeMetadata.uid !== 0n ||
  nodeMetadata.gid !== 0n ||
  nodeMetadata.nlink !== 1n ||
  (nodeMetadata.mode & 0o7777n) !== 0o755n ||
  nodeMetadata.size < 1n ||
  nodeMetadata.size > BigInt(maximumNodeBytes)
) {
  fail('Pinned bootstrap Node ELF is not a bounded canonical executable.');
}

const bridge = fromCore(addon);
if (
  typeof bridge?.createData !== 'function' ||
  typeof bridge?.createExecutable !== 'function' ||
  typeof bridge?.seal !== 'function' ||
  typeof bridge?.getSeals !== 'function'
) {
  fail('Deployed runtime memfd bridge API is invalid.');
}

for (const [label, create, expectedMode] of [
  ['data', bridge.createData, 0o444],
  ['executable', bridge.createExecutable, 0o555],
]) {
  const descriptor = create();
  try {
    if (!Number.isSafeInteger(descriptor) || descriptor < 0) {
      fail(`Memfd ${label} factory returned an invalid descriptor.`);
    }
    if (label === 'data') {
      let executeDenied = false;
      try {
        fchmodSync(descriptor, 0o555);
      } catch (error) {
        executeDenied = error?.code === 'EPERM';
      }
      if (!executeDenied) {
        fail('Data memfd accepted executable mode despite MFD_NOEXEC_SEAL.');
      }
    }

    fchmodSync(descriptor, expectedMode);
    let metadata = fstatSync(descriptor, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink !== 0n ||
      (metadata.mode & 0o7777n) !== BigInt(expectedMode)
    ) {
      fail(`Memfd ${label} did not retain its exact mode.`);
    }

    if (label === 'data') {
      if (writeSync(descriptor, Buffer.from('data'), 0, 4, 0) !== 4) {
        fail('Data memfd short write.');
      }
    } else {
      const source = openSync(nodePath, 'r');
      try {
        const sourceMetadata = fstatSync(source, { bigint: true });
        if (
          !sourceMetadata.isFile() ||
          sourceMetadata.nlink !== 1n ||
          sourceMetadata.size !== nodeMetadata.size ||
          sourceMetadata.size < 1n ||
          sourceMetadata.size > BigInt(maximumNodeBytes)
        ) {
          fail('Pinned Node stream source changed during the closure probe.');
        }
        const hash = createHash('sha256');
        const buffer = Buffer.allocUnsafe(65_536);
        const byteLength = Number(sourceMetadata.size);
        let offset = 0;
        while (offset < byteLength) {
          const read = readSync(
            source,
            buffer,
            0,
            Math.min(buffer.byteLength, byteLength - offset),
            offset,
          );
          if (read <= 0) fail('Pinned Node ELF stream was truncated.');
          hash.update(buffer.subarray(0, read));
          let written = 0;
          while (written < read) {
            const count = writeSync(
              descriptor,
              buffer,
              written,
              read - written,
              offset + written,
            );
            if (count <= 0) fail('Executable memfd stream short write.');
            written += count;
          }
          offset += read;
        }
        if (hash.digest('hex') !== nodeSha256) {
          fail('Pinned Node ELF stream hash mismatched.');
        }
      } finally {
        closeSync(source);
      }
    }

    fsyncSync(descriptor);
    const added = bridge.seal(descriptor);
    const seals = bridge.getSeals(descriptor);
    if (
      (added & requiredSeals) !== requiredSeals ||
      (seals & requiredSeals) !== requiredSeals
    ) {
      fail(`Memfd ${label} did not attest WRITE|GROW|SHRINK|SEAL|EXEC.`);
    }
    metadata = fstatSync(descriptor, { bigint: true });
    if (
      !metadata.isFile() ||
      metadata.nlink !== 0n ||
      (metadata.mode & 0o7777n) !== BigInt(expectedMode)
    ) {
      fail(`Sealed memfd ${label} lost its exact mode.`);
    }

    let writeDenied = false;
    try {
      writeSync(descriptor, Buffer.from('x'), 0, 1, 0);
    } catch (error) {
      writeDenied = error?.code === 'EPERM';
    }
    if (!writeDenied) fail(`Sealed memfd ${label} accepted a write.`);

    if (label === 'data') {
      let executeDenied = false;
      try {
        fchmodSync(descriptor, 0o555);
      } catch (error) {
        executeDenied = error?.code === 'EPERM';
      }
      if (!executeDenied) fail('Sealed data memfd accepted execute permission.');
    } else {
      const result = spawnSync(`/proc/self/fd/${descriptor}`, ['--version'], {
        encoding: 'utf8',
        env: {
          HOME: '/nonexistent',
          LANG: 'C.UTF-8',
          LC_ALL: 'C.UTF-8',
          NO_COLOR: '1',
          PATH: '/usr/bin:/bin',
        },
        shell: false,
        windowsHide: true,
      });
      if (
        result.error ||
        result.status !== 0 ||
        String(result.stdout).trim() !== 'v24.18.1' ||
        String(result.stderr) !== ''
      ) {
        fail('Executable sealed memfd did not run the pinned Node ELF.');
      }
    }
  } finally {
    closeSync(descriptor);
  }
}

process.stdout.write('Deployed runtime closure smoke passed.\n');
