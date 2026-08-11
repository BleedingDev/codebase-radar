import { createHash } from 'node:crypto';
import { fstatSync, readSync } from 'node:fs';

/**
 * Narrow child-safe descriptor proofs. This module deliberately imports only
 * Node builtins: it is safe to bundle into the resource-governance launcher
 * without pulling analyzer-control inventory, target traversal, or anchors.
 */
export const runtimeDescriptorProofSchemaVersion =
  'codebase-radar.analyzer-runtime-descriptor-proofs/v1';
export const requiredRuntimeMemfdSeals = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0020;
export const runtimeDescriptorProofChunkBytes = 64 * 1024;

export class RuntimeDescriptorProofError extends Error {
  constructor(code, message, cause) {
    super(`[runtime-descriptor-proof:${code}] ${message}`, cause === undefined ? undefined : { cause });
    this.name = 'RuntimeDescriptorProofError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new RuntimeDescriptorProofError(code, message, cause);
};

const validIdentity = value =>
  value !== null && typeof value === 'object' &&
  ['device', 'inode', 'mode', 'size', 'nlink'].every(key =>
    typeof value[key] === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value[key]),
  );

export const serializeRuntimeDescriptorIdentity = metadata => Object.freeze({
  device: metadata.dev.toString(10),
  inode: metadata.ino.toString(10),
  mode: metadata.mode.toString(10),
  size: metadata.size.toString(10),
  nlink: metadata.nlink.toString(10),
});

export const matchesRuntimeDescriptorIdentity = (metadata, expected) => {
  if (!validIdentity(expected)) return false;
  const actual = serializeRuntimeDescriptorIdentity(metadata);
  return (
    actual.device === expected.device &&
    actual.inode === expected.inode &&
    actual.mode === expected.mode &&
    actual.size === expected.size &&
    actual.nlink === expected.nlink
  );
};

const assertFd = (fd, label) => {
  if (!Number.isSafeInteger(fd) || fd < 0) {
    fail('descriptor-invalid', `The ${label} descriptor is invalid.`);
  }
};

const boundedHash = ({ fd, byteLength, maximumBytes, label }) => {
  if (
    !Number.isSafeInteger(byteLength) || byteLength < 1 ||
    !Number.isSafeInteger(maximumBytes) || maximumBytes < byteLength
  ) {
    fail('descriptor-invalid', `The ${label} byte bounds are invalid.`);
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(runtimeDescriptorProofChunkBytes);
  let position = 0;
  while (position < byteLength) {
    let read;
    try {
      read = readSync(fd, buffer, 0, Math.min(buffer.byteLength, byteLength - position), position);
    } catch (cause) {
      fail('descriptor-unavailable', `The ${label} could not be read.`, cause);
    }
    if (read <= 0) fail('descriptor-truncated', `The ${label} became truncated.`);
    hash.update(buffer.subarray(0, read));
    position += read;
  }
  return hash.digest('hex');
};

export const assertTrustedRuntimeControlDescriptor = ({
  fd,
  byteLength,
  sha256,
  identity,
  maximumBytes,
  requiredMode,
  label = 'runtime control',
}) => {
  assertFd(fd, label);
  if (
    typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(sha256) ||
    !Number.isSafeInteger(byteLength) || byteLength < 1 ||
    !Number.isSafeInteger(maximumBytes) || maximumBytes < byteLength ||
    (requiredMode !== undefined && ![0o444, 0o555].includes(requiredMode))
  ) {
    fail('descriptor-invalid', `The ${label} control identity is invalid.`);
  }
  let metadata;
  try {
    metadata = fstatSync(fd, { bigint: true });
  } catch (cause) {
    fail('descriptor-unavailable', `The ${label} control descriptor is unavailable.`, cause);
  }
  if (
    !metadata.isFile() ||
    metadata.nlink !== 1n ||
    metadata.size !== BigInt(byteLength) ||
    !matchesRuntimeDescriptorIdentity(metadata, identity) ||
    (requiredMode !== undefined && (metadata.mode & 0o7777n) !== BigInt(requiredMode)) ||
    boundedHash({ fd, byteLength, maximumBytes, label }) !== sha256
  ) {
    fail('descriptor-invalid', `The ${label} control descriptor no longer matches its retained identity.`);
  }
  return Object.freeze({
    fd,
    byteLength,
    sha256,
    identity: serializeRuntimeDescriptorIdentity(metadata),
  });
};

export const loadRuntimeMemfdBridgeFromDescriptor = ({
  addonFd,
  addonBytes,
  addonSha256,
  addonIdentity,
  addonMaximumBytes,
}) => {
  const artifact = assertTrustedRuntimeControlDescriptor({
    fd: addonFd,
    byteLength: addonBytes,
    sha256: addonSha256,
    identity: addonIdentity,
    maximumBytes: addonMaximumBytes,
    requiredMode: 0o555,
    label: 'runtime memfd bridge',
  });
  try {
    const addon = { exports: {} };
    process.dlopen(addon, `/proc/self/fd/${artifact.fd}`);
    const bridge = addon.exports;
    if (
      typeof bridge?.createData !== 'function' ||
      typeof bridge?.createExecutable !== 'function' ||
      typeof bridge?.seal !== 'function' ||
      typeof bridge?.getSeals !== 'function'
    ) {
      fail('bridge-invalid', 'The retained runtime memfd bridge has an invalid API.');
    }
    return bridge;
  } catch (cause) {
    if (cause instanceof RuntimeDescriptorProofError) throw cause;
    fail('bridge-unavailable', 'The retained runtime memfd bridge could not be loaded.', cause);
  }
};

export const assertSealedRuntimeMemfdDescriptor = ({
  bridge,
  fd,
  byteLength,
  identity,
  maximumBytes,
  executable = false,
  sha256,
  label = 'sealed runtime memfd',
}) => {
  assertFd(fd, label);
  if (
    bridge === null || typeof bridge !== 'object' || typeof bridge.getSeals !== 'function' ||
    !Number.isSafeInteger(byteLength) || byteLength < 0 ||
    !Number.isSafeInteger(maximumBytes) || maximumBytes < byteLength ||
    typeof executable !== 'boolean' ||
    (sha256 !== undefined && (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(sha256)))
  ) {
    fail('memfd-invalid', `The ${label} proof inputs are invalid.`);
  }
  let metadata;
  let seals;
  try {
    metadata = fstatSync(fd, { bigint: true });
    seals = bridge.getSeals(fd);
  } catch (cause) {
    fail('memfd-unavailable', `The ${label} seal proof is unavailable.`, cause);
  }
  const expectedMode = executable ? 0o555 : 0o444;
  if (
    !metadata.isFile() ||
    metadata.nlink !== 0n ||
    metadata.size !== BigInt(byteLength) ||
    metadata.size > BigInt(maximumBytes) ||
    (metadata.mode & 0o7777n) !== BigInt(expectedMode) ||
    !matchesRuntimeDescriptorIdentity(metadata, identity) ||
    (seals & requiredRuntimeMemfdSeals) !== requiredRuntimeMemfdSeals ||
    (sha256 !== undefined && boundedHash({ fd, byteLength, maximumBytes, label }) !== sha256)
  ) {
    fail('memfd-invalid', `The ${label} is not the retained immutable anonymous descriptor.`);
  }
  return Object.freeze({
    fd,
    byteLength,
    seals,
    identity: serializeRuntimeDescriptorIdentity(metadata),
  });
};

export const assertMaterializedRuntimeRootDescriptor = ({
  runtimeRootFd,
  runtimeRootIdentity,
  label = 'materialized runtime root',
}) => {
  assertFd(runtimeRootFd, label);
  let metadata;
  try {
    metadata = fstatSync(runtimeRootFd, { bigint: true });
  } catch (cause) {
    fail('root-unavailable', `The ${label} descriptor is unavailable.`, cause);
  }
  if (
    !metadata.isDirectory() ||
    (metadata.mode & 0o7777n) !== 0o555n ||
    !matchesRuntimeDescriptorIdentity(metadata, runtimeRootIdentity)
  ) {
    fail('root-invalid', `The ${label} no longer matches its retained identity.`);
  }
  return Object.freeze({
    runtimeRootFd,
    runtimeRootIdentity: serializeRuntimeDescriptorIdentity(metadata),
  });
};
