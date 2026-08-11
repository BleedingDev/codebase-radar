// The sealed-runtime codec is intentionally small and dependency-free. Both
// the packer and the in-sandbox loader use these exact records; do not replace
// it with tar/cpio or a command-line extractor.

export const sealedRuntimeSnapshotMagic = Buffer.from('RDRSNAP1', 'ascii');
export const sealedRuntimeSnapshotVersion = 1;
// Four anchored control digests bind the archive to the manifest, semantic
// runner, runtime Node executable, and the immutable OSV database snapshot.
// Keep this fixed-width: the loader must never need an attacker-sized header.
export const sealedRuntimeSnapshotHeaderBytes = 144;
export const sealedRuntimeSnapshotRecordPrefixBytes = 19;
export const sealedRuntimeSnapshotPathBytes = 4 * 1024;
export const sealedRuntimeSnapshotLinkBytes = 4 * 1024;

export const sealedRuntimeSnapshotRecordKind = Object.freeze({
  directory: 1,
  file: 2,
  symlink: 3,
});

const sha256 = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError('A lowercase SHA-256 digest is required.');
  }
  return Buffer.from(value, 'hex');
};

const u32 = (value, label) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new TypeError(`${label} must be an unsigned 32-bit integer.`);
  }
  return value;
};

const u64 = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TypeError(`${label} must be an unsigned 64-bit integer.`);
  }
  return value;
};

export const compareSnapshotPaths = (left, right) =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

export const assertSnapshotRelativePath = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > sealedRuntimeSnapshotPathBytes ||
    value.includes('\\') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError('Snapshot paths must be bounded printable POSIX relative paths.');
  }
  const parts = value.split('/');
  if (parts.some(part => part.length === 0 || part === '.' || part === '..')) {
    throw new TypeError('Snapshot paths must not contain empty or traversal components.');
  }
  return value;
};

export const assertSnapshotLinkTarget = value => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > sealedRuntimeSnapshotLinkBytes ||
    value.startsWith('/') ||
    value.includes('\\') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError('Snapshot links must use a bounded printable relative target.');
  }
  return value;
};

export const encodeSealedRuntimeSnapshotHeader = ({
  entryCount,
  manifestSha256,
  runnerSha256,
  nodeSha256,
  osvDatabaseSha256,
}) => {
  const header = Buffer.alloc(sealedRuntimeSnapshotHeaderBytes);
  sealedRuntimeSnapshotMagic.copy(header, 0);
  header.writeUInt32BE(sealedRuntimeSnapshotVersion, 8);
  header.writeUInt32BE(u32(entryCount, 'entryCount'), 12);
  sha256(manifestSha256).copy(header, 16);
  sha256(runnerSha256).copy(header, 48);
  sha256(nodeSha256).copy(header, 80);
  sha256(osvDatabaseSha256).copy(header, 112);
  return header;
};

export const decodeSealedRuntimeSnapshotHeader = bytes => {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== sealedRuntimeSnapshotHeaderBytes) {
    throw new TypeError('Snapshot header has an invalid length.');
  }
  if (!bytes.subarray(0, sealedRuntimeSnapshotMagic.byteLength).equals(sealedRuntimeSnapshotMagic)) {
    throw new TypeError('Snapshot header has an invalid magic value.');
  }
  if (bytes.readUInt32BE(8) !== sealedRuntimeSnapshotVersion) {
    throw new TypeError('Snapshot header has an unsupported version.');
  }
  const reserved = bytes.subarray(144);
  if (reserved.some(byte => byte !== 0)) {
    throw new TypeError('Snapshot header has non-canonical reserved bytes.');
  }
  return Object.freeze({
    entryCount: bytes.readUInt32BE(12),
    manifestSha256: bytes.subarray(16, 48).toString('hex'),
    runnerSha256: bytes.subarray(48, 80).toString('hex'),
    nodeSha256: bytes.subarray(80, 112).toString('hex'),
    osvDatabaseSha256: bytes.subarray(112, 144).toString('hex'),
  });
};

export const encodeSealedRuntimeSnapshotRecordPrefix = ({
  kind,
  mode,
  pathBytes,
  payloadBytes,
}) => {
  if (!Object.values(sealedRuntimeSnapshotRecordKind).includes(kind)) {
    throw new TypeError('Snapshot record kind is invalid.');
  }
  if (!Number.isSafeInteger(mode) || mode < 0 || mode > 0o777) {
    throw new TypeError('Snapshot record mode is invalid.');
  }
  const path = Buffer.isBuffer(pathBytes) ? pathBytes : Buffer.from(pathBytes, 'utf8');
  if (path.byteLength === 0 || path.byteLength > sealedRuntimeSnapshotPathBytes) {
    throw new TypeError('Snapshot record path length is invalid.');
  }
  const result = Buffer.alloc(sealedRuntimeSnapshotRecordPrefixBytes);
  result.writeUInt8(kind, 0);
  result.writeUInt16BE(mode, 1);
  result.writeUInt32BE(u32(path.byteLength, 'pathBytes'), 3);
  result.writeBigUInt64BE(u64(payloadBytes, 'payloadBytes'), 7);
  result.writeUInt32BE(0, 15);
  return result;
};

export const decodeSealedRuntimeSnapshotRecordPrefix = bytes => {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== sealedRuntimeSnapshotRecordPrefixBytes) {
    throw new TypeError('Snapshot record prefix has an invalid length.');
  }
  const kind = bytes.readUInt8(0);
  const mode = bytes.readUInt16BE(1);
  const pathBytes = bytes.readUInt32BE(3);
  const payloadBytes = bytes.readBigUInt64BE(7);
  if (
    !Object.values(sealedRuntimeSnapshotRecordKind).includes(kind) ||
    ![0o444, 0o555].includes(mode) ||
    pathBytes === 0 ||
    pathBytes > sealedRuntimeSnapshotPathBytes ||
    bytes.readUInt32BE(15) !== 0
  ) {
    throw new TypeError('Snapshot record prefix is non-canonical.');
  }
  if (
    (kind === sealedRuntimeSnapshotRecordKind.directory && payloadBytes !== 0n) ||
    (kind === sealedRuntimeSnapshotRecordKind.symlink && payloadBytes > BigInt(sealedRuntimeSnapshotLinkBytes))
  ) {
    throw new TypeError('Snapshot record payload is invalid.');
  }
  return Object.freeze({ kind, mode, pathBytes, payloadBytes });
};
