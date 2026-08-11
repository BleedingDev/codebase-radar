import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inflateRawSync } from 'node:zlib';

export const osvNpmSnapshotEvidenceSchemaVersion =
  'codebase-radar.osv-npm-snapshot-evidence/v1';

export const pinnedOsvNpmSnapshotRelease = Object.freeze({
  url: 'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=1786418349414076',
  generation: '1786418349414076',
  size: 218_758_368,
  sha256: '38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69',
  publishedAt: '2026-08-11T03:19:09Z',
  maxAge: 604_800,
  entryCount: 226_504,
  uncompressedBytes: 371_036_838,
});

export const osvNpmSnapshotValidationBounds = Object.freeze({
  maxArchiveBytes: 256 * 1024 * 1024,
  maxEntries: 250_000,
  maxCentralDirectoryBytes: 64 * 1024 * 1024,
  maxNameBytes: 128,
  maxExtraBytes: 4 * 1024,
  maxEntryUncompressedBytes: 1024 * 1024,
  maxAggregateUncompressedBytes: 512 * 1024 * 1024,
  maxCompressionRatio: 200,
});

export class OsvNpmSnapshotValidationError extends Error {
  constructor(code, message, cause) {
    super(
      `[osv-npm-snapshot:${code}] ${message}`,
      cause === undefined ? undefined : { cause },
    );
    this.name = 'OsvNpmSnapshotValidationError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new OsvNpmSnapshotValidationError(code, message, cause);
};

const signatures = Object.freeze({
  local: 0x04034b50,
  central: 0x02014b50,
  dataDescriptor: 0x08074b50,
  eocd: 0x06054b50,
  zip64Eocd: 0x06064b50,
  zip64Locator: 0x07064b50,
});

const limits = Object.freeze({
  uint16: 0xffff,
  uint32: 0xffffffff,
  eocdBytes: 22,
  zip64LocatorBytes: 20,
  zip64EocdBytes: 56,
  centralHeaderBytes: 46,
  localHeaderBytes: 30,
  dataDescriptorBytes: 16,
});

const dataDescriptorFlag = 0x0008;
const utf8Flag = 0x0800;
const allowedGeneralPurposeFlags = dataDescriptorFlag | utf8Flag;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const utf8Encoder = new TextEncoder();
const sha256Pattern = /^[0-9a-f]{64}$/u;
const generationPattern = /^(?:0|[1-9][0-9]*)$/u;
const canonicalTimestampPattern =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u;
const pathSeparatorPattern = /[\\/]/u;

const crc32Table = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

const crc32 = bytes => {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value = crc32Table[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
};

const assertSafeInteger = (value, label, { minimum = 0 } = {}) => {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail('policy-invalid', `${label} must be a safe integer no smaller than ${minimum}.`);
  }
  return value;
};

const normalizeRelease = release => {
  if (release === null || typeof release !== 'object' || Array.isArray(release)) {
    fail('release-invalid', 'Release metadata must be an object.');
  }
  const keys = Object.keys(release).sort();
  const expectedKeys = [
    'entryCount',
    'generation',
    'maxAge',
    'publishedAt',
    'sha256',
    'size',
    'uncompressedBytes',
    'url',
  ];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(
      'release-invalid',
      `Release metadata must contain exactly ${expectedKeys.join(', ')}.`,
    );
  }
  if (
    typeof release.generation !== 'string' ||
    !generationPattern.test(release.generation)
  ) {
    fail('release-invalid', 'Release generation must be a canonical decimal string.');
  }
  if (typeof release.url !== 'string') {
    fail('release-invalid', 'Release URL must be a string.');
  }
  let sourceUrl;
  try {
    sourceUrl = new URL(release.url);
  } catch (cause) {
    fail('release-invalid', 'Release URL is invalid.', cause);
  }
  const query = [...sourceUrl.searchParams.entries()];
  if (
    sourceUrl.protocol !== 'https:' ||
    sourceUrl.username !== '' ||
    sourceUrl.password !== '' ||
    sourceUrl.hash !== '' ||
    query.length !== 1 ||
    query[0]?.[0] !== 'generation' ||
    query[0]?.[1] !== release.generation
  ) {
    fail(
      'release-generation-mismatch',
      'Release URL must be HTTPS and qualified by exactly the declared generation.',
    );
  }
  if (typeof release.sha256 !== 'string' || !sha256Pattern.test(release.sha256)) {
    fail('release-invalid', 'Release sha256 must be 64 lowercase hexadecimal characters.');
  }
  if (
    typeof release.publishedAt !== 'string' ||
    !canonicalTimestampPattern.test(release.publishedAt) ||
    Number.isNaN(Date.parse(release.publishedAt)) ||
    new Date(release.publishedAt).toISOString().replace('.000Z', 'Z') !==
      release.publishedAt
  ) {
    fail('release-invalid', 'Release publishedAt must be a canonical UTC timestamp.');
  }
  assertSafeInteger(release.size, 'Release size', { minimum: 1 });
  assertSafeInteger(release.maxAge, 'Release maxAge', { minimum: 1 });
  assertSafeInteger(release.entryCount, 'Release entryCount', { minimum: 1 });
  assertSafeInteger(
    release.uncompressedBytes,
    'Release uncompressedBytes',
    { minimum: 1 },
  );
  return Object.freeze({
    url: release.url,
    generation: release.generation,
    size: release.size,
    sha256: release.sha256,
    publishedAt: release.publishedAt,
    maxAge: release.maxAge,
    entryCount: release.entryCount,
    uncompressedBytes: release.uncompressedBytes,
  });
};

const normalizeBounds = overrides => {
  if (overrides === undefined) return osvNpmSnapshotValidationBounds;
  if (overrides === null || typeof overrides !== 'object' || Array.isArray(overrides)) {
    fail('policy-invalid', 'Validation bounds must be an object.');
  }
  const knownKeys = Object.keys(osvNpmSnapshotValidationBounds);
  for (const key of Object.keys(overrides)) {
    if (!knownKeys.includes(key)) {
      fail('policy-invalid', `Unknown validation bound ${key}.`);
    }
  }
  const result = {};
  for (const key of knownKeys) {
    const value = Object.hasOwn(overrides, key)
      ? overrides[key]
      : osvNpmSnapshotValidationBounds[key];
    result[key] = assertSafeInteger(value, `Validation bound ${key}`, {
      minimum: 1,
    });
  }
  return Object.freeze(result);
};

const asStableBuffer = bytes => {
  if (!(bytes instanceof Uint8Array)) {
    fail('bytes-invalid', 'Snapshot bytes must be a Uint8Array or Buffer.');
  }
  if (
    typeof SharedArrayBuffer !== 'undefined' &&
    bytes.buffer instanceof SharedArrayBuffer
  ) {
    fail('bytes-invalid', 'Snapshot bytes must not use shared mutable storage.');
  }
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
};

const assertReadableRange = (archive, offset, size, label) => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    offset < 0 ||
    size < 0 ||
    offset > archive.length - size
  ) {
    fail('zip-range-invalid', `${label} is outside the archive.`);
  }
};

const readUint16 = (archive, offset, label) => {
  assertReadableRange(archive, offset, 2, label);
  return archive.readUInt16LE(offset);
};

const readUint32 = (archive, offset, label) => {
  assertReadableRange(archive, offset, 4, label);
  return archive.readUInt32LE(offset);
};

const safeUint64 = (archive, offset, label) => {
  assertReadableRange(archive, offset, 8, label);
  const value = archive.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('zip64-range-invalid', `${label} exceeds the safe integer range.`);
  }
  return Number(value);
};

const checkedEnd = (offset, size, limit, label) => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    offset < 0 ||
    size < 0 ||
    offset > limit - size
  ) {
    fail('zip-range-invalid', `${label} is outside its containing ZIP region.`);
  }
  return offset + size;
};

const locateEocd = archive => {
  if (archive.length < limits.eocdBytes) {
    fail('eocd-invalid', 'Archive is too short to contain an EOCD record.');
  }
  const expectedOffset = archive.length - limits.eocdBytes;
  if (readUint32(archive, expectedOffset, 'EOCD signature') === signatures.eocd) {
    return expectedOffset;
  }
  const signatureBytes = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const searchStart = Math.max(0, archive.length - limits.uint16 - limits.eocdBytes);
  const candidate = archive.lastIndexOf(signatureBytes, expectedOffset - 1);
  if (candidate >= searchStart && candidate + limits.eocdBytes <= archive.length) {
    const commentBytes = readUint16(archive, candidate + 20, 'EOCD comment length');
    if (candidate + limits.eocdBytes + commentBytes < archive.length) {
      fail('trailing-data', 'Archive contains bytes after its EOCD record.');
    }
    if (candidate + limits.eocdBytes + commentBytes === archive.length) {
      fail('eocd-comment', 'Archive comments are not permitted.');
    }
  }
  fail('eocd-invalid', 'Archive does not end with a canonical EOCD record.');
};

const parseDirectoryLocation = (archive, bounds) => {
  const eocdOffset = locateEocd(archive);
  const diskNumber = readUint16(archive, eocdOffset + 4, 'EOCD disk number');
  const directoryDisk = readUint16(
    archive,
    eocdOffset + 6,
    'EOCD central-directory disk',
  );
  const entriesOnDisk32 = readUint16(
    archive,
    eocdOffset + 8,
    'EOCD disk entry count',
  );
  const totalEntries32 = readUint16(
    archive,
    eocdOffset + 10,
    'EOCD total entry count',
  );
  const directorySize32 = readUint32(
    archive,
    eocdOffset + 12,
    'EOCD central-directory size',
  );
  const directoryOffset32 = readUint32(
    archive,
    eocdOffset + 16,
    'EOCD central-directory offset',
  );
  const commentBytes = readUint16(archive, eocdOffset + 20, 'EOCD comment length');
  if (commentBytes !== 0) {
    fail('eocd-comment', 'Archive comments are not permitted.');
  }
  if (diskNumber !== 0 || directoryDisk !== 0) {
    fail('multidisk-unsupported', 'Multidisk ZIP archives are not permitted.');
  }
  const needsZip64 =
    entriesOnDisk32 === limits.uint16 ||
    totalEntries32 === limits.uint16 ||
    directorySize32 === limits.uint32 ||
    directoryOffset32 === limits.uint32;

  let entryCount = totalEntries32;
  let directorySize = directorySize32;
  let directoryOffset = directoryOffset32;
  let metadataOffset = eocdOffset;
  if (needsZip64) {
    const locatorOffset = eocdOffset - limits.zip64LocatorBytes;
    if (
      locatorOffset < 0 ||
      readUint32(archive, locatorOffset, 'ZIP64 locator signature') !==
        signatures.zip64Locator
    ) {
      fail('zip64-locator-invalid', 'ZIP64 EOCD locator is missing or misplaced.');
    }
    const zip64Disk = readUint32(archive, locatorOffset + 4, 'ZIP64 EOCD disk');
    const zip64Offset = safeUint64(
      archive,
      locatorOffset + 8,
      'ZIP64 EOCD offset',
    );
    const totalDisks = readUint32(
      archive,
      locatorOffset + 16,
      'ZIP64 total disk count',
    );
    if (zip64Disk !== 0 || totalDisks !== 1) {
      fail('multidisk-unsupported', 'Multidisk ZIP64 archives are not permitted.');
    }
    if (zip64Offset + limits.zip64EocdBytes !== locatorOffset) {
      fail('zip64-layout-invalid', 'ZIP64 EOCD and locator must be contiguous.');
    }
    if (
      readUint32(archive, zip64Offset, 'ZIP64 EOCD signature') !==
      signatures.zip64Eocd
    ) {
      fail('zip64-eocd-invalid', 'ZIP64 EOCD signature is invalid.');
    }
    if (safeUint64(archive, zip64Offset + 4, 'ZIP64 EOCD record size') !== 44) {
      fail('zip64-eocd-invalid', 'ZIP64 EOCD extensible data is not permitted.');
    }
    const versionNeeded = readUint16(
      archive,
      zip64Offset + 14,
      'ZIP64 version needed',
    );
    const recordDisk = readUint32(archive, zip64Offset + 16, 'ZIP64 disk number');
    const recordDirectoryDisk = readUint32(
      archive,
      zip64Offset + 20,
      'ZIP64 central-directory disk',
    );
    const entriesOnDisk = safeUint64(
      archive,
      zip64Offset + 24,
      'ZIP64 disk entry count',
    );
    entryCount = safeUint64(
      archive,
      zip64Offset + 32,
      'ZIP64 total entry count',
    );
    directorySize = safeUint64(
      archive,
      zip64Offset + 40,
      'ZIP64 central-directory size',
    );
    directoryOffset = safeUint64(
      archive,
      zip64Offset + 48,
      'ZIP64 central-directory offset',
    );
    if (
      versionNeeded !== 45 ||
      recordDisk !== 0 ||
      recordDirectoryDisk !== 0 ||
      entriesOnDisk !== entryCount
    ) {
      fail('zip64-eocd-invalid', 'ZIP64 EOCD policy fields are inconsistent.');
    }
    if (
      (entriesOnDisk32 !== limits.uint16 && entriesOnDisk32 !== entryCount) ||
      (totalEntries32 !== limits.uint16 && totalEntries32 !== entryCount) ||
      (directorySize32 !== limits.uint32 && directorySize32 !== directorySize) ||
      (directoryOffset32 !== limits.uint32 &&
        directoryOffset32 !== directoryOffset)
    ) {
      fail('zip64-eocd-invalid', 'ZIP64 and classic EOCD values disagree.');
    }
    metadataOffset = zip64Offset;
  } else {
    const locatorOffset = eocdOffset - limits.zip64LocatorBytes;
    if (
      locatorOffset >= 0 &&
      readUint32(archive, locatorOffset, 'possible ZIP64 locator') ===
        signatures.zip64Locator
    ) {
      fail('zip64-unexpected', 'ZIP64 records are not permitted without EOCD sentinels.');
    }
    if (entriesOnDisk32 !== totalEntries32) {
      fail('multidisk-unsupported', 'EOCD entry counts disagree.');
    }
  }
  if (entryCount < 1 || entryCount > bounds.maxEntries) {
    fail('entry-count-limit', `Archive entry count ${entryCount} exceeds policy.`);
  }
  if (directorySize > bounds.maxCentralDirectoryBytes) {
    fail('central-directory-limit', 'Central directory exceeds its byte limit.');
  }
  const directoryEnd = checkedEnd(
    directoryOffset,
    directorySize,
    archive.length,
    'central directory',
  );
  if (directoryEnd !== metadataOffset) {
    fail(
      'central-directory-layout',
      'Central directory must end immediately before end-of-directory metadata.',
    );
  }
  return Object.freeze({
    entryCount,
    directoryOffset,
    directorySize,
    directoryEnd,
    zip64: needsZip64,
  });
};

const parseExtraFields = (archive, offset, length, bounds, label) => {
  if (length > bounds.maxExtraBytes) {
    fail('extra-field-limit', `${label} exceeds the extra-field byte limit.`);
  }
  const end = checkedEnd(offset, length, archive.length, label);
  const fields = new Map();
  let cursor = offset;
  while (cursor < end) {
    if (end - cursor < 4) {
      fail('extra-field-invalid', `${label} has a truncated field header.`);
    }
    const id = readUint16(archive, cursor, `${label} field id`);
    const size = readUint16(archive, cursor + 2, `${label} field size`);
    const dataOffset = cursor + 4;
    const dataEnd = checkedEnd(dataOffset, size, end, `${label} field data`);
    if (fields.has(id)) {
      fail('extra-field-invalid', `${label} repeats field 0x${id.toString(16)}.`);
    }
    if (id === 0x7075 || id === 0x6375) {
      fail(
        'alternate-name-unsupported',
        `${label} contains a Unicode path or comment override.`,
      );
    }
    fields.set(id, archive.subarray(dataOffset, dataEnd));
    cursor = dataEnd;
  }
  return fields;
};

const zip64EntryValues = ({
  fields,
  uncompressed32,
  compressed32,
  localOffset32,
  diskStart32,
  label,
}) => {
  const required = [
    uncompressed32 === limits.uint32,
    compressed32 === limits.uint32,
    localOffset32 === limits.uint32,
    diskStart32 === limits.uint16,
  ];
  const zip64 = fields.get(0x0001);
  if (!required.some(Boolean)) {
    if (zip64 !== undefined) {
      fail('zip64-entry-unexpected', `${label} has an unnecessary ZIP64 extra field.`);
    }
    return Object.freeze({
      uncompressedSize: uncompressed32,
      compressedSize: compressed32,
      localOffset: localOffset32,
      diskStart: diskStart32,
    });
  }
  if (zip64 === undefined) {
    fail('zip64-entry-invalid', `${label} is missing its ZIP64 extra field.`);
  }
  let cursor = 0;
  const readZip64 = (needed, width, name, fallback) => {
    if (!needed) return fallback;
    if (cursor > zip64.length - width) {
      fail('zip64-entry-invalid', `${label} has a truncated ZIP64 ${name}.`);
    }
    let value;
    if (width === 8) {
      const raw = zip64.readBigUInt64LE(cursor);
      if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
        fail('zip64-range-invalid', `${label} ZIP64 ${name} exceeds safe range.`);
      }
      value = Number(raw);
    } else {
      value = zip64.readUInt32LE(cursor);
    }
    cursor += width;
    return value;
  };
  const result = Object.freeze({
    uncompressedSize: readZip64(
      required[0],
      8,
      'uncompressed size',
      uncompressed32,
    ),
    compressedSize: readZip64(
      required[1],
      8,
      'compressed size',
      compressed32,
    ),
    localOffset: readZip64(required[2], 8, 'local-header offset', localOffset32),
    diskStart: readZip64(required[3], 4, 'disk start', diskStart32),
  });
  if (cursor !== zip64.length) {
    fail('zip64-entry-invalid', `${label} has non-canonical ZIP64 extra data.`);
  }
  return result;
};

const assertFlagsAndMethod = (flags, method, label) => {
  if ((flags & ~allowedGeneralPurposeFlags) !== 0) {
    fail(
      'unsupported-flags',
      `${label} uses encryption or unsupported general-purpose flags.`,
    );
  }
  if (method !== 8) {
    fail('unsupported-compression', `${label} uses compression method ${method}.`);
  }
};

const assertRegularFileAttributes = ({
  versionMadeBy,
  internalAttributes,
  externalAttributes,
  label,
}) => {
  if ((internalAttributes & ~0x0001) !== 0) {
    fail('entry-kind-invalid', `${label} has unsupported internal attributes.`);
  }
  const hostSystem = versionMadeBy >>> 8;
  const dosAttributes = externalAttributes & 0xff;
  if ((dosAttributes & 0x18) !== 0) {
    fail('entry-kind-invalid', `${label} is a directory or volume-label entry.`);
  }
  const unixMode = externalAttributes >>> 16;
  if (hostSystem === 0) {
    if (unixMode !== 0) {
      fail('entry-kind-invalid', `${label} mixes DOS origin with Unix attributes.`);
    }
    return;
  }
  if (hostSystem !== 3 || (unixMode & 0xf000) !== 0x8000) {
    fail(
      'entry-kind-invalid',
      `${label} is not a regular file from a supported ZIP host system.`,
    );
  }
};

const canonicalName = (nameBytes, bounds, label) => {
  if (nameBytes.length < 1 || nameBytes.length > bounds.maxNameBytes) {
    fail('entry-name-limit', `${label} has an invalid name length.`);
  }
  let name;
  try {
    name = utf8Decoder.decode(nameBytes);
  } catch (cause) {
    fail('entry-name-invalid', `${label} is not valid UTF-8.`, cause);
  }
  const hasControlCharacter = [...name].some(character => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
  });
  if (
    !Buffer.from(utf8Encoder.encode(name)).equals(nameBytes) ||
    name !== name.normalize('NFC') ||
    name !== name.trim() ||
    name === '.' ||
    name === '..' ||
    pathSeparatorPattern.test(name) ||
    hasControlCharacter ||
    !name.endsWith('.json') ||
    name.length === '.json'.length
  ) {
    fail(
      'entry-name-invalid',
      `${label} must be a single-segment canonical UTF-8 .json name.`,
    );
  }
  return name;
};

const parseCentralEntries = (archive, directory, bounds) => {
  const entries = [];
  const names = new Set();
  let cursor = directory.directoryOffset;
  for (let index = 0; index < directory.entryCount; index += 1) {
    const label = `central entry ${index}`;
    if (cursor > directory.directoryEnd - limits.centralHeaderBytes) {
      fail('central-entry-truncated', `${label} header is truncated.`);
    }
    if (readUint32(archive, cursor, `${label} signature`) !== signatures.central) {
      fail('central-entry-invalid', `${label} signature is invalid.`);
    }
    const versionMadeBy = readUint16(archive, cursor + 4, `${label} made-by version`);
    const versionNeeded = readUint16(archive, cursor + 6, `${label} version needed`);
    const flags = readUint16(archive, cursor + 8, `${label} flags`);
    const method = readUint16(archive, cursor + 10, `${label} method`);
    const modifiedTime = readUint16(archive, cursor + 12, `${label} time`);
    const modifiedDate = readUint16(archive, cursor + 14, `${label} date`);
    const expectedCrc32 = readUint32(archive, cursor + 16, `${label} CRC32`);
    const compressed32 = readUint32(archive, cursor + 20, `${label} compressed size`);
    const uncompressed32 = readUint32(
      archive,
      cursor + 24,
      `${label} uncompressed size`,
    );
    const nameLength = readUint16(archive, cursor + 28, `${label} name length`);
    const extraLength = readUint16(archive, cursor + 30, `${label} extra length`);
    const commentLength = readUint16(archive, cursor + 32, `${label} comment length`);
    const diskStart32 = readUint16(archive, cursor + 34, `${label} disk start`);
    const internalAttributes = readUint16(
      archive,
      cursor + 36,
      `${label} internal attributes`,
    );
    const externalAttributes = readUint32(
      archive,
      cursor + 38,
      `${label} external attributes`,
    );
    const localOffset32 = readUint32(
      archive,
      cursor + 42,
      `${label} local-header offset`,
    );
    assertFlagsAndMethod(flags, method, label);
    assertRegularFileAttributes({
      versionMadeBy,
      internalAttributes,
      externalAttributes,
      label,
    });
    if (versionNeeded > 45) {
      fail('zip-version-unsupported', `${label} requires ZIP version ${versionNeeded}.`);
    }
    if (commentLength !== 0) {
      fail('entry-comment-unsupported', `${label} has a file comment.`);
    }
    const variableOffset = cursor + limits.centralHeaderBytes;
    const variableLength = nameLength + extraLength + commentLength;
    const nextCursor = checkedEnd(
      variableOffset,
      variableLength,
      directory.directoryEnd,
      `${label} variable fields`,
    );
    const nameBytes = archive.subarray(variableOffset, variableOffset + nameLength);
    const name = canonicalName(nameBytes, bounds, label);
    if (nameBytes.some(byte => byte >= 0x80) && (flags & utf8Flag) === 0) {
      fail(
        'entry-name-encoding',
        `${label} has non-ASCII UTF-8 bytes without the UTF-8 flag.`,
      );
    }
    if (names.has(name)) {
      fail('duplicate-entry', `Archive repeats entry ${JSON.stringify(name)}.`);
    }
    names.add(name);
    const extraOffset = variableOffset + nameLength;
    const centralExtra = archive.subarray(extraOffset, extraOffset + extraLength);
    const fields = parseExtraFields(
      archive,
      extraOffset,
      extraLength,
      bounds,
      `${label} extra data`,
    );
    const values = zip64EntryValues({
      fields,
      uncompressed32,
      compressed32,
      localOffset32,
      diskStart32,
      label,
    });
    if (values.diskStart !== 0) {
      fail('multidisk-unsupported', `${label} starts on a nonzero disk.`);
    }
    if (values.uncompressedSize > bounds.maxEntryUncompressedBytes) {
      fail('entry-size-limit', `${label} exceeds its uncompressed byte limit.`);
    }
    if (
      values.uncompressedSize > 0 &&
      (values.compressedSize === 0 ||
        values.uncompressedSize / values.compressedSize >
          bounds.maxCompressionRatio)
    ) {
      fail('compression-ratio-limit', `${label} exceeds its compression-ratio limit.`);
    }
    entries.push({
      index,
      name,
      nameBytes,
      versionMadeBy,
      versionNeeded,
      flags,
      method,
      modifiedTime,
      modifiedDate,
      expectedCrc32,
      compressedSize: values.compressedSize,
      uncompressedSize: values.uncompressedSize,
      localOffset: values.localOffset,
      internalAttributes,
      externalAttributes,
      centralExtra,
    });
    cursor = nextCursor;
  }
  if (cursor !== directory.directoryEnd) {
    fail(
      'central-directory-count-mismatch',
      'Central-directory byte size and entry count disagree.',
    );
  }
  return entries;
};

const parseLocalEntry = (archive, entry, directory, bounds) => {
  const label = `local entry ${JSON.stringify(entry.name)}`;
  const headerEnd = checkedEnd(
    entry.localOffset,
    limits.localHeaderBytes,
    directory.directoryOffset,
    `${label} header`,
  );
  if (readUint32(archive, entry.localOffset, `${label} signature`) !== signatures.local) {
    fail('local-entry-invalid', `${label} signature is invalid.`);
  }
  const versionNeeded = readUint16(archive, entry.localOffset + 4, `${label} version`);
  const flags = readUint16(archive, entry.localOffset + 6, `${label} flags`);
  const method = readUint16(archive, entry.localOffset + 8, `${label} method`);
  const modifiedTime = readUint16(archive, entry.localOffset + 10, `${label} time`);
  const modifiedDate = readUint16(archive, entry.localOffset + 12, `${label} date`);
  const expectedCrc32 = readUint32(archive, entry.localOffset + 14, `${label} CRC32`);
  const compressed32 = readUint32(
    archive,
    entry.localOffset + 18,
    `${label} compressed size`,
  );
  const uncompressed32 = readUint32(
    archive,
    entry.localOffset + 22,
    `${label} uncompressed size`,
  );
  const nameLength = readUint16(archive, entry.localOffset + 26, `${label} name length`);
  const extraLength = readUint16(
    archive,
    entry.localOffset + 28,
    `${label} extra length`,
  );
  assertFlagsAndMethod(flags, method, label);
  const nameOffset = headerEnd;
  const extraOffset = checkedEnd(
    nameOffset,
    nameLength,
    directory.directoryOffset,
    `${label} name`,
  );
  const dataOffset = checkedEnd(
    extraOffset,
    extraLength,
    directory.directoryOffset,
    `${label} extra data`,
  );
  const localNameBytes = archive.subarray(nameOffset, extraOffset);
  if (!localNameBytes.equals(entry.nameBytes)) {
    fail('local-central-mismatch', `${label} name disagrees with its central entry.`);
  }
  const localExtra = archive.subarray(extraOffset, dataOffset);
  const fields = parseExtraFields(
    archive,
    extraOffset,
    extraLength,
    bounds,
    `${label} extra data`,
  );
  const values = zip64EntryValues({
    fields,
    uncompressed32,
    compressed32,
    localOffset32: 0,
    diskStart32: 0,
    label,
  });
  const usesDataDescriptor = (entry.flags & dataDescriptorFlag) !== 0;
  const localUsesZeros =
    expectedCrc32 === 0 &&
    values.compressedSize === 0 &&
    values.uncompressedSize === 0;
  const localUsesKnownValues =
    expectedCrc32 === entry.expectedCrc32 &&
    values.compressedSize === entry.compressedSize &&
    values.uncompressedSize === entry.uncompressedSize;
  if (
    versionNeeded !== entry.versionNeeded ||
    flags !== entry.flags ||
    method !== entry.method ||
    modifiedTime !== entry.modifiedTime ||
    modifiedDate !== entry.modifiedDate ||
    (usesDataDescriptor
      ? !localUsesZeros && !localUsesKnownValues
      : !localUsesKnownValues)
  ) {
    fail(
      'local-central-mismatch',
      `${label} metadata disagrees with its central entry.`,
    );
  }
  const dataEnd = checkedEnd(
    dataOffset,
    entry.compressedSize,
    directory.directoryOffset,
    `${label} compressed payload`,
  );
  let descriptorEnd = dataEnd;
  let dataDescriptor = Buffer.alloc(0);
  if (usesDataDescriptor) {
    if (dataEnd > directory.directoryOffset - limits.dataDescriptorBytes) {
      fail('descriptor-truncated', `${label} has a truncated data descriptor.`);
    }
    descriptorEnd = dataEnd + limits.dataDescriptorBytes;
    dataDescriptor = archive.subarray(dataEnd, descriptorEnd);
  }
  entry.localExtra = localExtra;
  entry.dataOffset = dataOffset;
  entry.dataEnd = dataEnd;
  entry.dataDescriptor = dataDescriptor;
  entry.rangeEnd = descriptorEnd;
};

const validateDataDescriptors = entries => {
  for (const entry of entries) {
    if (entry.dataDescriptor.length === 0) continue;
    const label = `data descriptor for ${JSON.stringify(entry.name)}`;
    if (entry.dataDescriptor.readUInt32LE(0) !== signatures.dataDescriptor) {
      fail(
        'descriptor-signature-invalid',
        `${label} must use the unambiguous signed 16-byte layout.`,
      );
    }
    const descriptorCrc32 = entry.dataDescriptor.readUInt32LE(4);
    const descriptorCompressedSize = entry.dataDescriptor.readUInt32LE(8);
    const descriptorUncompressedSize = entry.dataDescriptor.readUInt32LE(12);
    if (
      descriptorCrc32 !== entry.expectedCrc32 ||
      descriptorCompressedSize !== entry.compressedSize ||
      descriptorUncompressedSize !== entry.uncompressedSize
    ) {
      fail(
        'descriptor-mismatch',
        `${label} disagrees with its authoritative central entry.`,
      );
    }
  }
};

const assertEntryRanges = (entries, directoryOffset) => {
  const ordered = [...entries].sort((left, right) => left.localOffset - right.localOffset);
  let expectedOffset = 0;
  for (const entry of ordered) {
    if (entry.localOffset < expectedOffset) {
      fail('entry-overlap', `Entry ${JSON.stringify(entry.name)} overlaps another entry.`);
    }
    if (entry.localOffset !== expectedOffset) {
      fail('entry-gap', 'Local entries must form one canonical contiguous region.');
    }
    expectedOffset = entry.rangeEnd;
  }
  if (expectedOffset !== directoryOffset) {
    fail(
      'entry-gap',
      'Local entries must end immediately before the central directory.',
    );
  }
};

const validatePayloads = (archive, entries) => {
  for (const entry of entries) {
    const compressed = archive.subarray(entry.dataOffset, entry.dataEnd);
    let uncompressed;
    if (entry.method === 0) {
      uncompressed = compressed;
    } else {
      let result;
      try {
        result = inflateRawSync(compressed, {
          info: true,
          maxOutputLength: Math.max(1, entry.uncompressedSize + 1),
        });
      } catch (cause) {
        fail(
          'deflate-invalid',
          `Entry ${JSON.stringify(entry.name)} could not be bounded-inflated.`,
          cause,
        );
      }
      if (result.engine.bytesWritten !== compressed.length) {
        fail(
          'deflate-trailing-data',
          `Entry ${JSON.stringify(entry.name)} has bytes after its DEFLATE stream.`,
        );
      }
      uncompressed = result.buffer;
    }
    if (uncompressed.length !== entry.uncompressedSize) {
      fail(
        'uncompressed-size-mismatch',
        `Entry ${JSON.stringify(entry.name)} inflated to an unexpected size.`,
      );
    }
    if (crc32(uncompressed) !== entry.expectedCrc32) {
      fail('crc-mismatch', `Entry ${JSON.stringify(entry.name)} failed CRC32 validation.`);
    }
  }
};

const hashUint16 = (hash, value) => {
  const bytes = Buffer.allocUnsafe(2);
  bytes.writeUInt16BE(value);
  hash.update(bytes);
};

const hashUint32 = (hash, value) => {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32BE(value);
  hash.update(bytes);
};

const hashUint64 = (hash, value) => {
  const bytes = Buffer.allocUnsafe(8);
  bytes.writeBigUInt64BE(BigInt(value));
  hash.update(bytes);
};

const hashBytes = (hash, bytes) => {
  hashUint32(hash, bytes.length);
  hash.update(bytes);
};

const canonicalStructuralSha256 = ({ directory, entries, totals }) => {
  const hash = createHash('sha256');
  hash.update('codebase-radar.osv-npm-zip-structure/v1\0', 'utf8');
  hashUint64(hash, directory.entryCount);
  hashUint64(hash, directory.directoryOffset);
  hashUint64(hash, directory.directorySize);
  hashUint16(hash, directory.zip64 ? 1 : 0);
  hashUint64(hash, totals.compressedBytes);
  hashUint64(hash, totals.uncompressedBytes);
  const canonicalEntries = [...entries].sort((left, right) =>
    Buffer.compare(left.nameBytes, right.nameBytes),
  );
  for (const entry of canonicalEntries) {
    hashBytes(hash, entry.nameBytes);
    hashUint16(hash, entry.versionMadeBy);
    hashUint16(hash, entry.versionNeeded);
    hashUint16(hash, entry.flags);
    hashUint16(hash, entry.method);
    hashUint16(hash, entry.modifiedTime);
    hashUint16(hash, entry.modifiedDate);
    hashUint32(hash, entry.expectedCrc32);
    hashUint64(hash, entry.compressedSize);
    hashUint64(hash, entry.uncompressedSize);
    hashUint64(hash, entry.localOffset);
    hashUint32(hash, entry.internalAttributes);
    hashUint32(hash, entry.externalAttributes);
    hashBytes(hash, entry.centralExtra);
    hashBytes(hash, entry.localExtra);
    hashBytes(hash, entry.dataDescriptor);
  }
  return hash.digest('hex');
};

const totalEntryBytes = (entries, bounds) => {
  let compressedBytes = 0;
  let uncompressedBytes = 0;
  let storedEntries = 0;
  let deflatedEntries = 0;
  let signedDataDescriptorEntries = 0;
  let dataDescriptorBytes = 0;
  for (const entry of entries) {
    compressedBytes += entry.compressedSize;
    uncompressedBytes += entry.uncompressedSize;
    if (
      !Number.isSafeInteger(compressedBytes) ||
      !Number.isSafeInteger(uncompressedBytes)
    ) {
      fail('aggregate-size-limit', 'Entry sizes exceed the safe integer range.');
    }
    if (uncompressedBytes > bounds.maxAggregateUncompressedBytes) {
      fail('aggregate-size-limit', 'Archive exceeds its aggregate uncompressed limit.');
    }
    if (entry.method === 0) storedEntries += 1;
    else deflatedEntries += 1;
    if (entry.dataDescriptor.length > 0) {
      signedDataDescriptorEntries += 1;
      dataDescriptorBytes += entry.dataDescriptor.length;
    }
  }
  return Object.freeze({
    compressedBytes,
    uncompressedBytes,
    storedEntries,
    deflatedEntries,
    signedDataDescriptorEntries,
    dataDescriptorBytes,
  });
};

const frozenEvidence = ({ release, archiveSha256, directory, totals, structuralSha256 }) =>
  Object.freeze({
    schemaVersion: osvNpmSnapshotEvidenceSchemaVersion,
    source: Object.freeze({
      url: release.url,
      generation: release.generation,
      publishedAt: release.publishedAt,
      maxAge: release.maxAge,
    }),
    archive: Object.freeze({
      size: release.size,
      sha256: archiveSha256,
      format: 'zip',
      zip64: directory.zip64,
      entryCount: directory.entryCount,
      compressedBytes: totals.compressedBytes,
      uncompressedBytes: totals.uncompressedBytes,
      storedEntries: totals.storedEntries,
      deflatedEntries: totals.deflatedEntries,
      signedDataDescriptorEntries: totals.signedDataDescriptorEntries,
      dataDescriptorBytes: totals.dataDescriptorBytes,
      compressionMethods: Object.freeze(['deflate']),
      centralDirectoryOffset: directory.directoryOffset,
      centralDirectoryBytes: directory.directorySize,
      structuralSha256,
    }),
  });

export const generateOsvNpmSnapshotEvidence = ({
  bytes,
  release,
  bounds: boundsOverride,
}) => {
  const expected = normalizeRelease(release);
  const bounds = normalizeBounds(boundsOverride);
  const archive = asStableBuffer(bytes);
  if (expected.size > bounds.maxArchiveBytes) {
    fail('archive-size-limit', 'Declared archive size exceeds the validation bound.');
  }
  if (archive.length !== expected.size) {
    fail(
      'archive-size-mismatch',
      `Archive has ${archive.length} bytes; expected ${expected.size}.`,
    );
  }
  const archiveSha256 = createHash('sha256').update(archive).digest('hex');
  if (archiveSha256 !== expected.sha256) {
    fail(
      'archive-sha256-mismatch',
      `Archive sha256 ${archiveSha256} does not match the release metadata.`,
    );
  }
  const directory = parseDirectoryLocation(archive, bounds);
  if (directory.entryCount !== expected.entryCount) {
    fail(
      'entry-count-mismatch',
      `Archive has ${directory.entryCount} entries; expected ${expected.entryCount}.`,
    );
  }
  const entries = parseCentralEntries(archive, directory, bounds);
  const localOffsets = new Set();
  for (const entry of entries) {
    if (localOffsets.has(entry.localOffset)) {
      fail('entry-overlap', 'Multiple central entries reference the same local header.');
    }
    localOffsets.add(entry.localOffset);
  }
  for (const entry of entries) parseLocalEntry(archive, entry, directory, bounds);
  assertEntryRanges(entries, directory.directoryOffset);
  validateDataDescriptors(entries);
  const totals = totalEntryBytes(entries, bounds);
  if (totals.uncompressedBytes !== expected.uncompressedBytes) {
    fail(
      'uncompressed-size-mismatch',
      `Archive expands to ${totals.uncompressedBytes} bytes; expected ${expected.uncompressedBytes}.`,
    );
  }
  validatePayloads(archive, entries);
  return frozenEvidence({
    release: expected,
    archiveSha256,
    directory,
    totals,
    structuralSha256: canonicalStructuralSha256({ directory, entries, totals }),
  });
};

const sameFileSnapshot = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.mode === right.mode &&
  left.nlink === right.nlink &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

export const generateOsvNpmSnapshotEvidenceFile = ({
  path,
  release,
  bounds: boundsOverride,
}) => {
  const expected = normalizeRelease(release);
  const bounds = normalizeBounds(boundsOverride);
  if (expected.size > bounds.maxArchiveBytes) {
    fail('archive-size-limit', 'Declared archive size exceeds the validation bound.');
  }
  if (typeof path !== 'string' || path.length === 0 || path !== path.trim()) {
    fail('path-invalid', 'Snapshot path must be a nonempty trimmed string.');
  }
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (cause) {
    fail('file-open-failed', 'Snapshot could not be opened without following links.', cause);
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size !== BigInt(expected.size)) {
      fail(
        'file-invalid',
        'Snapshot must be a regular non-symlink file with the declared exact size.',
      );
    }
    const bytes = Buffer.allocUnsafe(expected.size);
    let offset = 0;
    while (offset < bytes.length) {
      const bytesRead = readSync(
        descriptor,
        bytes,
        offset,
        Math.min(64 * 1024, bytes.length - offset),
        offset,
      );
      if (bytesRead <= 0) {
        fail('file-changed', 'Snapshot became shorter while its bytes were captured.');
      }
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    if (readSync(descriptor, extra, 0, 1, expected.size) !== 0) {
      fail('file-changed', 'Snapshot grew while its bytes were captured.');
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (bytes.length !== expected.size || !sameFileSnapshot(before, after)) {
      fail('file-changed', 'Snapshot changed while its exact bytes were captured.');
    }
    return generateOsvNpmSnapshotEvidence({ bytes, release: expected, bounds });
  } finally {
    closeSync(descriptor);
  }
};

export const generatePinnedOsvNpmSnapshotEvidence = bytes =>
  generateOsvNpmSnapshotEvidence({
    bytes,
    release: pinnedOsvNpmSnapshotRelease,
  });

export const generatePinnedOsvNpmSnapshotEvidenceFile = path =>
  generateOsvNpmSnapshotEvidenceFile({
    path,
    release: pinnedOsvNpmSnapshotRelease,
  });

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  pathToFileURL(resolve(invokedPath)).href === import.meta.url
) {
  if (process.argv.length !== 3) {
    process.stderr.write(
      'Usage: node osv-npm-snapshot-validator.mjs <generation-qualified-all.zip>\n',
    );
    process.exitCode = 64;
  } else {
    try {
      const evidence = generatePinnedOsvNpmSnapshotEvidenceFile(process.argv[2]);
      process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    }
  }
}
