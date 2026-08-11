import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { test } from 'node:test';
import {
  OsvNpmSnapshotValidationError,
  generateOsvNpmSnapshotEvidence,
  generateOsvNpmSnapshotEvidenceFile,
  osvNpmSnapshotEvidenceSchemaVersion,
} from './osv-npm-snapshot-validator.mjs';

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

const zipFixture = (descriptions, { forceZip64 = false } = {}) => {
  const localParts = [];
  const layouts = [];
  let localOffset = 0;
  for (const description of descriptions) {
    const nameBytes = Buffer.from(description.name, 'utf8');
    const uncompressed = Buffer.from(description.contents);
    const method = description.method ?? 8;
    const encoded = method === 0 ? uncompressed : deflateRawSync(uncompressed);
    const compressed =
      description.compressedSuffix === undefined
        ? encoded
        : Buffer.concat([encoded, Buffer.from(description.compressedSuffix)]);
    const usesDataDescriptor = description.dataDescriptor === true;
    const flags = description.flags ?? (usesDataDescriptor ? 0x0008 : 0);
    const checksum = crc32(uncompressed);
    const localExtra = Buffer.from(description.localExtra ?? []);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(flags, 6);
    header.writeUInt16LE(method, 8);
    header.writeUInt32LE(
      usesDataDescriptor && description.localKnownValues !== true ? 0 : checksum,
      14,
    );
    header.writeUInt32LE(
      usesDataDescriptor && description.localKnownValues !== true
        ? 0
        : compressed.length,
      18,
    );
    header.writeUInt32LE(
      usesDataDescriptor && description.localKnownValues !== true
        ? 0
        : uncompressed.length,
      22,
    );
    header.writeUInt16LE(nameBytes.length, 26);
    header.writeUInt16LE(localExtra.length, 28);
    const dataOffset =
      localOffset + header.length + nameBytes.length + localExtra.length;
    const descriptorOffset = dataOffset + compressed.length;
    let descriptor = Buffer.alloc(0);
    if (usesDataDescriptor) {
      descriptor = Buffer.alloc(description.descriptorLength ?? 16);
      if (description.unsignedDescriptor === true) {
        if (descriptor.length >= 4) descriptor.writeUInt32LE(checksum, 0);
        if (descriptor.length >= 8) descriptor.writeUInt32LE(compressed.length, 4);
        if (descriptor.length >= 12) descriptor.writeUInt32LE(uncompressed.length, 8);
      } else {
        if (descriptor.length >= 4) descriptor.writeUInt32LE(0x08074b50, 0);
        if (descriptor.length >= 8) {
          descriptor.writeUInt32LE(description.descriptorCrc32 ?? checksum, 4);
        }
        if (descriptor.length >= 12) {
          descriptor.writeUInt32LE(
            description.descriptorCompressedBytes ?? compressed.length,
            8,
          );
        }
        if (descriptor.length >= 16) {
          descriptor.writeUInt32LE(
            description.descriptorUncompressedBytes ?? uncompressed.length,
            12,
          );
        }
      }
    }
    layouts.push({
      localOffset,
      dataOffset,
      descriptorOffset,
      descriptorBytes: descriptor.length,
      compressedBytes: compressed.length,
      uncompressedBytes: uncompressed.length,
      checksum,
    });
    localParts.push(header, nameBytes, localExtra, compressed, descriptor);
    localOffset = descriptorOffset + descriptor.length;
  }

  const centralParts = [];
  let centralCursor = localOffset;
  for (let index = 0; index < descriptions.length; index += 1) {
    const description = descriptions[index];
    const layout = layouts[index];
    const nameBytes = Buffer.from(description.name, 'utf8');
    const flags =
      description.flags ?? (description.dataDescriptor === true ? 0x0008 : 0);
    const method = description.method ?? 8;
    const centralExtra = Buffer.from(description.centralExtra ?? []);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(description.versionMadeBy ?? 20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(flags, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt32LE(layout.checksum, 16);
    header.writeUInt32LE(layout.compressedBytes, 20);
    header.writeUInt32LE(layout.uncompressedBytes, 24);
    header.writeUInt16LE(nameBytes.length, 28);
    header.writeUInt16LE(centralExtra.length, 30);
    header.writeUInt16LE(description.internalAttributes ?? 0, 36);
    header.writeUInt32LE(description.externalAttributes ?? 0, 38);
    header.writeUInt32LE(layout.localOffset, 42);
    layout.centralOffset = centralCursor;
    centralParts.push(header, nameBytes, centralExtra);
    centralCursor += header.length + nameBytes.length + centralExtra.length;
  }

  const directoryOffset = localOffset;
  const directoryBytes = centralCursor - directoryOffset;
  const metadataParts = [];
  if (forceZip64) {
    const zip64Offset = centralCursor;
    const zip64 = Buffer.alloc(56);
    zip64.writeUInt32LE(0x06064b50, 0);
    zip64.writeBigUInt64LE(44n, 4);
    zip64.writeUInt16LE(45, 12);
    zip64.writeUInt16LE(45, 14);
    zip64.writeBigUInt64LE(BigInt(descriptions.length), 24);
    zip64.writeBigUInt64LE(BigInt(descriptions.length), 32);
    zip64.writeBigUInt64LE(BigInt(directoryBytes), 40);
    zip64.writeBigUInt64LE(BigInt(directoryOffset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeBigUInt64LE(BigInt(zip64Offset), 8);
    locator.writeUInt32LE(1, 16);
    metadataParts.push(zip64, locator);
    centralCursor += zip64.length + locator.length;
  }
  const eocdOffset = centralCursor;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(forceZip64 ? 0xffff : descriptions.length, 8);
  eocd.writeUInt16LE(forceZip64 ? 0xffff : descriptions.length, 10);
  eocd.writeUInt32LE(directoryBytes, 12);
  eocd.writeUInt32LE(directoryOffset, 16);
  metadataParts.push(eocd);
  return {
    bytes: Buffer.concat([...localParts, ...centralParts, ...metadataParts]),
    layouts,
    eocdOffset,
    entryCount: descriptions.length,
    uncompressedBytes: layouts.reduce(
      (sum, layout) => sum + layout.uncompressedBytes,
      0,
    ),
  };
};

const releaseFor = (bytes, entryCount, uncompressedBytes) => ({
  url: 'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=42',
  generation: '42',
  size: bytes.length,
  sha256: createHash('sha256').update(bytes).digest('hex'),
  publishedAt: '2026-08-11T03:19:09Z',
  maxAge: 604_800,
  entryCount,
  uncompressedBytes,
});

const validateFixture = (fixture, bounds) =>
  generateOsvNpmSnapshotEvidence({
    bytes: fixture.bytes,
    release: releaseFor(
      fixture.bytes,
      fixture.entryCount,
      fixture.uncompressedBytes,
    ),
    bounds,
  });

const assertCode = (code, operation) =>
  assert.throws(
    operation,
    error =>
      error instanceof OsvNpmSnapshotValidationError && error.code === code,
  );

test('generates deterministic evidence for a small DEFLATE-only ZIP', () => {
  const fixture = zipFixture([
    { name: 'GHSA-aaaa-bbbb-cccc.json', contents: '{"id":"one"}\n' },
    { name: 'CVE-2026-0001.json', contents: '{"id":"two","value":true}\n' },
  ]);
  const first = validateFixture(fixture);
  const second = validateFixture(fixture);
  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, osvNpmSnapshotEvidenceSchemaVersion);
  assert.equal(first.archive.entryCount, 2);
  assert.equal(first.archive.storedEntries, 0);
  assert.equal(first.archive.deflatedEntries, 2);
  assert.equal(first.archive.signedDataDescriptorEntries, 0);
  assert.equal(first.archive.dataDescriptorBytes, 0);
  assert.deepEqual(first.archive.compressionMethods, ['deflate']);
  assert.equal(first.archive.zip64, false);
  assert.match(first.archive.structuralSha256, /^[0-9a-f]{64}$/u);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.archive));
});

test('accepts exact signed 16-byte descriptors with zero or known local sizes', () => {
  const fixture = zipFixture([
    {
      name: 'zero-local.json',
      contents: '{"descriptor":"zero"}',
      dataDescriptor: true,
    },
    {
      name: 'known-local.json',
      contents: '{"descriptor":"known"}',
      dataDescriptor: true,
      localKnownValues: true,
    },
  ]);
  const evidence = validateFixture(fixture);
  assert.equal(evidence.archive.signedDataDescriptorEntries, 2);
  assert.equal(evidence.archive.dataDescriptorBytes, 32);
  assert.equal(evidence.archive.deflatedEntries, 2);
});

test('rejects missing signatures and unsigned descriptor ambiguity', () => {
  const missing = zipFixture([
    { name: 'missing-signature.json', contents: '{}', dataDescriptor: true },
  ]);
  missing.bytes.writeUInt32LE(0, missing.layouts[0].descriptorOffset);
  assertCode('descriptor-signature-invalid', () => validateFixture(missing));

  const unsigned = zipFixture([
    {
      name: 'unsigned.json',
      contents: '{}',
      dataDescriptor: true,
      unsignedDescriptor: true,
    },
  ]);
  assertCode('descriptor-signature-invalid', () => validateFixture(unsigned));
});

test('rejects descriptor CRC and size disagreement with the central record', () => {
  const mutations = [
    { offset: 4, value: 0x01020304 },
    { offset: 8, value: 1 },
    { offset: 12, value: 1 },
  ];
  for (const mutation of mutations) {
    const fixture = zipFixture([
      { name: `descriptor-${mutation.offset}.json`, contents: '{}', dataDescriptor: true },
    ]);
    fixture.bytes.writeUInt32LE(
      mutation.value,
      fixture.layouts[0].descriptorOffset + mutation.offset,
    );
    assertCode('descriptor-mismatch', () => validateFixture(fixture));
  }
});

test('rejects descriptor overlap and truncation before reading descriptor fields', () => {
  const overlap = zipFixture([
    { name: 'overlap-first.json', contents: '{}', dataDescriptor: true },
    { name: 'overlap-second.json', contents: '{}', dataDescriptor: true },
  ]);
  overlap.bytes.writeUInt32LE(
    overlap.layouts[0].compressedBytes + 16,
    overlap.layouts[0].centralOffset + 20,
  );
  assertCode('entry-overlap', () => validateFixture(overlap));

  const truncated = zipFixture([
    {
      name: 'truncated.json',
      contents: '{}',
      dataDescriptor: true,
      descriptorLength: 12,
    },
  ]);
  assertCode('descriptor-truncated', () => validateFixture(truncated));
});

test('rejects mixed zero and known local descriptor metadata', () => {
  const fixture = zipFixture([
    { name: 'mixed-local.json', contents: '{}', dataDescriptor: true },
  ]);
  fixture.bytes.writeUInt32LE(
    fixture.layouts[0].checksum,
    fixture.layouts[0].localOffset + 14,
  );
  assertCode('local-central-mismatch', () => validateFixture(fixture));
});

test('accepts a strict contiguous ZIP64 EOCD chain', () => {
  const fixture = zipFixture(
    [{ name: 'GHSA-zip6-4000-test.json', contents: '{"zip64":true}\n' }],
    { forceZip64: true },
  );
  assert.equal(validateFixture(fixture).archive.zip64, true);
});

test('rejects traversal, non-segment, non-json, and duplicate entry names', () => {
  for (const name of ['../bad.json', 'nested/bad.json', 'bad.txt', ' bad.json']) {
    const fixture = zipFixture([{ name, contents: '{}' }]);
    assertCode('entry-name-invalid', () => validateFixture(fixture));
  }
  const duplicate = zipFixture([
    { name: 'same.json', contents: '{"one":1}' },
    { name: 'same.json', contents: '{"two":2}' },
  ]);
  assertCode('duplicate-entry', () => validateFixture(duplicate));
});

test('rejects ambiguous filename encodings and alternate Unicode path fields', () => {
  const ambiguous = zipFixture([{ name: 'žluťoučký.json', contents: '{}' }]);
  assertCode('entry-name-encoding', () => validateFixture(ambiguous));

  const canonical = zipFixture([
    { name: 'žluťoučký.json', contents: '{}', flags: 0x0800 },
  ]);
  assert.equal(validateFixture(canonical).archive.entryCount, 1);

  const unicodePathField = Buffer.alloc(4);
  unicodePathField.writeUInt16LE(0x7075, 0);
  const alternate = zipFixture([
    {
      name: 'safe.json',
      contents: '{}',
      centralExtra: unicodePathField,
    },
  ]);
  assertCode('alternate-name-unsupported', () => validateFixture(alternate));
});

test('rejects high-ratio and oversized entries before inflation', () => {
  const fixture = zipFixture([
    { name: 'bomb.json', contents: Buffer.alloc(16 * 1024, 0x41) },
  ]);
  assertCode('compression-ratio-limit', () =>
    validateFixture(fixture, { maxCompressionRatio: 2 }),
  );
  assertCode('entry-size-limit', () =>
    validateFixture(fixture, { maxEntryUncompressedBytes: 1024 }),
  );
});

test('enforces DEFLATE-only, 128-byte names, and 1 MiB entries by default', () => {
  const stored = zipFixture([
    { name: 'stored.json', contents: '{"stored":true}', method: 0 },
  ]);
  assertCode('unsupported-compression', () => validateFixture(stored));

  const longName = zipFixture([
    { name: `${'a'.repeat(124)}.json`, contents: '{}' },
  ]);
  assert.equal(Buffer.byteLength(`${'a'.repeat(124)}.json`), 129);
  assertCode('entry-name-limit', () => validateFixture(longName));

  const oversized = zipFixture([
    { name: 'oversized.json', contents: Buffer.alloc(1024 * 1024 + 1, 0x5a) },
  ]);
  assertCode('entry-size-limit', () => validateFixture(oversized));
});

test('accepts entries exactly at the 128-byte name and 1 MiB content bounds', () => {
  const contents = Buffer.alloc(1024 * 1024);
  let state = 0x9e3779b9;
  for (let index = 0; index < contents.length; index += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    contents[index] = state & 0xff;
  }
  const name = `${'a'.repeat(123)}.json`;
  assert.equal(Buffer.byteLength(name), 128);
  const fixture = zipFixture([{ name, contents }]);
  assert.equal(validateFixture(fixture).archive.uncompressedBytes, contents.length);
});

test('rejects duplicate local ranges as overlap', () => {
  const fixture = zipFixture([
    { name: 'first.json', contents: '{"first":true}' },
    { name: 'second.json', contents: '{"second":true}' },
  ]);
  fixture.bytes.writeUInt32LE(
    fixture.layouts[0].localOffset,
    fixture.layouts[1].centralOffset + 42,
  );
  assertCode('entry-overlap', () => validateFixture(fixture));
});

test('rejects local and central header disagreement', () => {
  const fixture = zipFixture([
    { name: 'mismatch.json', contents: '{"mismatch":true}' },
  ]);
  fixture.bytes.writeUInt16LE(1, fixture.layouts[0].localOffset + 10);
  assertCode('local-central-mismatch', () => validateFixture(fixture));
});

test('rejects directory, symlink, device, and unsupported host attributes', () => {
  const cases = [
    { name: 'dos-directory.json', externalAttributes: 0x10 },
    {
      name: 'unix-symlink.json',
      versionMadeBy: 0x0314,
      externalAttributes: (0xa1ff << 16) >>> 0,
    },
    {
      name: 'unix-device.json',
      versionMadeBy: 0x0314,
      externalAttributes: (0x21b6 << 16) >>> 0,
    },
    { name: 'unknown-host.json', versionMadeBy: 0x0a14 },
  ];
  for (const description of cases) {
    const fixture = zipFixture([{ ...description, contents: '{}' }]);
    assertCode('entry-kind-invalid', () => validateFixture(fixture));
  }
});

test('accepts an explicitly regular Unix entry', () => {
  const fixture = zipFixture([
    {
      name: 'unix-regular.json',
      contents: '{}',
      versionMadeBy: 0x0314,
      externalAttributes: (0x81a4 << 16) >>> 0,
    },
  ]);
  assert.equal(validateFixture(fixture).archive.entryCount, 1);
});

test('rejects CRC corruption after bounded inflation', () => {
  const fixture = zipFixture([
    { name: 'crc.json', contents: '{"crc":true,"padding":"abcdef"}' },
  ]);
  const invalidCrc = (fixture.layouts[0].checksum + 1) >>> 0;
  fixture.bytes.writeUInt32LE(invalidCrc, fixture.layouts[0].localOffset + 14);
  fixture.bytes.writeUInt32LE(invalidCrc, fixture.layouts[0].centralOffset + 16);
  assertCode('crc-mismatch', () => validateFixture(fixture));
});

test('rejects bytes hidden after a DEFLATE stream inside an entry range', () => {
  const fixture = zipFixture([
    {
      name: 'deflate-tail.json',
      contents: '{"valid":true}',
      compressedSuffix: 'polyglot',
    },
  ]);
  assertCode('deflate-trailing-data', () => validateFixture(fixture));
});

test('rejects trailing polyglot bytes and EOCD comments', () => {
  const fixture = zipFixture([{ name: 'clean.json', contents: '{}' }]);
  fixture.bytes = Buffer.concat([fixture.bytes, Buffer.from('polyglot')]);
  assertCode('trailing-data', () => validateFixture(fixture));

  const commented = zipFixture([{ name: 'comment.json', contents: '{}' }]);
  commented.bytes.writeUInt16LE(1, commented.eocdOffset + 20);
  commented.bytes = Buffer.concat([commented.bytes, Buffer.from('x')]);
  assertCode('eocd-comment', () => validateFixture(commented));
});

test('rejects encryption and unknown general-purpose flags', () => {
  for (const flags of [0x0001, 0x0004, 0x0010]) {
    const fixture = zipFixture([
      { name: `flags-${flags}.json`, contents: '{}', flags },
    ]);
    assertCode('unsupported-flags', () => validateFixture(fixture));
  }
});

test('rejects multidisk EOCD and a misplaced ZIP64 locator', () => {
  const multidisk = zipFixture([{ name: 'disk.json', contents: '{}' }]);
  multidisk.bytes.writeUInt16LE(1, multidisk.eocdOffset + 4);
  assertCode('multidisk-unsupported', () => validateFixture(multidisk));

  const zip64 = zipFixture(
    [{ name: 'locator.json', contents: '{}' }],
    { forceZip64: true },
  );
  const insertion = zip64.eocdOffset - 20;
  zip64.bytes = Buffer.concat([
    zip64.bytes.subarray(0, insertion),
    Buffer.from([0]),
    zip64.bytes.subarray(insertion),
  ]);
  zip64.eocdOffset += 1;
  assertCode('zip64-layout-invalid', () => validateFixture(zip64));
});

test('rejects a SHA mismatch before trusting archive structure', () => {
  const fixture = zipFixture([{ name: 'digest.json', contents: '{}' }]);
  const release = releaseFor(
    fixture.bytes,
    fixture.entryCount,
    fixture.uncompressedBytes,
  );
  release.sha256 = '0'.repeat(64);
  assertCode('archive-sha256-mismatch', () =>
    generateOsvNpmSnapshotEvidence({ bytes: fixture.bytes, release }),
  );
});

test('requires exact generation-qualified release metadata', () => {
  const fixture = zipFixture([{ name: 'generation.json', contents: '{}' }]);
  const release = releaseFor(
    fixture.bytes,
    fixture.entryCount,
    fixture.uncompressedBytes,
  );
  release.url = 'https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip';
  assertCode('release-generation-mismatch', () =>
    generateOsvNpmSnapshotEvidence({ bytes: fixture.bytes, release }),
  );
});

test('file entrypoint hashes and validates the same captured bytes', () => {
  const fixture = zipFixture([{ name: 'file.json', contents: '{"file":true}' }]);
  const release = releaseFor(
    fixture.bytes,
    fixture.entryCount,
    fixture.uncompressedBytes,
  );
  const root = mkdtempSync(join(tmpdir(), 'radar-osv-validator-'));
  const path = join(root, 'all.zip');
  try {
    writeFileSync(path, fixture.bytes);
    const evidence = generateOsvNpmSnapshotEvidenceFile({ path, release });
    assert.equal(evidence.archive.sha256, release.sha256);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
