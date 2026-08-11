import { Effect, Exit, Schema } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  ContractLimits,
  OpaqueId,
  PathFreeText,
  sanitizeAndDecodeContractText,
  sanitizeContractText,
} from '../src/index.js';

describe('bounded privacy primitives', () => {
  it('rejects local paths independently of surrounding punctuation', () => {
    const attacks = [
      'failure,/Users/alice/private.ts',
      'failure;/home/alice/private.ts',
      'failure=/tmp/private.ts',
      'failure:C:\\Users\\alice\\private.ts',
      'failure“/private/var/folders/xy/private.ts”',
      'failure\n/var/folders/xy/private.ts',
      'failure \\\\server\\share\\private.ts',
      'failure ~/private.ts',
      'failure,/custom/build/checkout/private.ts',
      'failure;/nix/store/abc-private/source.ts',
      'failure=/github/workspace/source.ts',
      'failure“/arbitrary-unicode/žluťoučký.ts”',
      'failure:/secrets',
      'failure=file://localhost/Users/alice/private.ts',
      'failure=file://host/home/alice/private.ts',
      'failure=file:relative/private.ts',
      'failure=file:%2Fetc%2Fpasswd',
      'failure=smb://server/share/private.ts',
      'failure=smb:server/share/private.ts',
      'failure=vscode://file/Users/alice/private.ts',
      'failure=vscode:extension/private.ts',
      'failure=vscode-insiders://file/Users/alice/private.ts',
      'failure=vscode-insiders:file/Users/alice/private.ts',
    ];
    for (const attack of attacks) {
      expect(Exit.isFailure(Schema.decodeUnknownExit(PathFreeText)(attack))).toBe(
        true,
      );
    }
    expect(
      Exit.isSuccess(
        Schema.decodeUnknownExit(PathFreeText)(
          'GET /api/v1, POST /v2/scans, and read https://example.com/home/alice/reference',
        ),
      ),
    ).toBe(true);
  });

  it('rejects terminal controls and credential-bearing query material', () => {
    for (let codePoint = 0; codePoint <= 0x1f; codePoint += 1) {
      expect(
        Exit.isFailure(
          Schema.decodeUnknownExit(PathFreeText)(`unsafe${String.fromCodePoint(codePoint)}text`),
        ),
      ).toBe(true);
    }
    for (let codePoint = 0x7f; codePoint <= 0x9f; codePoint += 1) {
      expect(
        Exit.isFailure(
          Schema.decodeUnknownExit(PathFreeText)(`unsafe${String.fromCodePoint(codePoint)}text`),
        ),
      ).toBe(true);
    }
    const credentialUrls = [
      'https://example.test/?client_secret=x',
      'https://example.test/?refresh_token=x',
      'https://example.test/?id_token=x',
      'https://example.test/?session-token=x',
      'https://example.test/?private_token=x',
      'https://example.test/?x-api-key=x',
      'https://example.test/?AWSAccessKeyId=x',
      'https://example.test/?Signature=x',
      'https://example.test/?sig=azure-sas-signature',
      'https://example.test/?s%69g=encoded-azure-sas-signature',
      'https://example.test/?x%2Dapi%2Dkey=encoded-api-key',
      'https://example.test/?pass=credential',
      'https://example.test/?pwd=credential',
      'https://example.test/?p%61ss=encoded-credential',
      'https:user:password@example.test',
      'https:/user@example.test',
      'ftp://user:password@example.test/private',
      'ftp:user:password@example.test/private',
      'postgres://user:password@example.test/database',
      'postgres:user:password@example.test/database',
      'redis://user:password@example.test/0',
      'rediss:user:password@example.test/0',
      'mysql://user:password@example.test/database',
      'mongodb+srv://user:password@example.test/database',
      'amqp://user:password@example.test/queue',
      'ssh://user@example.test/private',
      'https://example.test/path;access_token=semicolon-delimited',
      'https://example.test/path#authorization=fragment-secret',
      `https://example.test/#${'prefix'.repeat(40)}access_token=fragment-secret`,
    ];
    for (const value of credentialUrls) {
      expect(Exit.isFailure(Schema.decodeUnknownExit(PathFreeText)(value))).toBe(
        true,
      );
    }
  });

  it('redacts known workspace roots before concrete decoding', () => {
    const root = '/custom/build/checkout';
    const input = `failure=${root}/src/private.ts`;
    const sanitized = sanitizeContractText([root], input);
    expect(sanitized).toBe('failure=<workspace>/src/private.ts');
    expect(sanitized).not.toContain(root);
    const exit = Effect.runSync(
      Effect.exit(sanitizeAndDecodeContractText([root], input)),
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    expect(sanitizeContractText([], 'failure=/custom/checkout/private.ts')).toBe(
      'failure=<local-path>',
    );
    const localUri = 'failure=file:%2Fetc%2Fpasswd';
    expect(sanitizeContractText([], localUri)).toBe('failure=<local-path>');
    expect(
      Exit.isSuccess(
        Effect.runSync(
          Effect.exit(sanitizeAndDecodeContractText([], localUri)),
        ),
      ),
    ).toBe(true);
    const vscodeInsidersUri = 'failure=vscode-insiders://file/Users/alice/private.ts';
    expect(sanitizeContractText([], vscodeInsidersUri)).toBe('failure=<local-path>');
    expect(
      Exit.isSuccess(
        Effect.runSync(
          Effect.exit(sanitizeAndDecodeContractText([], vscodeInsidersUri)),
        ),
      ),
    ).toBe(true);
    const credentialUri = 'failure=postgres://user:password@example.test/database';
    const redactedCredentialUri = sanitizeContractText([], credentialUri);
    expect(redactedCredentialUri).not.toContain('user:password');
    expect(
      Exit.isSuccess(
        Effect.runSync(
          Effect.exit(sanitizeAndDecodeContractText([], credentialUri)),
        ),
      ),
    ).toBe(true);
    const connectionUris = [
      'redis://user:password@example.test/0',
      'mysql://user:password@example.test/database',
      'mongodb+srv://user:password@example.test/database',
      'amqp://user:password@example.test/queue',
    ];
    for (const connectionUri of connectionUris) {
      const sanitizedConnectionUri = sanitizeContractText([], `failure=${connectionUri}`);
      expect(sanitizedConnectionUri).not.toContain('user:password');
      expect(
        Exit.isSuccess(
          Effect.runSync(
            Effect.exit(sanitizeAndDecodeContractText([], `failure=${connectionUri}`)),
          ),
        ),
      ).toBe(true);
    }
    const tripleEncodedLocalUri = 'failure=file%25253A%25252F%25252FUsers%25252Falice%25252Fprivate.ts';
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(PathFreeText)(tripleEncodedLocalUri)),
    ).toBe(true);
    const sanitizedTripleEncodedLocalUri = sanitizeContractText([], tripleEncodedLocalUri);
    expect(sanitizedTripleEncodedLocalUri).not.toContain('Users');
    expect(
      Exit.isSuccess(
        Effect.runSync(
          Effect.exit(sanitizeAndDecodeContractText([], tripleEncodedLocalUri)),
        ),
      ),
    ).toBe(true);
    const encodedControl = 'failure=https://example.test/%C2%80unsafe';
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(PathFreeText)(encodedControl)),
    ).toBe(true);
    expect(
      Exit.isSuccess(
        Effect.runSync(
          Effect.exit(sanitizeAndDecodeContractText([], encodedControl)),
        ),
      ),
    ).toBe(true);
    const webText =
      'GET /home/alice and https://example.com/home/alice/reference';
    expect(sanitizeContractText(['/home/alice'], webText)).toBe(webText);
  });

  it('separates bounded opaque identifiers from prose', () => {
    const exact = `id-${'x'.repeat(ContractLimits.identifierCharacters - 3)}`;
    const invalid = [
      `${exact}x`,
      'id/with/path',
      'id with space',
      'id\nwith-control',
    ];
    expect(Exit.isSuccess(Schema.decodeUnknownExit(OpaqueId)(exact))).toBe(true);
    for (const value of invalid) {
      expect(Exit.isFailure(Schema.decodeUnknownExit(OpaqueId)(value))).toBe(true);
    }

    const exactProse = 'x'.repeat(ContractLimits.proseCharacters);
    expect(Exit.isSuccess(Schema.decodeUnknownExit(PathFreeText)(exactProse))).toBe(
      true,
    );
    expect(
      Exit.isFailure(Schema.decodeUnknownExit(PathFreeText)(`${exactProse}x`)),
    ).toBe(true);
  });
});
