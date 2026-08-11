import { Schema } from 'effect';

export const ContractLimits = Object.freeze({
  encodedResultBytes: 4_194_304,
  evidencePerFinding: 200,
  externalReferencesPerFinding: 100,
  findings: 1_000,
  identifierCharacters: 200,
  languageCoverageEntries: 100,
  limitations: 100,
  pathCharacters: 1_024,
  progressEvents: 10_000,
  proseCharacters: 4_000,
  referencesPerComparisonSet: 5_000,
  semanticAnalyzerInventoryEntries: 8_000,
  semanticAnalyzerFileBytes: 2_097_152,
  semanticAnalyzerRequestBytes: 4_194_304,
  semanticAnalyzerSourceBytes: 268_435_456,
  tagsPerFinding: 50,
  tagCharacters: 100,
  violations: 17,
  warningsPerAnalyzer: 100,
  webUrlCharacters: 2_048,
});

const NonEmptyString = Schema.String.check(
  Schema.isTrimmed(),
  Schema.isMinLength(1),
);
const ControlCharacter = /[\u0000-\u001f\u007f-\u009f]/u;
const LocalPathUri = /\b(?:file|smb|vscode(?:-[a-z0-9]+)*):(?=\S)/iu;
const LocalPathUriGlobal = /\b(?:file|smb|vscode(?:-[a-z0-9]+)*):(?=\S)[^\s)\]}>,;]*/giu;
const QueryParameterGlobal = /[?&#;]([^=&\s?&#;]{1,4000})=/gu;
const QueryParameterWithValueGlobal = /[?&#;]([^=&\s?&#;]{1,4000})=[^\s?&#;)\]}>,]*/gu;
const UriGlobal = /\b[a-z][a-z0-9+.-]*:[^\s)\]}>,]*/giu;
const UserInfoWithoutAuthorityScheme =
  /^(?:https?|ftp|postgres(?:ql)?|redis(?:s)?|mysql|mongodb(?:\+srv)?|amqp(?:s)?|ssh)$/iu;
const PercentEncodedBytesGlobal = /(?:%[0-9a-f]{2})+/giu;
const ProtectedWebMaterialGlobal =
  /(?:\bhttps?:\/\/[^\s)\]}>,;]+|\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\/[^\s)\]}>,;]*)/giu;
const HighConfidenceLocalPath =
  /(?:~[\\/][^\s)\]}>,;]+|(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s)\]}>,;]+|\\\\[^\\/\s]+[\\/][^\s)\]}>,;]+|(?<!:)\/\/[^/\s]+\/[^\s)\]}>,;]+|(?<![A-Za-z0-9./>])\/(?!\/)[^/\s)\]}>,;]+(?:\/[^/\s)\]}>,;]+)*)/u;
const HighConfidenceLocalPathGlobal =
  /(?:~[\\/][^\s)\]}>,;]+|(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s)\]}>,;]+|\\\\[^\\/\s]+[\\/][^\s)\]}>,;]+|(?<!:)\/\/[^/\s]+\/[^\s)\]}>,;]+|(?<![A-Za-z0-9./>])\/(?!\/)[^/\s)\]}>,;]+(?:\/[^/\s)\]}>,;]+)*)/gu;

export const containsControlCharacter = (value: string) =>
  ControlCharacter.test(value);

const containsLocalPathMaterialDirect = (value: string) => {
  if (LocalPathUri.test(value)) return true;
  let cursor = 0;
  for (const match of value.matchAll(ProtectedWebMaterialGlobal)) {
    const index = match.index;
    if (HighConfidenceLocalPath.test(value.slice(cursor, index))) return true;
    cursor = index + match[0].length;
  }
  return HighConfidenceLocalPath.test(value.slice(cursor));
};

const decodedCandidates = (value: string) => {
  const candidates = [value];
  let decoded = value;
  for (let index = 0; index < 3; index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      candidates.push(next);
      decoded = next;
    } catch {
      break;
    }
  }
  return candidates;
};

export const containsEncodedControlCharacter = (value: string) =>
  Array.from(value.matchAll(PercentEncodedBytesGlobal)).some(match => {
    let decoded = match[0];
    for (let index = 0; index <= 3; index += 1) {
      if (containsControlCharacter(decoded)) return true;
      if (index === 3) break;
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        return Array.from(decoded.matchAll(/%([0-9a-f]{2})/giu)).some(byte => {
          const hexadecimal = byte[1];
          if (hexadecimal === undefined) return false;
          const value = Number.parseInt(hexadecimal, 16);
          return value <= 0x1f || (value >= 0x7f && value <= 0x9f);
        });
      }
    }
    return false;
  });

export const containsLocalPathMaterial = (value: string) =>
  decodedCandidates(value).some(containsLocalPathMaterialDirect);

const normalizeQueryParameterName = (value: string) => {
  let decoded = value;
  try {
    decoded = decodeURIComponent(value.replaceAll('+', ' '));
  } catch {
    // Keep the original text when malformed escapes cannot be decoded.
  }
  return decoded.toLocaleLowerCase('en-US').replaceAll(/[^a-z0-9]/gu, '');
};

const isCredentialQueryParameter = (value: string) => {
  const normalized = normalizeQueryParameterName(value);
  return (
    normalized.includes('secret') ||
    normalized.includes('token') ||
    normalized.includes('password') ||
    normalized.includes('passwd') ||
    normalized === 'pass' ||
    normalized === 'pwd' ||
    normalized.includes('credential') ||
    normalized.includes('apikey') ||
    normalized.includes('accesskey') ||
    normalized.includes('signature') ||
    normalized === 'sig' ||
    normalized === 'auth' ||
    normalized === 'authorization'
  );
};

const containsCredentialQueryMaterial = (value: string) => {
  for (const match of value.matchAll(QueryParameterGlobal)) {
    const key = match[1];
    if (key === undefined) continue;
    if (isCredentialQueryParameter(key)) return true;
  }
  return false;
};

const containsCredentialUriMaterial = (value: string) => {
  for (const match of value.matchAll(UriGlobal)) {
    const candidate = match[0];
    try {
      const url = new URL(candidate);
      if (url.username || url.password) return true;
      for (const [key] of url.searchParams) {
        if (isCredentialQueryParameter(key)) return true;
      }
    } catch {
      // The query-key scan still covers credential-shaped material in invalid URLs.
    }
    const separator = candidate.indexOf(':');
    const scheme = candidate.slice(0, separator);
    const afterScheme = candidate.slice(separator + 1);
    const hasAuthority = afterScheme.startsWith('//');
    const authority = (hasAuthority ? afterScheme.slice(2) : afterScheme)
      .split(/[/?#]/u, 1)[0];
    if (
      authority?.includes('@') &&
      (hasAuthority || UserInfoWithoutAuthorityScheme.test(scheme))
    ) {
      return true;
    }
  }
  return false;
};

export const containsCredentialMaterial = (value: string) =>
  decodedCandidates(value).some(candidate =>
    containsCredentialQueryMaterial(candidate) || containsCredentialUriMaterial(candidate),
  );

export const PathFreeText = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.proseCharacters),
  Schema.makeFilter(value => {
    if (containsControlCharacter(value) || containsEncodedControlCharacter(value)) {
      return 'text must not contain control characters';
    }
    if (containsCredentialMaterial(value)) {
      return 'text must not contain credential material';
    }
    return containsLocalPathMaterial(value)
      ? 'text must not contain absolute local path material'
      : undefined;
  }),
);

export const OpaqueId = NonEmptyString.check(
  Schema.isMaxLength(ContractLimits.identifierCharacters),
  Schema.makeFilter(value =>
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)
      ? undefined
      : 'identity must use bounded opaque identifier syntax',
  ),
);

export const BoundedTag = PathFreeText.check(
  Schema.isMaxLength(ContractLimits.tagCharacters),
);

const escapeRegExp = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

const redactKnownRoot = (text: string, root: string) => {
  const normalized = root.replaceAll('\\', '/').replace(/\/+$/u, '');
  if (normalized.length === 0) return text;
  const rootPattern = new RegExp(`${escapeRegExp(normalized)}(?=$|[\\/])`, 'gu');
  return text.replace(rootPattern, '<workspace>');
};

const transformUnprotectedMaterial = (
  value: string,
  transform: (segment: string) => string,
) => {
  let cursor = 0;
  let transformed = '';
  for (const match of value.matchAll(ProtectedWebMaterialGlobal)) {
    const index = match.index;
    transformed += transform(value.slice(cursor, index));
    transformed += match[0];
    cursor = index + match[0].length;
  }
  return transformed + transform(value.slice(cursor));
};

const redactCredentialMaterial = (value: string) => {
  const redactedUris = value.replace(UriGlobal, candidate =>
    containsCredentialMaterial(candidate) ? '<redacted-url>' : candidate,
  );
  const redactedParameters = redactedUris.replace(
    QueryParameterWithValueGlobal,
    (match, key: string) =>
      isCredentialQueryParameter(key) ? '<redacted-credential>' : match,
  );
  return containsCredentialMaterial(redactedParameters)
    ? '<redacted-credential-material>'
    : redactedParameters;
};

const redactEncodedControlMaterial = (value: string) =>
  value.replace(PercentEncodedBytesGlobal, encoded =>
    containsEncodedControlCharacter(encoded) ? '<encoded-control>' : encoded,
  );

export const sanitizeContractText = (
  knownWorkspaceRoots: ReadonlyArray<string>,
  value: string,
) => {
  const roots = Array.from(new Set(knownWorkspaceRoots))
    .map(root => root.trim())
    .filter(root => root.length > 0)
    .sort((left, right) => right.length - left.length || (left < right ? -1 : 1));
  const normalized = redactCredentialMaterial(value.replaceAll('\\', '/'));
  const redactedRoots = roots.reduce(
    (text, root) => transformUnprotectedMaterial(
      text,
      segment => redactKnownRoot(segment, root),
    ),
    normalized,
  );
  const redactedLocalPaths = transformUnprotectedMaterial(
    redactedRoots,
    segment =>
      segment
        .replace(LocalPathUriGlobal, '<local-path>')
        .replace(HighConfidenceLocalPathGlobal, '<local-path>'),
  );
  const redacted = redactEncodedControlMaterial(redactedLocalPaths);
  return containsCredentialMaterial(redacted) || containsLocalPathMaterial(redacted)
    ? '<redacted-sensitive-material>'
    : redacted;
};

export const sanitizeAndDecodeContractText = (
  knownWorkspaceRoots: ReadonlyArray<string>,
  value: string,
) => Schema.decodeUnknownEffect(PathFreeText)(sanitizeContractText(knownWorkspaceRoots, value));
