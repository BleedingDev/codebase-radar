import { sanitizeContractText } from '@codebase-radar/contracts';

const ControlCharacter = /[\u0000-\u001f\u007f-\u009f]/u;
const ControlCharacterGlobal = /[\u0000-\u001f\u007f-\u009f]/gu;
const CredentialUrl = /\b(https?:\/\/)[^/\s@]+@/giu;
const CredentialValue = /(\bBearer\s+)[A-Za-z0-9._~+\/-]{8,}={0,2}/giu;
const CredentialAssignment = /("?(?:access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|password|secret|token)"?)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu;

const redactSensitiveText = (value: string) =>
  value
    .replace(CredentialUrl, '$1<redacted>@')
    .replace(CredentialValue, '$1<redacted>')
    .replace(CredentialAssignment, '$1=<redacted>');

const redactPublicText = (value: string) =>
  sanitizeContractText([], redactSensitiveText(value));

const escapeControlCharacter = (value: string) => {
  if (value === '\n') return '\\n';
  if (value === '\r') return '\\r';
  if (value === '\t') return '\\t';
  const codePoint = value.codePointAt(0);
  return codePoint === undefined
    ? ''
    : `\\u${codePoint.toString(16).padStart(4, '0')}`;
};

export const safeHumanText = (value: string) =>
  redactPublicText(value).replace(ControlCharacterGlobal, escapeControlCharacter);

export const safeDiagnosticText = (value: string) => {
  const rendered = safeHumanText(value).replace(/\s+/gu, ' ').trim().slice(0, 512);
  return rendered.length === 0
    ? 'The command failed without a diagnostic.'
    : rendered;
};

export const isSafePublicText = (value: string) =>
  !ControlCharacter.test(value) && redactPublicText(value) === value;
