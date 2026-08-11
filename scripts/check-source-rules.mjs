import { readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageRoot = resolve(repositoryRoot, 'packages');
const sourceRoots = [
  resolve(repositoryRoot, 'apps/radar'),
  ...readdirSync(packageRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && entry.name.startsWith('radar-'))
    .map(entry => resolve(packageRoot, entry.name)),
];
const ignored = new Set(['.output', 'dist', 'modern-tanstack', 'node_modules']);
const extensions = new Set(['.ts', '.tsx']);
const violations = [];

const forbiddenCode = [
  { pattern: /\bany\b/gu, reason: 'explicit any type' },
  { pattern: /\bunknown\b/gu, reason: 'explicit unknown type' },
  { pattern: /\basync\b/gu, reason: 'raw async function' },
  { pattern: /(?<!\.)\bawait\b/gu, reason: 'raw await expression' },
  { pattern: /\bthrow\b/gu, reason: 'raw throw statement' },
  { pattern: /\bnew\s+Error\b/gu, reason: 'raw Error construction' },
  {
    pattern: /(?:[\w$)\]])!\s*(?=[.\[,;)}\]])/gu,
    reason: 'non-null assertion',
  },
];

const eraseNonCode = source => {
  let output = '';
  let state = 'code';
  let quote = '';
  const templateExpressionDepths = [];
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === 'line-comment') {
      if (character === '\n') {
        state = 'code';
        output += '\n';
      } else {
        output += ' ';
      }
      continue;
    }
    if (state === 'block-comment') {
      if (character === '*' && next === '/') {
        output += '  ';
        index += 1;
        state = 'code';
      } else {
        output += character === '\n' ? '\n' : ' ';
      }
      continue;
    }
    if (state === 'string') {
      if (character === '\\') {
        output += ' ';
        if (next !== undefined) {
          output += next === '\n' ? '\n' : ' ';
          index += 1;
        }
      } else if (character === quote) {
        output += ' ';
        state = 'code';
      } else {
        output += character === '\n' ? '\n' : ' ';
      }
      continue;
    }
    if (state === 'template') {
      if (character === '\\') {
        output += ' ';
        if (next !== undefined) {
          output += next === '\n' ? '\n' : ' ';
          index += 1;
        }
      } else if (character === '`') {
        output += ' ';
        state = 'code';
      } else if (character === '$' && next === '{') {
        output += '  ';
        index += 1;
        templateExpressionDepths.push(0);
        state = 'code';
      } else {
        output += character === '\n' ? '\n' : ' ';
      }
      continue;
    }
    if (character === '/' && next === '/') {
      output += '  ';
      index += 1;
      state = 'line-comment';
    } else if (character === '/' && next === '*') {
      output += '  ';
      index += 1;
      state = 'block-comment';
    } else if (character === '"' || character === "'") {
      output += ' ';
      quote = character;
      state = 'string';
    } else if (character === '`') {
      output += ' ';
      state = 'template';
    } else if (character === '{' && templateExpressionDepths.length > 0) {
      const top = templateExpressionDepths.length - 1;
      templateExpressionDepths[top] = (templateExpressionDepths[top] ?? 0) + 1;
      output += character;
    } else if (character === '}' && templateExpressionDepths.length > 0) {
      const top = templateExpressionDepths.length - 1;
      const depth = templateExpressionDepths[top] ?? 0;
      if (depth === 0) {
        templateExpressionDepths.pop();
        output += ' ';
        state = 'template';
      } else {
        templateExpressionDepths[top] = depth - 1;
        output += character;
      }
    } else {
      output += character;
    }
  }
  return output;
};

const hasForbiddenReason = (source, reason) => {
  const code = eraseNonCode(source);
  const rule = forbiddenCode.find(candidate => candidate.reason === reason);
  if (rule === undefined) return false;
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(code);
};

const scannerSelfCheckFailed =
  !hasForbiddenReason('const value = `${await operation}`;', 'raw await expression') ||
  hasForbiddenReason('const value = Deferred.await(operation);', 'raw await expression') ||
  !/(?<!\.)\bas\b/gu.test(eraseNonCode('const value = `${input as string}`;')) ||
  hasForbiddenReason('const value = "await"; // await', 'raw await expression');

if (scannerSelfCheckFailed) {
  process.stderr.write('Source token scanner self-check failed.\n');
  process.exit(1);
}

const locationFor = (source, offset) => {
  const prefix = source.slice(0, offset);
  const lines = prefix.split('\n');
  const lastLine = lines[lines.length - 1] ?? '';
  return { line: lines.length, column: lastLine.length + 1 };
};

function inspectSource(path) {
  const source = readFileSync(path, 'utf-8');
  const code = eraseNonCode(source);
  for (const rule of forbiddenCode) {
    rule.pattern.lastIndex = 0;
    for (const match of code.matchAll(rule.pattern)) {
      const location = locationFor(code, match.index);
      violations.push(`${path}:${location.line}:${location.column}: ${rule.reason}`);
    }
  }

  const lines = code.split('\n');
  lines.forEach((line, index) => {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('import ') || trimmed.startsWith('export ')) return;
    const assertion = /(?<!\.)\bas\b/gu.exec(line);
    if (assertion !== null) {
      violations.push(`${path}:${index + 1}:${assertion.index + 1}: handwritten type assertion`);
    }
  });
}

function inspect(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      inspect(path);
      continue;
    }
    if (!extensions.has(extname(entry.name))) continue;
    inspectSource(path);
  }
}

for (const sourceRoot of sourceRoots) inspect(sourceRoot);

if (violations.length > 0) {
  process.stderr.write(`Forbidden source tokens found:\n${violations.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Source token policy passed.\n');
}
