import { readdirSync, readFileSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../apps/radar');
const ignored = new Set(['.output', 'dist', 'node_modules']);
const extensions = new Set(['.ts', '.tsx']);
const tokens = [
  String.fromCharCode(97, 115),
  String.fromCharCode(117, 110, 107, 110, 111, 119, 110),
  String.fromCharCode(97, 110, 121),
];
const forbidden = new RegExp(String.raw`\b(${tokens.join('|')})\b`, 'giu');
const violations = [];

function inspect(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      inspect(path);
      continue;
    }
    if (!extensions.has(extname(entry.name))) continue;
    const lines = readFileSync(path, 'utf8').split('\n');
    lines.forEach((line, index) => {
      forbidden.lastIndex = 0;
      if (forbidden.test(line)) {
        violations.push(`${path}:${index + 1}: ${line.trim()}`);
      }
    });
  }
}

inspect(sourceRoot);

if (violations.length > 0) {
  process.stderr.write(`Forbidden source tokens found:\n${violations.join('\n')}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('Source token policy passed.\n');
}
