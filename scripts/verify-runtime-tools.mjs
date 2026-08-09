import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const root = resolve('.zerops/analyzer-runtime');
const tools = [
  [resolve(root, 'node_modules/.bin/oxlint'), ['--version'], '1.77.0'],
  [resolve(root, 'node_modules/.bin/jscpd'), ['--version'], '5.0.14'],
  [resolve(root, 'bin/tracedecay'), ['--version'], '0.0.73'],
  [resolve(root, 'bin/zizmor'), ['--version'], '1.29.0'],
  [resolve(root, 'bin/osv-scanner'), ['--version'], '2.5.0'],
];

for (const [command, args, expected] of tools) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0 || !output.includes(expected)) {
    throw new Error(`Runtime tool verification failed: ${command} expected ${expected}; got ${output}`);
  }
  process.stdout.write(`${command}: ${output.trim()}\n`);
}
