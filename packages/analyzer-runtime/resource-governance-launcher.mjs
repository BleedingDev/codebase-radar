import { readFileSync } from 'node:fs';
import {
  ResourceGovernanceError,
  resourceGovernanceSchemaVersion,
  runResourceGovernanceLaunchProtocol,
  runResourceGovernanceProbeProtocol,
} from './resource-governance.mjs';

const writeFailure = error => {
  const code = error instanceof ResourceGovernanceError ? error.code : 'launcher-failed';
  process.stderr.write(`[resource-governance:${code}] launcher failed.\n`);
};

const runProbe = () => {
  let input;
  try {
    input = readFileSync(0, 'utf8');
    const evidence = runResourceGovernanceProbeProtocol(input);
    process.stdout.write(`${JSON.stringify({ schemaVersion: resourceGovernanceSchemaVersion, kind: 'probe-result', evidence })}\n`);
  } catch (error) {
    writeFailure(error);
    process.exitCode = 125;
  }
};

const runLaunch = () => {
  if (typeof process.send !== 'function') {
    writeFailure(new ResourceGovernanceError('ipc-required', 'The launcher requires its trusted IPC parent.'));
    process.exitCode = 125;
    return;
  }
  let received = false;
  const timeout = setTimeout(() => {
    if (received) return;
    writeFailure(new ResourceGovernanceError('protocol-timeout', 'The launcher did not receive a bounded request.'));
    process.exitCode = 125;
  }, 5_000);
  process.once('message', request => {
    received = true;
    clearTimeout(timeout);
    void runResourceGovernanceLaunchProtocol(request).catch(error => {
      writeFailure(error);
      process.exitCode = 125;
    });
  });
};

if (process.argv.length === 3 && process.argv[2] === '--probe') runProbe();
else if (process.argv.length === 2) runLaunch();
else {
  writeFailure(new ResourceGovernanceError('launcher-usage', 'Unsupported launcher arguments.'));
  process.exitCode = 125;
}
