const sandbox = Object.freeze({
  kind: 'bubblewrap',
  path: '/usr/bin/bwrap',
  required: true,
  packageVersion: '0.9.0-1ubuntu0.1',
  versionOutput: 'bubblewrap 0.9.0',
});

// Package versions remain deployment provenance only. Runtime authority is the
// independently pinned byte identities below. The launcher Node is a dedicated
// immutable bootstrap installation; analyzer code executes only the separately
// sealed /runtime/bin/node from the authenticated runtime snapshot.
const resourceGovernance = Object.freeze({
  schemaVersion: 'codebase-radar.analyzer-resource-governance/v1',
  bwrap: Object.freeze({
    path: '/usr/bin/bwrap',
    sha256: '52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712',
    versionFirstLine: 'bubblewrap 0.9.0',
  }),
  prlimit: Object.freeze({
    path: '/usr/bin/prlimit',
    sha256: 'f27cfd8c1512a4cc6541b59b80cb4cdfd6ef28c34aa21db4299b48264cd0d128',
    versionFirstLine: 'prlimit from util-linux 2.39.3',
  }),
  node: Object.freeze({
    path: '/usr/local/lib/radar-node-v24.18.1/bin/node',
    sha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a',
    versionFirstLine: 'v24.18.1',
  }),
  seccompPolicySha256: '7eaed131680d9a177b0ab3ac928b84ce4ba0c4cbebd57fff000bada375904f7d',
});

export const runtimeTrustAnchor = Object.freeze({
  schemaVersion: 'codebase-radar.analyzer-runtime-trust-anchor/v1',
  manifestSha256: '57da34b61256844dc120c8596e25b97cb1e2eb362db2fb5b6fa645ee769f1a7e',
  policyDigest: 'ae5eab1fea82a3f06692132d9102ff9626f837d2efa9d7626c6c6b5312da81b8',
  runnerSha256: '483a580f586da6e206f95207b7e64231bd0668bea1a8a71aa0576f470034ec1f',
  buildIdentity: 'codebase-radar-analyzer-runtime-0.1.0-dogfood-max-v1',
  analyzerControl: Object.freeze({
    schemaVersion: 'codebase-radar.analyzer-control/v1',
    root: Object.freeze({ uid: 0, gid: 0, mode: '0555' }),
    files: Object.freeze([
      Object.freeze({
        path: 'runtime-snapshot-loader.mjs',
        byteLength: 25020,
        sha256: '6799a5628b5ed2f0f08b46e03c9dce0b4d45f0b8fafdd2b0b3074795934ce0d2',
        mode: '0444',
      }),
      Object.freeze({
        path: 'resource-governance-launcher.mjs',
        byteLength: 55418,
        sha256: 'ae1d0a39697e6ac051a5f21fc62998637897504cee5871be682c18471519bcaf',
        mode: '0444',
      }),
      Object.freeze({
        path: 'runtime-memfd-addon.node',
        byteLength: 16304,
        sha256: '8d4a2fcf087648afc60d560af21e2decb49f4ca82ca721f072ed26cc780d9ee6',
        mode: '0555',
      }),
    ]),
  }),
  sandbox,
  resourceGovernance,
});
