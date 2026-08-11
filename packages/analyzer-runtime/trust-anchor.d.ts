export interface RuntimeTrustAnchor {
  readonly schemaVersion: 'codebase-radar.analyzer-runtime-trust-anchor/v1';
  readonly manifestSha256: string;
  readonly policyDigest: string;
  readonly runnerSha256: string;
  readonly buildIdentity: string;
  readonly analyzerControl: Readonly<{
    readonly schemaVersion: 'codebase-radar.analyzer-control/v1';
    readonly root: Readonly<{ readonly uid: 0; readonly gid: 0; readonly mode: '0555' }>;
    readonly files: readonly [
      Readonly<{
        readonly path: 'runtime-snapshot-loader.mjs';
        readonly byteLength: 25020;
        readonly sha256: 'be4b1b1c1bef166888f0c2dc32f5a7e6b0dc802bef5e3ebc4d30769dd8f9fd74';
        readonly mode: '0444';
      }>,
      Readonly<{
        readonly path: 'resource-governance-launcher.mjs';
        readonly byteLength: 55418;
        readonly sha256: 'a70f862c766430f066471cda351f42bb32ac0aa7a33c5502d1f0acf01d79639d';
        readonly mode: '0444';
      }>,
      Readonly<{
        readonly path: 'runtime-memfd-addon.node';
        readonly byteLength: 16304;
        readonly sha256: '8d4a2fcf087648afc60d560af21e2decb49f4ca82ca721f072ed26cc780d9ee6';
        readonly mode: '0555';
      }>,
    ];
  }>;
  readonly sandbox: Readonly<{
    kind: 'bubblewrap';
    path: '/usr/bin/bwrap';
    required: true;
    packageVersion: '0.9.0-1ubuntu0.1';
    versionOutput: 'bubblewrap 0.9.0';
  }>;
  /** Host bootstrap identities; analyzer code uses sealed /runtime/bin/node. */
  readonly resourceGovernance: Readonly<{
    readonly schemaVersion: 'codebase-radar.analyzer-resource-governance/v1';
    readonly bwrap: Readonly<{
      readonly path: '/usr/bin/bwrap';
      readonly sha256: '52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712';
      readonly versionFirstLine: 'bubblewrap 0.9.0';
    }>;
    readonly prlimit: Readonly<{
      readonly path: '/usr/bin/prlimit';
      readonly sha256: 'f27cfd8c1512a4cc6541b59b80cb4cdfd6ef28c34aa21db4299b48264cd0d128';
      readonly versionFirstLine: 'prlimit from util-linux 2.39.3';
    }>;
    readonly node: Readonly<{
      readonly path: '/usr/local/lib/radar-node-v24.18.1/bin/node';
      readonly sha256: 'f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a';
      readonly versionFirstLine: 'v24.18.1';
    }>;
    readonly seccompPolicySha256: '7eaed131680d9a177b0ab3ac928b84ce4ba0c4cbebd57fff000bada375904f7d';
  }>;
}

export declare const runtimeTrustAnchor: Readonly<RuntimeTrustAnchor>;
