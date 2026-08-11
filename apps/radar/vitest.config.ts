import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { defineConfig } from 'vitest/config';

const appRequire = createRequire(import.meta.url);
const tanstackRuntime = join(
  dirname(appRequire.resolve('@modern-js/plugin-tanstack/package.json')),
  'dist/esm/runtime/index.mjs',
);

/**
 * Modern.js publishes its runtime only behind a nonstandard nested `module`
 * condition. Alias that one test-only import to its declared ESM entry instead
 * of globally enabling `module`: doing so would select OpenTelemetry's
 * extensionless ESM export, which Node SSR cannot load. All other packages
 * therefore keep the same default export selection as Node production.
 */
export default defineConfig({
  test: {
    include: [
      'api/**/*.test.ts',
      'server/**/*.test.ts',
      'shared/**/*.test.ts',
      'src/**/*.test.tsx',
    ],
  },
  resolve: {
    alias: [
      {
        find: /^@modern-js\/plugin-tanstack\/runtime$/,
        replacement: tanstackRuntime,
      },
    ],
  },
});
