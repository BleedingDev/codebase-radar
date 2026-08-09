import { appTools, defineConfig } from '@modern-js/app-tools';
import { bffPlugin } from '@modern-js/plugin-bff';
import { tanstackRouterPlugin } from '@modern-js/plugin-tanstack';

export default defineConfig({
  plugins: [appTools(), tanstackRouterPlugin(), bffPlugin()],
  bff: {
    runtimeFramework: 'effect',
    effect: {
      entry: 'api/index.ts',
    },
  },
  server: {
    ssr: {
      mode: 'stream',
    },
  },
});
