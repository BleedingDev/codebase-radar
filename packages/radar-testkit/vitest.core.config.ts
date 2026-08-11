import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    conditions: ["test"],
  },
  ssr: {
    resolve: {
      conditions: ["test"],
    },
  },
  test: {
    include: ["src/{clock,coverage-digest,exports,ids,normalize,progress,temp}.test.ts"],
  },
});
