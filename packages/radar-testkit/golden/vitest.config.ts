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
    include: ["golden/**/*.test.ts"],
  },
});
