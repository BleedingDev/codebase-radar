import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageDirectory = fileURLToPath(new URL("../", import.meta.url));

function importWithCondition(specifier: string, condition?: string) {
  const conditions = condition === undefined ? [] : [`--conditions=${condition}`];
  return spawnSync(process.execPath, [
    ...conditions,
    "--input-type=module",
    "--eval",
    [
      `import(${JSON.stringify(specifier)})`,
      ".then(() => process.stdout.write(\"loaded\"))",
      ".catch(error => { process.stderr.write(String(error)); process.exitCode = 1; })",
    ].join(""),
  ], {
    cwd: packageDirectory,
    encoding: "utf8",
  });
}

describe("test-only package exports", () => {
  it("loads every entry point only under the explicit test condition", () => {
    for (const specifier of ["@codebase-radar/testkit", "@codebase-radar/testkit/runtime"]) {
      const testImport = importWithCondition(specifier, "test");
      expect(testImport.status).toBe(0);
      expect(testImport.stdout).toBe("loaded");
      expect(importWithCondition(specifier).status).not.toBe(0);
      expect(importWithCondition(specifier, "development").status).not.toBe(0);
    }
  });
});
