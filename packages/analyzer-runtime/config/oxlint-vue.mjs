import { defineConfig } from 'oxlint';
import core from 'ultracite/oxlint/core';
import vue from 'ultracite/oxlint/vue';

export default defineConfig({
  extends: [core, vue],
  ignorePatterns: core.ignorePatterns,
});
