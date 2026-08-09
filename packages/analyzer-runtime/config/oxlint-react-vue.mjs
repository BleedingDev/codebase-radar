import { defineConfig } from 'oxlint';
import core from 'ultracite/oxlint/core';
import react from 'ultracite/oxlint/react';
import vue from 'ultracite/oxlint/vue';

export default defineConfig({
  extends: [core, react, vue],
  ignorePatterns: core.ignorePatterns,
  rules: { 'react/react-compiler': 'off' },
});
