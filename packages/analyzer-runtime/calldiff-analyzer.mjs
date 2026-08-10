import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative, resolve, sep } from 'node:path';
import {
  buildCallTree,
  buildIndex,
  extractFunctions,
} from 'calldiff/dist/index.js';

const sourceExtensions = new Set([
  '.cjs',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.mts',
  '.ts',
  '.tsx',
]);
const skippedDirectories = new Set([
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'out',
  'vendor',
]);
const maximumDepth = 32;
const maximumPathSamples = 32;

function sourceFiles(root) {
  const files = [];
  const walk = directory => {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!skippedDirectories.has(entry.name) && !entry.name.startsWith('.')) {
          walk(fullPath);
        }
        continue;
      }
      if (
        entry.isFile() &&
        sourceExtensions.has(extname(entry.name).toLowerCase()) &&
        !entry.name.endsWith('.d.ts')
      ) {
        files.push(relative(root, fullPath).split(sep).join('/'));
      }
    }
  };
  walk(root);
  return files.sort();
}

function lineAt(source, offset) {
  return source.slice(0, offset).split('\n').length;
}

function calledKeys(steps, index, output = new Set()) {
  for (const step of steps) {
    if (step.type === 'call' && index.has(step.key)) output.add(step.key);
    calledKeys(step.children ?? [], index, output);
  }
  return output;
}

function rootKeys(index) {
  const incoming = new Set();
  for (const info of index.values()) {
    for (const key of calledKeys(info.steps, index)) incoming.add(key);
  }
  const roots = [...index.entries()]
    .filter(([key]) => !incoming.has(key))
    .map(([key]) => key)
    .sort();
  const reached = new Set();
  const visit = key => {
    if (reached.has(key)) return;
    reached.add(key);
    const info = index.get(key);
    if (!info) return;
    for (const called of calledKeys(info.steps, index)) visit(called);
  };
  roots.forEach(visit);
  for (const key of [...index.keys()].sort()) {
    if (!reached.has(key)) {
      roots.push(key);
      visit(key);
    }
  }
  return roots;
}

function signatureId(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 20);
}

function repeatedNodes(tree, index) {
  const occurrences = new Map();
  const walk = (node, parents) => {
    const path = [...parents, node.label];
    const childSignatures = node.children.map(child => walk(child, path));
    const signature = JSON.stringify([
      node.kind ?? 'call',
      node.key,
      childSignatures.map(child => child.signature),
    ]);
    const subtreeNodes = 1 + childSignatures.reduce(
      (total, child) => total + child.subtreeNodes,
      0,
    );
    if (node.kind !== 'branch' && !node.label.includes('⇄')) {
      const local = index.has(node.key);
      const identity = local ? `local:${node.key}` : `expanded:${signature}`;
      const id = signatureId(identity);
      const current = occurrences.get(identity) ?? {
        id,
        key: node.key,
        label: node.label,
        local,
        count: 0,
        subtreeNodes,
        pathSamples: [],
      };
      current.count += 1;
      current.subtreeNodes = Math.max(current.subtreeNodes, subtreeNodes);
      if (current.pathSamples.length < maximumPathSamples) {
        current.pathSamples.push(path.join(' → '));
      }
      occurrences.set(identity, current);
    }
    return { signature, subtreeNodes };
  };
  walk(tree, []);
  return [...occurrences.values()].filter(
    occurrence =>
      occurrence.count > 1 &&
      (occurrence.local || occurrence.subtreeNodes > 1),
  );
}

function inspectRepository(repositoryRoot) {
  const files = sourceFiles(repositoryRoot);
  const sources = new Map();
  const functions = [];
  const failedFiles = [];
  for (const file of files) {
    try {
      const source = readFileSync(resolve(repositoryRoot, file), 'utf8');
      sources.set(file, source);
      functions.push(...extractFunctions(file, source));
    } catch (error) {
      failedFiles.push({
        path: file,
        diagnostic: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const index = buildIndex(functions);
  const definitions = new Map(
    [...index.entries()].map(([key, info]) => [
      key,
      {
        path: info.file,
        line: lineAt(sources.get(info.file) ?? '', info.start),
      },
    ]),
  );
  const entries = rootKeys(index);
  const duplicates = new Map();
  for (const entry of entries) {
    const tree = buildCallTree(entry, index, maximumDepth);
    const entryDefinition = definitions.get(entry);
    for (const repeated of repeatedNodes(tree, index)) {
      const groupKey = `${repeated.key}\0${repeated.id}`;
      const current = duplicates.get(groupKey) ?? {
        signatureId: repeated.id,
        key: repeated.key,
        label: repeated.label,
        local: repeated.local,
        subtreeNodes: repeated.subtreeNodes,
        maximumOccurrences: 0,
        definition: definitions.get(repeated.key),
        entrypoints: [],
      };
      current.maximumOccurrences = Math.max(
        current.maximumOccurrences,
        repeated.count,
      );
      current.entrypoints.push({
        key: entry,
        path: entryDefinition?.path,
        line: entryDefinition?.line,
        occurrenceCount: repeated.count,
        pathSamples: repeated.pathSamples,
      });
      duplicates.set(groupKey, current);
    }
  }
  return {
    schemaVersion: 'codebase-radar.calldiff-report/v1',
    calldiffVersion: '0.4.1',
    maximumDepth,
    eligibleFiles: files.length,
    analyzedFiles: files.length - failedFiles.length,
    functionCount: index.size,
    entrypointCount: entries.length,
    failedFiles,
    duplicates: [...duplicates.values()].sort(
      (left, right) =>
        right.maximumOccurrences - left.maximumOccurrences ||
        right.subtreeNodes - left.subtreeNodes ||
        left.key.localeCompare(right.key),
    ),
  };
}

const repositoryRoot = process.argv[2];
if (!repositoryRoot) {
  process.stderr.write('Repository root is required.\n');
  process.exitCode = 2;
} else {
  try {
    process.stdout.write(`${JSON.stringify(inspectRepository(resolve(repositoryRoot)))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
