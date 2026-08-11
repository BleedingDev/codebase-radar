import { createHash } from 'node:crypto';
import { lstatSync, opendirSync, readFileSync, readSync } from 'node:fs';
import { createRequire } from 'node:module';
import { extname, join, relative, resolve, sep } from 'node:path';

// Lock down every loader and package-manager escape before importing Calldiff.
// Its grammar helper has an on-demand npm fallback; a missing packaged grammar
// must fail closed, never mutate a cache or reach a registry at runtime.
for (const key of Object.keys(process.env)) {
  if (
    key === 'NODE_OPTIONS' ||
    key === 'NODE_PATH' ||
    key === 'NODE_PRESERVE_SYMLINKS' ||
    key === 'NODE_PRESERVE_SYMLINKS_MAIN' ||
    key === 'NODE_COMPILE_CACHE' ||
    key === 'NODE_LOADER' ||
    key === 'NODE_REQUIRE' ||
    key === 'LD_PRELOAD' ||
    key.startsWith('LD_') ||
    key.startsWith('DYLD_') ||
    key === 'BUN_OPTIONS' ||
    key === 'ESM_LOADER' ||
    key.startsWith('DENO_') ||
    key.startsWith('TSX_')
  ) {
    delete process.env[key];
  }
}
process.env.PATH = '';
process.env.HOME = '/dev/null';
process.env.CALLDIFF_GRAMMAR_CACHE = '/dev/null';
process.env.npm_config_audit = 'false';
process.env.npm_config_fund = 'false';
process.env.npm_config_ignore_scripts = 'true';
process.env.npm_config_offline = 'true';
process.env.npm_config_registry = 'http://127.0.0.1:9';
process.env.npm_config_update_notifier = 'false';

const [{ detectLanguage }, { loadGrammarPackage, resolveLanguage }] = await Promise.all([
  import('calldiff/dist/languages/registry.js'),
  import('calldiff/dist/languages/grammars.js'),
]);
const calldiffRequire = createRequire(
  import.meta.resolve('calldiff/dist/extract.js'),
);
const Parser = calldiffRequire('tree-sitter');
const syntaxParser = new Parser();
const syntaxLanguageCache = new Map();

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
  '.hg',
  '.svn',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.cache',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'vendor',
]);
const maximumDepth = 32;
const maximumPathSamples = 32;
const maximumOutputTextCharacters = 1_024;
const maximumPathSampleCharacters = 4_000;
const maximumInputFiles = 8_000;
const maximumInputFileBytes = 2_097_152;
const maximumInputBytes = 64 * 1024 * 1024;
const maximumAuditedPathInputBytes = 4 * 1024 * 1024;
const maximumInputTruncationSamples = 100;
const maximumFailedFiles = 100;
const maximumDirectoryTraversalDepth = 128;
const maximumDirectoryTraversalDirectories = 25_000;
const maximumDirectoryTraversalEntries = 100_000;
const maximumDirectoryTraversalSamples = 100;
const maximumExpandedNodesPerRoot = 25_000;
const maximumExpandedNodesTotal = 250_000;
const maximumIndexedSteps = 100_000;
const maximumCollisionGroups = 1_000;
const maximumCollisionMembers = 1_000;
const maximumDuplicateGroups = 1_000;
const maximumDuplicateEntrypoints = 8_000;
const maximumUnmodeledCrossFileCalls = 100;
const maximumEvidenceBytes = 8 * 1024 * 1024;

class CalldiffExpansionLimit extends Error {}

function boundedOutputText(value, maximum = maximumOutputTextCharacters) {
  const normalized = String(value).replace(/[\u0000-\u001f\u007f-\u009f]/gu, ' ');
  return normalized.length <= maximum
    ? normalized
    : `${normalized.slice(0, Math.max(0, maximum - 1))}…`;
}

function boundedRepositoryPath(value) {
  return boundedOutputText(String(value).replace(/\\/gu, '/'));
}

function boundedRepositoryDiagnostic(root, error) {
  const message = error instanceof Error ? error.message : String(error);
  const normalizedRoot = String(root).replace(/\\/gu, '/');
  return boundedOutputText(
    message
      .replace(/\\/gu, '/')
      .split(normalizedRoot)
      .join('repository'),
  );
}

function claimEvidenceBytes(evidenceBudget, value) {
  const bytes = Buffer.byteLength(JSON.stringify(value), 'utf8');
  if (bytes > maximumEvidenceBytes - evidenceBudget.bytes) {
    evidenceBudget.truncated = true;
    return false;
  }
  evidenceBudget.bytes += bytes;
  return true;
}

function pathSetDigest(paths) {
  return `sha256:${createHash('sha256')
    .update(JSON.stringify(paths))
    .digest('hex')}`;
}

function strictUtf8(sourceBytes) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
    sourceBytes,
  );
}

function syntaxLanguage(extractor) {
  const key = extractor.grammarExport === undefined
    ? extractor.grammarPackage
    : `${extractor.grammarPackage}:${extractor.grammarExport}`;
  const cached = syntaxLanguageCache.get(key);
  if (cached !== undefined) return cached;
  const language = resolveLanguage(
    loadGrammarPackage(extractor.grammarPackage),
    extractor.grammarExport,
  );
  syntaxLanguageCache.set(key, language);
  return language;
}

function extractStrictFunctions(file, source) {
  const extractor = detectLanguage(file);
  if (extractor === null) return [];
  syntaxParser.setLanguage(syntaxLanguage(extractor));
  const tree = syntaxParser.parse(source);
  if (tree.rootNode.hasError) {
    throw new Error('Source contains syntax errors.');
  }
  return extractor.extract(file, source, tree);
}

function isSafeRepositoryPath(path) {
  return (
    typeof path === 'string' &&
    path.length > 0 &&
    path.length <= maximumOutputTextCharacters &&
    !/[\u0000-\u001f\u007f-\u009f\\\\]/u.test(path) &&
    !path.startsWith('/') &&
    !path.startsWith('~/') &&
    !/^[A-Za-z]:\//u.test(path) &&
    path.split('/').every(segment =>
      segment.length > 0 && segment !== '.' && segment !== '..')
  );
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function insertCanonicalPath(paths, path) {
  let lower = 0;
  let upper = paths.length;
  while (lower < upper) {
    const middle = lower + Math.floor((upper - lower) / 2);
    if (compareUtf8(paths[middle], path) < 0) lower = middle + 1;
    else upper = middle;
  }
  paths.splice(lower, 0, path);
}

function readAuditedSourceFiles() {
  const chunks = [];
  let byteLength = 0;
  const buffer = Buffer.allocUnsafe(65_536);
  while (true) {
    const bytesRead = readSync(0, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    if (bytesRead > maximumAuditedPathInputBytes - byteLength) {
      throw new Error('Audited source-path input exceeded its bounded envelope.');
    }
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    byteLength += bytesRead;
  }
  const input = Buffer.concat(chunks, byteLength);
  const text = input.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(input)) {
    throw new Error('Audited source-path input was not valid UTF-8.');
  }
  let decoded;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new Error('Audited source-path input was not valid JSON.');
  }
  if (
    decoded === null ||
    typeof decoded !== 'object' ||
    Array.isArray(decoded) ||
    !Array.isArray(decoded.sourceFiles) ||
    Object.keys(decoded).length !== 1
  ) {
    throw new Error('Audited source-path input did not contain exactly sourceFiles.');
  }
  const paths = decoded.sourceFiles;
  if (paths.length > maximumInputFiles) {
    throw new Error('Audited source-path input exceeded the file-count envelope.');
  }
  for (let index = 0; index < paths.length; index += 1) {
    const path = paths[index];
    if (!isSafeRepositoryPath(path)) {
      throw new Error('Audited source-path input contained an unsafe path.');
    }
    if (!sourceExtensions.has(extname(path).toLowerCase())) {
      throw new Error('Audited source-path input contained an unsupported file.');
    }
    if (path.split('/').some(segment => skippedDirectories.has(segment))) {
      throw new Error('Audited source-path input contained a canonically excluded directory.');
    }
    const previous = paths[index - 1];
    if (previous !== undefined && compareUtf8(previous, path) >= 0) {
      throw new Error('Audited source-path input was not uniquely ordered by UTF-8 bytes.');
    }
  }
  return paths;
}

function sourceFiles(root, auditedSourceFiles) {
  if (auditedSourceFiles !== undefined) {
    return {
      files: auditedSourceFiles,
      eligibleFiles: auditedSourceFiles.length,
      requestedPathSetDigest: pathSetDigest(auditedSourceFiles),
      truncatedInputFileCount: 0,
      truncatedInputFiles: [],
      maximumDirectoryTraversalDepth,
      maximumDirectoryTraversalDirectories,
      maximumDirectoryTraversalEntries,
      traversedDirectoryCount: 0,
      traversedDirectoryEntryCount: 0,
      directoryTraversalFailureCount: 0,
      directoryTraversalFailuresTruncated: false,
      directoryTraversalFailures: [],
      directoryTraversalTruncated: false,
      truncatedDirectoryCount: 0,
      truncatedDirectories: [],
    };
  }
  const files = [];
  const truncatedInputFiles = [];
  const directoryTraversalFailures = [];
  const truncatedDirectories = [];
  let eligibleFiles = 0;
  let truncatedInputFileCount = 0;
  let directoryTraversalFailureCount = 0;
  let truncatedDirectoryCount = 0;
  let traversedDirectoryCount = 0;
  let traversedDirectoryEntryCount = 0;
  const recordTruncatedInputFile = file => {
    truncatedInputFileCount += 1;
    if (truncatedInputFiles.length < maximumInputTruncationSamples) {
      truncatedInputFiles.push({
        path: boundedRepositoryPath(file),
        reason: 'file_count',
      });
    }
  };
  const directoryPath = directory => {
    const path = relative(root, directory).split(sep).join('/');
    return path === '' ? 'repository-root' : boundedRepositoryPath(path);
  };
  const recordDirectoryFailure = (directory, error) => {
    directoryTraversalFailureCount += 1;
    if (directoryTraversalFailures.length < maximumDirectoryTraversalSamples) {
      directoryTraversalFailures.push({
        path: directoryPath(directory),
        diagnostic: boundedRepositoryDiagnostic(root, error),
      });
    }
  };
  const recordTruncatedDirectory = (directory, reason) => {
    truncatedDirectoryCount += 1;
    if (truncatedDirectories.length < maximumDirectoryTraversalSamples) {
      truncatedDirectories.push({
        path: directoryPath(directory),
        reason,
      });
    }
  };
  const pending = [{ directory: root, depth: 0 }];
  let traversalBudgetExhausted = false;
  while (pending.length > 0 && !traversalBudgetExhausted) {
    if (traversedDirectoryCount >= maximumDirectoryTraversalDirectories) {
      for (const skipped of pending) {
        recordTruncatedDirectory(skipped.directory, 'directory_budget');
      }
      break;
    }
    const current = pending.pop();
    traversedDirectoryCount += 1;
    let directory;
    try {
      directory = opendirSync(current.directory);
    } catch (error) {
      recordDirectoryFailure(current.directory, error);
      continue;
    }
    try {
      let entry;
      while ((entry = directory.readSync()) !== null) {
        if (traversedDirectoryEntryCount >= maximumDirectoryTraversalEntries) {
          recordTruncatedDirectory(current.directory, 'entry_budget');
          for (const skipped of pending) {
            recordTruncatedDirectory(skipped.directory, 'entry_budget');
          }
          traversalBudgetExhausted = true;
          break;
        }
        traversedDirectoryEntryCount += 1;
        const fullPath = join(current.directory, entry.name);
        if (entry.isDirectory()) {
          if (skippedDirectories.has(entry.name)) continue;
          if (current.depth >= maximumDirectoryTraversalDepth) {
            recordTruncatedDirectory(fullPath, 'depth');
            continue;
          }
          pending.push({ directory: fullPath, depth: current.depth + 1 });
          continue;
        }
        if (
          entry.isFile() &&
          sourceExtensions.has(extname(entry.name).toLowerCase())
        ) {
          const file = relative(root, fullPath).split(sep).join('/');
          eligibleFiles += 1;
          if (files.length < maximumInputFiles) {
            insertCanonicalPath(files, file);
          }
          else recordTruncatedInputFile(file);
        }
      }
    } catch (error) {
      recordDirectoryFailure(current.directory, error);
    } finally {
      try {
        directory.closeSync();
      } catch {}
    }
  }
  return {
    files,
    eligibleFiles,
    requestedPathSetDigest: pathSetDigest(files),
    truncatedInputFileCount,
    truncatedInputFiles: truncatedInputFiles.sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    maximumDirectoryTraversalDepth,
    maximumDirectoryTraversalDirectories,
    maximumDirectoryTraversalEntries,
    traversedDirectoryCount,
    traversedDirectoryEntryCount,
    directoryTraversalFailureCount,
    directoryTraversalFailuresTruncated:
      directoryTraversalFailureCount > directoryTraversalFailures.length,
    directoryTraversalFailures: directoryTraversalFailures.sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    directoryTraversalTruncated: truncatedDirectoryCount > 0,
    truncatedDirectoryCount,
    truncatedDirectories: truncatedDirectories.sort(
      (left, right) =>
        left.path.localeCompare(right.path) ||
        left.reason.localeCompare(right.reason),
    ),
  };
}

function lineAt(source, offset) {
  return source.slice(0, offset).split('\n').length;
}

// Upstream Calldiff's buildIndex deliberately keeps the first definition for
// an unqualified key. That is useful for interactive use, but it makes a
// whole-repository quality report dependent on traversal order. Build a
// qualified index instead: every local node is file::key, and ambiguous calls
// stay external until a single deterministic resolution rule proves otherwise.
function qualifiedKey(file, key) {
  return `${file}::${key}`;
}

function compareDefinitions(left, right) {
  return (
    left.file.localeCompare(right.file) ||
    left.start - right.start ||
    left.end - right.end ||
    left.key.localeCompare(right.key)
  );
}

function constructorAlias(definition) {
  if (!definition.key.endsWith('.constructor')) return [];
  const className = definition.key.slice(0, -'.constructor'.length);
  const key = `new ${className}`;
  return [{ ...definition, key, label: `new ${className}()` }];
}

function createDefinitionGroups(functions) {
  const groups = new Map();
  for (const original of functions) {
    const aliases = constructorAlias(original);
    const definition = aliases.length === 1 ? aliases[0] : original;
    const group = groups.get(definition.key) ?? [];
    group.push(definition);
    groups.set(definition.key, group);
  }
  for (const group of groups.values()) group.sort(compareDefinitions);
  return groups;
}

function createQualifiedIndex(
  groups,
  unresolvedLabels,
  ambiguousCalls,
  unmodeledCrossFileCalls,
  graphBudget,
  rewriteTruncation,
) {
  const qualifiedCounts = new Map();
  for (const definitions of groups.values()) {
    for (const definition of definitions) {
      const key = qualifiedKey(definition.file, definition.key);
      qualifiedCounts.set(key, (qualifiedCounts.get(key) ?? 0) + 1);
    }
  }
  const available = new Set(
    [...qualifiedCounts.entries()]
      .filter(([, count]) => count === 1)
      .map(([key]) => key),
  );
  const canonicalConstructorCallKey = key => {
    if (!key.endsWith('.constructor')) return key;
    const className = key.slice(0, -'.constructor'.length);
    const alias = `new ${className}`;
    return groups.has(alias) ? alias : key;
  };
  const resolveCall = (caller, rawKey) => {
    const key = canonicalConstructorCallKey(rawKey);
    const candidates = (groups.get(key) ?? []).filter(candidate =>
      available.has(qualifiedKey(candidate.file, candidate.key)),
    );
    const sameFile = candidates.filter(candidate => candidate.file === caller.file);
    if (sameFile.length === 1) return qualifiedKey(sameFile[0].file, sameFile[0].key);
    const externalKey = `external:${caller.file}::${caller.start}::${key}`;
    const localDefinitions = groups.get(key) ?? [];
    const isAmbiguous = localDefinitions.length > 1;
    unresolvedLabels.set(
      externalKey,
      isAmbiguous ? `${key} (ambiguous local definition)` : key,
    );
    if (localDefinitions.length > 0) {
      unmodeledCrossFileCalls.count += 1;
      if (unmodeledCrossFileCalls.calls.length < maximumUnmodeledCrossFileCalls) {
        unmodeledCrossFileCalls.calls.push({
          key,
          caller,
          localDefinitionCount: localDefinitions.length,
        });
      }
    }
    if (isAmbiguous) {
      const callers = ambiguousCalls.get(key) ?? new Map();
      callers.set(qualifiedKey(caller.file, caller.key), caller);
      ambiguousCalls.set(key, callers);
    }
    return externalKey;
  };
  const rewriteSteps = (caller, steps) => {
    const rewritten = [];
    const pending = [{ source: steps, index: 0, output: rewritten }];
    while (pending.length > 0) {
      const frame = pending[pending.length - 1];
      if (frame.index >= frame.source.length) {
        pending.pop();
        continue;
      }
      if (graphBudget.count >= maximumIndexedSteps) return undefined;
      claimGraphStep(graphBudget);
      const step = frame.source[frame.index];
      frame.index += 1;
      const children = step.children;
      if (step.type === 'branch') {
        const rewrittenStep = { ...step, children: [] };
        frame.output.push(rewrittenStep);
        if (children?.length) {
          pending.push({
            source: children,
            index: 0,
            output: rewrittenStep.children,
          });
        }
        continue;
      }
      const rewrittenStep = { ...step, key: resolveCall(caller, step.key) };
      if (children === undefined) {
        frame.output.push(rewrittenStep);
        continue;
      }
      rewrittenStep.children = [];
      frame.output.push(rewrittenStep);
      if (children.length > 0) {
        pending.push({
          source: children,
          index: 0,
          output: rewrittenStep.children,
        });
      }
    }
    return rewritten;
  };
  const recordTruncatedDefinition = definition => {
    rewriteTruncation.definitionCount += 1;
    if (rewriteTruncation.definitions.length < maximumInputTruncationSamples) {
      rewriteTruncation.definitions.push(definition);
    }
  };
  const index = new Map();
  let rewriteBudgetExhausted = false;
  for (const definitions of groups.values()) {
    for (const definition of definitions) {
      const key = qualifiedKey(definition.file, definition.key);
      if (!available.has(key)) continue;
      if (rewriteBudgetExhausted) {
        recordTruncatedDefinition(definition);
        continue;
      }
      const steps = rewriteSteps(definition, definition.steps);
      if (steps === undefined) {
        recordTruncatedDefinition(definition);
        rewriteBudgetExhausted = true;
        continue;
      }
      index.set(key, { ...definition, key, steps });
    }
  }
  return index;
}

function rewriteTruncationEvidence(rewriteTruncation, sources) {
  const definitions = [...rewriteTruncation.definitions]
    .sort(compareDefinitions)
    .map(definition => ({
      key: boundedOutputText(qualifiedKey(definition.file, definition.key)),
      path: boundedRepositoryPath(definition.file),
      line: lineAt(sources.get(definition.file) ?? '', definition.start),
    }));
  return {
    rewriteTruncatedDefinitionCount: rewriteTruncation.definitionCount,
    rewriteTruncatedDefinitionsTruncated:
      rewriteTruncation.definitionCount > definitions.length,
    rewriteTruncatedDefinitions: definitions,
  };
}

function unmodeledCrossFileEvidence(unmodeledCrossFileCalls, sources) {
  const calls = [...unmodeledCrossFileCalls.calls]
    .sort(
      (left, right) =>
        left.key.localeCompare(right.key) ||
        compareDefinitions(left.caller, right.caller),
    )
    .map(call => ({
      key: boundedOutputText(call.key),
      callerKey: boundedOutputText(
        qualifiedKey(call.caller.file, call.caller.key),
      ),
      path: boundedRepositoryPath(call.caller.file),
      line: lineAt(sources.get(call.caller.file) ?? '', call.caller.start),
      localDefinitionCount: call.localDefinitionCount,
    }));
  return {
    unmodeledCrossFileCallCount: unmodeledCrossFileCalls.count,
    unmodeledCrossFileCallsTruncated:
      unmodeledCrossFileCalls.count > calls.length,
    unmodeledCrossFileCalls: calls,
  };
}

function displayCallLabel(key, index, unresolvedLabels) {
  const info = index.get(key);
  if (info) return info.label;
  const label = unresolvedLabels.get(key) ?? key;
  return label.includes('(') ? label : `${label}()`;
}

function buildQualifiedCallTree(
  entryKey,
  index,
  unresolvedLabels,
  maxDepth,
  globalExpansion,
  depthCuts,
) {
  let rootExpansion = 0;
  let rootDepthCut = false;
  const recordDepthCut = () => {
    depthCuts.count += 1;
    if (rootDepthCut) return;
    rootDepthCut = true;
    depthCuts.entrypointCount += 1;
    if (depthCuts.entrypoints.length < maximumPathSamples) {
      depthCuts.entrypoints.push(boundedOutputText(entryKey));
    }
  };
  const claimNode = () => {
    if (
      rootExpansion >= maximumExpandedNodesPerRoot ||
      globalExpansion.count >= maximumExpandedNodesTotal
    ) {
      throw new CalldiffExpansionLimit('Calldiff expansion budget exhausted.');
    }
    rootExpansion += 1;
    globalExpansion.count += 1;
  };
  const expandSteps = (steps, depth, visiting) =>
    steps.map(step => {
      claimNode();
      if (step.type === 'branch') {
        if (depth >= maxDepth) {
          if (step.children.length > 0) recordDepthCut();
          return {
            key: boundedOutputText(step.key),
            label: boundedOutputText(step.label),
            kind: 'branch',
            children: [],
          };
        }
        return {
          key: boundedOutputText(step.key),
          label: boundedOutputText(step.label),
          kind: 'branch',
          children: expandSteps(step.children, depth + 1, visiting),
        };
      }
      return expandCall(step.key, depth, visiting, step.children);
    });
  const expandCall = (key, depth, visiting, inlineChildren) => {
    claimNode();
    const outputKey = boundedOutputText(key);
    const label = boundedOutputText(displayCallLabel(key, index, unresolvedLabels));
    const info = index.get(key);
    if (depth >= maxDepth) {
      if ((info?.steps.length ?? 0) > 0 || (inlineChildren?.length ?? 0) > 0) {
        recordDepthCut();
      }
      return { key: outputKey, label, kind: 'call', children: [] };
    }
    if (!info && !inlineChildren?.length) {
      return { key: outputKey, label, kind: 'call', children: [] };
    }
    if (info && visiting.has(key)) {
      return {
        key: outputKey,
        label: `${label} ⇄`,
        kind: 'call',
        children: inlineChildren?.length
          ? expandSteps(inlineChildren, depth + 1, visiting)
          : [],
      };
    }
    if (info) visiting.add(key);
    const bodyChildren = info
      ? expandSteps(info.steps, depth + 1, visiting)
      : [];
    const callSiteChildren = inlineChildren?.length
      ? expandSteps(inlineChildren, depth + 1, visiting)
      : [];
    if (info) visiting.delete(key);
    return {
      key: outputKey,
      label,
      kind: 'call',
      children: [...bodyChildren, ...callSiteChildren],
    };
  };
  return expandCall(entryKey, 0, new Set());
}

function collisionEvidence(groups, sources, ambiguousCalls, evidenceBudget) {
  const collisionEntries = [...groups.entries()]
    .filter(([, definitions]) => definitions.length > 1)
    .sort(([left], [right]) => left.localeCompare(right));
  const collisions = [];
  let collisionsTruncated = collisionEntries.length > maximumCollisionGroups;
  for (const [key, definitions] of collisionEntries) {
    if (
      collisions.length >= maximumCollisionGroups ||
      evidenceBudget.truncated
    ) {
      collisionsTruncated = true;
      break;
    }
    const callers = [...(ambiguousCalls.get(key)?.values() ?? [])].sort(
      compareDefinitions,
    );
    const collision = {
      key: boundedOutputText(key),
      definitionCount: definitions.length,
      definitionsTruncated: definitions.length > maximumCollisionMembers,
      definitions: [],
      ambiguousCallerCount: callers.length,
      ambiguousCallersTruncated: callers.length > maximumCollisionMembers,
      ambiguousCallers: [],
    };
    if (!claimEvidenceBytes(evidenceBudget, {
      key: collision.key,
      definitionCount: collision.definitionCount,
      ambiguousCallerCount: collision.ambiguousCallerCount,
    })) {
      collisionsTruncated = true;
      break;
    }
    for (const definition of definitions.slice(0, maximumCollisionMembers)) {
      const member = {
        key: boundedOutputText(qualifiedKey(definition.file, definition.key)),
        path: boundedRepositoryPath(definition.file),
        line: lineAt(sources.get(definition.file) ?? '', definition.start),
        exported: definition.exported,
      };
      if (!claimEvidenceBytes(evidenceBudget, member)) {
        collision.definitionsTruncated = true;
        break;
      }
      collision.definitions.push(member);
    }
    for (const caller of callers.slice(0, maximumCollisionMembers)) {
      const member = {
        key: boundedOutputText(qualifiedKey(caller.file, caller.key)),
        path: boundedRepositoryPath(caller.file),
        line: lineAt(sources.get(caller.file) ?? '', caller.start),
      };
      if (!claimEvidenceBytes(evidenceBudget, member)) {
        collision.ambiguousCallersTruncated = true;
        break;
      }
      collision.ambiguousCallers.push(member);
    }
    collisions.push(collision);
  }
  return {
    collisionCount: collisionEntries.length,
    collisionsTruncated,
    collisions,
  };
}

function claimGraphStep(graphBudget) {
  if (graphBudget.count >= maximumIndexedSteps) {
    throw new CalldiffExpansionLimit('Calldiff graph budget exhausted.');
  }
  graphBudget.count += 1;
}

function createAdjacency(index, graphBudget) {
  const adjacency = new Map();
  for (const [key, info] of index) {
    const output = new Set();
    const pending = [...info.steps];
    while (pending.length > 0) {
      claimGraphStep(graphBudget);
      const step = pending.pop();
      if (step.type === 'call' && index.has(step.key)) output.add(step.key);
      pending.push(...(step.children ?? []));
    }
    adjacency.set(key, output);
  }
  return adjacency;
}

function rootKeys(index, adjacency, graphBudget) {
  const incoming = new Set();
  for (const calledKeys of adjacency.values()) {
    for (const key of calledKeys) {
      claimGraphStep(graphBudget);
      incoming.add(key);
    }
  }
  const roots = [...index.entries()]
    .filter(([key]) => !incoming.has(key))
    .map(([key]) => key)
    .sort();
  const reached = new Set();
  const visit = root => {
    const pending = [root];
    while (pending.length > 0) {
      claimGraphStep(graphBudget);
      const key = pending.pop();
      if (reached.has(key)) continue;
      reached.add(key);
      for (const called of adjacency.get(key) ?? []) pending.push(called);
    }
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

function repeatedNodes(tree, index, evidenceBudget) {
  const occurrences = new Map();
  const walk = (node, parents) => {
    const path = [...parents, node.label];
    const childSignatures = node.children.map(child => walk(child, path));
    const signature = signatureId(
      JSON.stringify([
        node.kind ?? 'call',
        node.key,
        childSignatures.map(child => child.signature),
      ]),
    );
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
        const sample = boundedOutputText(
          path.join(' → '),
          maximumPathSampleCharacters,
        );
        if (claimEvidenceBytes(evidenceBudget, sample)) {
          current.pathSamples.push(sample);
        }
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

function inspectRepository(repositoryRoot, auditedSourceFiles) {
  const sourceFileInventory = sourceFiles(repositoryRoot, auditedSourceFiles);
  const { files } = sourceFileInventory;
  const sources = new Map();
  const functions = [];
  const failedFiles = [];
  const analyzedPaths = [];
  let failedFileCount = 0;
  let analyzedFiles = 0;
  let inputFileCount = 0;
  let inputBytes = 0;
  let truncatedInputFileCount = sourceFileInventory.truncatedInputFileCount;
  const truncatedInputFiles = [...sourceFileInventory.truncatedInputFiles];
  const recordTruncatedInputFile = (file, reason) => {
    truncatedInputFileCount += 1;
    if (truncatedInputFiles.length < maximumInputTruncationSamples) {
      truncatedInputFiles.push({
        path: boundedRepositoryPath(file),
        reason,
      });
    }
  };
  const recordFailedFile = (file, error) => {
    failedFileCount += 1;
    if (failedFiles.length < maximumFailedFiles) {
      failedFiles.push({
        path: boundedRepositoryPath(file),
        diagnostic: boundedRepositoryDiagnostic(repositoryRoot, error),
      });
    }
  };
  for (const file of files) {
    let inputFileBytes;
    try {
      const sourceInfo = lstatSync(resolve(repositoryRoot, file));
      if (!sourceInfo.isFile()) {
        throw new Error('Audited source path was not a regular file.');
      }
      inputFileBytes = sourceInfo.size;
    } catch (error) {
      recordFailedFile(file, error);
      continue;
    }
    if (
      !Number.isSafeInteger(inputFileBytes) ||
      inputFileBytes < 0 ||
      inputFileBytes > maximumInputFileBytes
    ) {
      recordTruncatedInputFile(file, 'file_bytes');
      continue;
    }
    if (inputBytes > maximumInputBytes - inputFileBytes) {
      recordTruncatedInputFile(file, 'total_bytes');
      continue;
    }
    inputFileCount += 1;
    inputBytes += inputFileBytes;
    try {
      const source = strictUtf8(readFileSync(resolve(repositoryRoot, file)));
      const extracted = extractStrictFunctions(file, source);
      sources.set(file, source);
      functions.push(...extracted);
      analyzedPaths.push(file);
      analyzedFiles += 1;
    } catch (error) {
      recordFailedFile(file, error);
    }
  }
  const inputReport = {
    maximumInputFiles,
    maximumInputFileBytes,
    maximumInputBytes,
    inputFileCount,
    inputBytes,
    inputTruncated: truncatedInputFileCount > 0,
    truncatedInputFileCount,
    truncatedInputFiles: truncatedInputFiles.sort(
      (left, right) =>
        left.path.localeCompare(right.path) ||
        left.reason.localeCompare(right.reason),
    ),
  };
  const traversalReport = {
    maximumDirectoryTraversalDepth:
      sourceFileInventory.maximumDirectoryTraversalDepth,
    maximumDirectoryTraversalDirectories:
      sourceFileInventory.maximumDirectoryTraversalDirectories,
    maximumDirectoryTraversalEntries:
      sourceFileInventory.maximumDirectoryTraversalEntries,
    traversedDirectoryCount: sourceFileInventory.traversedDirectoryCount,
    traversedDirectoryEntryCount:
      sourceFileInventory.traversedDirectoryEntryCount,
    directoryTraversalFailureCount:
      sourceFileInventory.directoryTraversalFailureCount,
    directoryTraversalFailuresTruncated:
      sourceFileInventory.directoryTraversalFailuresTruncated,
    directoryTraversalFailures: sourceFileInventory.directoryTraversalFailures,
    directoryTraversalTruncated:
      sourceFileInventory.directoryTraversalTruncated,
    truncatedDirectoryCount: sourceFileInventory.truncatedDirectoryCount,
    truncatedDirectories: sourceFileInventory.truncatedDirectories,
  };
  const pathSetReport = {
    requestedPaths: sourceFileInventory.files,
    requestedPathSetDigest: sourceFileInventory.requestedPathSetDigest,
    analyzedPaths,
    analyzedPathSetDigest: pathSetDigest(analyzedPaths),
  };
  const groups = createDefinitionGroups(functions);
  const unresolvedLabels = new Map();
  const ambiguousCalls = new Map();
  const unmodeledCrossFileCalls = { count: 0, calls: [] };
  const graphBudget = { count: 0 };
  const rewriteTruncation = { definitionCount: 0, definitions: [] };
  const evidenceBudget = { bytes: 0, truncated: false };
  const evidenceReport = () => ({
    maximumEvidenceBytes,
    evidenceBytes: evidenceBudget.bytes,
    evidenceTruncated: evidenceBudget.truncated,
  });
  const index = createQualifiedIndex(
    groups,
    unresolvedLabels,
    ambiguousCalls,
    unmodeledCrossFileCalls,
    graphBudget,
    rewriteTruncation,
  );
  const crossFileReport = unmodeledCrossFileEvidence(
    unmodeledCrossFileCalls,
    sources,
  );
  const rewriteReport = rewriteTruncationEvidence(rewriteTruncation, sources);
  const definitions = new Map(
    [...index.entries()].map(([key, info]) => [
      key,
      {
        path: boundedRepositoryPath(info.file),
        line: lineAt(sources.get(info.file) ?? '', info.start),
      },
    ]),
  );
  let adjacency;
  let entries;
  try {
    adjacency = createAdjacency(index, graphBudget);
    entries = rootKeys(index, adjacency, graphBudget);
  } catch (error) {
    if (!(error instanceof CalldiffExpansionLimit)) throw error;
    return {
      schemaVersion: 'codebase-radar.calldiff-report/v1',
      calldiffVersion: '0.4.1',
      maximumDepth,
      maximumExpandedNodes: maximumExpandedNodesTotal,
      expandedNodes: 0,
      indexedStepLimit: maximumIndexedSteps,
      indexedSteps: graphBudget.count,
      eligibleFiles: sourceFileInventory.eligibleFiles,
      analyzedFiles,
      ...pathSetReport,
      functionCount: index.size,
      entrypointCount: 0,
      ...inputReport,
      ...traversalReport,
      failedFileCount,
      failedFilesTruncated: failedFileCount > failedFiles.length,
      failedFiles,
      collisionCount: 0,
      collisionsTruncated: false,
      collisions: [],
      ...crossFileReport,
      ...rewriteReport,
      ...evidenceReport(),
      depthCutCount: 0,
      depthTruncatedEntrypointCount: 0,
      depthTruncatedEntrypointsTruncated: false,
      depthTruncatedEntrypoints: [],
      truncatedEntrypointCount: index.size,
      truncatedEntrypoints: [...index.keys()]
        .sort()
        .slice(0, maximumPathSamples)
        .map(key => boundedOutputText(key)),
      duplicateCount: 0,
      duplicatesTruncated: false,
      duplicates: [],
    };
  }
  const duplicates = new Map();
  const duplicateGroupKeys = new Set();
  let duplicateGroupsTruncated = false;
  const globalExpansion = { count: 0 };
  const depthCuts = { count: 0, entrypointCount: 0, entrypoints: [] };
  const truncatedEntrypoints = [];
  let truncatedEntrypointCount = 0;
  for (let entryIndex = 0; entryIndex < entries.length; entryIndex += 1) {
    const entry = entries[entryIndex];
    let tree;
    try {
      tree = buildQualifiedCallTree(
        entry,
        index,
        unresolvedLabels,
        maximumDepth,
        globalExpansion,
        depthCuts,
      );
    } catch (error) {
      if (!(error instanceof CalldiffExpansionLimit)) throw error;
      truncatedEntrypointCount += 1;
      if (truncatedEntrypoints.length < maximumPathSamples) {
        truncatedEntrypoints.push(boundedOutputText(entry));
      }
      if (globalExpansion.count >= maximumExpandedNodesTotal) {
        truncatedEntrypointCount += entries.length - entryIndex - 1;
        for (
          let sampleIndex = entryIndex + 1;
          sampleIndex < entries.length && truncatedEntrypoints.length < maximumPathSamples;
          sampleIndex += 1
        ) {
          truncatedEntrypoints.push(boundedOutputText(entries[sampleIndex]));
        }
        break;
      }
      continue;
    }
    const entryDefinition = definitions.get(entry);
    for (const repeated of repeatedNodes(tree, index, evidenceBudget)) {
      const groupKey = `${repeated.key}\0${repeated.id}`;
      duplicateGroupKeys.add(groupKey);
      let current = duplicates.get(groupKey);
      if (!current) {
        const group = {
          signatureId: repeated.id,
          key: boundedOutputText(repeated.key),
          label: boundedOutputText(repeated.label),
          local: repeated.local,
          subtreeNodes: repeated.subtreeNodes,
          maximumOccurrences: 0,
          definition: definitions.get(repeated.key),
          entrypointCount: 0,
          entrypointsTruncated: false,
          entrypoints: [],
        };
        if (
          duplicates.size >= maximumDuplicateGroups ||
          !claimEvidenceBytes(evidenceBudget, group)
        ) {
          duplicateGroupsTruncated = true;
          continue;
        }
        current = group;
      }
      current.maximumOccurrences = Math.max(
        current.maximumOccurrences,
        repeated.count,
      );
      current.entrypointCount += 1;
      if (current.entrypoints.length < maximumDuplicateEntrypoints) {
        const entrypoint = {
          key: boundedOutputText(entry),
          path: entryDefinition?.path,
          line: entryDefinition?.line,
          occurrenceCount: repeated.count,
          pathSamples: repeated.pathSamples,
        };
        if (claimEvidenceBytes(evidenceBudget, entrypoint)) {
          current.entrypoints.push(entrypoint);
        } else {
          current.entrypointsTruncated = true;
        }
      } else {
        current.entrypointsTruncated = true;
      }
      duplicates.set(groupKey, current);
    }
  }
  const collisionReport = collisionEvidence(
    groups,
    sources,
    ambiguousCalls,
    evidenceBudget,
  );
  const sortedDuplicates = [...duplicates.values()].sort(
    (left, right) =>
      right.maximumOccurrences - left.maximumOccurrences ||
      right.subtreeNodes - left.subtreeNodes ||
      left.key.localeCompare(right.key),
  );
  return {
    schemaVersion: 'codebase-radar.calldiff-report/v1',
    calldiffVersion: '0.4.1',
    maximumDepth,
    maximumExpandedNodes: maximumExpandedNodesTotal,
    expandedNodes: globalExpansion.count,
    indexedStepLimit: maximumIndexedSteps,
    indexedSteps: graphBudget.count,
    eligibleFiles: sourceFileInventory.eligibleFiles,
    analyzedFiles,
    ...pathSetReport,
    functionCount: index.size,
    entrypointCount: entries.length,
    ...inputReport,
    ...traversalReport,
    failedFileCount,
    failedFilesTruncated: failedFileCount > failedFiles.length,
    failedFiles,
    ...collisionReport,
    ...crossFileReport,
    ...rewriteReport,
    ...evidenceReport(),
    depthCutCount: depthCuts.count,
    depthTruncatedEntrypointCount: depthCuts.entrypointCount,
    depthTruncatedEntrypointsTruncated:
      depthCuts.entrypointCount > depthCuts.entrypoints.length,
    depthTruncatedEntrypoints: depthCuts.entrypoints,
    truncatedEntrypointCount,
    truncatedEntrypoints,
    duplicateCount: duplicateGroupKeys.size,
    duplicatesTruncated: duplicateGroupsTruncated,
    duplicates: sortedDuplicates,
  };
}

const [repositoryRoot, inputMode, ...unexpectedArguments] = process.argv.slice(2);
if (
  !repositoryRoot ||
  unexpectedArguments.length > 0 ||
  (inputMode !== undefined && inputMode !== '--audited-source-files-stdin')
) {
  process.stderr.write(
    'Repository root and an optional audited source-path input mode are required.\n',
  );
  process.exitCode = 2;
} else {
  try {
    const auditedSourceFiles =
      inputMode === '--audited-source-files-stdin'
        ? readAuditedSourceFiles()
        : undefined;
    process.stdout.write(
      `${JSON.stringify(inspectRepository(resolve(repositoryRoot), auditedSourceFiles))}\n`,
    );
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
