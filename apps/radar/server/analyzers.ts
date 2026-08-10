import {
  Clock,
  Config,
  Crypto,
  Effect,
  FileSystem,
  Option,
  Path,
  Schema,
} from 'effect';
import stripJsonComments from 'strip-json-comments';
import {
  AnalyzerCoverage,
  AnalyzerRun,
  Evidence,
  ExternalReference,
  FindingCategory,
} from '../shared/domain';
import { RepositoryInventory, repositoryRelative } from './inventory';
import { boundedDiagnostic, runCommand } from './process';

export class FindingCandidate extends Schema.Class<FindingCandidate>(
  'FindingCandidate',
)({
  fingerprintSeed: Schema.String,
  title: Schema.String,
  category: FindingCategory,
  summary: Schema.String,
  technicalSummary: Schema.String,
  recommendation: Schema.String,
  evidence: Schema.Array(Evidence),
  externalReferences: Schema.optional(Schema.Array(ExternalReference)),
  tags: Schema.Array(Schema.String),
  consequence: Schema.Number,
  blastRadius: Schema.Number,
  confidence: Schema.Number,
  effort: Schema.Number,
  changeExposure: Schema.Number,
}) {}

export class AnalyzerOutput extends Schema.Class<AnalyzerOutput>('AnalyzerOutput')({
  run: AnalyzerRun,
  candidates: Schema.Array(FindingCandidate),
  context: Schema.optional(
    Schema.Struct({
      duplicatePercentage: Schema.optional(Schema.Number),
      duplicatedLines: Schema.optional(Schema.Number),
    }),
  ),
}) {}

const OxlintReport = Schema.Struct({
  diagnostics: Schema.optional(
    Schema.Array(
      Schema.Struct({
        message: Schema.optional(Schema.String),
        code: Schema.optional(Schema.String),
        url: Schema.optional(Schema.String),
        filename: Schema.optional(Schema.String),
        labels: Schema.optional(
          Schema.Array(
            Schema.Struct({
              span: Schema.optional(
                Schema.Struct({
                  line: Schema.optional(Schema.Number),
                  column: Schema.optional(Schema.Number),
                }),
              ),
            }),
          ),
        ),
      }),
    ),
  ),
  number_of_files: Schema.optional(Schema.Number),
});

const JscpdReport = Schema.Struct({
  statistics: Schema.optional(
    Schema.Struct({
      total: Schema.optional(
        Schema.Struct({
          clones: Schema.optional(Schema.Number),
          percentage: Schema.optional(Schema.Number),
          sources: Schema.optional(Schema.Number),
          duplicatedLines: Schema.optional(Schema.Number),
        }),
      ),
    }),
  ),
  duplicates: Schema.optional(
    Schema.Array(
      Schema.Struct({
        lines: Schema.optional(Schema.Number),
        tokens: Schema.optional(Schema.Number),
        firstFile: Schema.optional(
          Schema.Struct({
            name: Schema.optional(Schema.String),
            start: Schema.optional(Schema.Number),
          }),
        ),
        secondFile: Schema.optional(
          Schema.Struct({
            name: Schema.optional(Schema.String),
            start: Schema.optional(Schema.Number),
          }),
        ),
      }),
    ),
  ),
});

const ZizmorReport = Schema.Array(
  Schema.Struct({
    ident: Schema.optional(Schema.String),
    desc: Schema.optional(Schema.String),
    url: Schema.optional(Schema.String),
    determinations: Schema.optional(
      Schema.Struct({
        confidence: Schema.optional(Schema.String),
        severity: Schema.optional(Schema.String),
      }),
    ),
    locations: Schema.optional(
      Schema.Array(
        Schema.Struct({
          concrete: Schema.optional(
            Schema.Struct({
              path: Schema.optional(Schema.String),
              location: Schema.optional(
                Schema.Struct({ row: Schema.optional(Schema.Number) }),
              ),
            }),
          ),
          symbolic: Schema.optional(
            Schema.Struct({ path: Schema.optional(Schema.String) }),
          ),
        }),
      ),
    ),
  }),
);

const OsvReport = Schema.Struct({
  results: Schema.optional(
    Schema.Array(
      Schema.Struct({
        source: Schema.optional(Schema.Struct({ path: Schema.optional(Schema.String) })),
        packages: Schema.optional(
          Schema.Array(
            Schema.Struct({
              package: Schema.optional(
                Schema.Struct({
                  name: Schema.optional(Schema.String),
                  version: Schema.optional(Schema.String),
                }),
              ),
              vulnerabilities: Schema.optional(
                Schema.Array(
                  Schema.Struct({
                    id: Schema.optional(Schema.String),
                    summary: Schema.optional(Schema.String),
                    aliases: Schema.optional(Schema.Array(Schema.String)),
                    references: Schema.optional(
                      Schema.Array(
                        Schema.Struct({
                          url: Schema.optional(Schema.String),
                          type: Schema.optional(Schema.String),
                        }),
                      ),
                    ),
                  }),
                ),
              ),
              groups: Schema.optional(
                Schema.Array(
                  Schema.Struct({
                    ids: Schema.optional(Schema.Array(Schema.String)),
                    aliases: Schema.optional(Schema.Array(Schema.String)),
                  }),
                ),
              ),
            }),
          ),
        ),
      }),
    ),
  ),
});

const defectBearingOxlintRules = new Map<
  string,
  typeof FindingCategory.Type
>([
  ['exhaustive-deps', 'reliability'],
  ['jsx-no-target-blank', 'security'],
  ['no-async-promise-executor', 'reliability'],
  ['no-danger', 'security'],
  ['no-dupe-case', 'reliability'],
  ['no-dupe-keys', 'reliability'],
  ['no-eval', 'security'],
  ['no-implied-eval', 'security'],
  ['no-new-func', 'security'],
  ['no-promise-executor-return', 'reliability'],
  ['no-script-url', 'security'],
  ['no-side-effects-in-computed-properties', 'reliability'],
  ['no-unreachable', 'reliability'],
  ['no-unsafe-finally', 'reliability'],
  ['no-v-html', 'security'],
  ['rules-of-hooks', 'reliability'],
  ['use-isnan', 'reliability'],
  ['valid-typeof', 'reliability'],
]);

export const classifyOxlintRule = (code: string) => {
  const parenthesizedRule = code.match(/\(([^()]+)\)$/u)?.[1];
  const ruleName = parenthesizedRule ?? code.split('/').at(-1) ?? code;
  const category = defectBearingOxlintRules.get(ruleName);
  return {
    category: category ?? 'maintainability',
    policyOnly: category === undefined,
  };
};

const decodeJson = <S extends Schema.Constraint>(schema: S, text: string) =>
  Schema.decodeEffect(Schema.fromJsonString(schema))(text || 'null');

const unavailable = (
  analyzer: string,
  version: string,
  inventory: RepositoryInventory,
  diagnostic: string,
  status: typeof AnalyzerRun.fields.status.Type = 'partial',
) =>
  new AnalyzerOutput({
    run: new AnalyzerRun({
      analyzer,
      analyzerVersion: version,
      profileVersion: '2026-08-09',
      status,
      durationMs: 0,
      coverage: new AnalyzerCoverage({
        eligibleFiles: inventory.sourceFiles.length,
        analyzedFiles: 0,
        omittedCapabilities: [
          status === 'not_applicable'
            ? diagnostic
            : `${analyzer} executable unavailable`,
        ],
        warnings: status === 'not_applicable' ? [] : [diagnostic],
      }),
      observationCount: 0,
      ...(status === 'not_applicable' ? {} : { diagnostic }),
    }),
    candidates: [],
  });

const safeEnvironment = Effect.fn(function* (home: string) {
  const path = yield* Config.option(Config.string('PATH'));
  return {
    PATH: Option.getOrUndefined(path),
    HOME: home,
    LANG: 'C.UTF-8',
    NO_COLOR: '1',
  };
});

export const analyzerRoot = Effect.fn('analyzerRoot')(function* () {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const configured = yield* Config.option(Config.string('RADAR_ANALYZER_ROOT'));
  const candidates = [
    Option.getOrUndefined(configured),
    pathService.resolve(process.cwd(), '.zerops/analyzer-runtime'),
    pathService.resolve(process.cwd(), '../../packages/analyzer-runtime'),
    pathService.resolve(process.cwd(), 'packages/analyzer-runtime'),
  ].filter((value): value is string => value !== undefined);
  for (const candidate of candidates) {
    if (yield* fs.exists(candidate)) return candidate;
  }
  return candidates[0] ?? pathService.resolve(process.cwd(), 'packages/analyzer-runtime');
});

export const runStrictestComparator = Effect.fn('runStrictestComparator')(
  function* (repoRoot: string, inventory: RepositoryInventory) {
    const fs = yield* FileSystem.FileSystem;
    const pathService = yield* Path.Path;
    const startedAt = yield* Clock.currentTimeMillis;
    const gaps = new Set<string>();
    const warnings: Array<string> = [];
    let analyzed = 0;
    yield* Effect.forEach(
      inventory.tsconfigs,
      configPath =>
        fs.readFileString(pathService.resolve(repoRoot, configPath)).pipe(
          Effect.flatMap(text =>
            decodeJson(
              Schema.Struct({
                compilerOptions: Schema.optional(
                  Schema.Struct({
                    strict: Schema.optional(Schema.Boolean),
                    alwaysStrict: Schema.optional(Schema.Boolean),
                    exactOptionalPropertyTypes: Schema.optional(Schema.Boolean),
                    noFallthroughCasesInSwitch: Schema.optional(Schema.Boolean),
                    noImplicitAny: Schema.optional(Schema.Boolean),
                    noImplicitOverride: Schema.optional(Schema.Boolean),
                    noImplicitReturns: Schema.optional(Schema.Boolean),
                    noImplicitThis: Schema.optional(Schema.Boolean),
                    noPropertyAccessFromIndexSignature: Schema.optional(
                      Schema.Boolean,
                    ),
                    noUncheckedIndexedAccess: Schema.optional(Schema.Boolean),
                    noUnusedLocals: Schema.optional(Schema.Boolean),
                    noUnusedParameters: Schema.optional(Schema.Boolean),
                    useUnknownInCatchVariables: Schema.optional(Schema.Boolean),
                  }),
                ),
                extends: Schema.optional(
                  Schema.Union([Schema.String, Schema.Array(Schema.String)]),
                ),
              }),
              stripJsonComments(text, { trailingCommas: true }),
            ),
          ),
          Effect.tap(parsed =>
            Effect.sync(() => {
              analyzed += 1;
              const bases =
                typeof parsed.extends === 'string'
                  ? [parsed.extends]
                  : parsed.extends ?? [];
              const strictestInherited = bases.some(
                base =>
                  base === '@tsconfig/strictest' ||
                  base === '@tsconfig/strictest/tsconfig.json',
              );
              if (
                !strictestInherited &&
                bases.some(base => !base.startsWith('.'))
              ) {
                warnings.push(
                  `${configPath}: package-based extends was not executed or resolved`,
                );
              }
              const configured = {
                strict: parsed.compilerOptions?.strict,
                alwaysStrict: parsed.compilerOptions?.alwaysStrict,
                exactOptionalPropertyTypes:
                  parsed.compilerOptions?.exactOptionalPropertyTypes,
                noFallthroughCasesInSwitch:
                  parsed.compilerOptions?.noFallthroughCasesInSwitch,
                noImplicitAny: parsed.compilerOptions?.noImplicitAny,
                noImplicitOverride: parsed.compilerOptions?.noImplicitOverride,
                noImplicitReturns: parsed.compilerOptions?.noImplicitReturns,
                noImplicitThis: parsed.compilerOptions?.noImplicitThis,
                noPropertyAccessFromIndexSignature:
                  parsed.compilerOptions?.noPropertyAccessFromIndexSignature,
                noUncheckedIndexedAccess:
                  parsed.compilerOptions?.noUncheckedIndexedAccess,
                noUnusedLocals: parsed.compilerOptions?.noUnusedLocals,
                noUnusedParameters: parsed.compilerOptions?.noUnusedParameters,
                useUnknownInCatchVariables:
                  parsed.compilerOptions?.useUnknownInCatchVariables,
              };
              for (const [option, enabled] of Object.entries(configured)) {
                if (enabled === false || (!strictestInherited && enabled !== true)) {
                  gaps.add(option);
                }
              }
            }),
          ),
          Effect.catch(error =>
            Effect.sync(() => {
              warnings.push(`${configPath}: ${boundedDiagnostic(String(error), 140)}`);
            }),
          ),
        ),
      { concurrency: 1, discard: true },
    );
    const options = [...gaps].sort();
    const candidates =
      inventory.tsconfigs.length > 0 && options.length > 0
        ? [
            new FindingCandidate({
              fingerprintSeed: 'tsconfig/strictest:repository',
              title: `TypeScript safety baseline has ${options.length} gaps`,
              category: 'configuration',
              summary:
                'Compile-time checks are disabled, increasing the chance that avoidable defects reach review or production.',
              technicalSummary: `Compared ${analyzed} local TSConfig files with @tsconfig/strictest 2.0.8. Missing or disabled: ${options.join(', ')}. Package-based inheritance was not executed.`,
              recommendation:
                'Adopt the missing checks incrementally and budget the resulting cleanup.',
              evidence: [
                new Evidence({
                  analyzer: 'strictest-comparator',
                  kind: 'direct',
                  message: `${options.length} strictness options differ from @tsconfig/strictest 2.0.8`,
                  path: inventory.tsconfigs[0],
                }),
              ],
              tags: ['typescript', 'strictness'],
              consequence: Math.min(72, 35 + options.length * 2),
              blastRadius: inventory.tsconfigs.length > 1 ? 68 : 52,
              confidence: warnings.length > 0 ? 72 : 90,
              effort: Math.min(85, 28 + options.length * 3),
              changeExposure: 65,
            }),
          ]
        : [];
    return new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'strictest-comparator',
        analyzerVersion: '@tsconfig/strictest 2.0.8',
        profileVersion: 'radar.tsconfig-gap/v1',
        status:
          inventory.tsconfigs.length === 0
            ? 'not_applicable'
            : warnings.length > 0
              ? 'partial'
              : 'complete',
        durationMs: (yield* Clock.currentTimeMillis) - startedAt,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.tsconfigs.length,
          analyzedFiles: analyzed,
          omittedCapabilities: ['package-based TSConfig inheritance is not executed'],
          warnings,
        }),
        observationCount: options.length,
      }),
      candidates,
    });
  },
);

export const runOxlint = Effect.fn('runOxlint')(function* (
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const command = pathService.resolve(root, 'node_modules/.bin/oxlint');
  if (!(yield* fs.exists(command))) {
    return unavailable(
      'Oxlint + Ultracite',
      '1.77.0 + 7.10.2',
      inventory,
      'Pinned Oxlint binary was not found.',
    );
  }
  const react = inventory.frameworks.includes('react');
  const vue = inventory.frameworks.includes('vue');
  const configName = react
    ? vue
      ? 'oxlint-react-vue.mjs'
      : 'oxlint-react.mjs'
    : vue
      ? 'oxlint-vue.mjs'
      : 'oxlint-core.mjs';
  return yield* Effect.gen(function* () {
    const result = yield* runCommand({
      command,
      args: [
        '--disable-nested-config',
        '--no-error-on-unmatched-pattern',
        `--config=${pathService.resolve(root, 'config', configName)}`,
        '--format=json',
        '--threads=1',
        repoRoot,
      ],
      cwd: pathService.dirname(repoRoot),
      env: yield* safeEnvironment(pathService.dirname(repoRoot)),
      timeoutMs: 55_000,
    });
    const parsed = yield* decodeJson(OxlintReport, result.stdout || '{}');
    const diagnostics = parsed.diagnostics ?? [];
    const grouped = new Map<string, Array<(typeof diagnostics)[number]>>();
    for (const diagnostic of diagnostics) {
      const code = diagnostic.code ?? 'unidentified-rule';
      grouped.set(code, [...(grouped.get(code) ?? []), diagnostic]);
    }
    const candidates = [...grouped.entries()]
      .sort((left, right) => {
        const policyDelta =
          Number(classifyOxlintRule(left[0]).policyOnly) -
          Number(classifyOxlintRule(right[0]).policyOnly);
        return policyDelta || right[1].length - left[1].length;
      })
      .map(([code, matches]) => {
        const first = matches[0];
        const path = first?.filename
          ? repositoryRelative(pathService, repoRoot, first.filename)
          : undefined;
        const { category, policyOnly } = classifyOxlintRule(code);
        const title = policyOnly
          ? 'consistency preference'
          : category === 'security'
            ? 'risky code pattern'
            : category === 'performance'
              ? 'performance concern'
              : category === 'architecture'
                ? 'dependency concern'
                : category === 'reliability'
                  ? 'reliability concern'
                  : 'maintainability concern';
        const recommendation = policyOnly
          ? 'Apply this preference only while editing nearby code; do not schedule a repository-wide cleanup.'
          : category === 'security'
            ? 'Inspect representative locations, confirm whether inputs can reach them, then fix the smallest proven risk.'
            : 'Inspect representative locations, confirm the pattern matters, then address it within one bounded change.';
        return new FindingCandidate({
          fingerprintSeed: `oxlint:${code}:${path ?? 'repository'}`,
          title: `${matches.length} ${title}${matches.length === 1 ? '' : 's'}`,
          category,
          summary:
            policyOnly
              ? 'This is a consistency preference, not evidence of a defect. It should not displace behavior, security, or structural work.'
              : category === 'security'
              ? 'Static analysis found a risky code pattern that needs prompt human validation; this is not proof of exploitability.'
              : 'A repeated quality pattern is increasing review friction or defect risk.',
          technicalSummary: `${matches.length} diagnostics from the pinned Ultracite/Oxlint policy. First location: ${path ?? 'repository scope'}.`,
          recommendation,
          evidence: matches.map(
            match =>
              new Evidence({
                analyzer: 'Oxlint + Ultracite',
                kind: 'direct',
                message: match.message ?? code,
                ruleId: code,
                path: match.filename
                  ? repositoryRelative(pathService, repoRoot, match.filename)
                  : undefined,
                line: match.labels?.[0]?.span?.line,
              }),
          ),
          externalReferences: first?.url
            ? [
                new ExternalReference({
                  label: `${code} rule`,
                  url: first.url,
                  relationship: 'background',
                  applicability: 'unverified',
                }),
              ]
            : [],
          tags: [
            'oxlint',
            code,
            ...(policyOnly ? ['style-policy'] : []),
          ],
          consequence:
            policyOnly
              ? 14
              : category === 'security'
                ? 75
                : Math.min(68, 28 + matches.length * 3),
          blastRadius: policyOnly ? 18 : Math.min(78, 28 + matches.length * 4),
          confidence: 86,
          effort: policyOnly ? 78 : Math.min(75, 18 + matches.length * 2),
          changeExposure: policyOnly
            ? 16
            : Math.min(75, 30 + matches.length * 3),
        });
      });
    return new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'Oxlint + Ultracite',
        analyzerVersion: '1.77.0 + 7.10.2',
        profileVersion: `radar/${configName}`,
        status: result.timedOut
          ? 'timed_out'
          : result.truncated
            ? 'truncated'
            : 'complete',
        durationMs: result.durationMs,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.sourceFiles.length,
          analyzedFiles: parsed.number_of_files ?? inventory.sourceFiles.length,
          omittedCapabilities: [
            'type-aware rules (target dependencies are intentionally not installed)',
            ...(inventory.frameworks.some(framework =>
              ['angular', 'svelte', 'solid'].includes(framework),
            )
              ? ['Angular/Svelte/Solid template-specific semantic linting']
              : []),
          ],
          warnings: result.stderr ? [boundedDiagnostic(result.stderr)] : [],
        }),
        observationCount: diagnostics.length,
      }),
      candidates,
    });
  }).pipe(
    Effect.catch(error =>
      Effect.succeed(
        unavailable(
          'Oxlint + Ultracite',
          '1.77.0 + 7.10.2',
          inventory,
          boundedDiagnostic(String(error)),
        ),
      ),
    ),
  );
});

export const runJscpd = Effect.fn('runJscpd')(function* (
  scanRoot: string,
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const command = pathService.resolve(root, 'node_modules/.bin/jscpd');
  if (!(yield* fs.exists(command))) {
    return unavailable('JSCPD', '5.0.14', inventory, 'Pinned JSCPD binary was not found.');
  }
  return yield* Effect.gen(function* () {
    const outputDirectory = pathService.resolve(scanRoot, 'jscpd-output');
    yield* fs.makeDirectory(outputDirectory, { recursive: true });
    const result = yield* runCommand({
      command,
      args: [
        repoRoot,
        '--config',
        pathService.resolve(root, 'config/jscpd.json'),
        '--reporters',
        'json,silent',
        '--output',
        outputDirectory,
        '--workers',
        '2',
      ],
      cwd: scanRoot,
      env: yield* safeEnvironment(scanRoot),
      timeoutMs: 35_000,
    });
    const report = yield* fs
      .readFileString(pathService.resolve(outputDirectory, 'jscpd-report.json'))
      .pipe(Effect.flatMap(text => decodeJson(JscpdReport, text)));
    const duplicates = report.duplicates ?? [];
    const total = report.statistics?.total;
    const diagnostic = result.stderr
      .replace(/^Using config from .*$/gmu, '')
      .trim();
    const candidates = [...duplicates]
      .sort((left, right) => (right.lines ?? 0) - (left.lines ?? 0))
      .map(duplicate => {
        const firstPath = duplicate.firstFile?.name
          ? repositoryRelative(pathService, repoRoot, duplicate.firstFile.name)
          : undefined;
        const secondPath = duplicate.secondFile?.name
          ? repositoryRelative(pathService, repoRoot, duplicate.secondFile.name)
          : undefined;
        const generated = [firstPath, secondPath].some(path =>
          path
            ? /(?:test|spec|fixture|snapshot|generated|migration)/iu.test(path)
            : false,
        );
        return new FindingCandidate({
          fingerprintSeed: `jscpd:${[firstPath, secondPath].sort().join(':')}`,
          title: `${duplicate.lines ?? 0} duplicated lines across two regions`,
          category: 'maintainability',
          summary:
            'Two regions are substantially similar. Duplication alone does not prove that an abstraction is worthwhile.',
          technicalSummary: `JSCPD found a ${duplicate.tokens ?? 0}-token clone between ${firstPath ?? 'an unreported path'} and ${secondPath ?? 'an unreported path'}.`,
          recommendation: generated
            ? 'Do not prioritize unless a maintainer confirms both regions change together.'
            : 'Confirm that both regions represent one stable concept before extracting shared code.',
          evidence: [
            new Evidence({
              analyzer: 'JSCPD',
              kind: 'direct',
              message: `${duplicate.lines ?? 0} lines / ${duplicate.tokens ?? 0} tokens matched`,
              path: firstPath,
              line: duplicate.firstFile?.start,
            }),
            new Evidence({
              analyzer: 'JSCPD',
              kind: 'direct',
              message: 'Matching peer region',
              path: secondPath,
              line: duplicate.secondFile?.start,
            }),
          ],
          tags: ['duplication', ...(generated ? ['generated-or-test'] : [])],
          consequence: generated ? 18 : Math.min(60, 25 + (duplicate.lines ?? 0)),
          blastRadius: generated ? 15 : 42,
          confidence: 82,
          effort: 55,
          changeExposure: generated ? 20 : 48,
        });
      });
    return new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'JSCPD',
        analyzerVersion: '5.0.14',
        profileVersion: 'radar-duplicates-max/v2',
        status: result.timedOut
          ? 'timed_out'
          : result.truncated
            ? 'truncated'
            : 'complete',
        durationMs: result.durationMs,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.sourceFiles.length,
          analyzedFiles: total?.sources ?? inventory.sourceFiles.length,
          omittedCapabilities: [
            'semantic equivalence and abstraction value are not established',
          ],
          warnings: diagnostic ? [boundedDiagnostic(diagnostic)] : [],
        }),
        observationCount: total?.clones ?? duplicates.length,
      }),
      candidates,
      context: {
        duplicatePercentage: total?.percentage ?? 0,
        duplicatedLines: total?.duplicatedLines ?? 0,
      },
    });
  }).pipe(
    Effect.catch(error =>
      Effect.succeed(
        unavailable('JSCPD', '5.0.14', inventory, boundedDiagnostic(String(error))),
      ),
    ),
  );
});

export const runZizmor = Effect.fn('runZizmor')(function* (
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  if (inventory.workflowFiles.length === 0) {
    return unavailable(
      'zizmor',
      '1.29.0',
      inventory,
      'No local GitHub Actions workflows or actions were found.',
      'not_applicable',
    );
  }
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const command = pathService.resolve(root, 'bin/zizmor');
  if (!(yield* fs.exists(command))) {
    return unavailable('zizmor', '1.29.0', inventory, 'Pinned zizmor binary was not found.');
  }
  return yield* Effect.gen(function* () {
    const result = yield* runCommand({
      command,
      args: [
        '--offline',
        '--no-config',
        '--no-ignores',
        '--collect=workflows,actions',
        '--persona=regular',
        '--format=json-v1',
        '--no-progress',
        '--color=never',
        repoRoot,
      ],
      cwd: pathService.dirname(repoRoot),
      env: yield* safeEnvironment(pathService.dirname(repoRoot)),
      timeoutMs: 18_000,
    });
    const findings = yield* decodeJson(ZizmorReport, result.stdout || '[]');
    const candidates = findings.map(finding => {
      const severity = finding.determinations?.severity ?? 'medium';
      const severityScore =
        { informational: 25, low: 40, medium: 65, high: 84 }[severity] ?? 55;
      const location = finding.locations?.[0];
      const findingPath = location?.concrete?.path ?? location?.symbolic?.path;
      return new FindingCandidate({
        fingerprintSeed: `zizmor:${finding.ident ?? 'unidentified'}:${findingPath ?? 'workflow'}`,
        title: finding.ident
          ? `Workflow risk: ${finding.ident}`
          : 'GitHub Actions workflow risk',
        category: 'security',
        summary: `${finding.desc ?? 'A risky CI/CD construct was detected.'} Static evidence does not establish attacker reachability.`,
        technicalSummary: `zizmor offline audit reported ${severity} severity and ${finding.determinations?.confidence ?? 'unreported'} confidence.`,
        recommendation:
          'Review the affected workflow permissions and trust boundary before its next privileged execution.',
        evidence: [
          new Evidence({
            analyzer: 'zizmor',
            kind: 'direct',
            message: finding.desc ?? finding.ident ?? 'workflow audit',
            ruleId: finding.ident,
            path: findingPath,
            line:
              location?.concrete?.location?.row === undefined
                ? undefined
                : location.concrete.location.row + 1,
          }),
        ],
        externalReferences: finding.url
          ? [
              new ExternalReference({
                label: `${finding.ident ?? 'zizmor'} audit`,
                url: finding.url,
                relationship: 'background',
                applicability: 'unverified',
              }),
            ]
          : [],
        tags: ['github-actions', 'supply-chain'],
        consequence: severityScore,
        blastRadius: severity === 'high' ? 72 : 52,
        confidence: finding.determinations?.confidence === 'high' ? 88 : 72,
        effort: 38,
        changeExposure: 68,
      });
    });
    const successfulExit =
      result.exitCode === 0 ||
      (result.exitCode !== null && result.exitCode >= 11 && result.exitCode <= 14);
    return new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'zizmor',
        analyzerVersion: '1.29.0',
        profileVersion: 'offline-regular/v1',
        status: result.timedOut ? 'timed_out' : successfulExit ? 'complete' : 'failed',
        durationMs: result.durationMs,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.workflowFiles.length,
          analyzedFiles: inventory.workflowFiles.length,
          omittedCapabilities: ['online identity/reputation audits'],
          warnings: result.stderr ? [boundedDiagnostic(result.stderr)] : [],
        }),
        observationCount: findings.length,
      }),
      candidates,
    });
  }).pipe(
    Effect.catch(error =>
      Effect.succeed(
        unavailable('zizmor', '1.29.0', inventory, boundedDiagnostic(String(error))),
      ),
    ),
  );
});

export const runOsv = Effect.fn('runOsv')(function* (
  scanRoot: string,
  repoRoot: string,
  inventory: RepositoryInventory,
  root: string,
) {
  if (inventory.lockfiles.length === 0) {
    return unavailable(
      'OSV-Scanner',
      '2.5.0',
      inventory,
      'No supported JavaScript lockfile was found.',
      'not_applicable',
    );
  }
  const fs = yield* FileSystem.FileSystem;
  const pathService = yield* Path.Path;
  const command = pathService.resolve(root, 'bin/osv-scanner');
  if (!(yield* fs.exists(command))) {
    return unavailable(
      'OSV-Scanner',
      '2.5.0',
      inventory,
      'Pinned OSV-Scanner binary was not found.',
    );
  }
  return yield* Effect.gen(function* () {
    const config = pathService.resolve(scanRoot, 'osv-scanner.toml');
    yield* fs.writeFileString(config, '# Radar-owned empty configuration\n', {
      mode: 0o600,
    });
    const lockfileArgs = inventory.lockfiles.flatMap(path => [
      '-L',
      pathService.resolve(repoRoot, path),
    ]);
    const result = yield* runCommand({
      command,
      args: [
        'scan',
        'source',
        '--format=json',
        '--verbosity=error',
        '--no-resolve',
        `--config=${config}`,
        ...lockfileArgs,
      ],
      cwd: scanRoot,
      env: yield* safeEnvironment(scanRoot),
      timeoutMs: 48_000,
      maxOutputBytes: 8 * 1024 * 1024,
    });
    const parsed = yield* decodeJson(OsvReport, result.stdout || '{}');
    const candidates: Array<FindingCandidate> = [];
    for (const source of parsed.results ?? []) {
      for (const pkg of source.packages ?? []) {
        const vulnerabilities = pkg.vulnerabilities ?? [];
        const groups =
          pkg.groups && pkg.groups.length > 0
            ? pkg.groups
            : vulnerabilities.map(vulnerability => ({
                ids: vulnerability.id ? [vulnerability.id] : [],
                aliases: vulnerability.aliases,
              }));
        for (const group of groups) {
          const ids = [...new Set([...(group.ids ?? []), ...(group.aliases ?? [])])];
          const primary =
            vulnerabilities.find(
              vulnerability =>
                vulnerability.id !== undefined && ids.includes(vulnerability.id),
            ) ?? vulnerabilities[0];
          if (ids.length === 0 && !primary?.id) continue;
          const advisoryId = ids[0] ?? primary?.id ?? 'OSV advisory';
          candidates.push(
            new FindingCandidate({
              fingerprintSeed: `osv:${pkg.package?.name}:${advisoryId}`,
              title: `${advisoryId} affects ${pkg.package?.name ?? 'a dependency'}`,
              category: 'security',
              summary:
                'The locked dependency version matches a published vulnerability advisory. Runtime reachability and exploitability are not established.',
              technicalSummary: `${pkg.package?.name ?? 'Unidentified package'}@${pkg.package?.version ?? 'unreported'} matched ${ids.join(', ') || advisoryId}.`,
              recommendation:
                'Confirm whether the dependency is shipped and reachable, then upgrade to an advisory-listed fixed version.',
              evidence: [
                new Evidence({
                  analyzer: 'OSV-Scanner',
                  kind: 'direct',
                  message: primary?.summary ?? `Package/version matched ${advisoryId}`,
                  ruleId: advisoryId,
                  path: source.source?.path
                    ? repositoryRelative(pathService, repoRoot, source.source.path)
                    : undefined,
                }),
              ],
              externalReferences: [
                new ExternalReference({
                  label: advisoryId,
                  url: `https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}`,
                  relationship: 'advisory',
                  applicability: 'established',
                }),
                ...(primary?.references ?? [])
                  .filter(reference => reference.url?.startsWith('https://'))
                  .map(
                    reference =>
                      new ExternalReference({
                        label: reference.type ?? 'Advisory reference',
                        url: reference.url ?? '',
                        relationship: 'background',
                        applicability: 'unverified',
                      }),
                  ),
              ],
              tags: ['dependency', 'advisory', ...ids],
              consequence: 88,
              blastRadius: 64,
              confidence: 94,
              effort: 42,
              changeExposure: 76,
            }),
          );
        }
      }
    }
    const successfulExit = result.exitCode === 0 || result.exitCode === 1;
    return new AnalyzerOutput({
      run: new AnalyzerRun({
        analyzer: 'OSV-Scanner',
        analyzerVersion: '2.5.0',
        profileVersion: 'js-lockfiles-online/v1',
        status: result.timedOut
          ? 'timed_out'
          : result.truncated
            ? 'truncated'
            : successfulExit
              ? 'complete'
              : 'failed',
        durationMs: result.durationMs,
        coverage: new AnalyzerCoverage({
          eligibleFiles: inventory.lockfiles.length,
          analyzedFiles: inventory.lockfiles.length,
          omittedCapabilities: [
            'runtime reachability',
            'exploitability',
            'native package ecosystems',
          ],
          warnings: [
            'Dependency coordinates are queried against the public OSV advisory API.',
            ...(result.stderr ? [boundedDiagnostic(result.stderr)] : []),
          ],
        }),
        observationCount: candidates.length,
      }),
      candidates,
    });
  }).pipe(
    Effect.catch(error =>
      Effect.succeed(
        unavailable(
          'OSV-Scanner',
          '2.5.0',
          inventory,
          boundedDiagnostic(String(error)),
        ),
      ),
    ),
  );
});

export const candidateHash = Effect.fn('candidateHash')(function* (seed: string) {
  const crypto = yield* Crypto.Crypto;
  const digest = yield* crypto.digest('SHA-256', new TextEncoder().encode(seed));
  return [...digest]
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 20);
});
