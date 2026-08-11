import { posix, win32 } from "node:path";
import { Effect, flow, Schema } from "effect";

export type JsonValue = Schema.Json;
export type NormalizationPathSegment = "*" | number | string;

interface BaseNormalizationRule {
  readonly path: readonly NormalizationPathSegment[];
}

export type NormalizationRule =
  | (BaseNormalizationRule & { readonly kind: "duration"; readonly replacement?: number })
  | (BaseNormalizationRule & { readonly kind: "path" })
  | (BaseNormalizationRule & { readonly kind: "replace"; readonly replacement: JsonValue })
  | (BaseNormalizationRule & { readonly kind: "run-id"; readonly replacement?: string })
  | (BaseNormalizationRule & { readonly kind: "sort-array" })
  | (BaseNormalizationRule & { readonly kind: "timestamp"; readonly replacement?: string });

export interface NormalizationSchema<A extends JsonValue> {
  readonly input: Schema.Codec<A, A>;
  readonly rules: readonly NormalizationRule[];
  /** Type mismatches indicate schema drift and fail by default. */
  readonly strict?: boolean;
}

export interface NormalizationContext {
  readonly temporaryRoots?: readonly string[];
  readonly workspaceRoot?: string;
}

interface NormalizationRoot {
  readonly order: number;
  readonly path: ClassifiedPath;
  readonly token: string;
}

interface RootReplacement {
  readonly order: number;
  readonly path: string;
  readonly specificity: number;
}

type PathFamily = "posix" | "relative" | "unc" | "windows-drive";

interface ClassifiedPath {
  readonly family: PathFamily;
  readonly normalized: string;
  readonly segmentDepth: number;
}

export class NormalizationError extends Schema.TaggedErrorClass<NormalizationError>()(
  "NormalizationError",
  {
    kind: Schema.Literals([
      "duration",
      "path",
      "run-id",
      "sort-array",
      "timestamp",
    ]),
    path: Schema.String,
    expected: Schema.String,
  },
) {}

const JsonArray = Schema.Array(Schema.Json);
const JsonObject = Schema.Record(Schema.String, Schema.Json);

export function defineNormalizationSchema<A extends JsonValue>(
  input: Schema.Codec<A, A>,
  rules: readonly NormalizationRule[],
  options: { readonly strict?: boolean } = {},
): NormalizationSchema<A> {
  return options.strict === undefined
    ? { input, rules }
    : { input, rules, strict: options.strict };
}

function displayPath(path: readonly (number | string)[]): string {
  return path.length === 0 ? "$" : `$.${path.join(".")}`;
}

function matches(
  pattern: readonly NormalizationPathSegment[],
  path: readonly (number | string)[],
): boolean {
  return pattern.length === path.length && pattern.every((part, index) => {
    const actual = path[index];
    return part === "*" || part === actual;
  });
}

function mismatch(
  rule: Exclude<NormalizationRule, { readonly kind: "replace" }>,
  path: readonly (number | string)[],
  expected: string,
): NormalizationError {
  return new NormalizationError({
    kind: rule.kind,
    path: displayPath(path),
    expected,
  });
}

function portablePath(value: string): string {
  return value.replaceAll("\\", "/");
}

function pathFamily(value: string): PathFamily {
  if (value.startsWith("\\\\") || value.startsWith("//")) return "unc";
  if (/^[A-Za-z]:[\\/]/.test(value)) return "windows-drive";
  return value.startsWith("/") ? "posix" : "relative";
}

function pathImplementation(family: PathFamily) {
  return family === "unc" || family === "windows-drive" ? win32 : posix;
}

function pathInput(value: string, family: PathFamily): string {
  return family === "unc" || family === "windows-drive"
    ? value.replaceAll("/", "\\")
    : value.replaceAll("\\", "/");
}

function segmentDepth(value: string): number {
  return portablePath(value).split("/").filter(segment => segment.length > 0).length;
}

function classifyPath(value: string): ClassifiedPath {
  const family = pathFamily(value);
  const normalized = pathImplementation(family).normalize(pathInput(value, family));
  return { family, normalized, segmentDepth: segmentDepth(normalized) };
}

function replaceRoot(
  value: ClassifiedPath,
  root: NormalizationRoot,
): RootReplacement | undefined {
  if (root.path.family !== value.family) return undefined;
  const implementation = pathImplementation(value.family);
  const fromRoot = implementation.relative(root.path.normalized, value.normalized);
  if (fromRoot === "") {
    return {
      order: root.order,
      path: root.token,
      specificity: root.path.segmentDepth,
    };
  }
  if (
    fromRoot !== ".." &&
    !fromRoot.startsWith(`..${implementation.sep}`) &&
    !implementation.isAbsolute(fromRoot)
  ) {
    return {
      order: root.order,
      path: `${root.token}/${portablePath(fromRoot)}`,
      specificity: root.path.segmentDepth,
    };
  }
  return undefined;
}

function normalizePath(value: string, context: NormalizationContext): string {
  const classifiedValue = classifyPath(value);
  const roots: NormalizationRoot[] = [];
  let order = 0;
  if (context.workspaceRoot !== undefined) {
    roots.push({ order, path: classifyPath(context.workspaceRoot), token: "<workspace>" });
    order += 1;
  }
  for (const root of context.temporaryRoots ?? []) {
    roots.push({ order, path: classifyPath(root), token: "<tmp>" });
    order += 1;
  }

  let selected: RootReplacement | undefined;
  for (const root of roots) {
    const replacement = replaceRoot(classifiedValue, root);
    if (
      replacement !== undefined &&
      (
        selected === undefined ||
        replacement.specificity > selected.specificity ||
        (
          replacement.specificity === selected.specificity &&
          replacement.order < selected.order
        )
      )
    ) {
      selected = replacement;
    }
  }
  return selected === undefined ? portablePath(value) : selected.path;
}

function stableJson(value: JsonValue): string {
  return JSON.stringify(value);
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function applyRule(
  value: JsonValue,
  rule: NormalizationRule,
  path: readonly (number | string)[],
  strict: boolean,
  context: NormalizationContext,
): Effect.Effect<JsonValue, NormalizationError> {
  switch (rule.kind) {
    case "duration":
      return typeof value === "number"
        ? Effect.succeed(rule.replacement ?? 0)
        : strict
          ? Effect.fail(mismatch(rule, path, "a number"))
          : Effect.succeed(value);
    case "path":
      return typeof value === "string"
        ? Effect.succeed(normalizePath(value, context))
        : strict
          ? Effect.fail(mismatch(rule, path, "a string"))
          : Effect.succeed(value);
    case "replace":
      return canonicalize(rule.replacement, path, { rules: [] }, context);
    case "run-id":
      return typeof value === "string"
        ? Effect.succeed(rule.replacement ?? "<run-id>")
        : strict
          ? Effect.fail(mismatch(rule, path, "a string"))
          : Effect.succeed(value);
    case "sort-array":
      return Schema.is(JsonArray)(value)
        ? Effect.succeed([...value].sort((left, right) =>
          compareCodeUnits(stableJson(left), stableJson(right))))
        : strict
          ? Effect.fail(mismatch(rule, path, "an array"))
          : Effect.succeed(value);
    case "timestamp":
      return typeof value === "string" || typeof value === "number"
        ? Effect.succeed(rule.replacement ?? "<timestamp>")
        : strict
          ? Effect.fail(mismatch(rule, path, "a string or number"))
          : Effect.succeed(value);
  }
}

function canonicalize(
  value: JsonValue,
  path: readonly (number | string)[],
  normalization: Pick<NormalizationSchema<JsonValue>, "rules" | "strict">,
  context: NormalizationContext,
): Effect.Effect<JsonValue, NormalizationError> {
  return Effect.gen(function* () {
    let normalized: JsonValue = value;
    if (Schema.is(JsonArray)(value)) {
      normalized = yield* Effect.forEach(value, (item, index) =>
        canonicalize(item, [...path, index], normalization, context));
    } else if (Schema.is(JsonObject)(value)) {
      const entries = Object.entries(value).sort(([left], [right]) => compareCodeUnits(left, right));
      const normalizedEntries = yield* Effect.forEach(entries, entry =>
        canonicalize(entry[1], [...path, entry[0]], normalization, context).pipe(
          Effect.map(normalizedItem => ({ key: entry[0], item: normalizedItem })),
        ));
      const normalizedObject = new Map<string, JsonValue>();
      for (const entry of normalizedEntries) normalizedObject.set(entry.key, entry.item);
      normalized = Object.fromEntries(normalizedObject);
    }

    for (const rule of normalization.rules) {
      if (matches(rule.path, path)) {
        normalized = yield* applyRule(
          normalized,
          rule,
          path,
          normalization.strict ?? true,
          context,
        );
      }
    }
    return normalized;
  });
}

/**
 * Builds a decoder-normalizer for one public result schema. Contract-owning
 * tests provide the concrete Scan Result, CLI, or HTTP schema and path rules.
 */
export const createSchemaNormalizer = <A extends JsonValue>(
  normalization: NormalizationSchema<A>,
  context: NormalizationContext = {},
) => flow(
  Schema.decodeUnknownEffect(normalization.input),
  Effect.flatMap(value => canonicalize(value, [], normalization, context)),
);

export const normalizeForComparison = createSchemaNormalizer;

export function stableStringify(
  value: JsonValue,
): Effect.Effect<string, NormalizationError> {
  return canonicalize(value, [], { rules: [] }, {}).pipe(
    Effect.map(normalized => JSON.stringify(normalized, null, 2)),
  );
}
