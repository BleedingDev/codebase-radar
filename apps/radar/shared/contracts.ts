import { Effect, Schema } from '@modern-js/plugin-bff/effect-client';

export class InvalidRepository extends Schema.TaggedErrorClass<InvalidRepository>()(
  'InvalidRepository',
  { message: Schema.String },
) {}

export const parseGithubRepository = Effect.fn('parseGithubRepository')(
  function* (input: string) {
    const trimmed = input.trim();
    let repositoryPath = trimmed;
    if (trimmed.includes('://')) {
      const url = yield* Effect.try({
        try: () => new URL(trimmed),
        catch: () =>
          new InvalidRepository({
            message: 'Enter owner/repository or paste a public GitHub URL.',
          }),
      });
      if (
        url.protocol !== 'https:' ||
        url.hostname !== 'github.com' ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      ) {
        return yield* new InvalidRepository({
          message: 'Only credential-free public GitHub repositories are accepted.',
        });
      }
      repositoryPath = url.pathname;
    }
    const segments = repositoryPath
      .replace(/\.git$/u, '')
      .split('/')
      .filter(Boolean);
    const safe = /^[A-Za-z0-9_.-]+$/u;
    if (
      segments.length !== 2 ||
      !segments[0] ||
      !segments[1] ||
      !safe.test(segments[0]) ||
      !safe.test(segments[1])
    ) {
      return yield* new InvalidRepository({
        message: 'Enter exactly one GitHub repository using owner/repository.',
      });
    }
    return {
      owner: segments[0],
      repository: segments[1],
      url: `https://github.com/${segments[0]}/${segments[1]}`,
    };
  },
);
