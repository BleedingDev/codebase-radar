import { Effect, Schema } from '@modern-js/plugin-bff/effect-client';

export class InvalidRepository extends Schema.TaggedErrorClass<InvalidRepository>()(
  'InvalidRepository',
  { message: Schema.String },
) {}

export const parseGithubRepository = Effect.fn('parseGithubRepository')(
  function* (input: string) {
    const url = yield* Effect.try({
      try: () => new URL(input.trim()),
      catch: () =>
        new InvalidRepository({
          message: 'Enter a full public GitHub repository URL.',
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
        message:
          'Only credential-free https://github.com/owner/repository URLs are accepted.',
      });
    }
    const segments = url.pathname.replace(/\.git$/u, '').split('/').filter(Boolean);
    const safe = /^[A-Za-z0-9_.-]+$/u;
    if (
      segments.length !== 2 ||
      !segments[0] ||
      !segments[1] ||
      !safe.test(segments[0]) ||
      !safe.test(segments[1])
    ) {
      return yield* new InvalidRepository({
        message: 'The URL must identify exactly one GitHub owner and repository.',
      });
    }
    return {
      owner: segments[0],
      repository: segments[1],
      url: `https://github.com/${segments[0]}/${segments[1]}`,
    };
  },
);
