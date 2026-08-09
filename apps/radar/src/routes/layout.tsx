import { RegistryProvider } from '@effect/atom-react';
import { Outlet, useMatch } from '@modern-js/plugin-tanstack/runtime';

export default function Layout() {
  const match = useMatch({ from: '__root__' });
  const title = match.loaderData?.title ?? 'Codebase Radar';
  const description =
    match.loaderData?.description ??
    'A short, evidence-backed priority list for your codebase.';

  return (
    <>
      <title>{title}</title>
      <meta name="description" content={description} />
      <RegistryProvider>
        <Outlet />
      </RegistryProvider>
    </>
  );
}
