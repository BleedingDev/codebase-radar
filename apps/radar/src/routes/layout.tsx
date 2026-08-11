import { RegistryProvider } from '@effect/atom-react';
import { Outlet, useMatch, useRouterState } from '@modern-js/plugin-tanstack/runtime';
import React, { useEffect, useRef } from 'react';
import { consumeRouteFocus } from '../route-focus';

const routeShellId = 'radar-route-shell';

export default function Layout() {
  const match = useMatch({ from: '__root__' });
  const locationHref = useRouterState({ select: state => state.location.href });
  const routeShell = useRef<HTMLDivElement>(null);
  const title = match.loaderData?.title ?? 'Codebase Radar';
  const description =
    match.loaderData?.description ??
    'A short, evidence-backed priority list for your codebase.';

  useEffect(() => {
    if (!consumeRouteFocus()) return;

    const frame = window.requestAnimationFrame(() => {
      routeShell.current?.focus();
    });

    return () => {
      window.cancelAnimationFrame(frame);
    };
  }, [locationHref]);

  return (
    <>
      <title>{title}</title>
      <meta name="description" content={description} />
      <RegistryProvider>
        <div id={routeShellId} ref={routeShell} tabIndex={-1}>
          <Outlet />
        </div>
      </RegistryProvider>
    </>
  );
}
