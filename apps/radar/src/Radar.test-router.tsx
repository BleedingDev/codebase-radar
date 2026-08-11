import React, { useEffect, useState } from 'react';
import type { ComponentType, ReactNode } from 'react';

type RouteParameters = Readonly<Record<string, string>>;

type LinkProps = {
  readonly 'aria-label'?: string;
  readonly children: ReactNode;
  readonly className?: string;
  readonly params?: RouteParameters;
  readonly state?: (value: object) => object;
  readonly to: string;
};

type NavigateProps = {
  readonly params?: RouteParameters;
  readonly replace?: boolean;
  readonly to: string;
};

type RouterCall = {
  readonly operation: 'back' | 'replace';
  readonly to?: string;
};

type RouterLocation = {
  readonly href: string;
  readonly state: object;
};

type RouterSnapshot = {
  readonly location: RouterLocation;
};

type MatchOptions = {
  readonly from?: string;
};

type Match = {
  readonly loaderData?: {
    readonly description?: string;
    readonly title?: string;
  };
  readonly params: RouteParameters;
};

type RouterStateOptions<A> = {
  readonly select: (state: RouterSnapshot) => A;
};

const routerCalls: RouterCall[] = [];
const subscribers = new Set<() => void>();
let matchParameters: RouteParameters = {};
let location: RouterLocation = { href: '/', state: {} };
let outlet: ComponentType | undefined;

const notifyRouter = () => {
  subscribers.forEach(subscriber => subscriber());
};

const useRouterUpdates = () => {
  const [, setVersion] = useState(0);

  useEffect(() => {
    const subscriber = () => {
      setVersion(version => version + 1);
    };
    subscribers.add(subscriber);
    return () => {
      subscribers.delete(subscriber);
    };
  }, []);
};

const hrefFor = (to: string, parameters: RouteParameters = {}) =>
  to.replace(
    /\$([A-Za-z]+)/g,
    (_whole, key: string) => parameters[key] ?? `$${key}`,
  );

export const resetRadarRouter = () => {
  routerCalls.splice(0, routerCalls.length);
  matchParameters = {};
  location = { href: '/', state: {} };
  outlet = undefined;
  notifyRouter();
};

export const setRadarMatch = (parameters: RouteParameters) => {
  matchParameters = parameters;
};

export const setRadarRouterState = (state: object) => {
  location = { ...location, state };
  notifyRouter();
};

export const setRadarRoute = (href: string, state: object = {}) => {
  location = { href, state };
  notifyRouter();
};

export const setRadarOutlet = (content: ComponentType) => {
  outlet = content;
  notifyRouter();
};

export const radarRouteHref = () => location.href;

export const radarRouterCalls = () => [...routerCalls];

export function Link({
  'aria-label': ariaLabel,
  children,
  className,
  params,
  to,
}: LinkProps) {
  return (
    <a aria-label={ariaLabel} className={className} href={hrefFor(to, params)}>
      {children}
    </a>
  );
}

export function Navigate({ params, to }: NavigateProps) {
  return <output data-route={hrefFor(to, params)} />;
}

export const useMatch = (_options?: MatchOptions): Match => ({
  params: matchParameters,
});

export const useRouter = () => ({
  history: {
    back: () => {
      routerCalls.push({ operation: 'back' });
      setRadarRoute('/');
    },
    replace: (to: string) => {
      routerCalls.push({ operation: 'replace', to });
      setRadarRoute(to);
    },
  },
});

export function useRouterState<A>(options: RouterStateOptions<A>): A;
export function useRouterState(): RouterSnapshot;
export function useRouterState<A>(options?: RouterStateOptions<A>) {
  useRouterUpdates();
  const snapshot: RouterSnapshot = { location };
  return options ? options.select(snapshot) : snapshot;
}

export function Outlet() {
  useRouterUpdates();
  const Route = outlet;
  return Route ? <Route /> : null;
}
