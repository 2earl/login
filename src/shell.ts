import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * The signed-in app shell (DESIGN §4.5): who is signed in and where they are, for the request
 * being rendered. Set once per request by a middleware in app.ts, read by `page()` in pages.ts,
 * so every account, organization and admin page gets the same navigation without each page
 * function passing it along.
 */

export interface Viewer {
  name: string | null;
  email: string | null;
  isOwner: boolean;
}

export interface ShellContext {
  viewer: Viewer;
  path: string;
}

const store = new AsyncLocalStorage<ShellContext>();

export function withShell<T>(context: ShellContext, run: () => Promise<T>): Promise<T> {
  return store.run(context, run);
}

export function shellContext(): ShellContext | undefined {
  return store.getStore();
}

/** Pages under these paths are part of the signed-in app; everything else stays focused. */
export function isShellPath(path: string): boolean {
  return (
    path === '/account' ||
    path.startsWith('/account/') ||
    path.startsWith('/orgs') ||
    path === '/admin' ||
    path.startsWith('/admin/')
  );
}

export type NavKey = 'overview' | 'security' | 'devices' | 'apps' | 'orgs' | 'data' | 'admin';

export const NAV: { key: NavKey; label: string; href: string; ownerOnly?: boolean }[] = [
  { key: 'overview', label: 'Overview', href: '/account' },
  { key: 'security', label: 'Sign-in & security', href: '/account/security' },
  { key: 'devices', label: 'Devices', href: '/account/sessions' },
  { key: 'apps', label: 'Connected apps', href: '/account/apps' },
  { key: 'orgs', label: 'Organizations', href: '/account/orgs' },
  { key: 'data', label: 'Your data', href: '/account/data' },
  { key: 'admin', label: 'Admin', href: '/admin', ownerOnly: true },
];

/** Which navigation entry a path belongs to. */
export function navFor(path: string): NavKey {
  if (path.startsWith('/admin')) return 'admin';
  if (path.startsWith('/orgs') || path.startsWith('/account/orgs')) return 'orgs';
  if (path.startsWith('/account/sessions')) return 'devices';
  if (path.startsWith('/account/apps')) return 'apps';
  if (path.startsWith('/account/data') || path.startsWith('/account/delete')) return 'data';
  if (
    path.startsWith('/account/security') ||
    path.startsWith('/account/methods') ||
    path.startsWith('/account/passkeys')
  ) {
    return 'security';
  }
  return 'overview';
}
