/**
 * Server-rendered HTML. Every dynamic value goes through `escapeHtml`. No scripts.
 * Styles, font, lattice and icon are static assets in /public.
 */

import { ASSET_URLS } from './assets.generated';

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const LEGAL_LINKS =
  '<footer class="legal">' +
  '<a href="https://2earl.com/privacy">Privacy</a>' +
  '<a href="https://2earl.com/terms">Terms</a>' +
  '<a href="https://2earl.com/imprint">Imprint</a>' +
  '</footer>';

/** Google's "G" mark, as required next to "Continue with Google" by its branding guidelines. */
const GOOGLE_G =
  '<svg viewBox="0 0 48 48" aria-hidden="true" focusable="false">' +
  '<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>' +
  '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>' +
  '<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>' +
  '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>' +
  '</svg>';

const ALERT_ICON =
  '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">' +
  '<circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="1.5"/>' +
  '<path d="M8 4.25v4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
  '<circle cx="8" cy="11.25" r="0.9" fill="currentColor"/>' +
  '</svg>';

export function page(title: string, main: string): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="color-scheme" content="light dark">' +
    `<title>${escapeHtml(title)} · 2earl</title>` +
    `<link rel="icon" href="${ASSET_URLS.favicon}" type="image/svg+xml">` +
    `<link rel="preload" href="${ASSET_URLS.font}" as="font" type="font/woff2" crossorigin>` +
    `<link rel="stylesheet" href="${ASSET_URLS.appCss}">` +
    '</head><body><div class="frame">' +
    '<div class="panel"><a class="wordmark" href="/">2earl<small>Account</small></a></div>' +
    `<div class="content"><main class="main">${main}</main>${LEGAL_LINKS}</div>` +
    '</div></body></html>'
  );
}

export function signInPage(): string {
  return page(
    'Sign in',
    '<h1>Sign in to your 2earl account</h1>' +
      '<p class="lede">One account for 2earl services, and one place to decide which apps may act for you.</p>' +
      `<a class="gsi" href="/login">${GOOGLE_G}<span>Continue with Google</span></a>` +
      '<p class="note">Sign-up isn’t open yet. Only invited Google accounts can sign in.</p>' +
      '<p class="fine">By continuing, you agree to the ' +
      '<a href="https://2earl.com/terms">Terms of service</a> and acknowledge the ' +
      '<a href="https://2earl.com/privacy">Privacy policy</a>.</p>',
  );
}

function formatDate(unixSeconds: number): string {
  return new Intl.DateTimeFormat('en-GB', { dateStyle: 'long', timeZone: 'UTC' }).format(
    new Date(unixSeconds * 1000),
  );
}

function initial(name: string | null, email: string | null): string {
  const source = (name ?? email ?? '?').trim();
  const first = Array.from(source)[0] ?? '?';
  return first.toLocaleUpperCase('en');
}

export function accountPage(params: {
  email: string | null;
  name: string | null;
  memberSince: number;
}): string {
  const heading = params.name ?? 'Your account';
  return page(
    'Your account',
    '<header class="identity">' +
      `<div class="badge" aria-hidden="true">${escapeHtml(initial(params.name, params.email))}</div>` +
      `<div><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(params.email ?? '')}</p></div>` +
      '</header>' +
      '<section class="section" aria-labelledby="apps-heading">' +
      '<h2 id="apps-heading">Connected apps</h2>' +
      '<p class="empty">No apps are connected. When you allow an app to act for you, it appears here and you can disconnect it at any time.</p>' +
      '</section>' +
      '<section class="section" aria-labelledby="details-heading">' +
      '<h2 id="details-heading">Account details</h2>' +
      '<dl class="details">' +
      '<dt>Signs in with</dt><dd>Google</dd>' +
      `<dt>Member since</dt><dd>${formatDate(params.memberSince)}</dd>` +
      '</dl>' +
      '</section>' +
      '<div class="actions">' +
      '<form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form>' +
      '</div>',
  );
}

export interface Message {
  title: string;
  body: string;
  action?: { href: string; label: string };
}

export function messagePage(message: Message): string {
  return page(
    message.title,
    `<p class="status">${ALERT_ICON}<span>Sign-in stopped</span></p>` +
      `<h1>${escapeHtml(message.title)}</h1>` +
      `<p class="lede">${escapeHtml(message.body)}</p>` +
      (message.action
        ? `<a class="button primary" href="${escapeHtml(message.action.href)}">${escapeHtml(message.action.label)}</a>`
        : ''),
  );
}

export const MESSAGES = {
  tooManyAttempts: {
    title: 'Too many sign-in attempts',
    body: 'Sign-in is paused for this network for a minute. Wait, then try again.',
    action: { href: '/', label: 'Back to sign-in' },
  },
  signInFailed: {
    title: 'Sign-in didn’t complete',
    body: 'The sign-in link expired, was already used, or was cancelled. Start again to get a new one.',
    action: { href: '/login', label: 'Start again' },
  },
  notInvited: {
    title: 'This Google account can’t sign in yet',
    body: 'Sign-up isn’t open yet. If you were invited, use the Google account the invitation was for.',
    action: { href: '/login', label: 'Use a different Google account' },
  },
} satisfies Record<string, Message>;

export function notFoundPage(): string {
  return page(
    'Page not found',
    '<h1>There’s nothing at this address</h1>' +
      '<p class="lede">Check the link, or go to your account.</p>' +
      '<a class="button primary" href="/account">Go to your account</a>',
  );
}
