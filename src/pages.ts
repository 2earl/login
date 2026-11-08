/**
 * Server-rendered HTML. Every dynamic value goes through `escapeHtml`. No scripts.
 * Styles, font and icon are static assets in /public; the mark and panel are inline markup.
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

/** The 2earl mark (the same geometry as public/favicon.svg). */
const MARK =
  '<svg viewBox="0 0 100 100" aria-hidden="true" focusable="false">' +
  '<path fill="#F15A24" d="M0 0 50 50V100L0 50Z"/>' +
  '<path fill="#F7931E" d="M100 0 50 50V100L100 50Z"/>' +
  '<path fill="#ED1C24" d="M0 50 50 100H15A15 15 0 0 1 0 85Z"/>' +
  '<path fill="#FBB03B" d="M100 50V85A15 15 0 0 1 85 100H50Z"/>' +
  '</svg>';

const PANEL =
  '<div class="panel" aria-hidden="true">' +
  '<span class="facet facet-vermilion"></span>' +
  '<span class="facet facet-orange"></span>' +
  '<span class="facet facet-red"></span>' +
  '<span class="facet facet-amber"></span>' +
  '</div>';

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
    PANEL +
    '<div class="content">' +
    `<a class="brand" href="/">${MARK}<span class="brand-name">2earl</span><span class="brand-sub">Account</span></a>` +
    `<main class="main">${main}</main>` +
    LEGAL_LINKS +
    '</div></div></body></html>'
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

export interface ConnectedApp {
  grantId: string;
  name: string;
  /** Host of the app's Client ID Metadata Document URL, when it has one. */
  domain: string | null;
  scopes: string[];
  allowedAt: number;
}

function connectedApps(apps: ConnectedApp[]): string {
  if (apps.length === 0) {
    return '<p class="empty">No apps are connected. When you allow an app to act for you, it appears here and you can disconnect it at any time.</p>';
  }
  return (
    '<ul class="apps">' +
    apps
      .map(
        (app) =>
          '<li class="app">' +
          '<div class="app-main">' +
          `<p class="app-name">${escapeHtml(app.name)}</p>` +
          `<p class="app-meta">${app.domain ? `${escapeHtml(app.domain)} · ` : ''}Allowed ${formatDate(app.allowedAt)}</p>` +
          (app.scopes.length > 0
            ? `<ul class="app-scopes">${app.scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join('')}</ul>`
            : '') +
          '</div>' +
          '<form method="post" action="/account/apps/disconnect">' +
          `<input type="hidden" name="grant" value="${escapeHtml(app.grantId)}">` +
          `<button class="button secondary small" type="submit" aria-label="Disconnect ${escapeHtml(app.name)}">Disconnect</button>` +
          '</form>' +
          '</li>',
      )
      .join('') +
    '</ul>'
  );
}

export function accountPage(params: {
  email: string | null;
  name: string | null;
  memberSince: number;
  apps: ConnectedApp[];
  notice?: string;
}): string {
  const heading = params.name ?? 'Your account';
  return page(
    'Your account',
    (params.notice ? `<p class="notice" role="status">${escapeHtml(params.notice)}</p>` : '') +
      '<header class="identity">' +
      `<div class="badge" aria-hidden="true">${escapeHtml(initial(params.name, params.email))}</div>` +
      `<div><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(params.email ?? '')}</p></div>` +
      '</header>' +
      '<section class="section" aria-labelledby="apps-heading">' +
      '<h2 id="apps-heading">Connected apps</h2>' +
      connectedApps(params.apps) +
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

/** Everything the consent page shows comes from the library's validated description. */
export interface ConsentView {
  handle: string;
  clientName: string;
  /** Verified domain of a CIMD client; absent for a pre-registered or self-registered client. */
  clientDomain: string | null;
  /** Owner-marked as trusted (trusted_clients table). */
  trusted: boolean;
  redirectHost: string;
  redirectIsLoopback: boolean;
  resource: string;
  /** Requested scopes this server can grant, with their labels. */
  scopes: { scope: string; label: string }[];
  /** Requested scopes this server does not grant. */
  unavailable: string[];
}

export function consentPage(view: ConsentView): string {
  const name = escapeHtml(view.clientName);
  const origin = view.clientDomain
    ? `<p class="consent-origin">Published by <strong>${escapeHtml(view.clientDomain)}</strong>${
        view.trusted ? ' <span class="tag">Verified by 2earl</span>' : ''
      }</p>`
    : '<p class="consent-origin">This app named itself. 2earl has not verified who runs it.</p>';
  const loopback = view.redirectIsLoopback
    ? '<p class="warning">Access will be sent to an app on your own computer. Continue only if you just started signing in from that app.</p>'
    : '';
  const scopes =
    view.scopes.length > 0
      ? '<fieldset class="scopes"><legend>It will be able to</legend>' +
        view.scopes
          .map(
            ({ scope, label }) =>
              `<label class="scope"><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked>` +
              `<span>${escapeHtml(label)}</span></label>`,
          )
          .join('') +
        '</fieldset>'
      : '<p class="lede">It is asking only to know that you have a 2earl account.</p>';
  const unavailable =
    view.unavailable.length > 0
      ? `<p class="note">It also asked for permissions 2earl doesn’t grant: ${view.unavailable
          .map((s) => `<code>${escapeHtml(s)}</code>`)
          .join(', ')}. They will not be given.</p>`
      : '';

  return page(
    `Allow ${view.clientName}?`,
    `<h1>Allow <span class="client">${name}</span> to use your 2earl account?</h1>` +
      origin +
      '<dl class="details consent-facts">' +
      `<dt>Sends access to</dt><dd><strong>${escapeHtml(view.redirectHost)}</strong></dd>` +
      `<dt>For</dt><dd>${escapeHtml(view.resource)}</dd>` +
      '</dl>' +
      loopback +
      '<form method="post" action="/authorize" class="consent-form">' +
      `<input type="hidden" name="handle" value="${escapeHtml(view.handle)}">` +
      scopes +
      unavailable +
      '<label class="remember"><input type="checkbox" name="remember" value="on"> Don’t ask again for this app for 30 days</label>' +
      '<div class="consent-actions">' +
      '<button class="button primary" type="submit" name="decision" value="approve">Allow</button>' +
      '<button class="button secondary" type="submit" name="decision" value="deny">Deny</button>' +
      '</div>' +
      '</form>' +
      '<p class="fine">You can disconnect this app at any time in your account.</p>',
  );
}

export interface Message {
  title: string;
  body: string;
  action?: { href: string; label: string };
}

export function messagePage(message: Message, status = 'Sign-in stopped'): string {
  return page(
    message.title,
    `<p class="status">${ALERT_ICON}<span>${escapeHtml(status)}</span></p>` +
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
  authorizeInvalid: {
    title: 'This app’s request isn’t valid',
    body: 'The app sent an authorization request 2earl can’t accept, so nothing was shared. Return to the app and try connecting again; if it keeps happening, the app needs fixing.',
  },
  appUnverifiable: {
    title: 'This app couldn’t be checked',
    body: 'The app’s published details could not be loaded or are invalid, so nothing was shared. Try again later.',
  },
  consentExpired: {
    title: 'This approval page has expired',
    body: 'Approval pages work once, for ten minutes, in the browser that opened them. Return to the app and connect again.',
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
