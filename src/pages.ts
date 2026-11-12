/**
 * Server-rendered HTML. Every dynamic value goes through `escapeHtml`. No inline scripts; the
 * second-factor pages load /passkey.js (with MFA_CSP).
 * Styles, font and icon are static assets in /public; the mark is inline markup.
 */

import { ASSET_URLS } from './assets.generated';
import type { SignupMode } from './settings';
import { PROVIDER_NAMES, providerName, type FederatedProvider } from './providers';
import type { DeviceSession } from './sessions';
import type { Identity } from './users';

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

export function page(
  title: string,
  main: string,
  options: {
    passkeyScript?: boolean;
    /** Wider content column (admin tables). */
    wide?: boolean;
    /** Label next to the logo. */
    section?: string;
  } = {},
): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="color-scheme" content="light dark">' +
    `<title>${escapeHtml(title)} · 2earl</title>` +
    `<link rel="icon" href="${ASSET_URLS.favicon}" type="image/svg+xml">` +
    `<link rel="preload" href="${ASSET_URLS.font}" as="font" type="font/woff2" crossorigin>` +
    `<link rel="stylesheet" href="${ASSET_URLS.appCss}">` +
    (options.passkeyScript ? `<script type="module" src="${ASSET_URLS.passkeyJs}"></script>` : '') +
    `</head><body><div class="page${options.wide ? ' page-wide' : ''}">` +
    `<header class="site"><a class="brand" href="/">${MARK}<span class="brand-name">2earl</span><span class="brand-sub">${escapeHtml(options.section ?? 'Account')}</span></a></header>` +
    `<main class="main${options.wide ? ' main-wide' : ''}">${main}</main>` +
    LEGAL_LINKS +
    '</div></body></html>'
  );
}

/** Hidden return_to, so each way of signing in comes back to where the user was going. */
function returnField(returnTo: string | null): string {
  return returnTo ? `<input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">` : '';
}

function withReturn(path: string, returnTo: string | null, extra = ''): string {
  const query = [returnTo ? `return_to=${encodeURIComponent(returnTo)}` : '', extra]
    .filter(Boolean)
    .join('&');
  return query ? `${path}?${query}` : path;
}

/**
 * Sign in or sign up (DESIGN §4.9): with Google, or with a code sent by email. `reauth` asks a
 * signed-in user to prove it's them again, with the methods their account has.
 */
export function signInPage(
  params: {
    returnTo?: string | null;
    mode?: SignupMode;
    reauth?: {
      google: boolean;
      email: string | null;
      passkey?: boolean;
      providers?: FederatedProvider[];
    } | null;
    error?: string;
    email?: string;
    /** Microsoft, GitHub, Apple: the ones switched on (DESIGN §4.14). */
    providers?: FederatedProvider[];
  } = {},
): string {
  const returnTo = params.returnTo ?? null;
  const reauth = params.reauth ?? null;
  const google = !reauth || reauth.google;
  const providers = params.reauth ? (params.reauth.providers ?? []) : (params.providers ?? []);
  const fixedEmail = reauth?.email ?? null;
  const showEmail = !reauth || fixedEmail !== null;
  const emailForm = showEmail
    ? '<form method="post" action="/login/email" class="email-form" novalidate>' +
      returnField(returnTo) +
      (reauth ? '<input type="hidden" name="reauth" value="1">' : '') +
      (fixedEmail
        ? `<input type="hidden" name="email" value="${escapeHtml(fixedEmail)}">` +
          `<p class="section-text">We’ll send a code to <strong>${escapeHtml(fixedEmail)}</strong>.</p>`
        : '<label class="field"><span>Email address</span>' +
          `<input name="email" type="email" autocomplete="email webauthn" inputmode="email" required maxlength="254" value="${escapeHtml(params.email ?? '')}"${params.error ? ' aria-invalid="true" aria-describedby="email-error"' : ''}></label>` +
          (params.error
            ? `<p class="field-error" id="email-error">${escapeHtml(params.error)}</p>`
            : '')) +
      `<button class="button ${google || providers.length > 0 ? 'secondary' : 'primary'} wide" type="submit">${fixedEmail ? 'Send me a code' : 'Continue with email'}</button>` +
      '</form>'
    : '';
  const googleButton =
    (google
      ? `<a class="gsi" href="${escapeHtml(withReturn('/login/google', returnTo, reauth ? 'reauth=1' : ''))}">${GOOGLE_G}<span>Continue with Google</span></a>`
      : '') +
    providers
      .map(
        (p) =>
          `<a class="gsi provider-button" href="${escapeHtml(withReturn(`/login/${p}`, returnTo, reauth ? 'reauth=1' : ''))}">Continue with ${PROVIDER_NAMES[p]}</a>`,
      )
      .join('');
  // A passkey signs in with one step (DESIGN §4.10). Without JavaScript the button stays hidden.
  const passkey = !reauth || reauth.passkey === true;
  const passkeyButton = passkey
    ? `<button class="button secondary wide passkey-button" type="button" hidden data-passkey="sign-in" data-status="passkey-status" data-return-to="${escapeHtml(returnTo ?? '')}"${reauth ? ' data-reauth="1"' : ''}>Sign in with a passkey</button>` +
      '<p class="passkey-status" id="passkey-status" role="status" aria-live="polite"></p>'
    : '';
  const invite = params.mode === 'invite';
  return page(
    reauth ? 'Confirm it’s you' : 'Sign in',
    (reauth
      ? '<h1>Confirm it’s you</h1>' +
        '<p class="lede">Sign in again to continue. It keeps someone who finds your browser signed in from changing your account.</p>'
      : '<h1>Sign in or create your account</h1>' +
        '<p class="lede">One 2earl account for every 2earl service, and one place to decide which apps may act for you.</p>') +
      googleButton +
      (googleButton && emailForm ? '<p class="or" role="separator"><span>or</span></p>' : '') +
      emailForm +
      passkeyButton +
      (reauth
        ? ''
        : invite
          ? '<p class="note">Sign-up is by invitation for now. Use the Google account or the address you were invited with.</p>'
          : '<p class="note">New here? The same buttons create your account. With email, there’s no password: we send you a code each time.</p>') +
      (reauth
        ? ''
        : '<p class="fine">By continuing, you agree to the ' +
          '<a href="https://2earl.com/terms">Terms of service</a> and acknowledge the ' +
          '<a href="https://2earl.com/privacy">Privacy policy</a>.</p>'),
    { passkeyScript: passkey },
  );
}

/** "Check your email": the code field, and what to do if it doesn't arrive. */
export function emailCodePage(params: {
  email: string;
  purpose: 'sign_in' | 'delete_account' | 'link_email';
  error?: string;
  resent?: boolean;
}): string {
  const title =
    params.purpose === 'delete_account'
      ? 'Confirm deleting your account'
      : params.purpose === 'link_email'
        ? 'Confirm your address'
        : 'Check your email';
  const button =
    params.purpose === 'delete_account'
      ? '<button class="button danger wide" type="submit">Delete my account</button>'
      : `<button class="button primary wide" type="submit">${params.purpose === 'link_email' ? 'Add this address' : 'Continue'}</button>`;
  return page(
    title,
    `<h1>${escapeHtml(title)}</h1>` +
      `<p class="lede">We sent a 6-digit code to <strong>${escapeHtml(params.email)}</strong>. It works for 10 minutes.</p>` +
      (params.resent
        ? '<p class="notice" role="status">We sent a new code. Earlier ones no longer work.</p>'
        : '') +
      '<form method="post" action="/login/email/code" class="code-form">' +
      '<label class="field"><span>Code</span>' +
      `<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus${params.error ? ' aria-invalid="true" aria-describedby="code-error"' : ''}></label>` +
      (params.error
        ? `<p class="field-error" id="code-error">${escapeHtml(params.error)}</p>`
        : '') +
      button +
      '</form>' +
      '<details class="manual"><summary>Didn’t get it?</summary>' +
      '<p class="note">Check your spam folder, and that the address is right. Codes can take a minute.</p>' +
      '<form method="post" action="/login/email/resend"><button class="button secondary small" type="submit">Send a new code</button></form>' +
      (params.purpose === 'sign_in'
        ? '<p class="note"><a href="/login">Use a different address, or Google</a></p>'
        : '') +
      '</details>',
  );
}

/** The link from the email opens this; the button does the sign-in (scanners only open links). */
export function emailLinkPage(token: string, purpose: string): string {
  const label =
    purpose === 'delete_account'
      ? 'Delete my account'
      : purpose === 'link_email'
        ? 'Add this address'
        : 'Continue to 2earl';
  return page(
    'Continue',
    '<h1>One more step</h1>' +
      '<p class="lede">Continue in this browser.</p>' +
      '<form method="post" action="/login/email/link">' +
      `<input type="hidden" name="token" value="${escapeHtml(token)}">` +
      `<button class="button ${purpose === 'delete_account' ? 'danger' : 'primary'} wide" type="submit">${escapeHtml(label)}</button>` +
      '</form>',
  );
}

/** First stop after a new account is created: a name, and a nudge towards a passkey. */
export function welcomePage(params: { email: string | null; returnTo: string | null }): string {
  return page(
    'Welcome',
    '<h1>Your account is ready</h1>' +
      `<p class="lede">You signed up as <strong>${escapeHtml(params.email ?? '')}</strong>.</p>` +
      '<form method="post" action="/welcome" class="code-form">' +
      returnField(params.returnTo) +
      '<label class="field"><span>Your name <span class="optional">optional, shown on your account and to people you share with</span></span>' +
      '<input name="name" type="text" autocomplete="name" maxlength="80"></label>' +
      '<button class="button primary wide" type="submit">Continue</button>' +
      '</form>' +
      '<section class="section" aria-labelledby="protect-heading">' +
      '<h2 id="protect-heading">Protect your account</h2>' +
      '<p class="section-text">Add a passkey or an authenticator app as a second factor. Then nobody can use your account with your email alone.</p>' +
      '<a class="button secondary" href="/account/security">Add a second factor</a>' +
      '</section>',
  );
}

/** Changing the name shown on the account. */
export function namePage(name: string | null): string {
  return page(
    'Your name',
    '<p class="crumb"><a href="/account">Your account</a></p>' +
      '<h1>Your name</h1>' +
      '<form method="post" action="/account/name" class="code-form">' +
      '<label class="field"><span>Name <span class="optional">leave empty to show only your address</span></span>' +
      `<input name="name" type="text" autocomplete="name" maxlength="80" value="${escapeHtml(name ?? '')}"></label>` +
      '<div class="consent-actions"><button class="button primary" type="submit">Save</button>' +
      '<a class="button secondary" href="/account">Cancel</a></div>' +
      '</form>',
  );
}

/** Adding an address as a way to sign in. */
export function addEmailPage(params: { error?: string; email?: string }): string {
  return page(
    'Add an email address',
    '<p class="crumb"><a href="/account">Your account</a></p>' +
      '<h1>Sign in with an email address</h1>' +
      '<p class="lede">We send a code to the address to check it’s yours. After that, you can sign in with a code sent there.</p>' +
      '<form method="post" action="/account/methods/email" class="email-form" novalidate>' +
      '<label class="field"><span>Email address</span>' +
      `<input name="email" type="email" autocomplete="email" required maxlength="254" value="${escapeHtml(params.email ?? '')}"${params.error ? ' aria-invalid="true" aria-describedby="email-error"' : ''}></label>` +
      (params.error
        ? `<p class="field-error" id="email-error">${escapeHtml(params.error)}</p>`
        : '') +
      '<div class="consent-actions"><button class="button primary" type="submit">Send a code</button>' +
      '<a class="button secondary" href="/account">Cancel</a></div>' +
      '</form>',
  );
}

function methodsList(methods: Identity[]): string {
  const removable = methods.length > 1;
  return (
    '<ul class="methods">' +
    methods
      .map(
        (m) =>
          '<li>' +
          `<span class="method-name">${m.provider === 'email' ? 'Email code' : PROVIDER_NAMES[m.provider]}</span>` +
          `<span class="method-what">${escapeHtml(m.email ?? '')}</span>` +
          (removable && !m.isOwner
            ? '<form method="post" action="/account/methods/remove">' +
              `<input type="hidden" name="identity" value="${escapeHtml(m.id)}">` +
              '<button class="link-button danger" type="submit">Remove</button></form>'
            : '') +
          '</li>',
      )
      .join('') +
    '</ul>'
  );
}

export function formatDate(unixSeconds: number): string {
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
  factors: { kind: 'webauthn' | 'totp' }[];
  notice?: string;
  /** The owner sees a link to /admin. */
  isOwner?: boolean;
  methods?: Identity[];
  /** Microsoft, GitHub, Apple: the ones switched on, for "Add …" buttons. */
  providers?: FederatedProvider[];
}): string {
  const heading = params.name ?? 'Your account';
  const methods = params.methods ?? [];
  const hasGoogle = methods.some((m) => m.provider === 'google');
  return page(
    'Your account',
    (params.notice ? `<p class="notice" role="status">${escapeHtml(params.notice)}</p>` : '') +
      '<header class="identity">' +
      `<div class="badge" aria-hidden="true">${escapeHtml(initial(params.name, params.email))}</div>` +
      `<div><h1>${escapeHtml(heading)}</h1><p>${escapeHtml(params.email ?? '')}</p></div>` +
      '</header>' +
      '<section class="section" aria-labelledby="services-heading">' +
      '<h2 id="services-heading">Use your account with</h2>' +
      '<ul class="services">' +
      '<li><a href="https://promptshare.cc"><span class="service-name">Prompt share</span><span class="service-what">Prompts and shared sessions for your assistants</span></a></li>' +
      '<li><a href="https://promptshare.cc/connect"><span class="service-name">Claude and other assistants</span><span class="service-what">Add a 2earl connector, then allow it here</span></a></li>' +
      (params.isOwner
        ? '<li><a href="/admin"><span class="service-name">Admin</span><span class="service-what">Users, invitations, apps and the security log</span></a></li>'
        : '') +
      '</ul>' +
      '</section>' +
      '<section class="section" aria-labelledby="apps-heading">' +
      '<h2 id="apps-heading">Connected apps</h2>' +
      connectedApps(params.apps) +
      '</section>' +
      '<section class="section" aria-labelledby="methods-heading">' +
      '<h2 id="methods-heading">How you sign in</h2>' +
      methodsList(methods) +
      (params.factors.some((f) => f.kind === 'webauthn')
        ? '<p class="section-text">Your passkeys also sign you in on their own, in one step. <a href="/account/security">Manage passkeys</a></p>'
        : '') +
      '<div class="data-actions">' +
      (hasGoogle
        ? ''
        : '<form method="post" action="/account/methods/google"><button class="button secondary" type="submit">Add Google</button></form>') +
      (params.providers ?? [])
        .filter((p) => !methods.some((m) => m.provider === p))
        .map(
          (p) =>
            `<form method="post" action="/account/methods/${p}"><button class="button secondary" type="submit">Add ${PROVIDER_NAMES[p]}</button></form>`,
        )
        .join('') +
      '<a class="button secondary" href="/account/methods/email">Add an email address</a>' +
      '</div>' +
      '</section>' +
      '<section class="section" aria-labelledby="security-heading">' +
      '<h2 id="security-heading">Security</h2>' +
      `<p class="section-text">${escapeHtml(factorSummary(params.factors))}</p>` +
      '<div class="data-actions">' +
      '<a class="button secondary" href="/account/security">Manage second factor</a>' +
      '<a class="button secondary" href="/account/sessions">Signed-in devices</a>' +
      '</div>' +
      '</section>' +
      '<section class="section" aria-labelledby="details-heading">' +
      '<h2 id="details-heading">Account details</h2>' +
      '<dl class="details">' +
      `<dt>Name</dt><dd>${escapeHtml(params.name ?? 'Not set')} · <a href="/account/name">Change</a></dd>` +
      `<dt>Member since</dt><dd>${formatDate(params.memberSince)}</dd>` +
      '</dl>' +
      '</section>' +
      '<section class="section" aria-labelledby="data-heading">' +
      '<h2 id="data-heading">Your data</h2>' +
      '<p class="section-text">Download a copy of everything your account holds, as a JSON file.</p>' +
      '<div class="data-actions">' +
      '<a class="button secondary" href="/account/export" download>Download your data</a>' +
      '<a class="danger-link" href="/account/delete">Delete account</a>' +
      '</div>' +
      '</section>' +
      '<div class="actions">' +
      '<form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form>' +
      '</div>',
  );
}

const METHOD_LABEL: Record<string, string> = {
  google: 'Google',
  email: 'an email code',
  passkey: 'a passkey',
  microsoft: 'Microsoft',
  github: 'GitHub',
  apple: 'Apple',
};

/** "5 minutes ago", "3 days ago": for when a device was last used. */
export function ago(now: number, then: number): string {
  const seconds = Math.max(0, now - then);
  if (seconds < 120) return 'Active now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `Active ${String(minutes)} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `Active ${String(hours)} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.floor(hours / 24);
  return `Active ${String(days)} day${days === 1 ? '' : 's'} ago`;
}

/** Signed-in devices (DESIGN §7): what each is, when it was used, and a way to sign it out. */
export function sessionsPage(params: {
  sessions: DeviceSession[];
  now: number;
  notice?: string | null;
}): string {
  const others = params.sessions.filter((s) => !s.current);
  const items = params.sessions
    .map(
      (s) =>
        '<li class="app">' +
        '<div class="app-main">' +
        `<p class="app-name">${escapeHtml(s.device ?? 'Unknown device')}${s.current ? ' <span class="tag">This device</span>' : ''}</p>` +
        `<p class="app-meta">${escapeHtml(ago(params.now, s.lastSeenAt))} · Signed in ${formatDate(s.createdAt)}${s.method ? ` with ${escapeHtml(METHOD_LABEL[s.method] ?? s.method)}` : ''}</p>` +
        '</div>' +
        (s.current
          ? ''
          : '<form method="post" action="/account/sessions/end">' +
            `<input type="hidden" name="session" value="${escapeHtml(s.ref)}">` +
            '<button class="button secondary" type="submit">Sign out</button></form>') +
        '</li>',
    )
    .join('');
  return page(
    'Signed-in devices',
    '<p class="crumb"><a href="/account">Your account</a></p>' +
      '<h1>Signed-in devices</h1>' +
      '<p class="lede">Every browser where your 2earl account is signed in. If you don’t recognise one, sign it out, then check how you sign in and add a second factor.</p>' +
      (params.notice ? `<p class="notice" role="status">${escapeHtml(params.notice)}</p>` : '') +
      `<ul class="apps">${items}</ul>` +
      (others.length > 0
        ? '<form method="post" action="/account/sessions/end-others" class="actions">' +
          '<button class="button danger" type="submit">Sign out all other devices</button></form>'
        : '<p class="note">This is the only device signed in.</p>') +
      '<p class="note">Apps you connected keep their access until you disconnect them on your account page. Signing out a device doesn’t disconnect apps.</p>',
  );
}

/** Device sign-in (DESIGN §4.13): the person enters the code their device shows. */
export function devicePage(params: { userCode: string; error?: string }): string {
  return page(
    'Sign in on a device',
    '<h1>Sign in on a device</h1>' +
      '<p class="lede">Enter the code your device shows, for example the 2earl command-line tool in your terminal.</p>' +
      '<form method="post" action="/device" class="stack-form">' +
      '<label class="field"><span>Code</span>' +
      `<input name="user_code" type="text" required maxlength="20" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="BCDF-GHJK" value="${escapeHtml(params.userCode)}"${params.error ? ' aria-invalid="true" aria-describedby="device-error"' : ''}></label>` +
      (params.error
        ? `<p class="field-error" id="device-error">${escapeHtml(params.error)}</p>`
        : '') +
      '<button class="button primary" type="submit">Continue</button></form>' +
      '<p class="warning">Only continue if you started this yourself, on a device in front of you. 2earl never asks you for this code by email, chat or phone.</p>',
  );
}

export function deviceDonePage(result: 'approved' | 'denied' | 'expired'): string {
  const texts: Record<typeof result, [string, string]> = {
    approved: [
      'Your device is signed in',
      'Go back to your device: it continues on its own in a few seconds. You can close this page.',
    ],
    denied: ['Nothing was approved', 'Your device stays signed out. You can close this page.'],
    expired: ['This request has expired', 'Start again on your device to get a new code.'],
  };
  const text = texts[result];
  return page(
    text[0],
    `<h1>${text[0]}</h1><p class="lede">${text[1]}</p>` +
      '<a class="button secondary" href="/account">Go to your account</a>',
  );
}

/** RP-Initiated Logout: an app asks to sign the person out of 2earl too (DESIGN §4.11). */
export function signOutPage(params: { appName: string | null; query: string }): string {
  return page(
    'Sign out',
    '<h1>Sign out of 2earl?</h1>' +
      `<p class="lede">${params.appName ? `${escapeHtml(params.appName)} signed you out and asks` : 'An app asks'} to sign you out of your 2earl account in this browser too.</p>` +
      '<form method="post" action="/oidc/logout" class="consent-actions">' +
      `<input type="hidden" name="query" value="${escapeHtml(params.query)}">` +
      '<button class="button primary" type="submit" name="decision" value="sign_out">Sign out</button>' +
      '<button class="button secondary" type="submit" name="decision" value="stay">Stay signed in</button>' +
      '</form>',
  );
}

export function signedOutPage(): string {
  return page(
    'Signed out',
    '<h1>You’re signed out</h1>' +
      '<p class="lede">Your 2earl account is signed out in this browser.</p>' +
      '<a class="button primary" href="/">Sign in again</a>',
  );
}

/** Everything the consent page shows comes from the library's validated description. */
export interface ConsentView {
  handle: string;
  /** The scopes offered on this page, signed and bound to the handle (app.ts offeredScopesMac). */
  offeredMac: string;
  /** OpenID Connect `nonce`, carried to the approval and bound to the handle (app.ts nonceMac). */
  nonce?: { value: string; mac: string } | null;
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
              // Signing in is what an OpenID Connect app is for: `openid` can't be unticked.
              (scope === 'openid'
                ? `<label class="scope"><input type="checkbox" checked disabled><input type="hidden" name="scope" value="openid">`
                : `<label class="scope"><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked>`) +
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
      `<input type="hidden" name="offered" value="${escapeHtml(view.scopes.map((s) => s.scope).join(' '))}">` +
      `<input type="hidden" name="offered_mac" value="${escapeHtml(view.offeredMac)}">` +
      (view.nonce
        ? `<input type="hidden" name="nonce" value="${escapeHtml(view.nonce.value)}">` +
          `<input type="hidden" name="nonce_mac" value="${escapeHtml(view.nonce.mac)}">`
        : '') +
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

export function deleteAccountPage(params: {
  email: string | null;
  appCount: number;
  invited: boolean;
  /** How the user can confirm: the account's methods. Defaults to Google. */
  confirmWith?: { google: boolean; email: string | null; providers?: FederatedProvider[] };
}): string {
  const confirmWith = params.confirmWith ?? { google: true, email: null };
  const providers = confirmWith.providers ?? [];
  const firstWay = confirmWith.google
    ? 'with Google'
    : providers[0]
      ? `with ${PROVIDER_NAMES[providers[0]]}`
      : 'with a code we email you';
  const apps =
    params.appCount === 0
      ? 'Connected apps: none right now'
      : `Access for your ${params.appCount === 1 ? 'connected app' : `${String(params.appCount)} connected apps`}`;
  return page(
    'Delete your account',
    '<h1>Delete your 2earl account</h1>' +
      `<p class="lede">Your account is deleted as soon as you confirm ${firstWay}. It can’t be restored.</p>` +
      '<div class="ledger">' +
      '<section aria-labelledby="deleted-heading">' +
      '<h2 id="deleted-heading">Deleted now</h2>' +
      '<ul>' +
      `<li>Your name and email address${params.email ? ` (${escapeHtml(params.email)})` : ''}, and how you sign in</li>` +
      `<li>${escapeHtml(apps)}</li>` +
      '<li>Every signed-in browser, including this one</li>' +
      (params.invited
        ? '<li>Your invitation. While sign-up is closed, signing in again needs a new one</li>'
        : '') +
      '</ul>' +
      '</section>' +
      '<section aria-labelledby="kept-heading">' +
      '<h2 id="kept-heading">Kept for a limited time</h2>' +
      '<ul>' +
      '<li>Security log entries, for up to 90 days, no longer linked to your name or email</li>' +
      '<li>Database backups, for up to 30 days, used only to recover from failures</li>' +
      '</ul>' +
      '</section>' +
      '</div>' +
      '<p class="note">Want a copy first? <a href="/account/export" download>Download your data</a>.</p>' +
      '<form method="post" action="/account/delete" class="delete-form">' +
      '<label class="confirm"><input type="checkbox" name="confirm" value="on" required>' +
      '<span>I understand my account and connected apps can’t be restored.</span></label>' +
      '<div class="consent-actions">' +
      (confirmWith.google
        ? '<button class="button danger" type="submit" name="method" value="google">Confirm with Google</button>'
        : '') +
      providers
        .map(
          (p, index) =>
            `<button class="button ${confirmWith.google || index > 0 ? 'secondary' : 'danger'}" type="submit" name="method" value="${p}">Confirm with ${PROVIDER_NAMES[p]}</button>`,
        )
        .join('') +
      (confirmWith.email
        ? `<button class="button ${confirmWith.google || providers.length > 0 ? 'secondary' : 'danger'}" type="submit" name="method" value="email">Confirm with an email code</button>`
        : '') +
      '<a class="button secondary" href="/account">Keep account</a>' +
      '</div>' +
      '</form>' +
      '<p class="fine">Google will ask you to choose your account. Choose the one you sign in to 2earl with.</p>',
  );
}

export function accountDeletedPage(): string {
  return page(
    'Account deleted',
    '<h1>Your account is deleted</h1>' +
      '<p class="lede">Your 2earl account, its link to Google and its sessions are gone, and connected apps no longer have access.</p>' +
      '<p class="note">Google still lists 2earl among the apps you signed in to. You can remove it in your Google Account under Security → Your connections to third-party apps &amp; services.</p>' +
      '<a class="button secondary" href="https://2earl.com">Go to 2earl.com</a>',
  );
}

// ---- Second factor (DESIGN §4.7) ---------------------------------------------------------------

function factorSummary(factors: { kind: 'webauthn' | 'totp' }[]): string {
  if (factors.length === 0) {
    return 'Second factor: off. Adding a passkey protects your account even if someone gets into your Google account or your inbox.';
  }
  const passkeys = factors.filter((f) => f.kind === 'webauthn').length;
  const parts = [];
  if (passkeys > 0) parts.push(passkeys === 1 ? '1 passkey' : `${String(passkeys)} passkeys`);
  if (factors.some((f) => f.kind === 'totp')) parts.push('an authenticator app');
  return `Second factor: on, with ${parts.join(' and ')}.`;
}

export interface FactorView {
  id: string;
  kind: 'webauthn' | 'totp';
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
}

function factorRow(factor: FactorView): string {
  const used = factor.lastUsedAt ? ` · Last used ${formatDate(factor.lastUsedAt)}` : '';
  // Under its own heading, the authenticator app needs no name of its own.
  const name = factor.kind === 'totp' ? 'Turned on' : factor.label;
  return (
    '<li class="app">' +
    '<div class="app-main">' +
    `<p class="app-name">${escapeHtml(name)}</p>` +
    `<p class="app-meta">Added ${formatDate(factor.createdAt)}${used}</p>` +
    '</div>' +
    '<form method="post" action="/account/security/factors/remove">' +
    `<input type="hidden" name="factor" value="${escapeHtml(factor.id)}">` +
    `<button class="button secondary small" type="submit" aria-label="Remove ${escapeHtml(factor.label)}">Remove</button>` +
    '</form>' +
    '</li>'
  );
}

export function securityPage(params: {
  factors: FactorView[];
  recoveryRemaining: number;
  mfaRequired: boolean;
  /** The account can't be used until a factor is added (MFA_REQUIRED). */
  mustEnrol: boolean;
  /** Where to continue after the first factor is set up. */
  next: string;
  notice?: string;
  error?: string;
}): string {
  const next = escapeHtml(params.next);
  const passkeys = params.factors.filter((f) => f.kind === 'webauthn');
  const totp = params.factors.find((f) => f.kind === 'totp');
  const hasFactor = params.factors.length > 0;
  const lastFactorLocked = params.mfaRequired && params.factors.length === 1;

  const passkeyList =
    passkeys.length > 0
      ? `<ul class="apps">${passkeys.map(factorRow).join('')}</ul>`
      : '<p class="empty">No passkeys yet.</p>';

  return page(
    'Security',
    (params.mustEnrol
      ? '<p class="warning" role="status">2earl requires a second factor. Add one to continue to your account.</p>'
      : '') +
      (params.notice ? `<p class="notice" role="status">${escapeHtml(params.notice)}</p>` : '') +
      (params.error ? `<p class="warning" role="alert">${escapeHtml(params.error)}</p>` : '') +
      (params.mustEnrol ? '' : '<p class="crumb"><a href="/account">Your account</a></p>') +
      '<h1>Second factor</h1>' +
      '<p class="lede">After signing in with Google, you confirm it’s you with something only you have. ' +
      'Someone who gets into your Google account still can’t get into 2earl.</p>' +
      '<section class="section" aria-labelledby="passkeys-heading">' +
      '<h2 id="passkeys-heading">Passkeys <span class="tag">Recommended</span></h2>' +
      '<p class="section-text">Your fingerprint, face, screen lock or a security key. Passkeys only work on login.2earl.com, so they can’t be phished. A passkey also signs you in on its own, in one step.</p>' +
      passkeyList +
      '<div class="add-passkey">' +
      '<label class="field"><span>Name (optional)</span>' +
      '<input id="passkey-label" type="text" maxlength="60" autocomplete="off" placeholder="e.g. MacBook, YubiKey"></label>' +
      `<button class="button primary" type="button" data-passkey="register" data-status="passkey-status" data-label="passkey-label" data-next="${next}" hidden>Add a passkey</button>` +
      '<noscript><p class="note">Adding a passkey needs JavaScript.</p></noscript>' +
      '<p class="field-status" id="passkey-status" role="alert"></p>' +
      '</div>' +
      '</section>' +
      '<section class="section" aria-labelledby="totp-heading">' +
      '<h2 id="totp-heading">Authenticator app</h2>' +
      (totp
        ? `<ul class="apps">${factorRow(totp)}</ul>`
        : '<p class="section-text">Six-digit codes from an app such as Google Authenticator, Microsoft Authenticator, 1Password or Aegis.</p>' +
          `<a class="button secondary" href="/account/security/totp?return_to=${encodeURIComponent(params.next)}">Set up an authenticator app</a>`) +
      '</section>' +
      '<section class="section" aria-labelledby="recovery-heading">' +
      '<h2 id="recovery-heading">Recovery codes</h2>' +
      (hasFactor
        ? `<p class="section-text">${String(params.recoveryRemaining)} of 10 unused. Use one if you can’t use your passkey or app. Creating new codes replaces the old ones.</p>` +
          '<form method="post" action="/account/security/recovery-codes">' +
          '<button class="button secondary" type="submit">Create new codes</button></form>'
        : '<p class="section-text">Created when you add your first passkey or app.</p>') +
      '</section>' +
      (lastFactorLocked
        ? '<p class="fine">2earl requires a second factor, so your only one can’t be removed. Add another first.</p>'
        : '') +
      '<p class="fine">Adding or removing a factor asks for your second factor again if you last used it more than 5 minutes ago.</p>' +
      '<div class="actions"><a class="button secondary" href="/account">Back to your account</a></div>',
    { passkeyScript: true },
  );
}

/** Groups a base32 secret in fours, as authenticator apps display them. */
function groupSecret(secret: string): string {
  return secret.replace(/(.{4})(?=.)/g, '$1 ');
}

export function totpSetupPage(params: {
  qrSvg: string;
  secret: string;
  next: string;
  error?: string;
}): string {
  return page(
    'Set up an authenticator app',
    '<h1>Set up an authenticator app</h1>' +
      (params.error ? `<p class="warning" role="alert">${escapeHtml(params.error)}</p>` : '') +
      '<p class="lede">Scan this code with your authenticator app. It adds 2earl and starts showing six-digit codes.</p>' +
      // The QR code is generated on the server from the secret; it contains no user input.
      `<div class="qr" role="img" aria-label="QR code for your authenticator app">${params.qrSvg}</div>` +
      '<details class="manual"><summary>Can’t scan it? Enter the key instead</summary>' +
      `<p><code class="secret">${escapeHtml(groupSecret(params.secret))}</code></p>` +
      '<p class="note">Account: 2earl. Type: time-based. Six digits, every 30 seconds.</p></details>' +
      '<form method="post" action="/account/security/totp" class="code-form">' +
      `<input type="hidden" name="next" value="${escapeHtml(params.next)}">` +
      '<label class="field"><span>Code from the app</span>' +
      '<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required></label>' +
      '<div class="consent-actions">' +
      '<button class="button primary" type="submit">Turn on</button>' +
      '<a class="button secondary" href="/account/security">Cancel</a>' +
      '</div></form>',
  );
}

export function recoveryCodesPage(params: { codes: string[]; next: string }): string {
  const text = `2earl recovery codes\n\nEach code works once.\n\n${params.codes.join('\n')}\n`;
  return page(
    'Save your recovery codes',
    '<h1>Save your recovery codes</h1>' +
      '<p class="lede">If you can’t use your passkey or app, each of these codes lets you in once. This is the only time they’re shown.</p>' +
      `<ul class="codes">${params.codes.map((code) => `<li><code>${escapeHtml(code)}</code></li>`).join('')}</ul>` +
      `<p class="note">Keep them in a password manager, or <a href="data:text/plain;charset=utf-8,${encodeURIComponent(text)}" download="2earl-recovery-codes.txt">download them as a text file</a>.</p>` +
      `<a class="button primary" href="${escapeHtml(params.next)}">I’ve saved them</a>`,
  );
}

export function challengePage(params: {
  hasPasskey: boolean;
  hasTotp: boolean;
  returnTo: string;
  stepUp: boolean;
  error?: string;
  lockedUntil?: number | null;
}): string {
  const returnTo = escapeHtml(params.returnTo);
  const locked = params.lockedUntil
    ? `<p class="warning" role="alert">Too many wrong codes. Try again after ${new Intl.DateTimeFormat('en-GB', { timeStyle: 'short', timeZone: 'UTC' }).format(new Date(params.lockedUntil * 1000))} UTC.</p>`
    : '';
  const disabled = params.lockedUntil ? ' disabled' : '';
  return page(
    'Confirm it’s you',
    `<p class="step">${params.stepUp ? 'Before this change' : 'Second step'}</p>` +
      '<h1>Confirm it’s you</h1>' +
      `<p class="lede">${
        params.stepUp
          ? 'This change needs your second factor, used in the last 5 minutes.'
          : 'Your account has a second factor. Use it to finish signing in.'
      }</p>` +
      locked +
      (params.error ? `<p class="warning" role="alert">${escapeHtml(params.error)}</p>` : '') +
      (params.hasPasskey
        ? `<button class="button primary wide" type="button" data-passkey="authenticate" data-status="challenge-status" data-return-to="${returnTo}" hidden${disabled}>Use a passkey</button>` +
          '<noscript><p class="note">Passkeys need JavaScript. Use a code instead.</p></noscript>' +
          '<p class="field-status" id="challenge-status" role="alert"></p>'
        : '') +
      (params.hasTotp
        ? '<form method="post" action="/mfa/totp" class="code-form">' +
          `<input type="hidden" name="return_to" value="${returnTo}">` +
          '<label class="field"><span>Code from your authenticator app</span>' +
          `<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required${disabled}></label>` +
          `<button class="button ${params.hasPasskey ? 'secondary' : 'primary'}" type="submit"${disabled}>Verify</button></form>`
        : '') +
      '<details class="manual"><summary>Use a recovery code</summary>' +
      '<form method="post" action="/mfa/recovery" class="code-form">' +
      `<input type="hidden" name="return_to" value="${returnTo}">` +
      '<label class="field"><span>Recovery code</span>' +
      `<input name="code" type="text" autocomplete="off" spellcheck="false" maxlength="20" required${disabled}></label>` +
      `<button class="button secondary" type="submit"${disabled}>Use code</button></form></details>` +
      '<form method="post" action="/logout" class="signout"><button class="link-button" type="submit">Sign out</button></form>',
    { passkeyScript: params.hasPasskey },
  );
}

export interface Message {
  title: string;
  body: string;
  action?: { href: string; label: string };
}

/**
 * A new account was refused because another account already signs in with this address (no
 * joining by address, THREAT_MODEL B3): send the person to that account's method.
 */
export function methodHasAccount(provider: string): Message {
  if (provider === 'email') return MESSAGES.emailHasAccount;
  if (provider === 'google') return MESSAGES.googleHasAccount;
  const name = providerName(provider);
  return {
    title: 'This address already has an account',
    body: `An account that signs in with ${name} uses this address. Continue with ${name}, then add other ways to sign in on your account page.`,
    action: { href: `/login/${provider}`, label: `Continue with ${name}` },
  };
}

/** Adding a provider's account that already signs in to another 2earl account. */
export function methodTaken(name: string): Message {
  return {
    title: `That ${name} account belongs to another 2earl account`,
    body: `A ${name} account can sign in to one 2earl account only. Nothing was changed.`,
    action: { href: '/account', label: 'Back to your account' },
  };
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
  providerEmailNotVerified: {
    title: 'That account has no verified email address',
    body: 'We need a verified address to keep your account safe. For a Microsoft work or school account, your organization has to verify its domain; for GitHub, verify your primary address there. Or sign in another way.',
    action: { href: '/login', label: 'Sign in another way' },
  },
  accountSuspended: {
    title: 'This account can’t sign in',
    body: 'This account is suspended. If you think that’s a mistake, write to us through the contact form on 2earl.com.',
    action: { href: 'https://2earl.com', label: 'Go to 2earl.com' },
  },
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
    title: 'This account can’t sign in yet',
    body: 'Sign-up is by invitation for now. If you were invited, use the Google account or the address the invitation was for.',
    action: { href: '/login', label: 'Try another account' },
  },
  emailHasAccount: {
    title: 'This address already has an account',
    body: 'An account that signs in with an email code uses this address. Sign in with email, then add Google on your account page, so both work.',
    action: { href: '/login', label: 'Sign in with email' },
  },
  googleHasAccount: {
    title: 'This address already has an account',
    body: 'An account that signs in with Google uses this address. Continue with Google, then add email sign-in on your account page if you like.',
    action: { href: '/login/google', label: 'Continue with Google' },
  },
  codeExpired: {
    title: 'That code no longer works',
    body: 'Codes work once, for 10 minutes, in the browser that asked for them, and stop after 5 wrong tries. Ask for a new one.',
    action: { href: '/login', label: 'Get a new code' },
  },
  linkOtherBrowser: {
    title: 'Open the link where you asked for it',
    body: 'For your safety, the link works only in the browser where you asked for the code. Go back to that browser and open the link there, or type the 6-digit code from the email.',
    action: { href: '/login', label: 'Start again here' },
  },
  tooManyCodes: {
    title: 'Too many codes for now',
    body: 'We’ve sent several codes recently, so we’re pausing for a while to protect the inbox. Use the newest code you got, or try again in an hour.',
    action: { href: '/login', label: 'Back to sign-in' },
  },
  emailNotSent: {
    title: 'We couldn’t send the email',
    body: 'Something went wrong on our side, and no code was sent. Try again in a minute, or continue with Google.',
    action: { href: '/login', label: 'Back to sign-in' },
  },
  googleTaken: {
    title: 'That Google account belongs to another 2earl account',
    body: 'A Google account can sign in to one 2earl account only. Nothing was changed.',
    action: { href: '/account', label: 'Back to your account' },
  },
  emailTaken: {
    title: 'That address belongs to another 2earl account',
    body: 'An address can sign in to one 2earl account only. Nothing was changed.',
    action: { href: '/account', label: 'Back to your account' },
  },
  linkNotConfirmed: {
    title: 'Nothing was added',
    body: 'The confirmation expired, was cancelled, or you signed out in between. Try again from your account page.',
    action: { href: '/account', label: 'Back to your account' },
  },
  deletionNotConfirmed: {
    title: 'Your account was not deleted',
    body: 'Google didn’t confirm it was you: the request expired, was cancelled, or you signed out in between. Nothing was deleted.',
    action: { href: '/account/delete', label: 'Try again' },
  },
  deletionWrongAccount: {
    title: 'Your account was not deleted',
    body: 'You chose a different Google account from the one you sign in to 2earl with. Nothing was deleted.',
    action: { href: '/account/delete', label: 'Try again' },
  },
  deletionFailed: {
    title: 'Deletion didn’t finish',
    body: 'Something went wrong on our side. Your apps may already be disconnected, but your account still exists. Try again in a minute.',
    action: { href: '/account/delete', label: 'Try again' },
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
