/**
 * Server-rendered HTML. Every dynamic value goes through `escapeHtml`. No inline scripts; the
 * second-factor pages load /passkey.js (with MFA_CSP).
 * Styles, font and icon are static assets in /public; the mark is inline markup.
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
}): string {
  const heading = params.name ?? 'Your account';
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
      '<section class="section" aria-labelledby="security-heading">' +
      '<h2 id="security-heading">Security</h2>' +
      `<p class="section-text">${escapeHtml(factorSummary(params.factors))}</p>` +
      '<a class="button secondary" href="/account/security">Manage second factor</a>' +
      '</section>' +
      '<section class="section" aria-labelledby="details-heading">' +
      '<h2 id="details-heading">Account details</h2>' +
      '<dl class="details">' +
      '<dt>Signs in with</dt><dd>Google</dd>' +
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

/** Everything the consent page shows comes from the library's validated description. */
export interface ConsentView {
  handle: string;
  /** The scopes offered on this page, signed and bound to the handle (app.ts offeredScopesMac). */
  offeredMac: string;
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
      `<input type="hidden" name="offered" value="${escapeHtml(view.scopes.map((s) => s.scope).join(' '))}">` +
      `<input type="hidden" name="offered_mac" value="${escapeHtml(view.offeredMac)}">` +
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
}): string {
  const apps =
    params.appCount === 0
      ? 'Connected apps: none right now'
      : `Access for your ${params.appCount === 1 ? 'connected app' : `${String(params.appCount)} connected apps`}`;
  return page(
    'Delete your account',
    '<h1>Delete your 2earl account</h1>' +
      '<p class="lede">Your account is deleted as soon as you confirm with Google. It can’t be restored.</p>' +
      '<div class="ledger">' +
      '<section aria-labelledby="deleted-heading">' +
      '<h2 id="deleted-heading">Deleted now</h2>' +
      '<ul>' +
      `<li>Your name and email address${params.email ? ` (${escapeHtml(params.email)})` : ''}, and the link to your Google account</li>` +
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
      '<button class="button danger" type="submit">Confirm with Google</button>' +
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
    return 'Second factor: off. Adding a passkey protects your account even if someone gets into your Google account.';
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
      '<p class="section-text">Your fingerprint, face, screen lock or a security key. Passkeys only work on login.2earl.com, so they can’t be phished.</p>' +
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
