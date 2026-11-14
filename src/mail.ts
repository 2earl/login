/**
 * Email from login.2earl.com (DESIGN §4.9): sign-in codes, security notices and invitations.
 * Sent with Cloudflare Email Service (the MAILER binding, wrangler.jsonc).
 *
 * Every message is written once, as a `Mail`, and rendered twice: plain text, and HTML that
 * looks like the web pages (the four-colour band, the 2earl wordmark, the vermilion button, light
 * and dark). The HTML follows Cloudflare's deliverability guidance and our privacy rules: no
 * images, no remote fonts or styles, nothing that tracks. Only our own addresses become links.
 * Replies reach a person. Sending never throws; a failure is logged by its code only.
 */

const SENDER = { email: 'noreply@2earl.com', name: '2earl' };
const REPLY_TO = 'legal@2earl.com';
const ISSUER = 'https://login.2earl.com';

/** The web pages' tokens (public/app.css), for clients that can't read a stylesheet. */
const C = {
  red: '#ed1c24',
  vermilion: '#f15a24',
  orange: '#f7931e',
  amber: '#fbb03b',
  bg: '#f7f7f8',
  surface: '#ffffff',
  fg: '#1c1b1f',
  muted: '#5c5a60',
  rule: '#e2e1e5',
  link: '#b23a0c',
  alert: '#c8141b',
};
const FONT = "system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";

export interface Mail {
  subject: string;
  /** The line inboxes show after the subject. */
  preview: string;
  heading: string;
  /** Paragraphs before the code or the button. */
  body: string[];
  /** A one-time code, set large. */
  code?: string;
  /** The one thing to do: a button in HTML, a labelled link in text. Our own addresses only. */
  action?: { label: string; url: string; showAddress?: boolean };
  /** What happened, when and from where: a small table. */
  facts?: [string, string][] | undefined;
  /** Paragraphs after it, in small print. */
  after?: string[];
  /** Highlight the heading as a warning (security changes). */
  alert?: boolean;
  /** Whether the footer links to the account (not once it is deleted). */
  accountLink?: boolean;
}

const escapeHtml = (value: string) =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const OWN_URL = /https:\/\/(?:[a-z0-9-]+\.)*2earl\.com(?:\/(?:[^\s<>"']*[^\s<>"'.,;:!?)])?)?/g;

/** Our own https links become links; everything else is text. A full stop or comma after a
 * link ends the sentence, not the address. */
const linkify = (escaped: string) =>
  escaped.replace(
    OWN_URL,
    (url) =>
      `<a href="${url}" class="link" style="color:${C.link};text-decoration:underline">${url}</a>`,
  );

function isOwnUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === 'https:' &&
      (parsed.hostname === '2earl.com' || parsed.hostname.endsWith('.2earl.com'))
    );
  } catch {
    return false;
  }
}

// ---- Text -------------------------------------------------------------------------------------

export function mailText(mail: Mail): string {
  const lines: string[] = [mail.heading, ''];
  for (const p of mail.body) lines.push(p, '');
  // The code on its own indented line, so it is easy to find and copy.
  if (mail.code) lines.push(`    ${mail.code}`, '');
  if (mail.action) lines.push(`${mail.action.label}:`, mail.action.url, '');
  if (mail.facts?.length) {
    for (const [label, value] of mail.facts) lines.push(`${label}: ${value}`);
    lines.push('');
  }
  for (const p of mail.after ?? []) lines.push(p, '');
  lines.push('—', '2earl · https://2earl.com');
  if (mail.accountLink !== false) lines.push(`Your account: ${ISSUER}/account`);
  return lines.join('\n');
}

// ---- HTML -------------------------------------------------------------------------------------

/** The band across the top of every page, in the mark's four colours. */
function band(): string {
  const cell = (color: string) =>
    `<td height="5" style="height:5px;line-height:5px;font-size:0;background:${color}">&nbsp;</td>`;
  return (
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse">' +
    `<tr>${cell(C.red)}${cell(C.vermilion)}${cell(C.orange)}${cell(C.amber)}</tr></table>`
  );
}

/** The wordmark, as on the web pages' header; the band below carries the mark's colours. */
function wordmark(): string {
  return (
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>' +
    `<td valign="middle" class="fg" style="font:700 22px/1 ${FONT};color:${C.fg};letter-spacing:-0.02em">2earl</td>` +
    `<td valign="middle" class="muted" style="padding:2px 0 0 10px;font:400 14px/1 ${FONT};color:${C.muted}">Account</td>` +
    '</tr></table>'
  );
}

function paragraph(text: string, small = false): string {
  return `<p class="${small ? 'muted' : 'fg'}" style="margin:0 0 ${small ? '10' : '16'}px;font:${small ? '400 14px/1.55' : '400 16px/1.6'} ${FONT};color:${small ? C.muted : C.fg}">${linkify(escapeHtml(text))}</p>`;
}

function codeBlock(code: string): string {
  return (
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 24px"><tr>' +
    `<td class="code" style="padding:14px 22px;background:${C.bg};border:1px solid ${C.rule};border-radius:10px;font:600 30px/1 ui-monospace,'SF Mono',Menlo,Consolas,monospace;letter-spacing:6px;color:${C.fg}">${escapeHtml(code)}</td>` +
    '</tr></table>'
  );
}

/** A button that works in Outlook too: the cell carries the colour, the link the click. */
function button(label: string, url: string, showAddress: boolean): string {
  if (!isOwnUrl(url)) return paragraph(`${label}: ${url}`);
  const href = escapeHtml(url);
  return (
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 12px"><tr>' +
    `<td bgcolor="${C.vermilion}" style="background:${C.vermilion};border-radius:10px">` +
    `<a href="${href}" style="display:inline-block;padding:13px 22px;font:600 15px/1 ${FONT};color:${C.fg};text-decoration:none;border-radius:10px">${escapeHtml(label)}</a>` +
    '</td></tr></table>' +
    (showAddress
      ? `<p class="muted" style="margin:0 0 24px;font:400 13px/1.5 ${FONT};color:${C.muted};word-break:break-all">Or paste this address into your browser: <a href="${href}" class="link" style="color:${C.link}">${href}</a></p>`
      : '<div style="height:12px;line-height:12px;font-size:0">&nbsp;</div>')
  );
}

function factsTable(facts: [string, string][]): string {
  const rows = facts
    .map(
      ([label, value], i) =>
        `<tr><td class="muted" style="padding:10px 16px 10px 0;${i ? `border-top:1px solid ${C.rule};` : ''}font:400 14px/1.4 ${FONT};color:${C.muted};white-space:nowrap;width:1%" valign="top">${escapeHtml(label)}</td>` +
        `<td class="fg" style="padding:10px 0;${i ? `border-top:1px solid ${C.rule};` : ''}font:600 14px/1.4 ${FONT};color:${C.fg}">${escapeHtml(value)}</td></tr>`,
    )
    .join('');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="facts" style="margin:4px 0 24px;border-collapse:collapse;border-top:1px solid ${C.rule};border-bottom:1px solid ${C.rule}">${rows}</table>`;
}

export function mailHtml(mail: Mail): string {
  const accountLink = mail.accountLink !== false;
  const footerLinks = [
    accountLink
      ? `<a href="${ISSUER}/account" class="muted" style="color:${C.muted}">Your account</a>`
      : null,
    `<a href="https://2earl.com/privacy" class="muted" style="color:${C.muted}">Privacy</a>`,
    `<a href="https://2earl.com/imprint" class="muted" style="color:${C.muted}">Imprint</a>`,
  ]
    .filter(Boolean)
    .join(' &nbsp;·&nbsp; ');
  const content =
    `<h1 class="${mail.alert ? 'alert' : 'fg'}" style="margin:0 0 16px;font:600 22px/1.3 ${FONT};color:${mail.alert ? C.alert : C.fg};letter-spacing:-0.01em">${escapeHtml(mail.heading)}</h1>` +
    mail.body.map((p) => paragraph(p)).join('') +
    (mail.code ? codeBlock(mail.code) : '') +
    (mail.action
      ? button(mail.action.label, mail.action.url, mail.action.showAddress === true)
      : '') +
    (mail.facts?.length ? factsTable(mail.facts) : '') +
    (mail.after ?? []).map((p) => paragraph(p, true)).join('');
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">' +
    `<title>${escapeHtml(mail.subject)}</title>` +
    '<style>' +
    // Dark mode where the client supports it (Apple Mail, Outlook apps): the web pages' dark tokens.
    '@media (prefers-color-scheme: dark){' +
    '.bg{background:#141315!important}.card{background:#1c1b1f!important;border-color:#2c2a2f!important}' +
    '.fg{color:#f2f1f3!important}.muted{color:#a19fa6!important}.link{color:#fbb03b!important}' +
    '.alert{color:#ff7a6b!important}.code{background:#141315!important;border-color:#2c2a2f!important;color:#f2f1f3!important}' +
    '.facts,.facts td{border-color:#2c2a2f!important}}' +
    '@media (max-width:600px){.card-body{padding:24px 20px 12px!important}}' +
    '</style></head>' +
    `<body class="bg" style="margin:0;padding:0;background:${C.bg};-webkit-text-size-adjust:100%">` +
    // What inboxes show after the subject; padded so they don't run into the body text.
    `<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all">${escapeHtml(mail.preview)}${'&#8199;&#847;'.repeat(40)}</div>` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="bg" style="background:${C.bg}"><tr><td align="center" style="padding:28px 12px 32px">` +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px">' +
    `<tr><td style="padding:0 4px 18px">${wordmark()}</td></tr>` +
    `<tr><td class="card" style="background:${C.surface};border:1px solid ${C.rule};border-radius:12px;overflow:hidden;padding:0">` +
    band() +
    `<div class="card card-body" style="padding:32px 32px 20px;background:${C.surface}">${content}</div>` +
    '</td></tr>' +
    `<tr><td style="padding:20px 4px 0;font:400 13px/1.6 ${FONT};color:${C.muted}" class="muted">` +
    `<p style="margin:0 0 6px">You got this email because of your 2earl account, or because someone used this address with 2earl. 2earl never asks for a password or a code by email or phone.</p>` +
    `<p style="margin:0">${footerLinks}</p>` +
    '</td></tr></table></td></tr></table></body></html>'
  );
}

// ---- Sending ------------------------------------------------------------------------------------

export async function sendMail(env: Env, to: string, mail: Mail): Promise<boolean> {
  try {
    await env.MAILER.send({
      to,
      from: SENDER,
      replyTo: REPLY_TO,
      subject: mail.subject,
      text: mailText(mail),
      html: mailHtml(mail),
    });
    return true;
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    console.error('email failed', typeof code === 'string' ? code : 'unknown');
    return false;
  }
}

// ---- Messages -----------------------------------------------------------------------------------

export type CodePurpose = 'sign_in' | 'delete_account' | 'link_email';

const CODE_TEXT: Record<CodePurpose, { heading: string; intro: string; action: string }> = {
  sign_in: {
    heading: 'Your sign-in code',
    intro: 'Enter this code to sign in to 2earl, or to create your account:',
    action: 'Sign in',
  },
  delete_account: {
    heading: 'Confirm deleting your account',
    intro: 'Enter this code to confirm deleting your 2earl account:',
    action: 'Confirm deletion',
  },
  link_email: {
    heading: 'Confirm your email address',
    intro: 'Enter this code to add this address to your 2earl account:',
    action: 'Add this address',
  },
};

/** The code, and a link that does the same in the browser that asked for it. */
export function codeMail(purpose: CodePurpose, code: string, link: string): Mail {
  const text = CODE_TEXT[purpose];
  return {
    subject:
      purpose === 'delete_account'
        ? `${code} confirms deleting your 2earl account`
        : `${code} is your 2earl code`,
    preview: `${text.intro.replace(/:$/, '')}. It works once, for 10 minutes.`,
    heading: text.heading,
    body: [text.intro],
    code,
    // The address too: a sign-in link must work where buttons don't.
    action: { label: `${text.action} in the same browser`, url: link, showAddress: true },
    after: [
      'The code and the link work once, for 10 minutes.',
      purpose === 'delete_account'
        ? 'If you didn’t ask to delete your account, sign in and add a second factor: someone may be using your account.'
        : 'If you didn’t ask for it, you can ignore this email. Nobody can use it without access to your inbox.',
    ],
    alert: purpose === 'delete_account',
  };
}

/** Security notices: what changed, when and where, and what to do if it wasn't you. */
export type Notice =
  | { kind: 'method_added'; method: string }
  | { kind: 'method_removed'; method: string }
  | { kind: 'factor_added'; factor: string }
  | { kind: 'factor_removed'; factor: string }
  | { kind: 'recovery_codes' }
  | { kind: 'app_connected'; app: string }
  | { kind: 'account_deleted' }
  | { kind: 'org_owner'; org: string }
  | { kind: 'domain_managed'; org: string; domain: string }
  | { kind: 'account_deactivated'; org: string }
  | { kind: 'account_reactivated'; org: string }
  | { kind: 'account_signed_out'; org: string }
  | {
      kind: 'sso_expiring';
      org: string;
      orgId: string;
      protocol: 'saml' | 'oidc';
      expiresAt: number;
      expired: boolean;
    };

/** Where a change came from, as the notice reports it. */
export interface NoticeContext {
  at: number;
  device: string | null;
  network: string | null;
}

/** "13 Nov 2026, 06:14 UTC". */
function when(unixSeconds: number): string {
  return `${new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(unixSeconds * 1000))} UTC`;
}

function facts(context: NoticeContext | undefined): [string, string][] | undefined {
  if (!context) return undefined;
  const rows: [string, string][] = [['When', when(context.at)]];
  if (context.device) rows.push(['Device', context.device]);
  if (context.network) rows.push(['Network', context.network.replace(/\.0\/24$|::\/48$/, '…')]);
  return rows;
}

const NOT_YOU =
  'If this wasn’t you, review how you sign in and the devices signed in to your account, and add a second factor.';

export function noticeMail(notice: Notice, context?: NoticeContext): Mail {
  const security = { label: 'Review your security', url: `${ISSUER}/account/security` };
  const base = { facts: facts(context), after: [NOT_YOU] };
  switch (notice.kind) {
    case 'method_added':
      return {
        ...base,
        subject: 'A sign-in method was added to your 2earl account',
        preview: `You can now sign in with ${notice.method}.`,
        heading: 'A sign-in method was added',
        body: [`You can now sign in to 2earl with ${notice.method}.`],
        action: security,
      };
    case 'method_removed':
      return {
        ...base,
        subject: 'A sign-in method was removed from your 2earl account',
        preview: `You can no longer sign in with ${notice.method}.`,
        heading: 'A sign-in method was removed',
        body: [`You can no longer sign in to 2earl with ${notice.method}.`],
        action: security,
        alert: true,
      };
    case 'factor_added':
      return {
        ...base,
        subject: 'A second factor was added to your 2earl account',
        preview: `${notice.factor} now protects your account.`,
        heading: 'A second factor was added',
        body: [`${notice.factor} now protects your 2earl account.`],
        action: security,
      };
    case 'factor_removed':
      return {
        ...base,
        subject: 'A second factor was removed from your 2earl account',
        preview: `${notice.factor} no longer protects your account.`,
        heading: 'A second factor was removed',
        body: [`${notice.factor} no longer protects your 2earl account.`],
        action: security,
        alert: true,
      };
    case 'recovery_codes':
      return {
        ...base,
        subject: 'New recovery codes for your 2earl account',
        preview: 'The earlier recovery codes no longer work.',
        heading: 'New recovery codes were created',
        body: [
          'New recovery codes were created for your 2earl account. The earlier ones no longer work.',
        ],
        action: security,
      };
    case 'app_connected':
      return {
        ...base,
        subject: `${notice.app} can now act for you`,
        preview: `You allowed ${notice.app} to use your 2earl account.`,
        heading: 'An app can now act for you',
        body: [
          `You allowed ${notice.app} to use your 2earl account.`,
          'You can see what it may do, and disconnect it at any time.',
        ],
        action: { label: 'Review connected apps', url: `${ISSUER}/account/apps` },
        after: [
          'If this wasn’t you, disconnect the app and review the devices signed in to your account.',
        ],
      };
    case 'org_owner':
      return {
        subject: 'You’re now an owner of an organization on 2earl',
        preview: `You’re now an owner of “${notice.org}”.`,
        heading: 'You’re now an owner',
        body: [
          `You’re now an owner of the organization “${notice.org}”, because its only owner deleted their 2earl account.`,
          'You can manage its members, or hand ownership to someone else.',
        ],
        action: { label: 'Open your organizations', url: `${ISSUER}/account/orgs` },
        // When only: the device and network were the previous owner's, not this person's.
        ...(context ? { facts: [['When', when(context.at)]] as [string, string][] } : {}),
      };
    case 'domain_managed':
      return {
        subject: `${notice.org} now manages 2earl accounts at ${notice.domain}`,
        preview: 'Choose whether it manages your account, the next time you sign in.',
        heading: 'Your organization manages accounts at your address’s domain',
        body: [
          `The organization “${notice.org}” proved it controls ${notice.domain} and now manages the 2earl accounts there.`,
          'Your account has an address at that domain. The next time you sign in, choose whether the organization manages your account, or keep it your own by removing that address from it.',
          'Nothing changes until you choose.',
        ],
        action: { label: 'Choose now', url: `${ISSUER}/account/managed` },
        ...(context ? { facts: [['When', when(context.at)]] as [string, string][] } : {}),
      };
    case 'account_deactivated':
      return {
        subject: 'Your 2earl account was deactivated',
        preview: `${notice.org} deactivated the account it manages.`,
        heading: 'Your account was deactivated',
        alert: true,
        body: [
          `“${notice.org}” manages your 2earl account and deactivated it. You can’t sign in, and connected apps lost access.`,
          'Your account and its data are kept. If you think this is a mistake, ask the organization’s admins.',
        ],
        ...(context ? { facts: [['When', when(context.at)]] as [string, string][] } : {}),
        accountLink: false,
      };
    case 'account_reactivated':
      return {
        subject: 'Your 2earl account works again',
        preview: `${notice.org} reactivated your account.`,
        heading: 'Your account works again',
        body: [
          `“${notice.org}” reactivated the 2earl account it manages. You can sign in again.`,
          'Apps you used before need to be connected again.',
        ],
        action: { label: 'Sign in', url: `${ISSUER}/login` },
        ...(context ? { facts: [['When', when(context.at)]] as [string, string][] } : {}),
      };
    case 'account_signed_out':
      return {
        subject: 'You were signed out of 2earl everywhere',
        preview: `${notice.org} signed you out on every device.`,
        heading: 'You were signed out everywhere',
        alert: true,
        body: [
          `“${notice.org}” manages your 2earl account and signed it out on every device. Connected apps lost access too.`,
          'You can sign in again as usual; apps you use need to be connected again. If you didn’t expect this, ask the organization’s admins.',
        ],
        action: { label: 'Sign in', url: `${ISSUER}/login` },
        ...(context ? { facts: [['When', when(context.at)]] as [string, string][] } : {}),
      };
    case 'sso_expiring': {
      const what =
        notice.protocol === 'saml'
          ? 'identity provider’s signing certificate'
          : 'OpenID Connect client secret';
      const date = new Intl.DateTimeFormat('en-GB', { dateStyle: 'long', timeZone: 'UTC' }).format(
        new Date(notice.expiresAt * 1000),
      );
      const fix =
        notice.protocol === 'saml'
          ? 'Your identity provider will sign with a new certificate around then. Paste the new one as the next signing certificate on Domains & SSO now: 2earl accepts both, so sign-in keeps working when the provider switches.'
          : 'Create a new client secret at your identity provider and save it, with its expiry date, on Domains & SSO before the old one stops working.';
      return {
        subject: notice.expired
          ? `${notice.org}: single sign-on’s ${notice.protocol === 'saml' ? 'certificate' : 'client secret'} has expired`
          : `${notice.org}: single sign-on’s ${notice.protocol === 'saml' ? 'certificate' : 'client secret'} expires on ${date}`,
        preview: notice.expired
          ? 'People may not be able to sign in with single sign-on.'
          : 'Replace it before then so people can keep signing in.',
        heading: notice.expired ? 'Single sign-on needs attention' : 'Single sign-on expires soon',
        alert: notice.expired,
        body: [
          notice.expired
            ? `The ${what} for “${notice.org}” expired on ${date}. People may not be able to sign in with single sign-on.`
            : `The ${what} for “${notice.org}” expires on ${date}.`,
          fix,
          'You get this because you’re an owner of the organization.',
        ],
        action: {
          label: 'Open Domains & SSO',
          url: `${ISSUER}/orgs/${encodeURIComponent(notice.orgId)}/directory`,
        },
      };
    }
    case 'account_deleted':
      return {
        subject: 'Your 2earl account was deleted',
        preview: 'This is the last email you get from us about this account.',
        heading: 'Your account was deleted',
        body: [
          'Your 2earl account and everything in it were deleted, and every connected app was disconnected.',
          'You can create a new account at any time. This is the last email you get from us about this account.',
        ],
        ...(base.facts ? { facts: base.facts } : {}),
        accountLink: false,
      };
  }
}

/**
 * Sends a security notice to the account's address, after the response (waitUntil). Accounts
 * without an address get none.
 */
export async function notify(
  env: Env,
  userId: string,
  notice: Notice,
  context?: NoticeContext,
): Promise<void> {
  const row = await env.DB.prepare('SELECT primary_email FROM users WHERE id = ?')
    .bind(userId)
    .first<{ primary_email: string | null }>();
  if (!row?.primary_email) return;
  await sendMail(env, row.primary_email, noticeMail(notice, context));
}

/**
 * An invitation to join an organization (DESIGN §4.14). The organization's name and the inviter
 * are chosen by users, so the email says plainly who sent it, and its only link is ours.
 */
export function invitationMail(params: {
  org: string;
  inviter: string | null;
  role: 'admin' | 'member';
  link: string;
}): Mail {
  const who = params.inviter ?? 'Someone';
  const role = params.role === 'admin' ? 'an admin' : 'a member';
  return {
    subject: `Join “${params.org}” on 2earl`,
    preview: `${who} invited you to join as ${role}.`,
    heading: `Join “${params.org}”`,
    body: [
      `${who} invited you to join the organization “${params.org}” on 2earl, as ${role}.`,
      'Open the invitation and sign in with this email address to accept or decline it.',
    ],
    action: { label: 'Open the invitation', url: params.link, showAddress: true },
    after: [
      'The invitation works for 7 days, and only for this address. If you don’t know who sent it, you can ignore this email.',
    ],
  };
}
