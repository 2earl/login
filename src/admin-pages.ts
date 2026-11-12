import type { AuditEvent } from './audit';
import type { PendingNotices } from './deletion-notices';
import type { ResourceServer } from './introspection';
import { escapeHtml, formatDate, page } from './pages';

/** Server-rendered pages for /admin (DESIGN §4.6). Owner-only; every value is escaped. */

export type AdminTab = 'users' | 'invitations' | 'orgs' | 'apps' | 'log';

const TABS: [AdminTab, string, string][] = [
  ['users', 'Users', '/admin/users'],
  ['invitations', 'Invitations', '/admin/invitations'],
  ['orgs', 'Organizations', '/admin/orgs'],
  ['apps', 'Apps', '/admin/apps'],
  ['log', 'Security log', '/admin/log'],
];

function adminPage(
  tab: AdminTab,
  title: string,
  body: string,
  flash: { notice?: string | undefined; error?: string | undefined } = {},
): string {
  const nav =
    '<nav class="tabs" aria-label="Admin">' +
    TABS.map(
      ([key, label, href]) =>
        `<a href="${href}"${key === tab ? ' aria-current="page"' : ''}>${label}</a>`,
    ).join('') +
    '</nav>';
  return page(
    `${title} · Admin`,
    nav +
      (flash.notice ? `<p class="notice" role="status">${escapeHtml(flash.notice)}</p>` : '') +
      (flash.error ? `<p class="warning" role="alert">${escapeHtml(flash.error)}</p>` : '') +
      `<h1>${escapeHtml(title)}</h1>` +
      body,
    { wide: true, section: 'Admin' },
  );
}

function dateTime(unixSeconds: number): string {
  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(new Date(unixSeconds * 1000));
}

/** A small POST form with one button. `fields` become hidden inputs. */
function actionForm(
  action: string,
  fields: Record<string, string>,
  label: string,
  style: 'secondary' | 'danger' = 'secondary',
): string {
  return (
    `<form method="post" action="${action}">` +
    Object.entries(fields)
      .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`)
      .join('') +
    `<button class="button ${style} small" type="submit">${escapeHtml(label)}</button></form>`
  );
}

// ---- Users ----------------------------------------------------------------------------------

export interface AdminUser {
  id: string;
  email: string | null;
  name: string | null;
  status: string;
  createdAt: number;
  lastSignInAt: number | null;
  factors: number;
  /** 'email', 'google': how the account signs in. */
  methods: string[];
  isOwner: boolean;
}

function userRow(user: AdminUser): string {
  const who = escapeHtml(user.email ?? user.id);
  const meta = [
    user.name ? escapeHtml(user.name) : null,
    `Joined ${formatDate(user.createdAt)}`,
    user.methods.length
      ? `signs in with ${user.methods.map((m) => (m === 'google' ? 'Google' : 'email code')).join(' and ')}`
      : null,
    user.lastSignInAt ? `last sign-in ${dateTime(user.lastSignInAt)} UTC` : 'never signed in',
    user.factors > 0 ? `second factor: ${String(user.factors)}` : 'no second factor',
  ]
    .filter(Boolean)
    .join(' · ');
  const badges =
    (user.isOwner ? '<span class="tag">Owner</span>' : '') +
    (user.status === 'suspended' ? '<span class="tag tag-alert">Suspended</span>' : '');

  const actions = user.isOwner
    ? '<p class="row-note">Manage your own account on the account page.</p>'
    : '<div class="row-actions">' +
      (user.status === 'suspended'
        ? actionForm('/admin/users', { action: 'reactivate', user: user.id }, 'Reactivate')
        : actionForm('/admin/users', { action: 'suspend', user: user.id }, 'Suspend')) +
      (user.factors > 0
        ? actionForm('/admin/users', { action: 'reset_mfa', user: user.id }, 'Reset second factor')
        : '') +
      '<details class="confirm-delete"><summary>Delete…</summary>' +
      '<form method="post" action="/admin/users">' +
      '<input type="hidden" name="action" value="delete">' +
      `<input type="hidden" name="user" value="${escapeHtml(user.id)}">` +
      `<label class="confirm"><input type="checkbox" name="confirm" value="on" required><span>Delete ${who} and disconnect their apps. This can’t be undone.</span></label>` +
      '<button class="button danger small" type="submit">Delete account</button></form></details>' +
      '</div>';

  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${who}${badges}</p>` +
    `<p class="app-meta">${meta}</p></div>` +
    actions +
    '</li>'
  );
}

export function adminUsersPage(params: {
  users: AdminUser[];
  pending: PendingNotices[];
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  return adminPage(
    'users',
    'Users',
    `<p class="section-text">${String(params.users.length)} ${params.users.length === 1 ? 'account' : 'accounts'}. Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.</p>` +
      `<ul class="admin-list">${params.users.map(userRow).join('')}</ul>` +
      pendingSection(params.pending),
    params,
  );
}

/** Deletion notices not yet confirmed by a service (DESIGN §4.8). Shown only when there are any. */
function pendingSection(pending: PendingNotices[]): string {
  if (pending.length === 0) return '';
  const rows = pending
    .map((p) => {
      const state =
        p.attempts === 0
          ? 'not delivered yet: the service has no binding in login, or delivery is about to run'
          : `${String(p.attempts)} failed ${p.attempts === 1 ? 'attempt' : 'attempts'}${p.lastError ? `, last error ${escapeHtml(p.lastError)}` : ''}`;
      return (
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(p.name)}: ${String(p.count)} waiting</p>` +
        `<p class="app-meta">Oldest from ${formatDate(p.oldest)} · ${state}</p>` +
        '</div></li>'
      );
    })
    .join('');
  return (
    '<section class="section" aria-labelledby="notices-heading">' +
    '<h2 id="notices-heading">Deletion notices waiting</h2>' +
    '<p class="section-text">Deleted accounts whose data a service hasn’t confirmed deleting yet. Delivery retries every 15 minutes.</p>' +
    `<ul class="admin-list">${rows}</ul></section>`
  );
}

// ---- Invitations --------------------------------------------------------------------------------

export interface AdminInvitation {
  id: string;
  kind: 'email' | 'google_sub';
  value: string;
  /** For a pinned invitation: the email of the account that used it. */
  accountEmail: string | null;
  /** Someone signed in with it. */
  used: boolean;
  createdAt: number;
  isOwner: boolean;
}

export function adminInvitationsPage(params: {
  invitations: AdminInvitation[];
  locked: boolean;
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  const rows = params.invitations
    .map((inv) => {
      const label =
        inv.kind === 'email'
          ? `${escapeHtml(inv.value)}<span class="tag tag-muted">${inv.used ? 'Signed in with email' : 'Not signed in yet'}</span>`
          : `${escapeHtml(inv.accountEmail ?? `Google account ${inv.value}`)}<span class="tag tag-muted">Signed in</span>`;
      return (
        '<li class="admin-row">' +
        `<div class="app-main"><p class="app-name">${label}</p>` +
        `<p class="app-meta">Invited ${formatDate(inv.createdAt)}</p></div>` +
        (inv.isOwner
          ? '<p class="row-note">Your own invitation</p>'
          : `<div class="row-actions">${actionForm('/admin/invitations', { action: 'remove', id: inv.id }, 'Withdraw')}</div>`) +
        '</li>'
      );
    })
    .join('');
  return adminPage(
    'invitations',
    'Invitations',
    '<section class="section" aria-labelledby="signup-heading">' +
      '<h2 id="signup-heading">Sign-up</h2>' +
      `<p class="section-text">${
        params.locked
          ? '<strong>By invitation.</strong> New accounts need an invitation below. Accounts that already exist keep working.'
          : '<strong>Open.</strong> Anyone can create an account with Google or an email code. Invitations below are not checked.'
      }</p>` +
      actionForm(
        '/admin/invitations',
        { action: 'signup', mode: params.locked ? 'open' : 'invite' },
        params.locked ? 'Open sign-up' : 'Close sign-up (invitation only)',
      ) +
      '</section>' +
      '<h2>Invitations</h2>' +
      '<p class="section-text">An invitation names a Google account’s address, or an address that signs in with email codes. At the first Google sign-in it is pinned to that Google account. Withdrawing one doesn’t sign anyone out; suspend the user for that.</p>' +
      '<form method="post" action="/admin/invitations" class="inline-form">' +
      '<input type="hidden" name="action" value="add">' +
      '<label class="field"><span>Invite by email address</span>' +
      '<input name="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false"></label>' +
      '<button class="button primary" type="submit">Invite</button></form>' +
      `<ul class="admin-list">${rows}</ul>`,
    params,
  );
}

// ---- Organizations (DESIGN §4.14) -----------------------------------------------------------

export interface AdminOrg {
  id: string;
  name: string;
  status: 'active' | 'suspended';
  members: number;
  invitations: number;
  owners: string[];
  createdAt: number;
}

function orgRow(org: AdminOrg): string {
  const meta = [
    `${String(org.members)} ${org.members === 1 ? 'member' : 'members'}`,
    org.invitations > 0 ? `${String(org.invitations)} open invitations` : null,
    org.owners.length > 0 ? `owners: ${org.owners.map(escapeHtml).join(', ')}` : null,
    `created ${formatDate(org.createdAt)}`,
    `<code>${escapeHtml(org.id)}</code>`,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${escapeHtml(org.name)}` +
    (org.status === 'suspended' ? '<span class="tag tag-alert">Suspended</span>' : '') +
    `</p><p class="app-meta">${meta}</p></div>` +
    '<div class="row-actions">' +
    (org.status === 'suspended'
      ? actionForm('/admin/orgs', { action: 'reactivate', org: org.id }, 'Reactivate')
      : actionForm('/admin/orgs', { action: 'suspend', org: org.id }, 'Suspend')) +
    '<details class="confirm-delete"><summary>Delete…</summary>' +
    '<form method="post" action="/admin/orgs">' +
    '<input type="hidden" name="action" value="delete">' +
    `<input type="hidden" name="org" value="${escapeHtml(org.id)}">` +
    `<label class="confirm"><input type="checkbox" name="confirm" value="on" required><span>Delete ${escapeHtml(org.name)}, its memberships and invitations. Members keep their accounts. This can’t be undone.</span></label>` +
    '<button class="button danger small" type="submit">Delete organization</button></form></details>' +
    '</div></li>'
  );
}

export function adminOrgsPage(params: {
  orgs: AdminOrg[];
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  return adminPage(
    'orgs',
    'Organizations',
    `<p class="section-text">${String(params.orgs.length)} ${params.orgs.length === 1 ? 'organization' : 'organizations'}. Suspending one freezes it: members can only leave, and 2earl services stop seeing it.</p>` +
      (params.orgs.length > 0
        ? `<ul class="admin-list">${params.orgs.map(orgRow).join('')}</ul>`
        : '<p class="empty">No organizations yet.</p>'),
    params,
  );
}

// ---- Apps -----------------------------------------------------------------------------------

export interface AdminTrustedApp {
  clientId: string;
  note: string | null;
  createdAt: number;
}

export interface AdminRegisteredApp {
  clientId: string;
  name: string | null;
  redirectUris: string[];
  createdAt: number | null;
}

export function adminAppsPage(params: {
  trusted: AdminTrustedApp[];
  registered: AdminRegisteredApp[];
  resourceServers?: ResourceServer[];
  /** Resources a resource server can be created for. */
  resources?: { resource: string; label: string }[];
  /** Just-created credentials: the only time the secret is shown. */
  created?: { id: string; secret: string } | undefined;
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  const servers = params.resourceServers ?? [];
  const resourceServers =
    (params.created
      ? '<div class="secret-once" role="status">' +
        '<p><strong>Copy the secret now.</strong> It isn’t stored and won’t be shown again.</p>' +
        `<p>ID <code>${escapeHtml(params.created.id)}</code></p>` +
        `<p>Secret <code>${escapeHtml(params.created.secret)}</code></p></div>`
      : '') +
    (servers.length === 0
      ? '<p class="empty">No resource servers.</p>'
      : `<ul class="admin-list">${servers
          .map(
            (rs) =>
              '<li class="admin-row">' +
              `<div class="app-main"><p class="app-name">${escapeHtml(rs.name)}</p>` +
              `<p class="app-meta">ID <code>${escapeHtml(rs.id)}</code> · for <code>${escapeHtml(rs.resource)}</code></p>` +
              `<p class="app-meta">Created ${formatDate(rs.createdAt)} · ${rs.lastUsedAt ? `last used ${formatDate(rs.lastUsedAt)}` : 'never used'}</p></div>` +
              `<div class="row-actions">${actionForm('/admin/apps', { action: 'rs_delete', id: rs.id }, 'Revoke', 'danger')}</div>` +
              '</li>',
          )
          .join('')}</ul>`) +
    '<form method="post" action="/admin/apps" class="stack-form">' +
    '<input type="hidden" name="action" value="rs_create">' +
    '<label class="field"><span>Name</span>' +
    '<input name="name" type="text" required maxlength="100" autocomplete="off" placeholder="e.g. Prompt share backup server"></label>' +
    '<label class="field"><span>Checks tokens for</span><select name="resource" required>' +
    (params.resources ?? [])
      .map((r) => `<option value="${escapeHtml(r.resource)}">${escapeHtml(r.label)}</option>`)
      .join('') +
    '</select></label>' +
    '<button class="button secondary" type="submit">Create credentials</button></form>';
  const trusted =
    params.trusted.length === 0
      ? '<p class="empty">No verified apps.</p>'
      : `<ul class="admin-list">${params.trusted
          .map(
            (app) =>
              '<li class="admin-row">' +
              `<div class="app-main"><p class="app-name"><code>${escapeHtml(app.clientId)}</code></p>` +
              `<p class="app-meta">${app.note ? `${escapeHtml(app.note)} · ` : ''}Verified ${formatDate(app.createdAt)}</p></div>` +
              `<div class="row-actions">${actionForm('/admin/apps', { action: 'untrust', client_id: app.clientId }, 'Remove verification')}</div>` +
              '</li>',
          )
          .join('')}</ul>`;
  const registered =
    params.registered.length === 0
      ? '<p class="empty">No registered apps.</p>'
      : `<ul class="admin-list">${params.registered
          .map(
            (app) =>
              '<li class="admin-row">' +
              `<div class="app-main"><p class="app-name">${escapeHtml(app.name ?? 'Unnamed app')}</p>` +
              `<p class="app-meta">Client ID <code>${escapeHtml(app.clientId)}</code></p>` +
              `<p class="app-meta">${app.redirectUris.map((u) => escapeHtml(u)).join('<br>')}</p></div>` +
              '<div class="row-actions">' +
              actionForm(
                '/admin/apps',
                { action: 'unregister', client_id: app.clientId },
                'Delete',
                'danger',
              ) +
              '</div></li>',
          )
          .join('')}</ul>`;

  return adminPage(
    'apps',
    'Apps',
    '<section class="section" aria-labelledby="verified-heading">' +
      '<h2 id="verified-heading">Verified apps</h2>' +
      '<p class="section-text">The consent page shows these as verified instead of “This app named itself”. Verify only apps whose publisher you have checked.</p>' +
      trusted +
      '<form method="post" action="/admin/apps" class="stack-form">' +
      '<input type="hidden" name="action" value="trust">' +
      '<label class="field"><span>Client ID (the app’s metadata URL, or a registered client ID)</span>' +
      '<input name="client_id" type="text" required maxlength="2000" autocomplete="off" spellcheck="false" placeholder="https://app.example/oauth/client.json"></label>' +
      '<label class="field"><span>Note (optional)</span>' +
      '<input name="note" type="text" maxlength="200" autocomplete="off" placeholder="e.g. Checked with the publisher on …"></label>' +
      '<button class="button secondary" type="submit">Mark as verified</button></form>' +
      '</section>' +
      '<section class="section" aria-labelledby="registered-heading">' +
      '<h2 id="registered-heading">Registered apps</h2>' +
      '<p class="section-text">For apps that can’t publish a client metadata document. Public clients only: they use PKCE and have no secret.</p>' +
      registered +
      '<form method="post" action="/admin/apps" class="stack-form">' +
      '<input type="hidden" name="action" value="register">' +
      '<label class="field"><span>App name</span>' +
      '<input name="name" type="text" required maxlength="100" autocomplete="off"></label>' +
      '<label class="field"><span>Redirect URIs, one per line (https, or http on localhost)</span>' +
      '<textarea name="redirect_uris" rows="3" required spellcheck="false"></textarea></label>' +
      '<button class="button secondary" type="submit">Register app</button></form>' +
      '</section>' +
      '<section class="section" aria-labelledby="rs-heading">' +
      '<h2 id="rs-heading">Resource servers</h2>' +
      '<p class="section-text">Credentials for a service that checks tokens at <code>/oauth/introspect</code> (RFC 7662) instead of a Service Binding. Each sees only tokens issued for its own resource.</p>' +
      resourceServers +
      '</section>',
    params,
  );
}

// ---- Security log ---------------------------------------------------------------------------------

export interface AdminLogEvent {
  at: number;
  event: string;
  account: string | null;
  clientId: string | null;
  ipPrefix: string | null;
  detail: string | null;
}

export const LOG_FILTERS: [string, string][] = [
  ['', 'All events'],
  ['login.', 'Sign-in'],
  ['mfa.', 'Second factor'],
  ['consent.', 'Consent'],
  ['grant.', 'App access'],
  ['account.', 'Account'],
  ['user.', 'Users'],
  ['org.', 'Organizations'],
  ['scim.', 'Directory sync'],
  ['admin.', 'Admin actions'],
];

/** What each event means, in words; the event's own name stays on hover. */
const EVENT_LABEL: Record<AuditEvent, string> = {
  'login.started': 'Sign-in started',
  'login.succeeded': 'Signed in',
  'login.denied': 'Sign-in refused (not invited)',
  'login.failed': 'Sign-in failed',
  'login.code_sent': 'Email code sent',
  'login.code_failed': 'Wrong email code',
  'login.code_refused': 'Email code not sent (limit)',
  'identity.added': 'Sign-in method added',
  'identity.removed': 'Sign-in method removed',
  'allowlist.pinned': 'Invitation used',
  'user.created': 'Account created',
  logout: 'Signed out',
  'device.approved': 'Signed in on a device',
  'session.ended': 'Signed out other devices',
  'consent.approved': 'App allowed',
  'consent.denied': 'App refused by the user',
  'consent.reused': 'App allowed (remembered)',
  'grant.revoked': 'App disconnected',
  'grant.refused': 'App access refused',
  'account.exported': 'Data downloaded',
  'account.deletion_started': 'Account deletion started',
  'account.deletion_stopped': 'Account deletion stopped',
  'user.deleted': 'Account deleted',
  'user.deletion_delivered': 'Deletion delivered to a service',
  'mfa.enrolled': 'Second factor added',
  'mfa.removed': 'Second factor removed',
  'mfa.verified': 'Second factor used',
  'mfa.failed': 'Second factor failed',
  'mfa.locked': 'Second factor locked after failures',
  'mfa.recovery_codes_created': 'Recovery codes created',
  'mfa.recovery_code_used': 'Recovery code used',
  'admin.invitation_added': 'Invitation added',
  'admin.invitation_removed': 'Invitation removed',
  'admin.user_suspended': 'User suspended',
  'admin.user_reactivated': 'User reactivated',
  'admin.user_deleted': 'User deleted',
  'admin.mfa_reset': 'Second factor reset',
  'admin.client_trusted': 'App marked verified',
  'admin.client_untrusted': 'App unmarked',
  'admin.client_registered': 'App registered',
  'admin.client_deleted': 'App removed',
  'admin.resource_server_created': 'Resource server credentials created',
  'admin.resource_server_deleted': 'Resource server credentials revoked',
  'admin.signup_changed': 'Sign-up switched',
  'admin.org_suspended': 'Organization suspended',
  'admin.org_reactivated': 'Organization reactivated',
  'admin.org_deleted': 'Organization deleted by admin',
  'org.created': 'Organization created',
  'org.renamed': 'Organization renamed',
  'org.deleted': 'Organization deleted',
  'org.deletion_delivered': 'Organization deletion delivered to a service',
  'org.invited': 'Invited to an organization',
  'org.invitation_revoked': 'Organization invitation withdrawn',
  'org.invitation_declined': 'Organization invitation declined',
  'org.joined': 'Joined an organization',
  'org.role_changed': 'Organization role changed',
  'org.member_removed': 'Removed from an organization',
  'org.left': 'Left an organization',
  'org.ownership_passed': 'Became owner (previous owner deleted)',
  'org.domain_added': 'Organization domain added',
  'org.domain_verified': 'Organization domain verified',
  'org.domain_removed': 'Organization domain removed',
  'org.scim_token_created': 'Directory sync token created',
  'org.scim_token_revoked': 'Directory sync token revoked',
  'scim.user_created': 'Directory provisioned a user',
  'scim.user_updated': 'Directory updated a user',
  'scim.user_deleted': 'Directory removed a user',
  'scim.member_added': 'Directory added a member',
  'scim.member_removed': 'Directory removed a member',
};

/** Events worth a second look when scanning the log. */
const ALERT_EVENTS =
  /\.(failed|denied|locked|refused|code_refused|code_failed)$|^admin\.(user_deleted|mfa_reset|signup_changed)$/;

function eventCell(event: string): string {
  const label = (EVENT_LABEL as Record<string, string | undefined>)[event] ?? event;
  return `<span title="${escapeHtml(event)}"${ALERT_EVENTS.test(event) ? ' class="log-alert"' : ''}>${escapeHtml(label)}</span>`;
}

/** An app's client ID as its host (a URL for CIMD clients), the full ID on hover. */
function appCell(clientId: string | null): string {
  if (!clientId) return '–';
  let shown = clientId;
  try {
    shown = new URL(clientId).host;
  } catch {
    // A pre-registered client's ID isn't a URL; show it as it is.
  }
  return `<span title="${escapeHtml(clientId)}">${escapeHtml(shown)}</span>`;
}

/** The detail JSON as `key: value` lines; anything else as written. */
function detailCell(detail: string | null): string {
  if (!detail) return '';
  try {
    const parsed = JSON.parse(detail) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return Object.entries(parsed as Record<string, unknown>)
        .map(
          ([key, value]) =>
            `<span class="kv"><span class="k">${escapeHtml(key)}</span> ${escapeHtml(typeof value === 'string' ? value : JSON.stringify(value))}</span>`,
        )
        .join('');
    }
  } catch {
    // Not JSON: shown below as written.
  }
  return `<code>${escapeHtml(detail)}</code>`;
}

export function adminLogPage(params: {
  events: AdminLogEvent[];
  filter: string;
  limit: number;
}): string {
  const options = LOG_FILTERS.map(
    ([value, label]) =>
      `<option value="${value}"${value === params.filter ? ' selected' : ''}>${label}</option>`,
  ).join('');
  const rows = params.events
    .map(
      (e) =>
        '<tr>' +
        `<td class="nowrap">${dateTime(e.at)}</td>` +
        `<td>${eventCell(e.event)}</td>` +
        `<td>${escapeHtml(e.account ?? '–')}</td>` +
        `<td class="clip">${appCell(e.clientId)}</td>` +
        `<td class="nowrap">${escapeHtml(e.ipPrefix ?? '–')}</td>` +
        `<td class="clip">${detailCell(e.detail)}</td>` +
        '</tr>',
    )
    .join('');
  return adminPage(
    'log',
    'Security log',
    '<form method="get" action="/admin/log" class="inline-form">' +
      `<label class="field"><span>Show</span><select name="event">${options}</select></label>` +
      '<button class="button secondary" type="submit">Filter</button></form>' +
      `<p class="section-text">The latest ${String(params.limit)} events, times in UTC. Entries are kept for 90 days.</p>` +
      (params.events.length === 0
        ? '<p class="empty">No events.</p>'
        : '<div class="table-wrap"><table class="log"><thead><tr>' +
          '<th scope="col">Time</th><th scope="col">Event</th><th scope="col">Account</th>' +
          '<th scope="col">App</th><th scope="col">Network</th><th scope="col">Detail</th>' +
          `</tr></thead><tbody>${rows}</tbody></table></div>`),
  );
}

export function adminNeedsFactorPage(): string {
  return page(
    'Admin',
    '<h1>Admin needs a second factor</h1>' +
      '<p class="lede">The admin area opens only after you confirm it’s you with a passkey or authenticator app.</p>' +
      '<a class="button primary" href="/account/security">Set up a second factor</a>',
    { section: 'Admin' },
  );
}
