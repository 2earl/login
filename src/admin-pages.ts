import type { AuditEvent } from './audit';
import type { PendingNotices } from './deletion-notices';
import type { ResourceServer } from './introspection';
import type { SetupInvitation } from './org-setup';
import { escapeHtml, formatDate, page } from './pages';
import { STAFF_LABEL, staffCan, type StaffMember, type StaffRole } from './staff';

/**
 * Server-rendered pages for /admin (DESIGN §4.6, §4.29). For 2earl staff; each page and action
 * shows only what the viewer's role may do (`staffCan`). Every value is escaped.
 */

export type AdminTab = 'users' | 'invitations' | 'orgs' | 'apps' | 'log' | 'team';

const TABS: [AdminTab, string, string, (role: StaffRole) => boolean][] = [
  ['users', 'Users', '/admin/users', staffCan.view],
  ['orgs', 'Organizations', '/admin/orgs', staffCan.view],
  ['invitations', 'Sign-up', '/admin/invitations', staffCan.manageSignUp],
  ['apps', 'Apps', '/admin/apps', staffCan.manageApps],
  ['log', 'Security log', '/admin/log', staffCan.view],
  ['team', 'Staff', '/admin/team', staffCan.manageStaff],
];

/** Who is looking, and the flash message. */
export interface AdminView {
  role: StaffRole;
  notice?: string | undefined;
  error?: string | undefined;
}

function adminPage(tab: AdminTab, title: string, body: string, flash: AdminView): string {
  const nav =
    '<nav class="tabs" aria-label="Admin">' +
    TABS.filter(([, , , allowed]) => allowed(flash.role))
      .map(
        ([key, label, href]) =>
          `<a href="${href}"${key === tab ? ' aria-current="page"' : ''}>${label}</a>`,
      )
      .join('') +
    `<span class="tag tag-muted admin-role">${STAFF_LABEL[flash.role]}</span>` +
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
  /** 2earl staff: 'owner', 'admin', 'support', or null (§4.29). */
  staff: StaffRole | null;
  /** The organization that manages the account (DESIGN §4.18), and whether it deactivated it. */
  managedBy: string | null;
  deactivatedByOrg: boolean;
}

function userRow(user: AdminUser, viewer: StaffRole): string {
  const who = escapeHtml(user.email ?? user.id);
  const meta = [
    user.name ? escapeHtml(user.name) : null,
    `Joined ${formatDate(user.createdAt)}`,
    user.methods.length
      ? `signs in with ${user.methods.map((m) => (m === 'google' ? 'Google' : 'email code')).join(' and ')}`
      : null,
    user.lastSignInAt ? `last sign-in ${dateTime(user.lastSignInAt)} UTC` : 'never signed in',
    user.factors > 0 ? `second factor: ${String(user.factors)}` : 'no second factor',
    user.managedBy ? `managed by ${escapeHtml(user.managedBy)}` : null,
  ]
    .filter(Boolean)
    .join(' · ');
  const badges =
    (user.staff ? `<span class="tag">${STAFF_LABEL[user.staff]}</span>` : '') +
    (user.status === 'suspended'
      ? user.deactivatedByOrg
        ? '<span class="tag tag-alert">Deactivated by its organization</span>'
        : '<span class="tag tag-alert">Suspended</span>'
      : '') +
    (user.managedBy ? '<span class="tag tag-muted">Managed</span>' : '');

  let actions: string;
  if (user.staff === 'owner') {
    actions =
      viewer === 'owner'
        ? '<p class="row-note">Manage your own account on the account page.</p>'
        : '<p class="row-note">Only the owner changes the owner’s account.</p>';
  } else if (!staffCan.actOn(viewer, user.staff)) {
    actions = '<p class="row-note">Staff accounts are managed by the owner.</p>';
  } else {
    const manage = staffCan.manageUsers(viewer);
    actions =
      '<div class="row-actions">' +
      (user.status === 'active'
        ? actionForm('/admin/users', { action: 'sign_out', user: user.id }, 'Sign out everywhere')
        : '') +
      (manage
        ? (user.status === 'suspended'
            ? actionForm('/admin/users', { action: 'reactivate', user: user.id }, 'Reactivate')
            : actionForm('/admin/users', { action: 'suspend', user: user.id }, 'Suspend')) +
          (user.factors > 0
            ? actionForm(
                '/admin/users',
                { action: 'reset_mfa', user: user.id },
                'Reset second factor',
              )
            : '') +
          '<details class="confirm-delete"><summary>Delete…</summary>' +
          '<form method="post" action="/admin/users">' +
          '<input type="hidden" name="action" value="delete">' +
          `<input type="hidden" name="user" value="${escapeHtml(user.id)}">` +
          `<label class="confirm"><input type="checkbox" name="confirm" value="on" required><span>Delete ${who} and disconnect their apps. This can’t be undone.</span></label>` +
          '<button class="button danger small" type="submit">Delete account</button></form></details>'
        : '') +
      '</div>';
  }

  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${who}${badges}</p>` +
    `<p class="app-meta">${meta}</p></div>` +
    actions +
    '</li>'
  );
}

export function adminUsersPage(
  params: AdminView & { users: AdminUser[]; pending: PendingNotices[]; query?: string },
): string {
  const query = params.query ?? '';
  return adminPage(
    'users',
    'Users',
    '<form method="get" action="/admin/users" class="inline-form" role="search">' +
      '<label class="field"><span>Find by email address or name</span>' +
      `<input name="q" type="search" maxlength="254" autocomplete="off" spellcheck="false" value="${escapeHtml(query)}"></label>` +
      '<button class="button secondary" type="submit">Find</button>' +
      (query ? '<a class="button secondary" href="/admin/users">Show all</a>' : '') +
      '</form>' +
      `<p class="section-text">${String(params.users.length)} ${params.users.length === 1 ? 'account' : 'accounts'}${query ? ' found' : ''}. ` +
      (staffCan.manageUsers(params.role)
        ? 'Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.'
        : 'Signing someone out everywhere ends every session and disconnects their apps; they can sign in again at once. Ask an admin to suspend or delete an account.') +
      '</p>' +
      (params.users.length > 0
        ? `<ul class="admin-list">${params.users.map((u) => userRow(u, params.role)).join('')}</ul>`
        : '<p class="empty">No account matches.</p>') +
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

export function adminInvitationsPage(
  params: AdminView & { invitations: AdminInvitation[]; locked: boolean },
): string {
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
    'Sign-up',
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
  /** The company setup (DESIGN §4.16–§4.19). */
  domains: number;
  verifiedDomains: number;
  managedDomains: number;
  managedAccounts: number;
  sso: 'off' | 'on' | 'required';
  directoryTokens: number;
  rules: boolean;
}

function orgRow(org: AdminOrg, viewer: StaffRole): string {
  const meta = [
    `${String(org.members)} ${org.members === 1 ? 'member' : 'members'}`,
    org.invitations > 0 ? `${String(org.invitations)} open invitations` : null,
    org.owners.length > 0 ? `owners: ${org.owners.map(escapeHtml).join(', ')}` : null,
    `created ${formatDate(org.createdAt)}`,
    `<code>${escapeHtml(org.id)}</code>`,
  ]
    .filter(Boolean)
    .join(' · ');
  const company = [
    org.domains > 0
      ? `domains: ${String(org.verifiedDomains)} verified of ${String(org.domains)}, ${String(org.managedDomains)} managed`
      : 'no domains',
    org.managedAccounts > 0 ? `${String(org.managedAccounts)} managed accounts` : null,
    org.sso === 'off' ? 'SSO off' : org.sso === 'required' ? 'SSO required' : 'SSO on',
    org.directoryTokens > 0 ? `directory sync: ${String(org.directoryTokens)} tokens` : null,
    org.rules ? 'security rules set' : null,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name"><a href="/admin/orgs/${escapeHtml(org.id)}">${escapeHtml(org.name)}</a>` +
    (org.status === 'suspended' ? '<span class="tag tag-alert">Suspended</span>' : '') +
    `</p><p class="app-meta">${meta}</p><p class="app-meta">${company}</p></div>` +
    (staffCan.manageOrgs(viewer)
      ? '<div class="row-actions">' +
        (org.status === 'suspended'
          ? actionForm('/admin/orgs', { action: 'reactivate', org: org.id }, 'Reactivate')
          : actionForm('/admin/orgs', { action: 'suspend', org: org.id }, 'Suspend')) +
        '<details class="confirm-delete"><summary>Delete…</summary>' +
        '<form method="post" action="/admin/orgs">' +
        '<input type="hidden" name="action" value="delete">' +
        `<input type="hidden" name="org" value="${escapeHtml(org.id)}">` +
        `<label class="confirm"><input type="checkbox" name="confirm" value="on" required><span>Delete ${escapeHtml(org.name)}, its memberships and invitations. Members keep their accounts. This can’t be undone.</span></label>` +
        '<button class="button danger small" type="submit">Delete organization</button></form></details>' +
        '</div>'
      : '') +
    '</li>'
  );
}

function setupRow(inv: SetupInvitation, viewer: StaffRole, now: number): string {
  const open = inv.usedAt === null && inv.expiresAt > now;
  const state = inv.usedAt
    ? inv.orgId
      ? `<span class="tag">Set up</span> as <a href="/admin/orgs/${escapeHtml(inv.orgId)}">${escapeHtml(inv.orgNow ?? 'an organization')}</a> on ${formatDate(inv.usedAt)}`
      : `<span class="tag tag-muted">Set up</span> on ${formatDate(inv.usedAt)} (organization since deleted)`
    : open
      ? `<span class="tag tag-muted">Waiting</span> until ${formatDate(inv.expiresAt)}`
      : `<span class="tag tag-alert">Expired</span> ${formatDate(inv.expiresAt)}`;
  const meta = [
    inv.orgName ? `suggested name “${escapeHtml(inv.orgName)}”` : null,
    `invited ${formatDate(inv.createdAt)}${inv.invitedBy ? ` by ${escapeHtml(inv.invitedBy)}` : ''}`,
    inv.sentAt > inv.createdAt ? `sent again ${dateTime(inv.sentAt)} UTC` : null,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${escapeHtml(inv.email)}</p>` +
    `<p class="app-meta">${state}</p><p class="app-meta">${meta}</p></div>` +
    (open
      ? '<div class="row-actions">' +
        (staffCan.resendOrgInvitations(viewer)
          ? actionForm('/admin/orgs', { action: 'setup_resend', invitation: inv.id }, 'Send again')
          : '') +
        (staffCan.createOrgs(viewer)
          ? actionForm(
              '/admin/orgs',
              { action: 'setup_withdraw', invitation: inv.id },
              'Withdraw',
              'danger',
            )
          : '') +
        '</div>'
      : '') +
    '</li>'
  );
}

export function adminOrgsPage(
  params: AdminView & {
    orgs: AdminOrg[];
    setup: SetupInvitation[];
    now: number;
    form?: { email: string; name: string };
  },
): string {
  const canCreate = staffCan.createOrgs(params.role);
  return adminPage(
    'orgs',
    'Organizations',
    '<section class="section section-first" aria-labelledby="setup-heading">' +
      '<h2 id="setup-heading">Invite an organization</h2>' +
      (canCreate
        ? '<p class="section-text">Organizations are set up by invitation. The person you invite signs in with the address (or creates an account with it), names the organization and becomes its owner: its top admin, who adds the other admins and members.</p>' +
          '<form method="post" action="/admin/orgs" class="stack-form">' +
          '<input type="hidden" name="action" value="setup_invite">' +
          '<label class="field"><span>Email address</span>' +
          `<input name="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false" value="${escapeHtml(params.form?.email ?? '')}"></label>` +
          '<label class="field"><span>Organization name (optional; they can change it)</span>' +
          `<input name="name" type="text" maxlength="60" autocomplete="off" value="${escapeHtml(params.form?.name ?? '')}"></label>` +
          '<div class="consent-actions"><button class="button primary" type="submit">Send invitation</button>' +
          '<a class="button secondary" href="/orgs/new">Create one yourself</a></div></form>'
        : '<p class="section-text">Owners and admins of 2earl invite organizations. You can send an invitation that is still waiting again.</p>') +
      (params.setup.length > 0
        ? `<ul class="admin-list">${params.setup.map((i) => setupRow(i, params.role, params.now)).join('')}</ul>`
        : '<p class="empty">No invitations yet.</p>') +
      '</section>' +
      '<section class="section" aria-labelledby="orgs-heading">' +
      '<h2 id="orgs-heading">Organizations</h2>' +
      `<p class="section-text">${String(params.orgs.length)} ${params.orgs.length === 1 ? 'organization' : 'organizations'}. Open one to see its members and setup. Suspending one freezes it: members can only leave, and 2earl services stop seeing it.</p>` +
      (params.orgs.length > 0
        ? `<ul class="admin-list">${params.orgs.map((o) => orgRow(o, params.role)).join('')}</ul>`
        : '<p class="empty">No organizations yet.</p>') +
      '</section>',
    params,
  );
}

export interface AdminOrgDetail {
  org: AdminOrg;
  members: {
    userId: string;
    email: string | null;
    name: string | null;
    role: string;
    joinedAt: number;
    managed: boolean;
  }[];
  invitations: { email: string; role: string; expiresAt: number }[];
  domains: { domain: string; verified: boolean; managed: boolean }[];
  activity: { at: number; event: string; actor: string | null }[];
}

/** One organization, for helping it (§4.29). Opening it is in the organization's own activity. */
export function adminOrgPage(params: AdminView & { detail: AdminOrgDetail }): string {
  const d = params.detail;
  const members = d.members
    .map(
      (m) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(m.email ?? m.userId)}<span class="tag">${escapeHtml(m.role)}</span>${m.managed ? '<span class="tag tag-muted">Managed</span>' : ''}</p>` +
        `<p class="app-meta">${m.name ? `${escapeHtml(m.name)} · ` : ''}joined ${formatDate(m.joinedAt)}</p>` +
        '</div></li>',
    )
    .join('');
  const rows = d.activity
    .map(
      (e) =>
        '<tr>' +
        `<td class="nowrap">${dateTime(e.at)}</td>` +
        `<td>${eventCell(e.event)}</td>` +
        `<td>${escapeHtml(e.actor ?? '–')}</td>` +
        '</tr>',
    )
    .join('');
  return adminPage(
    'orgs',
    d.org.name,
    '<p class="crumb"><a href="/admin/orgs">Organizations</a></p>' +
      `<ul class="admin-list">${orgRow(d.org, params.role)}</ul>` +
      '<p class="note">The organization sees in its activity that 2earl staff opened this page (not who).</p>' +
      '<section class="section" aria-labelledby="members-heading">' +
      `<h2 id="members-heading">Members <span class="count">${String(d.members.length)}</span></h2>` +
      (members ? `<ul class="admin-list">${members}</ul>` : '<p class="empty">No members.</p>') +
      (d.invitations.length > 0
        ? '<h3 class="subhead">Open invitations</h3><ul class="admin-list">' +
          d.invitations
            .map(
              (i) =>
                `<li class="admin-row"><div class="app-main"><p class="app-name">${escapeHtml(i.email)}<span class="tag tag-muted">${escapeHtml(i.role)}</span></p><p class="app-meta">until ${formatDate(i.expiresAt)}</p></div></li>`,
            )
            .join('') +
          '</ul>'
        : '') +
      '</section>' +
      '<section class="section" aria-labelledby="domains-heading">' +
      '<h2 id="domains-heading">Domains</h2>' +
      (d.domains.length > 0
        ? '<ul class="admin-list">' +
          d.domains
            .map(
              (x) =>
                `<li class="admin-row"><div class="app-main"><p class="app-name">${escapeHtml(x.domain)}${x.verified ? '<span class="tag">Verified</span>' : '<span class="tag tag-muted">Not verified</span>'}${x.managed ? '<span class="tag">Managed</span>' : ''}</p></div></li>`,
            )
            .join('') +
          '</ul>'
        : '<p class="empty">No domains.</p>') +
      '</section>' +
      '<section class="section" aria-labelledby="activity-heading">' +
      '<h2 id="activity-heading">Recent activity</h2>' +
      (rows
        ? '<div class="table-wrap"><table class="log"><thead><tr><th scope="col">Time (UTC)</th><th scope="col">Event</th><th scope="col">By</th></tr></thead>' +
          `<tbody>${rows}</tbody></table></div>`
        : '<p class="empty">No activity.</p>') +
      '</section>',
    params,
  );
}

// ---- Staff (DESIGN §4.29) -------------------------------------------------------------------

export function adminTeamPage(
  params: AdminView & { staff: StaffMember[]; form?: { email: string } },
): string {
  const rows = params.staff
    .map(
      (m) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(m.email ?? m.userId)}<span class="tag">${STAFF_LABEL[m.role]}</span></p>` +
        `<p class="app-meta">${m.name ? `${escapeHtml(m.name)} · ` : ''}since ${formatDate(m.grantedAt)}${m.grantedBy ? ` · given by ${escapeHtml(m.grantedBy)}` : ''}</p>` +
        '</div><div class="row-actions">' +
        actionForm(
          '/admin/team',
          { action: 'grant_user', user: m.userId, role: m.role === 'admin' ? 'support' : 'admin' },
          m.role === 'admin' ? 'Make support' : 'Make admin',
        ) +
        actionForm(
          '/admin/team',
          { action: 'revoke', user: m.userId },
          'Remove from staff',
          'danger',
        ) +
        '</div></li>',
    )
    .join('');
  return adminPage(
    'team',
    'Staff',
    '<p class="section-text"><strong>Admins</strong> run 2earl: users, sign-up, organizations and their invitations, apps. They can’t give or take staff roles or act on other staff. <strong>Support</strong> helps people and organizations: sees users, organizations and the security log, signs a person out everywhere, sends a waiting organization invitation again. Only you, the owner, change who is staff. Staff need a second factor.</p>' +
      '<form method="post" action="/admin/team" class="inline-form">' +
      '<input type="hidden" name="action" value="grant">' +
      '<label class="field"><span>Email address of an existing account</span>' +
      `<input name="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false" value="${escapeHtml(params.form?.email ?? '')}"></label>` +
      '<label class="field"><span>Role</span><select name="role"><option value="support">Support</option><option value="admin">Admin</option></select></label>' +
      '<button class="button primary" type="submit">Add to staff</button></form>' +
      (rows ? `<ul class="admin-list">${rows}</ul>` : '<p class="empty">No staff besides you.</p>'),
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

export function adminAppsPage(
  params: AdminView & {
    trusted: AdminTrustedApp[];
    registered: AdminRegisteredApp[];
    resourceServers?: ResourceServer[];
    /** Resources a resource server can be created for. */
    resources?: { resource: string; label: string }[];
    /** Just-created credentials: the only time the secret is shown. */
    created?: { id: string; secret: string } | undefined;
    notice?: string | undefined;
    error?: string | undefined;
  },
): string {
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
  'admin.org_viewed': 'Organization opened by staff',
  'admin.org_setup_invited': 'Invited someone to set up an organization',
  'admin.org_setup_resent': 'Organization setup invitation sent again',
  'admin.org_setup_withdrawn': 'Organization setup invitation withdrawn',
  'admin.user_signed_out': 'User signed out everywhere by staff',
  'admin.staff_granted': 'Staff role given',
  'admin.staff_revoked': 'Staff role removed',
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
  'org.saml_saved': 'Single sign-on settings saved',
  'org.domain_managed': 'Organization manages a domain',
  'org.domain_unmanaged': 'Organization stopped managing a domain',
  'org.require_sso_changed': 'Organization changed required SSO',
  'org.policy_changed': 'Organization changed its security rules',
  'org.oidc_saved': 'Organization saved OpenID Connect sign-on',
  'org.account_managed': 'Account became managed',
  'org.account_kept_personal': 'Account kept personal',
  'org.accounts_released': 'Managed accounts released',
  'org.account_deactivated': 'Organization deactivated an account',
  'org.account_reactivated': 'Organization reactivated an account',
  'org.account_signed_out': 'Organization signed an account out everywhere',
  'org.sso_expiry_warned': 'Owners warned that SSO credentials expire',
  'org.saml_metadata_refreshed': 'SAML certificates refreshed from metadata',
  'org.account_deleted': 'Organization deleted an account',
  'org.account_deletion_due': 'Scheduled deletion of a managed account',
  'scim.account_created': 'Directory created a managed account',
  'scim.group_created': 'Directory created a group',
  'scim.group_updated': 'Directory changed a group',
  'scim.group_deleted': 'Directory deleted a group',
  'scim.role_changed': 'Directory changed a role',
  'org.group_role_changed': 'Organization gave a directory group a role',
  'org.apps_restricted': 'Organization changed which apps its accounts may use',
  'org.app_allowed': 'Organization allowed an app',
  'org.app_disallowed': 'Organization removed an allowed app',
  'org.audit_exported': 'Organization downloaded its audit log',
  'org.audit_stream_changed': 'Organization changed its audit stream',
  'org.api_key_created': 'Organization created an API key',
  'org.api_key_revoked': 'Organization revoked an API key',
  'scim.account_deactivated': 'Directory deactivated an account',
  'scim.account_reactivated': 'Directory reactivated an account',
  'scim.account_deletion_scheduled': 'Directory scheduled an account deletion',
  'scim.user_created': 'Directory provisioned a user',
  'scim.user_updated': 'Directory updated a user',
  'scim.user_deleted': 'Directory removed a user',
  'scim.member_added': 'Directory added a member',
  'scim.member_removed': 'Directory removed a member',
};

/** Events worth a second look when scanning the log. */
const ALERT_EVENTS =
  /\.(failed|denied|locked|refused|code_refused|code_failed)$|^admin\.(user_deleted|mfa_reset|signup_changed|staff_granted|staff_revoked)$/;

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

export function adminLogPage(
  params: AdminView & { events: AdminLogEvent[]; filter: string; limit: number },
): string {
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
    params,
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
