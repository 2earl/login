import {
  ORG_NAME_MAX,
  ROLE_LABEL,
  canInvite,
  canManageOrganization,
  canRemove,
  canSetRole,
  type Member,
  type OpenInvitation,
  type OrgRole,
  type OrgSummary,
  type Organization,
  type InvitationView,
} from './orgs';
import { challengeRecordName, type OrgDomain } from './org-domains';
import {
  MAX_RANGES,
  POLICY_METHODS,
  SESSION_HOURS,
  isDefaultPolicy,
  type OrgPolicy,
  type PolicyMethod,
} from './org-policy';
import { escapeHtml, formatDate, formatDateTime, page } from './pages';
import type { ScimTokenInfo } from './scim';
import type { GroupSummary } from './scim-groups';
import type { AuditStream } from './org-audit';
import { MAX_KEYS, type ApiKeyInfo } from './org-api';
import { dateValue } from './sso-upkeep';

/** Server-rendered pages for organizations (DESIGN §4.14). Every value is escaped. */

const ROLE_HELP: Record<OrgRole, string> = {
  owner: 'Owners can do everything, including renaming and deleting the organization.',
  admin: 'Admins can invite people, remove members and admins, and change their roles.',
  member: 'Members can see who else is in the organization.',
};

function firstLetter(text: string | null): string {
  return (Array.from((text ?? '?').trim())[0] ?? '?').toUpperCase();
}

function hidden(fields: Record<string, string>): string {
  return Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`)
    .join('');
}

function flash(params: { notice?: string | undefined; error?: string | undefined }): string {
  return (
    (params.notice ? `<p class="notice" role="status">${escapeHtml(params.notice)}</p>` : '') +
    (params.error ? `<p class="warning" role="alert">${escapeHtml(params.error)}</p>` : '')
  );
}

export type OrgTab = 'members' | 'activity' | 'directory' | 'settings';

/** The organization's name, your role, and its tabs: the same on each of its pages. */
export function orgHeader(org: Organization, role: OrgRole, tab: OrgTab): string {
  const base = `/orgs/${escapeHtml(org.id)}`;
  const tabs: [OrgTab, string, string, boolean][] = [
    ['members', 'Members', base, true],
    ['activity', 'Activity', `${base}/activity`, role !== 'member'],
    ['directory', 'Domains & SSO', `${base}/directory`, role === 'owner'],
    ['settings', 'Settings', `${base}/settings`, true],
  ];
  return (
    '<header class="org-head">' +
    '<p class="crumb"><a href="/account/orgs">Organizations</a></p>' +
    `<div class="org-title"><h1>${escapeHtml(org.name)}</h1><span class="role-badge role-${role}">${escapeHtml(ROLE_LABEL[role])}</span></div>` +
    (org.status === 'active'
      ? ''
      : '<p class="warning" role="alert">This organization is suspended by 2earl. Nothing in it can be changed, and 2earl services don’t see it. Write to us through the contact form on 2earl.com if you think that’s a mistake.</p>') +
    '<nav class="tabs" aria-label="Organization">' +
    tabs
      .filter(([, , , shown]) => shown)
      .map(
        ([key, label, href]) =>
          `<a href="${href}"${key === tab ? ' aria-current="page"' : ''}>${escapeHtml(label)}</a>`,
      )
      .join('') +
    '</nav></header>'
  );
}

/** The account page's list of the account's organizations. */
export function organizationsSection(orgs: OrgSummary[]): string {
  // Each row is one link, the whole row: name, your role and its size.
  const items = orgs
    .map(
      (o) =>
        `<li><a class="org-row" href="/orgs/${escapeHtml(o.id)}">` +
        `<span class="avatar avatar-sm avatar-square" aria-hidden="true">${escapeHtml(firstLetter(o.name))}</span>` +
        `<span class="org-row-main"><span class="person-name">${escapeHtml(o.name)}` +
        (o.status === 'suspended' ? ' <span class="tag tag-alert">Suspended</span>' : '') +
        '</span>' +
        `<span class="person-meta">${String(o.members)} ${o.members === 1 ? 'member' : 'members'}</span></span>` +
        `<span class="role-badge role-${o.role}">${escapeHtml(ROLE_LABEL[o.role])}</span>` +
        '</a></li>',
    )
    .join('');
  return (
    '<section class="section section-first" aria-label="Your organizations">' +
    (orgs.length > 0
      ? `<ul class="people">${items}</ul>`
      : '<p class="empty">You’re not in an organization yet. Create one, or accept an invitation someone sends you.</p>') +
    '<div class="data-actions"><a class="button primary" href="/orgs/new">Create an organization</a></div>' +
    '</section>'
  );
}

export function newOrgPage(params: { name?: string; error?: string } = {}): string {
  return page(
    'Create an organization',
    '<p class="crumb"><a href="/account/orgs">Organizations</a></p>' +
      '<h1>Create an organization</h1>' +
      '<p class="lede">You become its owner. Then invite people by email; each one joins with their own 2earl account.</p>' +
      '<form method="post" action="/orgs" class="code-form" novalidate>' +
      '<label class="field"><span>Name</span>' +
      `<input name="name" type="text" required maxlength="${String(ORG_NAME_MAX)}" autocomplete="organization" value="${escapeHtml(params.name ?? '')}"${params.error ? ' aria-invalid="true" aria-describedby="name-error"' : ''}></label>` +
      (params.error
        ? `<p class="field-error" id="name-error">${escapeHtml(params.error)}</p>`
        : '') +
      '<div class="consent-actions"><button class="button primary" type="submit">Create organization</button>' +
      '<a class="button secondary" href="/account">Cancel</a></div>' +
      '</form>',
  );
}

function memberRow(
  base: string,
  member: Member,
  actor: { userId: string; role: OrgRole },
  editable: boolean,
): string {
  const me = member.userId === actor.userId;
  const who = escapeHtml(member.name ?? member.email ?? 'A 2earl account');
  const meta = [
    member.name && member.email ? escapeHtml(member.email) : null,
    `joined ${formatDate(member.joinedAt)}`,
  ]
    .filter(Boolean)
    .join(' · ');
  // A role the directory decides can only become owner here (DESIGN §4.21).
  const roles = (['member', 'admin', 'owner'] as const).filter(
    (r) =>
      r !== member.role &&
      canSetRole(actor.role, member.role, r) &&
      (!member.roleFromDirectory || r === 'owner'),
  );
  const actions =
    !editable || me
      ? ''
      : '<div class="row-actions">' +
        (roles.length > 0
          ? `<form method="post" action="${base}/members/role" class="role-form">` +
            hidden({ user: member.userId }) +
            `<select class="role-select" name="role" aria-label="New role for ${who}">` +
            roles
              .map((r) => `<option value="${r}">Make ${ROLE_LABEL[r].toLowerCase()}</option>`)
              .join('') +
            '</select><button class="button secondary small" type="submit">Change</button></form>'
          : '') +
        (canRemove(actor.role, member.role)
          ? member.managed
            ? // A managed account is deactivated, not removed (DESIGN §4.18).
              (member.deactivated
                ? ''
                : `<form method="post" action="${base}/members/sign-out">` +
                  hidden({ user: member.userId }) +
                  `<button class="button secondary small" type="submit" aria-label="Sign ${who} out everywhere">Sign out everywhere</button></form>`) +
              `<form method="post" action="${base}/members/${member.deactivated ? 'reactivate' : 'deactivate'}">` +
              hidden({ user: member.userId }) +
              `<button class="button secondary small" type="submit">${member.deactivated ? 'Reactivate' : 'Deactivate'}</button></form>` +
              (actor.role === 'owner'
                ? `<a class="button danger-outline small" href="${base}/accounts/delete?user=${encodeURIComponent(member.userId)}">Delete account…</a>`
                : '')
            : `<form method="post" action="${base}/members/remove">` +
              hidden({ user: member.userId }) +
              '<button class="button secondary small" type="submit">Remove</button></form>'
          : '') +
        '</div>';
  return (
    '<li class="person">' +
    `<span class="avatar avatar-sm" aria-hidden="true">${escapeHtml(firstLetter(member.name ?? member.email))}</span>` +
    `<div class="person-main"><p class="person-name">${who}${me ? ' <span class="tag">You</span>' : ''} <span class="role-badge role-${member.role}">${escapeHtml(ROLE_LABEL[member.role])}</span>` +
    (member.managed ? ' <span class="tag tag-muted">Managed</span>' : '') +
    (member.roleFromDirectory ? ' <span class="tag tag-muted">Role from directory</span>' : '') +
    (member.deactivated ? ' <span class="tag tag-alert">Deactivated</span>' : '') +
    '</p>' +
    `<p class="person-meta">${meta}</p></div>` +
    actions +
    '</li>'
  );
}

function invitationRow(base: string, invitation: OpenInvitation, editable: boolean): string {
  return (
    '<li class="person person-pending">' +
    '<span class="avatar avatar-sm avatar-pending" aria-hidden="true">@</span>' +
    `<div class="person-main"><p class="person-name">${escapeHtml(invitation.email)} <span class="tag tag-muted">Invited</span></p>` +
    `<p class="person-meta">${escapeHtml(ROLE_LABEL[invitation.role])}` +
    (invitation.invitedBy ? ` · by ${escapeHtml(invitation.invitedBy)}` : '') +
    ` · until ${formatDate(invitation.expiresAt)}</p></div>` +
    (editable
      ? '<div class="row-actions">' +
        `<form method="post" action="${base}/invitations/revoke">` +
        hidden({ invitation: invitation.id }) +
        '<button class="button secondary small" type="submit">Withdraw</button></form></div>'
      : '') +
    '</li>'
  );
}

export function orgPage(params: {
  org: Organization;
  role: OrgRole;
  userId: string;
  members: Member[];
  invitations: OpenInvitation[];
  notice?: string | undefined;
  error?: string | undefined;
  email?: string;
  /** For owners: how far the company setup is (steps done of 5), to point them to it. */
  setup?: SetupState;
}): string {
  const { org, role } = params;
  const base = `/orgs/${escapeHtml(org.id)}`;
  const active = org.status === 'active';
  const inviting = active && canInvite(role);
  const setupDone = params.setup ? setupSteps(params.setup).filter((s) => s.done).length : 5;
  return page(
    org.name,
    orgHeader(org, role, 'members') +
      flash(params) +
      (active && role === 'owner' && params.setup && setupDone < 5
        ? '<aside class="setup-callout" aria-labelledby="setup-callout-heading">' +
          `<h2 id="setup-callout-heading">Set up ${escapeHtml(org.name)} for your company</h2>` +
          `<p>Verify your domain, manage your people’s accounts, connect your single sign-on and directory, and set security rules. ${String(setupDone)} of 5 done.</p>` +
          `<a class="button primary" href="${base}/directory">${setupDone === 0 ? 'Start' : 'Continue'}</a>` +
          '</aside>'
        : '') +
      (inviting
        ? '<section class="section section-first invite-panel" aria-labelledby="invite-heading">' +
          '<h2 id="invite-heading">Invite people</h2>' +
          `<form method="post" action="${base}/invitations" class="invite-form" novalidate>` +
          '<label class="field invite-email"><span>Email address</span>' +
          `<input name="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false" placeholder="name@example.com" value="${escapeHtml(params.email ?? '')}"></label>` +
          '<label class="field invite-role"><span>Role</span><select name="role">' +
          '<option value="member">Member</option><option value="admin">Admin</option></select></label>' +
          '<button class="button primary" type="submit">Send invitation</button></form>' +
          '<p class="note">The link works for 7 days, for that address only. Owners are made from members once they’ve joined.</p>' +
          '</section>'
        : '') +
      '<section class="section' +
      (inviting ? '' : ' section-first') +
      '" aria-labelledby="members-heading">' +
      `<h2 id="members-heading">Members <span class="count">${String(params.members.length)}</span></h2>` +
      `<p class="section-text">${escapeHtml(ROLE_HELP[role])} Everyone here sees each member’s name and email address.</p>` +
      `<ul class="people">${params.members.map((m) => memberRow(base, m, { userId: params.userId, role }, active)).join('')}</ul>` +
      '</section>' +
      (params.invitations.length > 0
        ? '<section class="section" aria-labelledby="pending-heading">' +
          `<h2 id="pending-heading">Waiting to join <span class="count">${String(params.invitations.length)}</span></h2>` +
          `<ul class="people">${params.invitations.map((i) => invitationRow(base, i, inviting)).join('')}</ul>` +
          '</section>'
        : ''),
    { section: 'Organization' },
  );
}

/** Renaming, leaving and deleting. */
export function orgSettingsPage(params: {
  org: Organization;
  role: OrgRole;
  owners: number;
  /** The organization manages the viewer's account: they can't leave (DESIGN §4.18). */
  managed?: boolean;
  /** Owners: the organization's API keys (DESIGN §4.24), and a just-created one. */
  apiKeys?: ApiKeyInfo[];
  newKey?: string;
  issuer?: string;
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  const { org, role } = params;
  const base = `/orgs/${escapeHtml(org.id)}`;
  const active = org.status === 'active';
  const lastOwner = role === 'owner' && params.owners === 1;
  return page(
    `${org.name}: settings`,
    orgHeader(org, role, 'settings') +
      flash(params) +
      '<section class="section section-first" aria-labelledby="name-heading">' +
      '<h2 id="name-heading">Name</h2>' +
      (active && canManageOrganization(role)
        ? `<form method="post" action="${base}/name" class="inline-form">` +
          '<label class="field"><span>Organization name</span>' +
          `<input name="name" type="text" required maxlength="${String(ORG_NAME_MAX)}" value="${escapeHtml(org.name)}"></label>` +
          '<button class="button secondary" type="submit">Rename</button></form>'
        : `<p class="section-text">${escapeHtml(org.name)}. Only owners can rename it.</p>`) +
      `<p class="note">Created ${formatDate(org.createdAt)}.</p>` +
      '</section>' +
      (active && role === 'owner' && params.apiKeys
        ? apiKeysSection(base, params.apiKeys, params.newKey, params.issuer ?? '')
        : '') +
      '<section class="section" aria-labelledby="leave-heading">' +
      '<h2 id="leave-heading">Leave</h2>' +
      (params.managed
        ? '<p class="section-text">This organization manages your account, so you can’t leave it. Ask its admins.</p>'
        : lastOwner
          ? '<p class="section-text">You’re the only owner. To leave, make someone else an owner first, or delete the organization.</p>'
          : `<form method="post" action="${base}/leave" class="delete-form">` +
            '<label class="confirm"><input type="checkbox" name="confirm" value="on" required>' +
            '<span>I want to leave this organization. Rejoining needs a new invitation.</span></label>' +
            '<div class="consent-actions"><button class="button secondary" type="submit">Leave organization</button></div></form>') +
      '</section>' +
      (active && canManageOrganization(role)
        ? '<section class="section" aria-labelledby="delete-heading">' +
          '<h2 id="delete-heading">Delete</h2>' +
          '<p class="section-text">Deletes the organization, its memberships and invitations, for everyone. Members keep their own accounts.</p>' +
          `<div class="data-actions"><a class="button danger-outline" href="${base}/delete">Delete organization…</a></div>` +
          '</section>'
        : ''),
    { section: 'Organization' },
  );
}

/** The organization's API keys (DESIGN §4.24). */
function apiKeysSection(
  base: string,
  keys: ApiKeyInfo[],
  newKey: string | undefined,
  issuer: string,
): string {
  const rows = keys
    .map(
      (k) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(k.name)} <span class="tag tag-muted">${k.access === 'write' ? 'Read and write' : 'Read'}</span></p>` +
        `<p class="app-meta">Created ${formatDate(k.createdAt)} · ${k.lastUsedAt ? `last used ${formatDate(k.lastUsedAt)}` : 'never used'} · <code>${escapeHtml(k.id)}</code></p>` +
        '</div><div class="row-actions">' +
        `<form method="post" action="${base}/api-keys">` +
        hidden({ action: 'revoke', key: k.id }) +
        '<button class="button secondary small" type="submit">Revoke</button></form>' +
        '</div></li>',
    )
    .join('');
  return (
    '<section class="section" aria-labelledby="api-heading">' +
    '<h2 id="api-heading">API keys</h2>' +
    `<p class="section-text">For your own scripts: read members, domains and the audit log, and with a read-and-write key change roles, deactivate and reactivate managed accounts, and remove members. The API never acts on owners. Base URL <code>${escapeHtml(issuer)}/api/v1</code>; see <a href="/docs/api">the API reference</a>.</p>` +
    (newKey
      ? '<div class="secret-once" role="status"><p><strong>Your new key.</strong> Copy it now: it isn’t shown again.</p>' +
        `<p><code class="secret">${escapeHtml(newKey)}</code></p></div>`
      : '') +
    (rows ? `<ul class="admin-list">${rows}</ul>` : '') +
    `<form method="post" action="${base}/api-keys" class="inline-form">` +
    hidden({ action: 'create' }) +
    '<label class="field"><span>Name</span><input name="name" type="text" required maxlength="60" placeholder="HR sync" autocomplete="off"></label>' +
    '<label class="field"><span>Access</span><select name="access"><option value="read">Read</option><option value="write">Read and write</option></select></label>' +
    '<button class="button secondary" type="submit">Create key</button></form>' +
    `<p class="note">Up to ${String(MAX_KEYS)} keys. Every change made with a key is in the activity, with the key’s ID.</p>` +
    '</section>'
  );
}

export interface ActivityEntry {
  at: number;
  event: string;
  actor: string | null;
  target: string | null;
  detail: Record<string, unknown>;
}

const str = (value: unknown, fallback: string) => (typeof value === 'string' ? value : fallback);

const METHOD_WORD: Record<string, string> = {
  google: 'Google',
  email: 'an email code',
  passkey: 'a passkey',
  saml: 'single sign-on',
  oidc: 'single sign-on',
};

const ACTIVITY: Record<string, (e: ActivityEntry) => string> = {
  'login.succeeded': (e) => {
    const how = typeof e.detail.method === 'string' ? METHOD_WORD[e.detail.method] : undefined;
    return how ? `signed in with ${how}` : 'signed in';
  },
  'login.failed': () => 'failed to sign in',
  'login.denied': (e) =>
    `was refused sign-in${typeof e.detail.reason === 'string' ? ` (${e.detail.reason.replace(/_/g, ' ')})` : ''}`,
  logout: () => 'signed out',
  'session.ended': () => 'ended a session',
  'mfa.verified': () => 'confirmed a second factor',
  'mfa.failed': () => 'entered a wrong second-factor code',
  'mfa.locked': () => 'was locked out after wrong second-factor codes',
  'mfa.enrolled': () => 'added a second factor',
  'mfa.removed': () => 'removed a second factor',
  'mfa.recovery_code_used': () => 'used a recovery code',
  'identity.added': () => 'added a way to sign in',
  'identity.removed': () => 'removed a way to sign in',
  'consent.approved': () => 'connected an app',
  'consent.denied': () => 'was refused or declined an app',
  'grant.revoked': () => 'disconnected an app',
  'grant.refused': (e) =>
    e.detail.reason === 'app_not_allowed'
      ? 'lost access to an app that isn’t allowed'
      : 'lost access to an app',
  'account.exported': () => 'downloaded their data',
  'org.audit_exported': (e) =>
    `downloaded ${typeof e.detail.days === 'number' ? `${String(e.detail.days)} days of ` : ''}the audit log`,
  'org.api_key_created': (e) =>
    `created the API key “${str(e.detail.name, 'unnamed')}” (${e.detail.access === 'write' ? 'read and write' : 'read'})`,
  'org.api_key_revoked': () => 'revoked an API key',
  'org.audit_stream_changed': (e) =>
    e.detail.removed ? 'removed the audit stream' : 'changed the audit stream',
  'org.created': () => 'created the organization',
  'org.renamed': () => 'renamed the organization',
  'org.invited': (e) => `invited someone as ${str(e.detail.role, 'member')}`,
  'org.invitation_revoked': () => 'withdrew an invitation',
  'org.invitation_declined': () => 'declined an invitation',
  'org.joined': (e) => `joined as ${str(e.detail.role, 'member')}`,
  'org.role_changed': (e) => `made ${e.target ?? 'a former member'} ${str(e.detail.role, '')}`,
  'org.member_removed': (e) => `removed ${e.target ?? 'a former member'}`,
  'org.left': () => 'left the organization',
  'org.ownership_passed': () => 'became an owner, after the only owner deleted their account',
  'org.domain_added': (e) => `added the domain ${str(e.detail.domain, '')}`,
  'org.domain_verified': (e) => `verified the domain ${str(e.detail.domain, '')}`,
  'org.domain_removed': (e) => `removed the domain ${str(e.detail.domain, '')}`,
  'org.scim_token_created': () => 'created a directory sync token',
  'org.scim_token_revoked': () => 'revoked a directory sync token',
  'org.saml_saved': (e) =>
    `${e.detail.enabled ? 'turned on' : 'saved, turned off,'} single sign-on`,
  'org.domain_managed': (e) => `started managing the accounts at ${str(e.detail.domain, '')}`,
  'org.domain_unmanaged': (e) => `stopped managing the accounts at ${str(e.detail.domain, '')}`,
  'org.policy_changed': () => 'changed the security rules for managed accounts',
  'org.oidc_saved': (e) =>
    `saved OpenID Connect single sign-on${e.detail.enabled ? ', on' : ', off'}`,
  'org.require_sso_changed': (e) =>
    `${e.detail.on ? 'required' : 'stopped requiring'} single sign-on for managed accounts`,
  'org.account_managed': (e) =>
    e.detail.how === 'created' ? 'got a managed account' : 'made their account a managed account',
  'org.account_kept_personal': () => 'kept their account personal',
  'org.accounts_released': (e) =>
    `${String(typeof e.detail.count === 'number' ? e.detail.count : 'some')} managed accounts became personal again`,
  'org.account_deactivated': (e) => `deactivated ${e.target ?? 'an account'}`,
  'org.account_reactivated': (e) => `reactivated ${e.target ?? 'an account'}`,
  'org.account_signed_out': (e) => `signed ${e.target ?? 'an account'} out everywhere`,
  'org.sso_expiry_warned': (e) =>
    `told the owners that single sign-on’s ${e.detail.protocol === 'oidc' ? 'client secret' : 'certificate'} ${e.detail.days === 0 ? 'has expired' : `expires in ${String(e.detail.days)} ${e.detail.days === 1 ? 'day' : 'days'}`}`,
  'org.account_deleted': () => 'deleted a managed account',
  'org.account_deletion_due': () =>
    'deleted a managed account, 30 days after the directory removed it',
  'scim.account_created': (e) => `created a managed account for ${e.target ?? 'someone'}`,
  'scim.group_created': () => 'added a group',
  'scim.group_updated': () => 'changed a group',
  'scim.group_deleted': () => 'removed a group',
  'scim.role_changed': (e) =>
    `made ${e.target ?? 'someone'} ${e.detail.role === 'admin' ? 'an admin' : 'a member'}`,
  'org.apps_restricted': (e) =>
    e.detail.on ? 'allowed only chosen apps for managed accounts' : 'allowed any app again',
  'org.app_allowed': () => 'allowed an app',
  'org.app_disallowed': () => 'removed an allowed app',
  'org.group_role_changed': (e) =>
    `${e.detail.role === 'admin' ? 'made' : 'stopped making'} the members of “${str(e.detail.name, 'a group')}” admins`,
  'scim.account_deactivated': (e) => `deactivated ${e.target ?? 'an account'}`,
  'scim.account_reactivated': (e) => `reactivated ${e.target ?? 'an account'}`,
  'scim.account_deletion_scheduled': (e) =>
    `removed ${e.target ?? 'an account'}: deactivated, deleted in 30 days`,
  'scim.member_added': (e) => `added ${e.target ?? 'someone'}`,
  'scim.member_removed': (e) => `removed ${e.target ?? 'someone'}`,
  'scim.user_created': () => 'provisioned a person',
  'scim.user_updated': () => 'updated a person',
  'scim.user_deleted': () => 'deprovisioned a person',
};

/** What happened in the organization, newest first (DESIGN §4.14): owners and admins only. */
export function orgActivityPage(params: {
  org: Organization;
  role: OrgRole;
  entries: ActivityEntry[];
  now: number;
  /** Owners: the audit stream (DESIGN §4.23). */
  stream?: AuditStream | null;
  /** A just-created signing secret: shown once. */
  secret?: string;
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  const base = `/orgs/${escapeHtml(params.org.id)}`;
  const rows = params.entries
    .map((e) => {
      const what = ACTIVITY[e.event]?.(e) ?? e.event;
      const who = e.event.startsWith('scim.')
        ? 'Directory sync'
        : e.event === 'org.sso_expiry_warned'
          ? '2earl'
          : (e.actor ?? 'Someone');
      return (
        '<li class="activity-row">' +
        `<time datetime="${new Date(e.at * 1000).toISOString()}">${escapeHtml(formatDateTime(e.at))}</time>` +
        `<p><strong>${escapeHtml(who)}</strong> ${escapeHtml(what)}</p>` +
        '</li>'
      );
    })
    .join('');
  const download = (days: number) =>
    `<a href="${base}/activity/export?days=${String(days)}&amp;format=csv">CSV</a> · ` +
    `<a href="${base}/activity/export?days=${String(days)}&amp;format=json">JSON</a>`;
  return page(
    `${params.org.name}: activity`,
    orgHeader(params.org, params.role, 'activity') +
      flash(params) +
      (params.secret
        ? '<div class="secret-once" role="status"><p><strong>Your signing secret.</strong> Put it in your receiving endpoint now: it isn’t shown again.</p>' +
          `<p><code class="secret">${escapeHtml(params.secret)}</code></p></div>`
        : '') +
      '<section class="section section-first" aria-labelledby="activity-heading">' +
      '<h2 id="activity-heading" class="visually-hidden">Activity</h2>' +
      (rows
        ? `<ol class="activity">${rows}</ol>`
        : '<p class="empty">Nothing yet. Invitations, role changes, members joining and leaving, directory changes, and the sign-ins of accounts you manage appear here.</p>') +
      '<p class="note">The latest 200 events of the last 90 days, newest first. The sign-ins and security changes of accounts your organization manages are included.</p>' +
      '</section>' +
      '<section class="section" aria-labelledby="download-heading">' +
      '<h2 id="download-heading">Download the log</h2>' +
      '<p class="section-text">Every event, not only the latest 200, with times, people, apps and network prefixes. The log keeps 90 days; download it or stream it to keep it longer.</p>' +
      '<dl class="details">' +
      `<dt>Last 7 days</dt><dd>${download(7)}</dd>` +
      `<dt>Last 30 days</dt><dd>${download(30)}</dd>` +
      `<dt>Last 90 days</dt><dd>${download(90)}</dd>` +
      '</dl></section>' +
      (params.role === 'owner' ? streamSection(base, params.stream ?? null) : ''),
    { section: 'Organization' },
  );
}

/** Streaming the log to the organization's security monitoring (DESIGN §4.23). */
function streamSection(base: string, stream: AuditStream | null): string {
  const status = !stream
    ? 'Not set up'
    : !stream.enabled
      ? 'Paused'
      : stream.failures > 0
        ? `Failing: the last ${String(stream.failures)} ${stream.failures === 1 ? 'try' : 'tries'} got ${stream.lastStatus ?? 'no answer'}. Retrying, nothing is skipped.`
        : stream.lastDeliveredAt
          ? `Working: last delivered ${formatDateTime(stream.lastDeliveredAt)}`
          : 'Waiting for the first events';
  return (
    '<section class="section" aria-labelledby="stream-heading">' +
    '<h2 id="stream-heading">Stream to your security monitoring</h2>' +
    '<p class="section-text">New events are sent within a minute to an https endpoint of yours that accepts JSON (for example a small relay in front of Splunk, Datadog or Microsoft Sentinel), in batches of up to 500, each signed. Failed deliveries are retried until they’re accepted.</p>' +
    '<dl class="details">' +
    `<dt>Status</dt><dd>${escapeHtml(status)}</dd>` +
    '<dt>Signature</dt><dd><code>X-2earl-Signature: t=&lt;unix time&gt;,v1=&lt;hex HMAC-SHA256 of “t.body”&gt;</code></dd>' +
    '</dl>' +
    `<form method="post" action="${base}/activity/stream" class="stack-form">` +
    '<label class="field"><span>Endpoint URL</span>' +
    `<input name="url" type="url" required maxlength="1000" autocomplete="off" spellcheck="false" placeholder="https://siem.example.com/2earl" value="${escapeHtml(stream?.url ?? '')}"></label>` +
    `<label class="confirm"><input type="checkbox" name="enabled" value="on"${!stream || stream.enabled ? ' checked' : ''}><span>Send events</span></label>` +
    '<div class="consent-actions">' +
    `<button class="button secondary" type="submit" name="action" value="save">${stream ? 'Save' : 'Create the stream'}</button>` +
    (stream
      ? '<button class="button secondary" type="submit" name="action" value="test" formnovalidate>Send a test event</button>' +
        '<button class="button secondary" type="submit" name="action" value="rotate">New secret</button>' +
        '<button class="button danger-outline" type="submit" name="action" value="delete" formnovalidate>Remove</button>'
      : '') +
    '</div></form></section>'
  );
}

/** Deleting an account the organization manages (DESIGN §4.18): owners, with a confirmation. */
export function deleteManagedAccountPage(params: {
  org: Organization;
  member: Member;
  error?: string;
}): string {
  const base = `/orgs/${escapeHtml(params.org.id)}`;
  const who = params.member.name ?? params.member.email ?? 'this account';
  return page(
    'Delete account',
    `<p class="crumb"><a href="${base}">${escapeHtml(params.org.name)}</a></p>` +
      `<h1>Delete ${escapeHtml(who)}’s account</h1>` +
      '<p class="lede">The 2earl account and everything in it are deleted now, in every 2earl service, and every connected app loses access. It can’t be restored. Deactivating keeps the account instead.</p>' +
      (params.member.name && params.member.email
        ? `<p class="section-text">${escapeHtml(params.member.email)}</p>`
        : '') +
      flash({ error: params.error }) +
      `<form method="post" action="${base}/accounts/delete" class="delete-form">` +
      hidden({ user: params.member.userId }) +
      '<label class="confirm"><input type="checkbox" name="confirm" value="on" required>' +
      '<span>I want to delete this account and its data for good.</span></label>' +
      '<div class="consent-actions"><button class="button danger" type="submit">Delete account</button>' +
      `<a class="button secondary" href="${base}">Keep it</a></div>` +
      '</form>',
    { section: 'Organization' },
  );
}

export function deleteOrgPage(params: {
  org: Organization;
  members: number;
  error?: string;
}): string {
  const base = `/orgs/${escapeHtml(params.org.id)}`;
  return page(
    'Delete organization',
    `<p class="crumb"><a href="${base}">${escapeHtml(params.org.name)}</a></p>` +
      `<h1>Delete “${escapeHtml(params.org.name)}”</h1>` +
      `<p class="lede">The organization, its ${String(params.members)} ${params.members === 1 ? 'membership' : 'memberships'} and its open invitations are deleted now, and 2earl services are told to delete what they keep for it. It can’t be restored. Everyone keeps their own 2earl account.</p>` +
      flash({ error: params.error }) +
      `<form method="post" action="${base}/delete" class="delete-form">` +
      '<label class="field"><span>Type the organization’s name to confirm</span>' +
      `<input name="name" type="text" required maxlength="${String(ORG_NAME_MAX)}" autocomplete="off" spellcheck="false"></label>` +
      '<div class="consent-actions"><button class="button danger" type="submit">Delete organization</button>' +
      `<a class="button secondary" href="${base}">Keep it</a></div>` +
      '</form>',
    { section: 'Organization' },
  );
}

/** Someone opened an invitation link while signed in. */
export function invitationPage(params: {
  token: string;
  invitation: InvitationView;
  signedInAs: string | null;
  wrongAddress?: boolean;
}): string {
  const inv = params.invitation;
  const action = `/invite/${escapeHtml(params.token)}`;
  return page(
    `Join ${inv.orgName}`,
    `<h1>Join “${escapeHtml(inv.orgName)}”</h1>` +
      `<p class="lede">${escapeHtml(inv.inviter ?? 'Someone')} invited ${escapeHtml(inv.email)} to join this organization as ${inv.role === 'admin' ? 'an admin' : 'a member'}. ${escapeHtml(ROLE_HELP[inv.role])}</p>` +
      (params.wrongAddress
        ? `<p class="warning" role="alert">You’re signed in as ${escapeHtml(params.signedInAs ?? 'another account')}, which doesn’t sign in with ${escapeHtml(inv.email)}. Sign in with the account that uses that address, or add the address to this account first.</p>` +
          '<div class="consent-actions">' +
          '<a class="button secondary" href="/account/methods/email">Add an email address</a>' +
          '<form method="post" action="/logout"><button class="button secondary" type="submit">Sign out</button></form>' +
          '</div>'
        : '<p class="section-text">Members of the organization will see your name and email address, and you’ll see theirs. Your account stays yours: you can leave at any time.</p>' +
          `<form method="post" action="${action}" class="consent-actions">` +
          '<button class="button primary" type="submit" name="decision" value="accept">Join organization</button>' +
          '<button class="button secondary" type="submit" name="decision" value="decline">Decline</button>' +
          '</form>') +
      `<p class="fine">This invitation works until ${formatDate(inv.expiresAt)}.</p>`,
    { section: 'Organization' },
  );
}

/** Domains and directory sync (SCIM, DESIGN §4.16), for owners. */
export function directoryPage(params: {
  org: Organization;
  issuer: string;
  domains: OrgDomain[];
  tokens: ScimTokenInfo[];
  provisioned: { active: number; waiting: number; inactive: number };
  saml: SamlView | null;
  oidc: OidcView | null;
  now: number;
  managed: { managed: number; deactivated: number; requireSso: boolean };
  policy: OrgPolicy;
  groups?: GroupSummary[];
  apps?: AppsView;
  newToken?: string;
  notice?: string | undefined;
  error?: string | undefined;
}): string {
  const base = `/orgs/${escapeHtml(params.org.id)}`;
  const domainRows = params.domains
    .map(
      (d) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(d.domain)} ` +
        (d.verifiedAt !== null
          ? '<span class="tag">Verified</span>'
          : '<span class="tag tag-muted">Not verified</span>') +
        (d.managedAt !== null ? ' <span class="tag">Accounts managed</span>' : '') +
        '</p>' +
        (d.verifiedAt !== null
          ? `<p class="app-meta">Verified ${formatDate(d.verifiedAt)}</p>`
          : '<p class="app-meta">Add this TXT record to the domain’s DNS, then check:</p>' +
            `<p class="app-meta"><code>${escapeHtml(challengeRecordName(d.domain))}</code> TXT <code>${escapeHtml(d.challenge)}</code></p>`) +
        '</div><div class="row-actions">' +
        (d.verifiedAt === null
          ? `<form method="post" action="${base}/domains/verify">${hidden({ domain: d.domain })}<button class="button secondary small" type="submit">Check DNS</button></form>`
          : '') +
        `<form method="post" action="${base}/domains/remove">${hidden({ domain: d.domain })}<button class="button secondary small" type="submit">Remove</button></form>` +
        '</div></li>',
    )
    .join('');
  const tokenRows = params.tokens
    .map(
      (t) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name"><code>${escapeHtml(t.id)}</code></p>` +
        `<p class="app-meta">Created ${formatDate(t.createdAt)} · ${t.lastUsedAt ? `last used ${formatDate(t.lastUsedAt)}` : 'never used'}</p>` +
        '</div><div class="row-actions">' +
        `<form method="post" action="${base}/scim-tokens/revoke">${hidden({ token: t.id })}<button class="button secondary small" type="submit">Revoke</button></form>` +
        '</div></li>',
    )
    .join('');
  const verified = params.domains.some((d) => d.verifiedAt !== null);
  const p = params.provisioned;
  return page(
    'Domains and directory sync',
    orgHeader(params.org, 'owner', 'directory') +
      flash(params) +
      '<p class="lede">Verify your company’s domains, manage the 2earl accounts at them, connect your directory (Okta, Microsoft Entra ID or any SCIM 2.0 client) and your single sign-on.</p>' +
      setupList({
        verified,
        managed: params.domains.some((d) => d.managedAt !== null),
        sso: params.saml?.enabled === true || params.oidc?.enabled === true,
        directory: params.tokens.length > 0,
        rules: !isDefaultPolicy(params.policy),
      }) +
      '<section class="section" aria-labelledby="domains-heading">' +
      '<h2 id="domains-heading">Domains</h2>' +
      (domainRows ? `<ul class="admin-list">${domainRows}</ul>` : '') +
      `<form method="post" action="${base}/domains" class="inline-form">` +
      '<label class="field"><span>Domain</span><input name="domain" type="text" required maxlength="253" placeholder="example.com" autocomplete="off" spellcheck="false"></label>' +
      '<button class="button secondary" type="submit">Add domain</button></form>' +
      '</section>' +
      // In the order of the setup steps.
      managedSection(
        base,
        params.domains,
        params.managed,
        params.saml?.enabled === true || params.oidc?.enabled === true,
      ) +
      samlSection(
        base,
        params.issuer,
        params.org.id,
        verified,
        params.saml,
        params.oidc,
        params.now,
      ) +
      '<section class="section" aria-labelledby="scim-heading">' +
      '<h2 id="scim-heading">Directory sync (SCIM 2.0)</h2>' +
      '<dl class="details">' +
      `<dt>Base URL</dt><dd><code>${escapeHtml(params.issuer)}/scim/v2</code></dd>` +
      '<dt>Authentication</dt><dd>Bearer token (below)</dd>' +
      `<dt>From your directory</dt><dd>${String(p.active)} active · ${String(p.waiting)} without a 2earl account yet · ${String(p.inactive)} deactivated</dd>` +
      '</dl>' +
      (params.newToken
        ? '<div class="secret-once" role="status"><p><strong>Your new token.</strong> Copy it into your directory now: it isn’t shown again.</p>' +
          `<p><code class="secret">${escapeHtml(params.newToken)}</code></p></div>`
        : '') +
      (tokenRows ? `<ul class="admin-list">${tokenRows}</ul>` : '') +
      (verified
        ? `<form method="post" action="${base}/scim-tokens" class="actions"><button class="button secondary" type="submit">Create a token</button></form>` +
          '<p class="note">Up to two tokens, so you can rotate: create the new one, put it in your directory, then revoke the old one.</p>'
        : '<p class="note">Verify a domain first.</p>') +
      groupsBlock(base, params.groups ?? []) +
      '</section>' +
      policySection(
        base,
        params.policy,
        params.domains.some((d) => d.managedAt !== null),
      ) +
      (params.apps
        ? appsSection(
            base,
            params.apps,
            params.groups ?? [],
            params.domains.some((d) => d.managedAt !== null),
          )
        : ''),
    { section: 'Organization' },
  );
}

/** Managing the accounts at verified domains, and required SSO (DESIGN §4.18). */
function managedSection(
  base: string,
  domains: OrgDomain[],
  counts: { managed: number; deactivated: number; requireSso: boolean },
  ssoOn: boolean,
): string {
  const verified = domains.filter((d) => d.verifiedAt !== null);
  const rows = verified
    .map(
      (d) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(d.domain)}</p>` +
        `<p class="app-meta">${d.managedAt !== null ? `Managed since ${formatDate(d.managedAt)}` : 'Not managed: accounts there belong to their people'}</p>` +
        '</div><div class="row-actions">' +
        `<form method="post" action="${base}/domains/manage" class="${d.managedAt !== null ? '' : 'manage-form'}">` +
        hidden({ domain: d.domain, on: d.managedAt !== null ? '0' : '1' }) +
        (d.managedAt !== null
          ? '<button class="button secondary small" type="submit">Stop managing</button>'
          : '<label class="confirm small"><input type="checkbox" name="accept" value="on" required>' +
            '<span>We accept 2earl’s <a href="https://2earl.com/dpa">data processing terms</a> for these accounts</span></label>' +
            '<button class="button secondary small" type="submit">Manage accounts</button>') +
        '</form></div></li>',
    )
    .join('');
  return (
    '<section class="section" aria-labelledby="managed-heading">' +
    '<h2 id="managed-heading">Managed accounts</h2>' +
    '<p class="section-text">Manage the 2earl accounts at a verified domain. New accounts there are managed from the start; people who already have one choose at their next sign-in, or keep it their own by removing the address. You can deactivate and delete managed accounts, and require your single sign-on. People can always download their data.</p>' +
    (verified.length > 0
      ? '<dl class="details">' +
        `<dt>Accounts</dt><dd>${String(counts.managed)} managed · ${String(counts.deactivated)} deactivated</dd>` +
        '</dl>' +
        `<ul class="admin-list">${rows}</ul>` +
        '<h3 class="subhead">Require single sign-on</h3>' +
        (ssoOn
          ? `<form method="post" action="${base}/require-sso" class="stack-form">` +
            `<label class="confirm"><input type="checkbox" name="on" value="1"${counts.requireSso ? ' checked' : ''}>` +
            '<span>Managed accounts sign in only through your identity provider. Owners can still sign in other ways, so a broken identity provider can’t lock you out. Sessions started another way end at once.</span></label>' +
            '<div class="consent-actions"><button class="button secondary" type="submit">Save</button></div></form>'
          : `<p class="note">${counts.requireSso ? 'Required, but single sign-on is off, so it doesn’t apply. ' : ''}Turn on single sign-on below first.</p>`)
      : '<p class="note">Verify a domain first.</p>') +
    '</section>'
  );
}

export interface SetupState {
  verified: boolean;
  managed: boolean;
  sso: boolean;
  directory: boolean;
  rules: boolean;
}

/** The company setup, in order: each step needs the ones before it (DESIGN §4.16–§4.19). */
function setupSteps(state: SetupState) {
  return [
    {
      done: state.verified,
      anchor: 'domains-heading',
      title: 'Verify a domain',
      text: 'Prove your company controls it, with a DNS record.',
    },
    {
      done: state.managed,
      anchor: 'managed-heading',
      title: 'Manage the accounts at it',
      text: 'Accounts at the domain become your organization’s to deactivate and delete.',
    },
    {
      done: state.sso,
      anchor: 'saml-heading',
      title: 'Connect single sign-on',
      text: 'People sign in through your identity provider (OpenID Connect or SAML 2.0).',
    },
    {
      done: state.directory,
      anchor: 'scim-heading',
      title: 'Connect your directory',
      text: 'Joiners get an account, leavers lose access at once (SCIM 2.0).',
    },
    {
      done: state.rules,
      anchor: 'rules-heading',
      title: 'Set security rules',
      text: 'Second factor, passkeys, session length, ways in, networks.',
    },
  ];
}

function setupList(state: SetupState): string {
  const steps = setupSteps(state);
  const next = steps.findIndex((step) => !step.done);
  return (
    '<nav class="setup" aria-labelledby="setup-heading">' +
    `<h2 id="setup-heading" class="visually-hidden">Setup</h2><ol class="setup-steps">` +
    steps
      .map(
        (step, i) =>
          `<li class="${step.done ? 'is-done' : i === next ? 'is-next' : ''}">` +
          `<a href="#${step.anchor}"><span class="setup-title">${step.title}</span>` +
          `<span class="setup-text">${step.done ? 'Done' : step.text}</span></a></li>`,
      )
      .join('') +
    '</ol></nav>'
  );
}

export interface AppsView {
  restrict: boolean;
  allowed: { clientId: string; name: string; groupId: string; groupName: string | null }[];
  /** Apps managed people connected recently and that aren't allowed for everyone yet. */
  inUse: { clientId: string; name: string }[];
}

/** Which apps managed accounts may use (DESIGN §4.22). */
function appsSection(
  base: string,
  apps: AppsView,
  groups: GroupSummary[],
  managing: boolean,
): string {
  const who = (groupId: string, groupName: string | null) =>
    groupId === '' ? 'Everyone' : `Members of “${escapeHtml(groupName ?? 'a removed group')}”`;
  const groupSelect = (inRow: boolean) =>
    `<select name="group" aria-label="Who may use it"${inRow ? ' class="role-select"' : ''}>` +
    '<option value="">Everyone</option>' +
    groups
      .map((g) => `<option value="${escapeHtml(g.id)}">Members of “${escapeHtml(g.name)}”</option>`)
      .join('') +
    '</select>';
  const allowedRows = apps.allowed
    .map(
      (a) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(a.name)}</p>` +
        `<p class="app-meta">${who(a.groupId, a.groupName)} · <code>${escapeHtml(a.clientId)}</code></p>` +
        '</div><div class="row-actions">' +
        `<form method="post" action="${base}/apps">` +
        hidden({ action: 'remove', client_id: a.clientId, group: a.groupId }) +
        '<button class="button secondary small" type="submit">Remove</button></form>' +
        '</div></li>',
    )
    .join('');
  const inUseRows = apps.inUse
    .map(
      (a) =>
        '<li class="admin-row"><div class="app-main">' +
        `<p class="app-name">${escapeHtml(a.name)}</p>` +
        `<p class="app-meta"><code>${escapeHtml(a.clientId)}</code></p>` +
        '</div><div class="row-actions">' +
        `<form method="post" action="${base}/apps" class="manage-form">` +
        hidden({ action: 'allow', client_id: a.clientId }) +
        groupSelect(true) +
        '<button class="button secondary small" type="submit">Allow</button></form>' +
        '</div></li>',
    )
    .join('');
  return (
    '<section class="section" aria-labelledby="apps-heading">' +
    '<h2 id="apps-heading">Apps</h2>' +
    '<p class="section-text">Choose which apps the accounts you manage may connect, owners’ too. Apps that aren’t allowed lose access within 15 minutes.</p>' +
    (!managing
      ? '<p class="note">Available once you manage the accounts at a domain (step 2 above).</p>'
      : `<form method="post" action="${base}/apps" class="stack-form">` +
        hidden({ action: 'restrict' }) +
        `<label class="confirm"><input type="checkbox" name="on" value="1"${apps.restrict ? ' checked' : ''}>` +
        '<span><strong>Only allow the apps below</strong><br><span class="hint">Off: managed accounts may connect any app.</span></span></label>' +
        '<div class="consent-actions"><button class="button secondary" type="submit">Save</button></div></form>' +
        '<h3 class="subhead">Allowed</h3>' +
        (allowedRows
          ? `<ul class="admin-list">${allowedRows}</ul>`
          : '<p class="note">No apps allowed yet.</p>') +
        (inUseRows
          ? '<h3 class="subhead">In use by your people</h3>' +
            `<ul class="admin-list">${inUseRows}</ul>`
          : '') +
        '<h3 class="subhead">Allow another app</h3>' +
        `<form method="post" action="${base}/apps" class="stack-form">` +
        hidden({ action: 'allow' }) +
        '<label class="field"><span>Client ID</span>' +
        '<input name="client_id" type="text" required maxlength="500" autocomplete="off" spellcheck="false" placeholder="The app’s client ID, or its https client metadata URL"></label>' +
        `<label class="field"><span>Who may use it</span>${groupSelect(false)}</label>` +
        '<div class="consent-actions"><button class="button secondary" type="submit">Allow</button></div></form>') +
    '</section>'
  );
}

/** Groups from the directory, and the role each gives (DESIGN §4.21). */
function groupsBlock(base: string, groups: GroupSummary[]): string {
  const deciding = groups.some((g) => g.role === 'admin');
  return (
    '<h3 class="subhead">Groups and roles</h3>' +
    (groups.length === 0
      ? '<p class="note">Groups your directory sends appear here. Give a group the admin role, and your directory decides who is an admin.</p>'
      : '<p class="section-text">' +
        (deciding
          ? 'Your directory decides roles: members of a group marked admin are admins, everyone else it provisioned is a member. Owners never change.'
          : 'Mark a group admin, and your directory decides who is an admin. Owners never change.') +
        '</p>' +
        '<ul class="admin-list">' +
        groups
          .map(
            (g) =>
              '<li class="admin-row"><div class="app-main">' +
              `<p class="app-name">${escapeHtml(g.name)}${g.role === 'admin' ? ' <span class="role-badge role-admin">Admin</span>' : ''}</p>` +
              `<p class="app-meta">${String(g.members)} ${g.members === 1 ? 'person' : 'people'}</p>` +
              '</div><div class="row-actions">' +
              `<form method="post" action="${base}/groups/role">` +
              hidden({ group: g.id, role: g.role === 'admin' ? '' : 'admin' }) +
              `<button class="button secondary small" type="submit">${g.role === 'admin' ? 'Stop making admins' : 'Make its members admins'}</button></form>` +
              '</div></li>',
          )
          .join('') +
        '</ul>')
  );
}

/** Security rules for managed accounts (DESIGN §4.19). */
function policySection(base: string, policy: OrgPolicy, managing: boolean): string {
  const check = (name: string, on: boolean, label: string, hint: string) =>
    `<label class="confirm"><input type="checkbox" name="${name}" value="1"${on ? ' checked' : ''}>` +
    `<span><strong>${label}</strong><br><span class="hint">${hint}</span></span></label>`;
  const methodLabel: Record<PolicyMethod, string> = {
    google: 'Google',
    email: 'A code by email',
    passkey: 'A passkey',
  };
  const hours = (h: number) => (h < 24 ? `${String(h)} hours` : `${String(h / 24)} days`);
  return (
    '<section class="section" aria-labelledby="rules-heading">' +
    '<h2 id="rules-heading">Security rules</h2>' +
    '<p class="section-text">For the accounts you manage. Owners keep every way in and every network, so a broken identity provider or a new office network can’t lock you out; the second-factor rules and the session length apply to them too.</p>' +
    (!managing
      ? '<p class="note">Available once you manage the accounts at a domain (step 2 above). This is what you’ll set:</p>'
      : '') +
    (`<form method="post" action="${base}/policy" class="stack-form">` +
      (managing ? '' : '<fieldset class="locked" disabled>') +
      '<fieldset class="choices"><legend>Second factor</legend>' +
      check(
        'require_factor',
        policy.requireFactor,
        'Require a second factor',
        'People without one add a passkey or an authenticator app before going on.',
      ) +
      check(
        'passkeys_only',
        policy.passkeysOnly,
        'Require a passkey',
        'Phishing-resistant. Authenticator-app codes stop counting once someone has a passkey; recovery codes still work.',
      ) +
      '</fieldset>' +
      '<fieldset class="choices"><legend>Ways to sign in</legend>' +
      '<p class="hint">Single sign-on is always allowed while it’s on.</p>' +
      POLICY_METHODS.map(
        (m) =>
          `<label class="confirm"><input type="checkbox" name="methods" value="${m}"${policy.methods.includes(m) ? ' checked' : ''}><span>${methodLabel[m]}</span></label>`,
      ).join('') +
      '</fieldset>' +
      '<label class="field"><span>Sessions last</span>' +
      '<select name="session_hours">' +
      `<option value=""${policy.sessionHours === null ? ' selected' : ''}>7 days (2earl’s default)</option>` +
      SESSION_HOURS.map(
        (h) =>
          `<option value="${String(h)}"${policy.sessionHours === h ? ' selected' : ''}>${hours(h)}</option>`,
      ).join('') +
      '</select><span class="hint">Counted from sign-in. Sessions end after 12 hours unused in any case.</span></label>' +
      '<label class="field"><span>Allowed networks</span>' +
      `<textarea name="ip_ranges" rows="3" spellcheck="false" placeholder="203.0.113.0/24&#10;2001:db8::/32">${escapeHtml(policy.ipRanges.join('\n'))}</textarea>` +
      `<span class="hint">One range per line (IPv4 or IPv6, CIDR), up to ${String(MAX_RANGES)}. Empty: anywhere. Apps that people connected keep working elsewhere.</span></label>` +
      '<div class="consent-actions"><button class="button secondary" type="submit">Save rules</button></div>' +
      (managing ? '' : '</fieldset>') +
      '</form>') +
    '</section>'
  );
}

export interface SamlView {
  idpEntityId: string;
  ssoUrl: string;
  certificate: string;
  certificateNext: string | null;
  certificateExpiresAt: number | null;
  certificateNextExpiresAt: number | null;
  enabled: boolean;
}

export interface OidcView {
  issuer: string;
  clientId: string;
  secretExpiresAt: number | null;
  enabled: boolean;
}

/** "Expires 19 December 2027", flagged when it's within 30 days or past. */
function expiryText(at: number | null, now: number): string {
  if (at === null) return '';
  const date = formatDate(at);
  if (at <= now) return `<span class="tag tag-alert">Expired ${escapeHtml(date)}</span>`;
  if (at - now <= 30 * 86_400)
    return `<span class="tag tag-alert">Expires ${escapeHtml(date)}</span>`;
  return `<span class="tag tag-muted">Expires ${escapeHtml(date)}</span>`;
}

function samlSection(
  base: string,
  issuer: string,
  orgId: string,
  verified: boolean,
  saml: SamlView | null,
  oidc: OidcView | null,
  now: number,
): string {
  const sp = `${issuer}/saml/${encodeURIComponent(orgId)}`;
  const redirectUri = `${issuer}/sso/${encodeURIComponent(orgId)}/oidc`;
  const status = oidc?.enabled
    ? 'On, with OpenID Connect'
    : saml?.enabled
      ? 'On, with SAML 2.0'
      : 'Off';
  const oidcForm =
    `<details class="protocol"${oidc?.enabled || !saml?.enabled ? ' open' : ''}>` +
    '<summary>OpenID Connect: Microsoft Entra ID, Google Workspace, Okta and others</summary>' +
    '<dl class="details">' +
    `<dt>Redirect URI</dt><dd><code>${escapeHtml(redirectUri)}</code></dd>` +
    '<dt>Scopes</dt><dd><code>openid email profile</code></dd>' +
    '<dt>Client authentication</dt><dd>Client secret (basic)</dd>' +
    '</dl>' +
    `<form method="post" action="${base}/oidc" class="stack-form">` +
    '<label class="field"><span>Issuer URL</span>' +
    `<input name="issuer" type="url" required maxlength="500" autocomplete="off" spellcheck="false" placeholder="https://login.microsoftonline.com/<tenant ID>/v2.0" value="${escapeHtml(oidc?.issuer ?? '')}">` +
    '<span class="hint">Entra ID: https://login.microsoftonline.com/&lt;tenant ID&gt;/v2.0 · Google Workspace: https://accounts.google.com · Okta: https://&lt;your domain&gt;.okta.com</span></label>' +
    '<label class="field"><span>Client ID</span>' +
    `<input name="client_id" type="text" required maxlength="300" autocomplete="off" spellcheck="false" value="${escapeHtml(oidc?.clientId ?? '')}"></label>` +
    '<label class="field"><span>Client secret</span>' +
    `<input name="client_secret" type="password" maxlength="500" autocomplete="off"${oidc ? ' placeholder="Saved: leave empty to keep it"' : ' required'}></label>` +
    '<label class="field"><span>Client secret expires (optional)</span>' +
    `<input name="secret_expires" type="date" value="${dateValue(oidc?.secretExpiresAt ?? null)}">` +
    `<span class="hint">Entra ID’s secrets expire. Owners get an email 30, 7 and 1 days before. ${expiryText(oidc?.secretExpiresAt ?? null, now)}</span></label>` +
    `<label class="confirm"><input type="checkbox" name="enabled" value="on"${oidc?.enabled ? ' checked' : ''}><span>Let people sign in this way${saml?.enabled ? ' (turns SAML off)' : ''}</span></label>` +
    '<div class="consent-actions"><button class="button secondary" type="submit">Check and save</button></div>' +
    '</form></details>';
  const samlForm =
    `<details class="protocol"${saml?.enabled ? ' open' : ''}>` +
    '<summary>SAML 2.0</summary>' +
    '<dl class="details">' +
    `<dt>Entity ID</dt><dd><code>${escapeHtml(sp)}</code></dd>` +
    `<dt>Reply (ACS) URL</dt><dd><code>${escapeHtml(sp)}/acs</code> (HTTP-POST)</dd>` +
    '<dt>Name ID</dt><dd>The work email address</dd>' +
    (saml
      ? `<dt>Metadata</dt><dd><a href="${escapeHtml(sp)}/metadata">${escapeHtml(sp)}/metadata</a></dd>`
      : '') +
    '</dl>' +
    `<form method="post" action="${base}/saml" class="stack-form">` +
    '<label class="field"><span>Identity provider entity ID (issuer)</span>' +
    `<input name="idp_entity_id" type="text" required maxlength="500" autocomplete="off" spellcheck="false" value="${escapeHtml(saml?.idpEntityId ?? '')}"></label>` +
    '<label class="field"><span>Sign-in URL (HTTP-Redirect)</span>' +
    `<input name="sso_url" type="url" required maxlength="1000" autocomplete="off" spellcheck="false" value="${escapeHtml(saml?.ssoUrl ?? '')}"></label>` +
    `<label class="field"><span>Signing certificate (PEM or base64) ${expiryText(saml?.certificateExpiresAt ?? null, now)}</span>` +
    `<textarea name="certificate" rows="6" required spellcheck="false">${escapeHtml(saml?.certificate ?? '')}</textarea></label>` +
    `<label class="field"><span>Next signing certificate (optional) ${expiryText(saml?.certificateNextExpiresAt ?? null, now)}</span>` +
    `<textarea name="certificate_next" rows="4" spellcheck="false">${escapeHtml(saml?.certificateNext ?? '')}</textarea>` +
    '<span class="hint">When your provider announces a new certificate, paste it here: both are accepted, so sign-in keeps working when it switches. Owners get an email 30, 7 and 1 days before the certificates expire.</span></label>' +
    `<label class="confirm"><input type="checkbox" name="enabled" value="on"${saml?.enabled ? ' checked' : ''}><span>Let people sign in this way${oidc?.enabled ? ' (turns OpenID Connect off)' : ''}</span></label>` +
    '<div class="consent-actions"><button class="button secondary" type="submit">Save single sign-on</button></div>' +
    '</form></details>';
  return (
    '<section class="section" aria-labelledby="saml-heading">' +
    '<h2 id="saml-heading">Single sign-on</h2>' +
    '<p class="section-text">People with an address at your verified domains sign in through your identity provider, with OpenID Connect or SAML 2.0: one at a time. A second factor they set up on 2earl is still asked for. Turning single sign-on off also lifts required single sign-on.</p>' +
    `<dl class="details"><dt>Status</dt><dd>${status}</dd>` +
    `<dt>Sign-in link for your app dashboard</dt><dd><code>${escapeHtml(issuer)}/sso/${escapeHtml(encodeURIComponent(orgId))}/start</code>` +
    '<br><span class="hint">Entra ID: the application’s “Sign on URL”. Okta: “Initiate login URI”, or a bookmark app. It starts sign-in through your provider, so the 2earl tile in My Apps or the Okta dashboard works.</span></dd></dl>' +
    (verified ? oidcForm + samlForm : '<p class="note">Verify a domain first.</p>') +
    '</section>'
  );
}
