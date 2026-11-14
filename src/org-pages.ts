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
  const roles = (['member', 'admin', 'owner'] as const).filter(
    (r) => r !== member.role && canSetRole(actor.role, member.role, r),
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

export interface ActivityEntry {
  at: number;
  event: string;
  actor: string | null;
  target: string | null;
  detail: Record<string, unknown>;
}

const str = (value: unknown, fallback: string) => (typeof value === 'string' ? value : fallback);

const ACTIVITY: Record<string, (e: ActivityEntry) => string> = {
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
  'org.require_sso_changed': (e) =>
    `${e.detail.on ? 'required' : 'stopped requiring'} single sign-on for managed accounts`,
  'org.account_managed': (e) =>
    e.detail.how === 'created' ? 'got a managed account' : 'made their account a managed account',
  'org.account_kept_personal': () => 'kept their account personal',
  'org.accounts_released': (e) =>
    `${String(typeof e.detail.count === 'number' ? e.detail.count : 'some')} managed accounts became personal again`,
  'org.account_deactivated': (e) => `deactivated ${e.target ?? 'an account'}`,
  'org.account_reactivated': (e) => `reactivated ${e.target ?? 'an account'}`,
  'org.account_deleted': () => 'deleted a managed account',
  'org.account_deletion_due': () =>
    'deleted a managed account, 30 days after the directory removed it',
  'scim.account_created': (e) => `created a managed account for ${e.target ?? 'someone'}`,
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
}): string {
  const rows = params.entries
    .map((e) => {
      const what = ACTIVITY[e.event]?.(e) ?? e.event;
      const who = e.event.startsWith('scim.') ? 'Directory sync' : (e.actor ?? 'A former member');
      return (
        '<li class="activity-row">' +
        `<time datetime="${new Date(e.at * 1000).toISOString()}">${escapeHtml(formatDateTime(e.at))}</time>` +
        `<p><strong>${escapeHtml(who)}</strong> ${escapeHtml(what)}</p>` +
        '</li>'
      );
    })
    .join('');
  return page(
    `${params.org.name}: activity`,
    orgHeader(params.org, params.role, 'activity') +
      '<section class="section section-first" aria-labelledby="activity-heading">' +
      '<h2 id="activity-heading" class="visually-hidden">Activity</h2>' +
      (rows
        ? `<ol class="activity">${rows}</ol>`
        : '<p class="empty">Nothing yet. Invitations, role changes, members joining and leaving, and directory changes appear here.</p>') +
      '<p class="note">The last 90 days, newest first, up to 200 events.</p>' +
      '</section>',
    { section: 'Organization' },
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
  saml: { idpEntityId: string; ssoUrl: string; certificate: string; enabled: boolean } | null;
  managed: { managed: number; deactivated: number; requireSso: boolean };
  policy: OrgPolicy;
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
        sso: params.saml?.enabled === true,
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
      managedSection(base, params.domains, params.managed, params.saml?.enabled === true) +
      samlSection(base, params.issuer, params.org.id, verified, params.saml) +
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
      '</section>' +
      policySection(
        base,
        params.policy,
        params.domains.some((d) => d.managedAt !== null),
      ),
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
      text: 'People sign in through your identity provider (SAML 2.0).',
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

function samlSection(
  base: string,
  issuer: string,
  orgId: string,
  verified: boolean,
  saml: { idpEntityId: string; ssoUrl: string; certificate: string; enabled: boolean } | null,
): string {
  const sp = `${issuer}/saml/${encodeURIComponent(orgId)}`;
  return (
    '<section class="section" aria-labelledby="saml-heading">' +
    '<h2 id="saml-heading">Single sign-on (SAML 2.0)</h2>' +
    '<p class="section-text">People with an address at your verified domains can sign in through your identity provider. A second factor they set up on 2earl is still asked for. Turning it off also turns off required single sign-on.</p>' +
    '<dl class="details">' +
    `<dt>Entity ID</dt><dd><code>${escapeHtml(sp)}</code></dd>` +
    `<dt>Reply (ACS) URL</dt><dd><code>${escapeHtml(sp)}/acs</code> (HTTP-POST)</dd>` +
    '<dt>Name ID</dt><dd>The work email address</dd>' +
    (saml
      ? `<dt>Metadata</dt><dd><a href="${escapeHtml(sp)}/metadata">${escapeHtml(sp)}/metadata</a></dd>`
      : '') +
    `<dt>Status</dt><dd>${saml?.enabled ? 'On' : 'Off'}</dd>` +
    '</dl>' +
    (verified
      ? `<form method="post" action="${base}/saml" class="stack-form">` +
        '<label class="field"><span>Identity provider entity ID (issuer)</span>' +
        `<input name="idp_entity_id" type="text" required maxlength="500" autocomplete="off" spellcheck="false" value="${escapeHtml(saml?.idpEntityId ?? '')}"></label>` +
        '<label class="field"><span>Sign-in URL (HTTP-Redirect)</span>' +
        `<input name="sso_url" type="url" required maxlength="1000" autocomplete="off" spellcheck="false" value="${escapeHtml(saml?.ssoUrl ?? '')}"></label>` +
        '<label class="field"><span>Signing certificate (PEM or base64)</span>' +
        `<textarea name="certificate" rows="6" required spellcheck="false">${escapeHtml(saml?.certificate ?? '')}</textarea></label>` +
        `<label class="confirm"><input type="checkbox" name="enabled" value="on"${saml?.enabled ? ' checked' : ''}><span>Let people sign in this way</span></label>` +
        '<div class="consent-actions"><button class="button secondary" type="submit">Save single sign-on</button></div>' +
        '</form>'
      : '<p class="note">Verify a domain first.</p>') +
    '</section>'
  );
}
