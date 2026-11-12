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
import { escapeHtml, formatDate, page } from './pages';

/** Server-rendered pages for organizations (DESIGN §4.14). Every value is escaped. */

const ROLE_HELP: Record<OrgRole, string> = {
  owner: 'Owners can do everything, including renaming and deleting the organization.',
  admin: 'Admins can invite people, remove members and admins, and change their roles.',
  member: 'Members can see who else is in the organization.',
};

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

/** The account page's list of the account's organizations. */
export function organizationsSection(orgs: OrgSummary[]): string {
  const items = orgs
    .map(
      (o) =>
        '<li class="app"><div class="app-main">' +
        `<p class="app-name"><a href="/orgs/${escapeHtml(o.id)}">${escapeHtml(o.name)}</a>` +
        (o.status === 'suspended' ? ' <span class="tag tag-alert">Suspended</span>' : '') +
        '</p>' +
        `<p class="app-meta">${escapeHtml(ROLE_LABEL[o.role])} · ${String(o.members)} ${o.members === 1 ? 'member' : 'members'}</p>` +
        '</div></li>',
    )
    .join('');
  return (
    '<section class="section" aria-labelledby="orgs-heading">' +
    '<h2 id="orgs-heading">Organizations</h2>' +
    (orgs.length > 0
      ? `<ul class="apps">${items}</ul>`
      : '<p class="section-text">An organization lets a team use 2earl together: everyone keeps their own account, and the organization shows who belongs to it and with which role.</p>') +
    '<div class="data-actions"><a class="button secondary" href="/orgs/new">Create an organization</a></div>' +
    '</section>'
  );
}

export function newOrgPage(params: { name?: string; error?: string } = {}): string {
  return page(
    'Create an organization',
    '<p class="crumb"><a href="/account">Your account</a></p>' +
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
    escapeHtml(ROLE_LABEL[member.role]),
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
          ? `<form method="post" action="${base}/members/remove">` +
            hidden({ user: member.userId }) +
            '<button class="button secondary small" type="submit">Remove</button></form>'
          : '') +
        '</div>';
  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${who}${me ? ' <span class="tag">You</span>' : ''}</p>` +
    `<p class="app-meta">${meta}</p></div>` +
    actions +
    '</li>'
  );
}

function invitationRow(base: string, invitation: OpenInvitation, editable: boolean): string {
  return (
    '<li class="admin-row">' +
    `<div class="app-main"><p class="app-name">${escapeHtml(invitation.email)} <span class="tag tag-muted">Invited</span></p>` +
    `<p class="app-meta">${escapeHtml(ROLE_LABEL[invitation.role])}` +
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
}): string {
  const { org, role } = params;
  const base = `/orgs/${escapeHtml(org.id)}`;
  const active = org.status === 'active';
  const inviting = active && canInvite(role);
  const owners = params.members.filter((m) => m.role === 'owner').length;
  const lastOwner = role === 'owner' && owners === 1;
  return page(
    org.name,
    '<p class="crumb"><a href="/account">Your account</a></p>' +
      flash(params) +
      `<h1>${escapeHtml(org.name)}</h1>` +
      `<p class="lede">You’re ${role === 'admin' || role === 'owner' ? 'an' : 'a'} ${escapeHtml(ROLE_LABEL[role].toLowerCase())}. ${escapeHtml(ROLE_HELP[role])}</p>` +
      (active
        ? ''
        : '<p class="warning" role="alert">This organization is suspended by 2earl. Nothing in it can be changed, and 2earl services don’t see it. Write to us through the contact form on 2earl.com if you think that’s a mistake.</p>') +
      '<section class="section" aria-labelledby="members-heading">' +
      `<h2 id="members-heading">Members <span class="tag tag-muted">${String(params.members.length)}</span></h2>` +
      '<p class="section-text">Everyone in the organization sees each member’s name and email address.</p>' +
      `<ul class="admin-list">${params.members.map((m) => memberRow(base, m, { userId: params.userId, role }, active)).join('')}</ul>` +
      '</section>' +
      (inviting || params.invitations.length > 0
        ? '<section class="section" aria-labelledby="invite-heading">' +
          '<h2 id="invite-heading">Invitations</h2>' +
          (inviting
            ? `<form method="post" action="${base}/invitations" class="inline-form" novalidate>` +
              '<label class="field"><span>Email address</span>' +
              `<input name="email" type="email" required maxlength="254" autocomplete="off" spellcheck="false" value="${escapeHtml(params.email ?? '')}"></label>` +
              '<label class="field"><span>Role</span><select name="role">' +
              '<option value="member">Member</option><option value="admin">Admin</option></select></label>' +
              '<button class="button primary" type="submit">Send invitation</button></form>' +
              '<p class="note">We email a link that works for 7 days, for that address only. Owners are made from members, once they’ve joined.</p>'
            : '') +
          (params.invitations.length > 0
            ? `<ul class="admin-list">${params.invitations.map((i) => invitationRow(base, i, inviting)).join('')}</ul>`
            : '') +
          '</section>'
        : '') +
      (active && canManageOrganization(role)
        ? '<section class="section" aria-labelledby="settings-heading">' +
          '<h2 id="settings-heading">Settings</h2>' +
          `<form method="post" action="${base}/name" class="inline-form">` +
          '<label class="field"><span>Name</span>' +
          `<input name="name" type="text" required maxlength="${String(ORG_NAME_MAX)}" value="${escapeHtml(org.name)}"></label>` +
          '<button class="button secondary" type="submit">Rename</button></form>' +
          `<p class="section-text">Created ${formatDate(org.createdAt)}.</p>` +
          `<div class="data-actions"><a class="danger-link" href="${base}/delete">Delete organization</a></div>` +
          '</section>'
        : '') +
      '<section class="section" aria-labelledby="leave-heading">' +
      '<h2 id="leave-heading">Leave</h2>' +
      (lastOwner
        ? '<p class="section-text">You’re the only owner. To leave, make someone else an owner first, or delete the organization.</p>'
        : `<form method="post" action="${base}/leave" class="delete-form">` +
          '<label class="confirm"><input type="checkbox" name="confirm" value="on" required>' +
          '<span>I want to leave this organization. Rejoining needs a new invitation.</span></label>' +
          '<div class="consent-actions"><button class="button secondary" type="submit">Leave organization</button></div></form>') +
      '</section>',
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
