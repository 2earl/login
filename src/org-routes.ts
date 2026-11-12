import type { Hono } from 'hono';
import type { Deps } from './app';
import { audit, type AuditEvent } from './audit';
import { normaliseEmail } from './directory';
import {
  clientIp,
  isSameOrigin,
  underRateLimit,
  workerCtx,
  type AppContext,
  type AppEnv,
} from './http';
import { invitationMail, sendMail } from './mail';
import { changeCheck } from './mfa-routes';
import { deleteOrgPage, invitationPage, newOrgPage, orgPage } from './org-pages';
import {
  MAX_INVITATIONS_PER_DAY,
  acceptInvitation,
  accountHasAddress,
  canInvite,
  canManageOrganization,
  canRemove,
  canSetRole,
  createInvitation,
  createOrganization,
  deleteInvitation,
  deleteOrganization,
  invitationByToken,
  inviterLabel,
  isOrgRole,
  listInvitations,
  listMembers,
  membership,
  orgName,
  removeMember,
  renameOrganization,
  setRole,
  type OrgRole,
} from './orgs';
import { MESSAGES, messagePage, notFoundPage } from './pages';
import type { Session } from './sessions';

/**
 * Organizations (DESIGN §4.14): creating one, its page, invitations, roles, leaving and deleting.
 * Every route is for a signed-in member; to anyone else an organization doesn't exist (404).
 */

const NAME_ERROR = `Use 1 to 60 characters, without links or web addresses.`;

const DONE: Record<string, string> = {
  created: 'Organization created. Invite people below.',
  invited: 'Invitation sent.',
  withdrawn: 'Invitation withdrawn.',
  role: 'Role changed.',
  removed: 'Member removed.',
  renamed: 'Organization renamed.',
  joined: 'You joined the organization.',
};

export function registerOrgRoutes(app: Hono<AppEnv>, deps: Deps): void {
  const signIn = (c: AppContext) => {
    const url = new URL(c.req.url);
    return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
  };

  const record = (
    c: AppContext,
    session: Session,
    event: AuditEvent,
    detail: Record<string, string | number | boolean | null>,
  ) =>
    audit(c.env.DB, deps.now(), event, {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail,
    });

  /** The organization page, with a message, for a change that didn't go through. */
  async function showOrg(
    c: AppContext,
    session: Session,
    orgId: string,
    flash: { notice?: string; error?: string; email?: string } = {},
    status: 200 | 400 | 403 | 409 | 429 = 200,
  ) {
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found) return c.html(notFoundPage(), 404);
    const [members, invitations] = await Promise.all([
      listMembers(c.env.DB, orgId),
      canInvite(found.role) ? listInvitations(c.env.DB, orgId, deps.now()) : Promise.resolve([]),
    ]);
    return c.html(
      orgPage({
        org: found.org,
        role: found.role,
        userId: session.user.id,
        members,
        invitations,
        ...flash,
      }),
      status,
    );
  }

  /**
   * For changes: same origin, rate-limited, signed in, a member of an active organization.
   * Returns the session, the organization's ID and the account's role, or the response to send.
   */
  async function forChange(
    c: AppContext,
  ): Promise<{ session: Session; orgId: string; role: OrgRole; form: FormData } | Response> {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'orgs')))
      return c.html(messagePage(MESSAGES.tooManyAttempts, 'Nothing changed'), 429);
    const session = c.get('session');
    if (!session) return signIn(c);
    const orgId = c.req.param('org') ?? '';
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found) return c.html(notFoundPage(), 404);
    const form = await c.req.raw.formData();
    if (found.org.status !== 'active') {
      return showOrg(c, session, orgId, { error: 'This organization is suspended.' }, 403);
    }
    return { session, orgId, role: found.role, form };
  }

  const back = (orgId: string, done: string) => `/orgs/${encodeURIComponent(orgId)}?done=${done}`;

  // ---- Creating -------------------------------------------------------------------------------

  app.get('/orgs/new', (c) => (c.get('session') ? c.html(newOrgPage()) : signIn(c)));

  app.post('/orgs', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'orgs')))
      return c.html(messagePage(MESSAGES.tooManyAttempts, 'Nothing changed'), 429);
    const session = c.get('session');
    if (!session) return signIn(c);
    const form = await c.req.raw.formData();
    const raw = form.get('name');
    const name = orgName(raw);
    if (!name) {
      return c.html(
        newOrgPage({ name: typeof raw === 'string' ? raw : '', error: NAME_ERROR }),
        400,
      );
    }
    const id = await createOrganization(c.env.DB, deps.now(), session.user.id, name);
    if (!id) {
      return c.html(
        newOrgPage({
          name,
          error: 'You’re in 50 organizations, the most an account can be in. Leave one first.',
        }),
        409,
      );
    }
    await record(c, session, 'org.created', { org: id });
    return c.redirect(back(id, 'created'), 303);
  });

  // ---- The organization's page ----------------------------------------------------------------

  app.get('/orgs/:org', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    const done = DONE[c.req.query('done') ?? ''];
    return showOrg(c, session, c.req.param('org'), done ? { notice: done } : {});
  });

  app.post('/orgs/:org/name', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    if (!canManageOrganization(ctx.role))
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Only owners can rename the organization.' },
        403,
      );
    const name = orgName(ctx.form.get('name'));
    if (!name) return showOrg(c, ctx.session, ctx.orgId, { error: NAME_ERROR }, 400);
    await renameOrganization(c.env.DB, deps.now(), ctx.orgId, name);
    await record(c, ctx.session, 'org.renamed', { org: ctx.orgId });
    return c.redirect(back(ctx.orgId, 'renamed'), 303);
  });

  // ---- Invitations ----------------------------------------------------------------------------

  app.post('/orgs/:org/invitations', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const { session, orgId } = ctx;
    if (!canInvite(ctx.role))
      return showOrg(
        c,
        session,
        orgId,
        { error: 'Only owners and admins can invite people.' },
        403,
      );
    const rawEmail = ctx.form.get('email');
    const email = typeof rawEmail === 'string' ? normaliseEmail(rawEmail) : null;
    const role = ctx.form.get('role');
    if (!email)
      return showOrg(
        c,
        session,
        orgId,
        { error: 'Enter one email address.', email: typeof rawEmail === 'string' ? rawEmail : '' },
        400,
      );
    if (role !== 'member' && role !== 'admin')
      return showOrg(c, session, orgId, { error: 'Choose a role.', email }, 400);

    // How many invitation emails this account sent in the last day, across organizations.
    const now = deps.now();
    const sent = await c.env.DB.prepare(
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'org.invited' AND actor_user_id = ? AND at > ?",
    )
      .bind(session.user.id, now - 24 * 60 * 60)
      .first<{ n: number }>();
    if ((sent?.n ?? 0) >= MAX_INVITATIONS_PER_DAY) {
      return showOrg(
        c,
        session,
        orgId,
        {
          error: 'You’ve sent 50 invitations today, the most for one day. Try again tomorrow.',
          email,
        },
        429,
      );
    }

    const result = await createInvitation(c.env, now, {
      orgId,
      email,
      role,
      invitedBy: session.user.id,
    });
    if (!result.ok) {
      const error = {
        member: 'That address already belongs to a member.',
        invited: 'That address already has an open invitation. Withdraw it to send a new one.',
        full: 'This organization has reached its limit: 1,000 members and invitations, or 100 open invitations.',
      }[result.reason];
      return showOrg(c, session, orgId, { error, email }, 409);
    }
    const found = await membership(c.env.DB, orgId, session.user.id);
    const mail = invitationMail({
      org: found?.org.name ?? '',
      inviter: inviterLabel(session.user.displayName, session.user.primaryEmail),
      role,
      link: `${c.env.ISSUER}/invite/${result.token}`,
    });
    workerCtx(c).waitUntil(sendMail(c.env, email, mail.subject, mail.lines));
    await record(c, session, 'org.invited', { org: orgId, invitation: result.id, role });
    return c.redirect(back(orgId, 'invited'), 303);
  });

  app.post('/orgs/:org/invitations/revoke', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    if (!canInvite(ctx.role))
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Only owners and admins can withdraw invitations.' },
        403,
      );
    const id = ctx.form.get('invitation');
    if (typeof id === 'string' && (await deleteInvitation(c.env.DB, ctx.orgId, id))) {
      await record(c, ctx.session, 'org.invitation_revoked', { org: ctx.orgId, invitation: id });
    }
    return c.redirect(back(ctx.orgId, 'withdrawn'), 303);
  });

  // ---- Members --------------------------------------------------------------------------------

  /** The other member a change is about, and their role; or the page to show instead. */
  async function target(c: AppContext, ctx: { session: Session; orgId: string; form: FormData }) {
    const userId = ctx.form.get('user');
    if (typeof userId !== 'string' || userId === ctx.session.user.id) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'To change your own membership, use Leave below, or ask another owner.' },
        400,
      );
    }
    const found = await membership(c.env.DB, ctx.orgId, userId);
    if (!found)
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'That person is no longer a member.' },
        409,
      );
    return { userId, role: found.role };
  }

  app.post('/orgs/:org/members/role', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const who = await target(c, ctx);
    if (who instanceof Response) return who;
    const next = ctx.form.get('role');
    if (!isOrgRole(next))
      return showOrg(c, ctx.session, ctx.orgId, { error: 'Choose a role.' }, 400);
    if (!canSetRole(ctx.role, who.role, next)) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Only owners can make or change owners.' },
        403,
      );
    }
    // Making an owner hands over full control: only with a recent proof it's you.
    if (next === 'owner' || who.role === 'owner') {
      const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}`);
      if (redirect) return c.redirect(redirect, 303);
    }
    if (!(await setRole(c.env.DB, ctx.orgId, who.userId, next))) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Nothing changed: an organization always keeps at least one owner.' },
        409,
      );
    }
    await record(c, ctx.session, 'org.role_changed', {
      org: ctx.orgId,
      target: who.userId,
      role: next,
    });
    return c.redirect(back(ctx.orgId, 'role'), 303);
  });

  app.post('/orgs/:org/members/remove', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const who = await target(c, ctx);
    if (who instanceof Response) return who;
    if (!canRemove(ctx.role, who.role)) {
      return showOrg(c, ctx.session, ctx.orgId, { error: 'Only owners can remove owners.' }, 403);
    }
    if (!(await removeMember(c.env.DB, ctx.orgId, who.userId))) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Nothing changed: an organization always keeps at least one owner.' },
        409,
      );
    }
    await record(c, ctx.session, 'org.member_removed', { org: ctx.orgId, target: who.userId });
    return c.redirect(back(ctx.orgId, 'removed'), 303);
  });

  // Leaving works in a suspended organization too: nobody is kept in one against their will.
  app.post('/orgs/:org/leave', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return signIn(c);
    const orgId = c.req.param('org');
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found) return c.html(notFoundPage(), 404);
    const form = await c.req.raw.formData();
    if (form.get('confirm') !== 'on') return c.redirect(`/orgs/${encodeURIComponent(orgId)}`, 303);
    if (!(await removeMember(c.env.DB, orgId, session.user.id))) {
      return showOrg(
        c,
        session,
        orgId,
        {
          error:
            'You’re the only owner. Make someone else an owner first, or delete the organization.',
        },
        409,
      );
    }
    await record(c, session, 'org.left', { org: orgId });
    return c.redirect('/account?saved=left', 303);
  });

  // ---- Deleting -------------------------------------------------------------------------------

  app.get('/orgs/:org/delete', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    const found = await membership(c.env.DB, c.req.param('org'), session.user.id);
    if (!found || !canManageOrganization(found.role) || found.org.status !== 'active') {
      return c.html(notFoundPage(), 404);
    }
    const members = await listMembers(c.env.DB, found.org.id);
    return c.html(deleteOrgPage({ org: found.org, members: members.length }));
  });

  app.post('/orgs/:org/delete', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    if (!canManageOrganization(ctx.role)) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Only owners can delete the organization.' },
        403,
      );
    }
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/delete`);
    if (redirect) return c.redirect(redirect, 303);
    const found = await membership(c.env.DB, ctx.orgId, ctx.session.user.id);
    const typed = orgName(ctx.form.get('name'));
    if (!found || typed !== found.org.name) {
      const members = await listMembers(c.env.DB, ctx.orgId);
      return c.html(
        deleteOrgPage({
          org: found?.org ?? { id: ctx.orgId, name: '', status: 'active', createdAt: 0 },
          members: members.length,
          error: 'The name you typed doesn’t match. Nothing was deleted.',
        }),
        400,
      );
    }
    const now = deps.now();
    await deleteOrganization(c.env.DB, now, ctx.orgId);
    await record(c, ctx.session, 'org.deleted', { org: ctx.orgId });
    return c.redirect('/account?saved=org_deleted', 303);
  });

  // ---- Answering an invitation ------------------------------------------------------------------

  const invitationGone = () =>
    messagePage(
      {
        title: 'This invitation no longer works',
        body: 'It was already used, withdrawn or declined, or it expired after 7 days. Ask the person who invited you to send a new one.',
        action: { href: '/account', label: 'Go to your account' },
      },
      'Invitation',
    );

  app.get('/invite/:token', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    const token = c.req.param('token');
    const invitation = await invitationByToken(c.env, deps.now(), token);
    if (!invitation) return c.html(invitationGone(), 404);
    return c.html(invitationPage({ token, invitation, signedInAs: session.user.primaryEmail }));
  });

  app.post('/invite/:token', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'orgs')))
      return c.html(messagePage(MESSAGES.tooManyAttempts, 'Nothing changed'), 429);
    const session = c.get('session');
    if (!session) return signIn(c);
    const now = deps.now();
    const token = c.req.param('token');
    const invitation = await invitationByToken(c.env, now, token);
    if (!invitation) return c.html(invitationGone(), 404);
    const form = await c.req.raw.formData();

    if (form.get('decision') === 'decline') {
      // Only the invited person can decline, like accepting.
      const mine = await accountHasAddress(c.env.DB, session.user.id, invitation.email);
      if (!mine) {
        return c.html(
          invitationPage({
            token,
            invitation,
            signedInAs: session.user.primaryEmail,
            wrongAddress: true,
          }),
          403,
        );
      }
      await deleteInvitation(c.env.DB, invitation.orgId, invitation.id);
      await record(c, session, 'org.invitation_declined', {
        org: invitation.orgId,
        invitation: invitation.id,
      });
      return c.redirect('/account?saved=declined', 303);
    }

    const result = await acceptInvitation(c.env.DB, now, invitation, session.user.id);
    if (!result.ok) {
      if (result.reason === 'wrong_address') {
        return c.html(
          invitationPage({
            token,
            invitation,
            signedInAs: session.user.primaryEmail,
            wrongAddress: true,
          }),
          403,
        );
      }
      return c.html(
        messagePage(
          result.reason === 'suspended'
            ? {
                title: 'This organization is suspended',
                body: 'You can’t join it right now. The invitation still works until it expires.',
              }
            : {
                title: 'You’re in too many organizations',
                body: 'An account can be in 50 organizations. Leave one, then open the invitation again.',
                action: { href: '/account', label: 'Go to your account' },
              },
          'Invitation',
        ),
        409,
      );
    }
    await record(c, session, 'org.joined', { org: result.orgId, role: result.role });
    return c.redirect(back(result.orgId, 'joined'), 303);
  });
}
