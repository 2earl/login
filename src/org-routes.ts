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
import { invitationMail, notify, sendMail } from './mail';
import {
  deactivate,
  isManagedBy,
  managedCounts,
  reactivate,
  releaseAccounts,
  setDomainManaged,
  setRequireSso,
} from './managed';
import { authorizationServer } from './oauth';
import { noticeContext, removeAccount } from './sign-in';
import { changeCheck } from './mfa-routes';
import {
  deleteManagedAccountPage,
  deleteOrgPage,
  directoryPage,
  invitationPage,
  newOrgPage,
  orgActivityPage,
  orgPage,
  orgSettingsPage,
} from './org-pages';
import { addDomain, listDomains, normaliseDomain, removeDomain, verifyDomain } from './org-domains';
import { createScimToken, listScimTokens, revokeScimToken } from './scim';
import { samlConfig, signingKeyPem, ssoUrl } from './saml';
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
  deactivated: 'Account deactivated. It can’t sign in, and its apps lost access.',
  reactivated: 'Account reactivated. It can sign in again.',
  account_deleted: 'Account deleted, in every 2earl service.',
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

  app.get('/orgs/:org/settings', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    return showSettings(
      c,
      session,
      c.req.param('org'),
      c.req.query('done') === 'renamed' ? { notice: 'Organization renamed.' } : {},
    );
  });

  async function showSettings(
    c: AppContext,
    session: Session,
    orgId: string,
    flash: { notice?: string; error?: string } = {},
    status: 200 | 400 | 403 | 409 = 200,
  ) {
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found) return c.html(notFoundPage(), 404);
    const owners = (await listMembers(c.env.DB, orgId)).filter((m) => m.role === 'owner').length;
    return c.html(
      orgSettingsPage({
        org: found.org,
        role: found.role,
        owners,
        managed: session.user.managedBy === orgId,
        ...flash,
      }),
      status,
    );
  }

  // What happened in the organization: owners and admins (DESIGN §4.14).
  app.get('/orgs/:org/activity', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    const found = await membership(c.env.DB, c.req.param('org'), session.user.id);
    if (!found || found.role === 'member') return c.html(notFoundPage(), 404);
    const { results } = await c.env.DB.prepare(
      `SELECT e.at, e.event, e.detail,
              COALESCE(a.display_name, a.primary_email) AS actor,
              COALESCE(t.display_name, t.primary_email) AS target
       FROM audit_events e
       LEFT JOIN users a ON a.id = e.actor_user_id
       LEFT JOIN users t ON t.id = json_extract(e.detail, '$.target')
       WHERE json_extract(e.detail, '$.org') = ?
         AND (e.event LIKE 'org.%' OR e.event LIKE 'scim.%')
       ORDER BY e.at DESC LIMIT 200`,
    )
      .bind(found.org.id)
      .all<{
        at: number;
        event: string;
        detail: string | null;
        actor: string | null;
        target: string | null;
      }>();
    return c.html(
      orgActivityPage({
        org: found.org,
        role: found.role,
        now: deps.now(),
        entries: results.map((r) => ({
          at: r.at,
          event: r.event,
          actor: r.actor,
          target: r.target,
          detail: (() => {
            try {
              return JSON.parse(r.detail ?? '{}') as Record<string, unknown>;
            } catch {
              return {};
            }
          })(),
        })),
      }),
    );
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
    if (!name) return showSettings(c, ctx.session, ctx.orgId, { error: NAME_ERROR }, 400);
    await renameOrganization(c.env.DB, deps.now(), ctx.orgId, name);
    await record(c, ctx.session, 'org.renamed', { org: ctx.orgId });
    return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/settings?done=renamed`, 303);
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
    workerCtx(c).waitUntil(sendMail(c.env, email, mail));
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
    if (await isManagedBy(c.env.DB, who.userId, ctx.orgId)) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'The organization manages this account: deactivate it instead of removing it.' },
        409,
      );
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
    if (form.get('confirm') !== 'on')
      return c.redirect(`/orgs/${encodeURIComponent(orgId)}/settings`, 303);
    if (session.user.managedBy === orgId) {
      return showSettings(
        c,
        session,
        orgId,
        { error: 'This organization manages your account, so you can’t leave it. Ask its admins.' },
        409,
      );
    }
    if (!(await removeMember(c.env.DB, orgId, session.user.id))) {
      return showSettings(
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
    return c.redirect('/account/orgs?saved=left', 303);
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
    return c.redirect('/account/orgs?saved=org_deleted', 303);
  });

  // ---- Domains and directory sync (DESIGN §4.16) ---------------------------------------------------

  async function showDirectory(
    c: AppContext,
    orgId: string,
    flash: { notice?: string; error?: string; newToken?: string } = {},
    status: 200 | 400 | 403 | 409 = 200,
  ) {
    const session = c.get('session');
    const found = session ? await membership(c.env.DB, orgId, session.user.id) : null;
    if (!found || !canManageOrganization(found.role)) return c.html(notFoundPage(), 404);
    const counts = await c.env.DB.prepare(
      `SELECT
         SUM(CASE WHEN active = 1 AND user_id IS NOT NULL THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN active = 1 AND user_id IS NULL THEN 1 ELSE 0 END) AS waiting,
         SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) AS inactive
       FROM scim_users WHERE org_id = ?`,
    )
      .bind(orgId)
      .first<{ active: number | null; waiting: number | null; inactive: number | null }>();
    return c.html(
      directoryPage({
        org: found.org,
        issuer: c.env.ISSUER,
        domains: await listDomains(c.env.DB, orgId),
        tokens: await listScimTokens(c.env.DB, orgId),
        saml: await samlConfig(c.env.DB, orgId).then((config) =>
          config
            ? {
                idpEntityId: config.idpEntityId,
                ssoUrl: config.ssoUrl,
                certificate: config.certificate,
                enabled: config.enabled,
              }
            : null,
        ),
        provisioned: {
          active: counts?.active ?? 0,
          waiting: counts?.waiting ?? 0,
          inactive: counts?.inactive ?? 0,
        },
        managed: {
          ...(await managedCounts(c.env.DB, orgId)),
          requireSso: await c.env.DB.prepare('SELECT require_sso FROM organizations WHERE id = ?')
            .bind(orgId)
            .first<{ require_sso: number }>()
            .then((row) => row?.require_sso === 1),
        },
        ...flash,
      }),
      status,
    );
  }

  /** For directory changes: an owner of an active organization. */
  async function ownerChange(c: AppContext) {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    if (!canManageOrganization(ctx.role)) return c.html(notFoundPage(), 404);
    return ctx;
  }

  const DIRECTORY_DONE: Record<string, string> = {
    added: 'Domain added. Publish the TXT record, then check it.',
    verified: 'Domain verified.',
    removed: 'Domain removed.',
    revoked: 'Token revoked. Your directory can no longer use it.',
    saml: 'Single sign-on saved.',
    managed:
      'Accounts at the domain are managed now. People who already had one choose at their next sign-in.',
    unmanaged:
      'You stopped managing the accounts at the domain. They belong to their people again.',
    sso_required: 'Managed accounts now sign in only with single sign-on.',
    sso_optional: 'Managed accounts can sign in any way again.',
  };

  app.get('/orgs/:org/directory', async (c) => {
    if (!c.get('session')) return signIn(c);
    const done = DIRECTORY_DONE[c.req.query('done') ?? ''];
    return showDirectory(c, c.req.param('org'), done ? { notice: done } : {});
  });

  const directory = (orgId: string, done: string) =>
    `/orgs/${encodeURIComponent(orgId)}/directory?done=${done}`;

  app.post('/orgs/:org/domains', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const domain = normaliseDomain(ctx.form.get('domain'));
    if (!domain)
      return showDirectory(
        c,
        ctx.orgId,
        { error: 'Enter a domain name, such as example.com.' },
        400,
      );
    const result = await addDomain(c.env.DB, deps.now(), ctx.orgId, domain);
    if (result === 'full')
      return showDirectory(
        c,
        ctx.orgId,
        { error: 'An organization can have up to 10 domains.' },
        409,
      );
    if (result === 'added')
      await record(c, ctx.session, 'org.domain_added', { org: ctx.orgId, domain });
    return c.redirect(directory(ctx.orgId, 'added'), 303);
  });

  app.post('/orgs/:org/domains/verify', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const domain = normaliseDomain(ctx.form.get('domain'));
    if (!domain) return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/directory`, 303);
    const result = await verifyDomain(c.env.DB, deps.fetch, deps.now(), ctx.orgId, domain);
    if (result === 'verified') {
      await record(c, ctx.session, 'org.domain_verified', { org: ctx.orgId, domain });
      return c.redirect(directory(ctx.orgId, 'verified'), 303);
    }
    const error = {
      not_found:
        'The TXT record isn’t there yet. DNS changes can take a while to appear; check again later.',
      taken: 'Another organization has already verified this domain.',
      dns_error: 'We couldn’t look the record up just now. Try again in a minute.',
      unknown: 'That domain isn’t on this organization.',
    }[result];
    return showDirectory(c, ctx.orgId, { error }, 409);
  });

  app.post('/orgs/:org/domains/remove', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const domain = normaliseDomain(ctx.form.get('domain'));
    if (domain && (await removeDomain(c.env.DB, ctx.orgId, domain))) {
      await record(c, ctx.session, 'org.domain_removed', { org: ctx.orgId, domain });
      // Accounts managed through it become their people's own again (DESIGN §4.18).
      await releaseAccounts(c.env.DB, deps.now(), ctx.orgId);
    }
    return c.redirect(directory(ctx.orgId, 'removed'), 303);
  });

  app.post('/orgs/:org/scim-tokens', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    // A directory token adds and removes members: only with a recent proof it's you.
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const verified = (await listDomains(c.env.DB, ctx.orgId)).some((d) => d.verifiedAt !== null);
    if (!verified) return showDirectory(c, ctx.orgId, { error: 'Verify a domain first.' }, 409);
    const created = await createScimToken(c.env.DB, deps.now(), ctx.orgId);
    if (!created) {
      return showDirectory(
        c,
        ctx.orgId,
        { error: 'This organization has two tokens. Revoke one first.' },
        409,
      );
    }
    await record(c, ctx.session, 'org.scim_token_created', { org: ctx.orgId, token: created.id });
    return showDirectory(c, ctx.orgId, { newToken: created.token });
  });

  app.post('/orgs/:org/saml', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    // Single sign-on decides who signs in at the organization's domains: a recent proof first.
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const verified = (await listDomains(c.env.DB, ctx.orgId)).some((d) => d.verifiedAt !== null);
    if (!verified) return showDirectory(c, ctx.orgId, { error: 'Verify a domain first.' }, 409);
    const idp = ctx.form.get('idp_entity_id');
    const idpEntityId = typeof idp === 'string' ? idp.trim().slice(0, 500) : '';
    const url = ssoUrl(ctx.form.get('sso_url'));
    const certificate = signingKeyPem(ctx.form.get('certificate'));
    if (!idpEntityId || !url || !certificate) {
      return showDirectory(
        c,
        ctx.orgId,
        {
          error:
            'Enter the identity provider’s entity ID, an https sign-in URL and its signing certificate.',
        },
        400,
      );
    }
    const now = deps.now();
    await c.env.DB.prepare(
      `INSERT INTO org_saml (org_id, idp_entity_id, sso_url, certificate, enabled, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
       ON CONFLICT (org_id) DO UPDATE SET idp_entity_id = ?2, sso_url = ?3, certificate = ?4,
         enabled = ?5, updated_at = ?6`,
    )
      .bind(ctx.orgId, idpEntityId, url, certificate, ctx.form.get('enabled') === 'on' ? 1 : 0, now)
      .run();
    await record(c, ctx.session, 'org.saml_saved', {
      org: ctx.orgId,
      enabled: ctx.form.get('enabled') === 'on',
    });
    return c.redirect(directory(ctx.orgId, 'saml'), 303);
  });

  // ---- Managed accounts (DESIGN §4.18) ----------------------------------------------------------

  app.post('/orgs/:org/domains/manage', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    // Managing decides over other people's accounts: a recent proof it's you.
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const domain = normaliseDomain(ctx.form.get('domain'));
    if (!domain) return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/directory`, 303);
    const on = ctx.form.get('on') === '1';
    if (on && ctx.form.get('accept') !== 'on') {
      return showDirectory(
        c,
        ctx.orgId,
        { error: 'To manage accounts, accept the data processing terms: you decide over them.' },
        400,
      );
    }
    const now = deps.now();
    const result = await setDomainManaged(c.env.DB, now, ctx.orgId, domain, on);
    if (!result.changed) return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/directory`, 303);
    await record(c, ctx.session, on ? 'org.domain_managed' : 'org.domain_unmanaged', {
      org: ctx.orgId,
      domain,
    });
    if (on && result.notify.length > 0) {
      const found = await membership(c.env.DB, ctx.orgId, ctx.session.user.id);
      const org = found?.org.name ?? 'Your organization';
      const context = noticeContext(c, now);
      workerCtx(c).waitUntil(
        Promise.all(
          result.notify.map((userId) =>
            notify(c.env, userId, { kind: 'domain_managed', org, domain }, context),
          ),
        ).then(() => undefined),
      );
    }
    return c.redirect(directory(ctx.orgId, on ? 'managed' : 'unmanaged'), 303);
  });

  app.post('/orgs/:org/require-sso', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const on = ctx.form.get('on') === '1';
    if (on) {
      if (!(await samlConfig(c.env.DB, ctx.orgId))?.enabled) {
        return showDirectory(c, ctx.orgId, { error: 'Turn on single sign-on first.' }, 409);
      }
      // Owners stay able to sign in other ways; the one turning it on must protect that way.
      if (!ctx.session.hasFactor) {
        return showDirectory(
          c,
          ctx.orgId,
          {
            error:
              'Add a second factor to your own account first. Owners can still sign in without single sign-on, so their accounts need one.',
          },
          409,
        );
      }
    }
    const ended = await setRequireSso(c.env.DB, deps.now(), ctx.orgId, on);
    await record(c, ctx.session, 'org.require_sso_changed', { org: ctx.orgId, on, ended });
    return c.redirect(directory(ctx.orgId, on ? 'sso_required' : 'sso_optional'), 303);
  });

  /** A managed member a change is about: the actor's role must allow acting on theirs. */
  async function managedTarget(
    c: AppContext,
    ctx: { session: Session; orgId: string; role: OrgRole; form: FormData },
  ) {
    const who = await target(c, ctx);
    if (who instanceof Response) return who;
    if (!canRemove(ctx.role, who.role)) {
      return showOrg(c, ctx.session, ctx.orgId, { error: 'Only owners can act on owners.' }, 403);
    }
    if (!(await isManagedBy(c.env.DB, who.userId, ctx.orgId))) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'This organization doesn’t manage that account.' },
        409,
      );
    }
    return who;
  }

  app.post('/orgs/:org/members/deactivate', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const who = await managedTarget(c, ctx);
    if (who instanceof Response) return who;
    const now = deps.now();
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    if (await deactivate(c.env.DB, oauth, now, who.userId, ctx.orgId)) {
      await record(c, ctx.session, 'org.account_deactivated', {
        org: ctx.orgId,
        target: who.userId,
      });
      const found = await membership(c.env.DB, ctx.orgId, ctx.session.user.id);
      workerCtx(c).waitUntil(
        notify(
          c.env,
          who.userId,
          { kind: 'account_deactivated', org: found?.org.name ?? 'Your organization' },
          noticeContext(c, now),
        ),
      );
    }
    return c.redirect(back(ctx.orgId, 'deactivated'), 303);
  });

  app.post('/orgs/:org/members/reactivate', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const who = await managedTarget(c, ctx);
    if (who instanceof Response) return who;
    const now = deps.now();
    if (await reactivate(c.env.DB, now, who.userId, ctx.orgId)) {
      await record(c, ctx.session, 'org.account_reactivated', {
        org: ctx.orgId,
        target: who.userId,
      });
      const found = await membership(c.env.DB, ctx.orgId, ctx.session.user.id);
      workerCtx(c).waitUntil(
        notify(
          c.env,
          who.userId,
          { kind: 'account_reactivated', org: found?.org.name ?? 'Your organization' },
          noticeContext(c, now),
        ),
      );
    }
    return c.redirect(back(ctx.orgId, 'reactivated'), 303);
  });

  /** Deleting a managed account: owners only, with a recent proof and a confirmation. */
  async function deletable(c: AppContext, orgId: string, userId: unknown) {
    const session = c.get('session');
    if (!session) return signIn(c);
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found || !canManageOrganization(found.role)) return c.html(notFoundPage(), 404);
    if (typeof userId !== 'string' || userId === session.user.id)
      return c.html(notFoundPage(), 404);
    const member = (await listMembers(c.env.DB, orgId)).find((m) => m.userId === userId);
    if (!member?.managed) return c.html(notFoundPage(), 404);
    return { session, org: found.org, member };
  }

  app.get('/orgs/:org/accounts/delete', async (c) => {
    const orgId = c.req.param('org');
    const userId = c.req.query('user');
    const ctx = await deletable(c, orgId, userId);
    if (ctx instanceof Response) return ctx;
    const redirect = changeCheck(
      ctx.session,
      deps.now(),
      `/orgs/${orgId}/accounts/delete?user=${encodeURIComponent(ctx.member.userId)}`,
    );
    if (redirect) return c.redirect(redirect, 303);
    return c.html(deleteManagedAccountPage({ org: ctx.org, member: ctx.member }));
  });

  app.post('/orgs/:org/accounts/delete', async (c) => {
    const ctx = await forChange(c);
    if (ctx instanceof Response) return ctx;
    const found = await deletable(c, ctx.orgId, ctx.form.get('user'));
    if (found instanceof Response) return found;
    const now = deps.now();
    const redirect = changeCheck(
      ctx.session,
      now,
      `/orgs/${ctx.orgId}/accounts/delete?user=${encodeURIComponent(found.member.userId)}`,
    );
    if (redirect) return c.redirect(redirect, 303);
    if (ctx.form.get('confirm') !== 'on') {
      return c.html(
        deleteManagedAccountPage({
          org: found.org,
          member: found.member,
          error: 'Tick the box to confirm.',
        }),
        400,
      );
    }
    if (!(await removeAccount(c, now, found.member.userId))) {
      return c.html(
        deleteManagedAccountPage({
          org: found.org,
          member: found.member,
          error: 'The account couldn’t be deleted. Nothing changed; try again.',
        }),
        500,
      );
    }
    await record(c, ctx.session, 'org.account_deleted', { org: ctx.orgId });
    return c.redirect(back(ctx.orgId, 'account_deleted'), 303);
  });

  app.post('/orgs/:org/scim-tokens/revoke', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const id = ctx.form.get('token');
    if (typeof id === 'string' && (await revokeScimToken(c.env.DB, ctx.orgId, id))) {
      await record(c, ctx.session, 'org.scim_token_revoked', { org: ctx.orgId, token: id });
    }
    return c.redirect(directory(ctx.orgId, 'revoked'), 303);
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
      return c.redirect('/account/orgs?saved=declined', 303);
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
