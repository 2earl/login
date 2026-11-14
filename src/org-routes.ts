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
  ssoOn,
  ssoOnSql,
} from './managed';
import { discover, issuerUrl, oidcConfig, saveOidc } from './sso-oidc';
import { findGroup, listGroups, setGroupRole } from './scim-groups';
import { createApiKey, listApiKeys, revokeApiKey } from './org-api';
import {
  MAX_EXPORT,
  deleteStream,
  orgAuditEvents,
  publicRecord,
  readStream,
  saveStream,
  sendTest,
  streamUrl,
  toCsv,
} from './org-audit';

/** How far back the log goes (the security log's retention, DESIGN §4.6). */
const AUDIT_DAYS = 90;
import {
  allowApp,
  appsInUse,
  disallowApp,
  listAllowedApps,
  restrictsApps,
  setRestrictApps,
} from './app-access';
import { authorizationServer } from './oauth';
import {
  MAX_RANGES,
  POLICY_METHODS,
  SESSION_HOURS,
  parseRanges,
  isDefaultPolicy,
  readPolicy,
  savePolicy,
  type PolicyMethod,
} from './org-policy';
import { noticeContext, removeAccount } from './sign-in';
import { changeCheck } from './mfa-routes';
import {
  deleteManagedAccountPage,
  type AppsView,
  type SetupState,
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
  stream_removed: 'Stream removed. Nothing more is sent.',
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
    const [members, invitations, setup] = await Promise.all([
      listMembers(c.env.DB, orgId),
      canInvite(found.role) ? listInvitations(c.env.DB, orgId, deps.now()) : Promise.resolve([]),
      found.role === 'owner' ? setupState(c.env.DB, orgId) : Promise.resolve(undefined),
    ]);
    return c.html(
      orgPage({
        org: found.org,
        role: found.role,
        userId: session.user.id,
        members,
        invitations,
        ...(setup ? { setup } : {}),
        ...flash,
      }),
      status,
    );
  }

  /** How far the company setup is (the owner's guide on the organization's pages). */
  async function setupState(db: D1Database, orgId: string): Promise<SetupState> {
    const row = await db
      .prepare(
        `SELECT
           EXISTS (SELECT 1 FROM org_domains WHERE org_id = ?1 AND verified_at IS NOT NULL) AS verified,
           EXISTS (SELECT 1 FROM org_domains WHERE org_id = ?1 AND managed_at IS NOT NULL) AS managed,
           ${ssoOnSql('?1')} AS sso,
           EXISTS (SELECT 1 FROM scim_tokens WHERE org_id = ?1) AS directory`,
      )
      .bind(orgId)
      .first<{ verified: number; managed: number; sso: number; directory: number }>();
    return {
      verified: row?.verified === 1,
      managed: row?.managed === 1,
      sso: row?.sso === 1,
      directory: row?.directory === 1,
      rules: !isDefaultPolicy(await readPolicy(db, orgId)),
    };
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
    flash: { notice?: string; error?: string; newKey?: string } = {},
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
        issuer: c.env.ISSUER,
        ...(found.role === 'owner' ? { apiKeys: await listApiKeys(c.env.DB, orgId) } : {}),
        ...flash,
      }),
      status,
    );
  }

  // What happened in the organization: owners and admins (DESIGN §4.14, §4.23).
  app.get('/orgs/:org/activity', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    return showActivity(c, session, c.req.param('org'), DONE[c.req.query('done') ?? '']);
  });

  async function showActivity(
    c: AppContext,
    session: Session,
    orgId: string,
    notice?: string,
    flash: { error?: string; secret?: string } = {},
    status: 200 | 400 | 409 = 200,
  ) {
    const found = await membership(c.env.DB, orgId, session.user.id);
    if (!found || found.role === 'member') return c.html(notFoundPage(), 404);
    const now = deps.now();
    // Newest first: the latest 200 of the last 90 days.
    const records = await orgAuditEvents(c.env.DB, found.org.id, {
      afterAt: now - AUDIT_DAYS * 86_400,
      until: now,
      limit: MAX_EXPORT,
    });
    const names = await c.env.DB.prepare(
      `SELECT u.id, COALESCE(u.display_name, u.primary_email) AS name FROM users u
       JOIN org_members m ON m.user_id = u.id AND m.org_id = ?`,
    )
      .bind(found.org.id)
      .all<{ id: string; name: string | null }>();
    const nameOf = new Map(names.results.map((r) => [r.id, r.name]));
    return c.html(
      orgActivityPage({
        org: found.org,
        role: found.role,
        now,
        entries: records
          .slice(-200)
          .reverse()
          .map((r) => ({
            at: r.at,
            event: r.event,
            actor: r.actor ? (nameOf.get(r.actor.id) ?? r.actor.email) : null,
            target: r.target ? (nameOf.get(r.target.id) ?? r.target.email) : null,
            detail: r.detail,
          })),
        stream: found.role === 'owner' ? await readStream(c.env.DB, found.org.id) : null,
        ...(notice ? { notice } : {}),
        ...flash,
      }),
      status,
    );
  }

  // The log as a file (DESIGN §4.23): owners and admins, the last 7, 30 or 90 days.
  app.get('/orgs/:org/activity/export', async (c) => {
    const session = c.get('session');
    if (!session) return signIn(c);
    const found = await membership(c.env.DB, c.req.param('org'), session.user.id);
    if (!found || found.role === 'member') return c.html(notFoundPage(), 404);
    const days = [7, 30, 90].includes(Number(c.req.query('days')))
      ? Number(c.req.query('days'))
      : 30;
    const format = c.req.query('format') === 'json' ? 'json' : 'csv';
    const now = deps.now();
    const records = await orgAuditEvents(c.env.DB, found.org.id, {
      afterAt: now - days * 86_400,
      until: now,
      limit: MAX_EXPORT,
    });
    await record(c, session, 'org.audit_exported', {
      org: found.org.id,
      days,
      format,
      count: records.length,
    });
    const stamp = new Date(now * 1000).toISOString().slice(0, 10);
    const filename = `2earl-audit-${found.org.id}-${stamp}.${format}`;
    const headers = {
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store',
    };
    return format === 'json'
      ? c.body(
          JSON.stringify(
            { organization: found.org.id, days, events: records.map(publicRecord) },
            null,
            1,
          ),
          200,
          { ...headers, 'Content-Type': 'application/json; charset=utf-8' },
        )
      : c.body(toCsv(records), 200, { ...headers, 'Content-Type': 'text/csv; charset=utf-8' });
  });

  // The organization's API keys: owners, with a recent proof (DESIGN §4.24).
  app.post('/orgs/:org/api-keys', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/settings`);
    if (redirect) return c.redirect(redirect, 303);
    if (ctx.form.get('action') === 'revoke') {
      const key = ctx.form.get('key');
      if (typeof key === 'string' && (await revokeApiKey(c.env.DB, ctx.orgId, key))) {
        await record(c, ctx.session, 'org.api_key_revoked', { org: ctx.orgId, key });
      }
      return showSettings(c, ctx.session, ctx.orgId, {
        notice: 'Key revoked. It stops working at once.',
      });
    }
    const nameRaw = ctx.form.get('name');
    const name = typeof nameRaw === 'string' ? nameRaw.trim().slice(0, 60) : '';
    const access = ctx.form.get('access') === 'write' ? 'write' : 'read';
    if (!name)
      return showSettings(c, ctx.session, ctx.orgId, { error: 'Give the key a name.' }, 400);
    const created = await createApiKey(c.env.DB, now, ctx.orgId, {
      name,
      access,
      createdBy: ctx.session.user.id,
    });
    if (!created) {
      return showSettings(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'An organization can have up to 5 keys. Revoke one first.' },
        409,
      );
    }
    await record(c, ctx.session, 'org.api_key_created', {
      org: ctx.orgId,
      key: created.id,
      name,
      access,
    });
    return showSettings(c, ctx.session, ctx.orgId, { newKey: created.key });
  });

  // Streaming to the organization's own security monitoring: owners (DESIGN §4.23).
  app.post('/orgs/:org/activity/stream', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/activity`);
    if (redirect) return c.redirect(redirect, 303);
    const action = ctx.form.get('action');
    if (action === 'delete') {
      await deleteStream(c.env.DB, ctx.orgId);
      await record(c, ctx.session, 'org.audit_stream_changed', { org: ctx.orgId, removed: true });
      return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/activity?done=stream_removed`, 303);
    }
    if (action === 'test') {
      const status = await sendTest(c.env, deps.fetch, now, ctx.orgId);
      return showActivity(
        c,
        ctx.session,
        ctx.orgId,
        /^2\d\d$/.test(status) ? `Test event delivered (HTTP ${status}).` : undefined,
        /^2\d\d$/.test(status) ? {} : { error: `The test wasn’t accepted: ${status}.` },
      );
    }
    const url = streamUrl(ctx.form.get('url'));
    if (!url) {
      return showActivity(
        c,
        ctx.session,
        ctx.orgId,
        undefined,
        { error: 'Enter an https URL.' },
        400,
      );
    }
    const secret = await saveStream(c.env, now, ctx.orgId, {
      url,
      enabled: ctx.form.get('enabled') === 'on',
      rotate: action === 'rotate',
    });
    await record(c, ctx.session, 'org.audit_stream_changed', {
      org: ctx.orgId,
      enabled: ctx.form.get('enabled') === 'on',
      rotated: secret !== null,
    });
    return showActivity(
      c,
      ctx.session,
      ctx.orgId,
      'Stream saved. New events go out within a minute.',
      secret ? { secret } : {},
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
    // The directory decides admin or member for the people it provisioned (DESIGN §4.21).
    if (
      next !== 'owner' &&
      (await listMembers(c.env.DB, ctx.orgId)).some(
        (m) => m.userId === who.userId && m.roleFromDirectory,
      )
    ) {
      return showOrg(
        c,
        ctx.session,
        ctx.orgId,
        { error: 'Your directory decides this person’s role: change their groups there.' },
        409,
      );
    }
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
        oidc: await oidcConfig(c.env.DB, orgId).then((config) =>
          config
            ? { issuer: config.issuer, clientId: config.clientId, enabled: config.enabled }
            : null,
        ),
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
        policy: await readPolicy(c.env.DB, orgId),
        groups: await listGroups(c.env.DB, orgId),
        apps: await appsView(c, orgId),
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
    policy: 'Security rules saved. They apply from each person’s next request.',
    group_role: 'Roles now follow your directory’s groups.',
    apps_restricted: 'Managed accounts may now use only the allowed apps.',
    apps_open: 'Managed accounts may connect any app again.',
    app_allowed: 'App allowed.',
    app_removed: 'App removed. Its access ends within 15 minutes.',
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

  app.post('/orgs/:org/oidc', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    // Single sign-on decides who signs in at the organization's domains: a recent proof first.
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const verified = (await listDomains(c.env.DB, ctx.orgId)).some((d) => d.verifiedAt !== null);
    if (!verified) return showDirectory(c, ctx.orgId, { error: 'Verify a domain first.' }, 409);
    const issuer = issuerUrl(ctx.form.get('issuer'));
    const clientIdRaw = ctx.form.get('client_id');
    const clientId = typeof clientIdRaw === 'string' ? clientIdRaw.trim().slice(0, 300) : '';
    const secretRaw = ctx.form.get('client_secret');
    const clientSecret =
      typeof secretRaw === 'string' && secretRaw.trim() ? secretRaw.trim().slice(0, 500) : null;
    const existing = await oidcConfig(c.env.DB, ctx.orgId);
    if (!issuer || !clientId || (!clientSecret && !existing)) {
      return showDirectory(
        c,
        ctx.orgId,
        { error: 'Enter the provider’s https issuer URL, the client ID and the client secret.' },
        400,
      );
    }
    // Multi-tenant endpoints accept anyone's tenant: only the organization's own will do.
    if (
      /^https:\/\/login\.microsoftonline\.com\/(?:common|organizations|consumers)(?:$|[/?#])/i.test(
        issuer,
      )
    ) {
      return showDirectory(
        c,
        ctx.orgId,
        {
          error:
            'Use your own tenant’s issuer: https://login.microsoftonline.com/<tenant ID>/v2.0.',
        },
        400,
      );
    }
    // Check the provider answers as that issuer before anyone depends on it.
    try {
      await discover(deps.fetch, issuer);
    } catch {
      return showDirectory(
        c,
        ctx.orgId,
        {
          error: `Couldn’t read the provider’s configuration at ${issuer}/.well-known/openid-configuration, or it names another issuer. Check the issuer URL.`,
        },
        400,
      );
    }
    const enabled = ctx.form.get('enabled') === 'on';
    await saveOidc(c.env, now, ctx.orgId, { issuer, clientId, clientSecret, enabled });
    await record(c, ctx.session, 'org.oidc_saved', { org: ctx.orgId, enabled });
    return c.redirect(directory(ctx.orgId, 'saml'), 303);
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
    // One way of single sign-on at a time (DESIGN §4.20).
    if (ctx.form.get('enabled') === 'on') {
      await c.env.DB.prepare('UPDATE org_oidc SET enabled = 0, updated_at = ? WHERE org_id = ?')
        .bind(now, ctx.orgId)
        .run();
    }
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

  /** The organization's app access, with names (DESIGN §4.22). */
  async function appsView(c: AppContext, orgId: string): Promise<AppsView> {
    const oauth = authorizationServer(c.env).getOAuthApi(c.env);
    const names = new Map<string, string>();
    const nameOf = async (clientId: string) => {
      if (!names.has(clientId)) {
        const client = await oauth.lookupClient(clientId).catch(() => null);
        names.set(clientId, client?.clientName ?? clientId);
      }
      return names.get(clientId) ?? clientId;
    };
    const allowed = await listAllowedApps(c.env.DB, orgId);
    const forEveryone = new Set(allowed.filter((a) => a.groupId === '').map((a) => a.clientId));
    const inUse = (await appsInUse(c.env.DB, orgId)).filter((id) => !forEveryone.has(id));
    return {
      restrict: await restrictsApps(c.env.DB, orgId),
      allowed: await Promise.all(
        allowed.map(async (a) => ({ ...a, name: await nameOf(a.clientId) })),
      ),
      inUse: await Promise.all(
        inUse.map(async (clientId) => ({ clientId, name: await nameOf(clientId) })),
      ),
    };
  }

  app.post('/orgs/:org/apps', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const action = ctx.form.get('action');
    const clientRaw = ctx.form.get('client_id');
    const clientId = typeof clientRaw === 'string' ? clientRaw.trim().slice(0, 500) : '';
    const groupRaw = ctx.form.get('group');
    const groupId = typeof groupRaw === 'string' ? groupRaw : '';
    if (action === 'restrict') {
      const on = ctx.form.get('on') === '1';
      await setRestrictApps(c.env.DB, now, ctx.orgId, on);
      await record(c, ctx.session, 'org.apps_restricted', { org: ctx.orgId, on });
      return c.redirect(directory(ctx.orgId, on ? 'apps_restricted' : 'apps_open'), 303);
    }
    if (!clientId) return showDirectory(c, ctx.orgId, { error: 'Enter the app’s client ID.' }, 400);
    if (action === 'allow') {
      // Only apps login knows: a typo would otherwise allow nothing and look like it worked.
      const known = await authorizationServer(c.env)
        .getOAuthApi(c.env)
        .lookupClient(clientId)
        .catch(() => null);
      if (!known) {
        return showDirectory(
          c,
          ctx.orgId,
          { error: 'No app with that client ID has registered with 2earl.' },
          400,
        );
      }
      const result = await allowApp(c.env.DB, now, ctx.orgId, clientId, groupId);
      if (result !== 'added') {
        return showDirectory(
          c,
          ctx.orgId,
          {
            error:
              result === 'unknown_group'
                ? 'That group no longer exists.'
                : 'An organization can allow up to 200 apps.',
          },
          400,
        );
      }
      await record(c, ctx.session, 'org.app_allowed', {
        org: ctx.orgId,
        client: clientId,
        group: groupId || null,
      });
      return c.redirect(directory(ctx.orgId, 'app_allowed'), 303);
    }
    if (action === 'remove' && (await disallowApp(c.env.DB, ctx.orgId, clientId, groupId))) {
      await record(c, ctx.session, 'org.app_disallowed', {
        org: ctx.orgId,
        client: clientId,
        group: groupId || null,
      });
    }
    return c.redirect(directory(ctx.orgId, 'app_removed'), 303);
  });

  app.post('/orgs/:org/groups/role', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    // Making people admins through the directory: a recent proof first.
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const groupId = ctx.form.get('group');
    const role = ctx.form.get('role') === 'admin' ? 'admin' : null;
    if (typeof groupId !== 'string')
      return c.redirect(`/orgs/${encodeURIComponent(ctx.orgId)}/directory`, 303);
    const group = await findGroup(c.env.DB, ctx.orgId, groupId);
    if (group && (await setGroupRole(c.env.DB, now, ctx.orgId, groupId, role))) {
      await record(c, ctx.session, 'org.group_role_changed', {
        org: ctx.orgId,
        group: groupId,
        name: group.display_name,
        role,
      });
    }
    return c.redirect(directory(ctx.orgId, 'group_role'), 303);
  });

  app.post('/orgs/:org/policy', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const now = deps.now();
    const redirect = changeCheck(ctx.session, now, `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const methods = ctx.form
      .getAll('methods')
      .filter((m): m is PolicyMethod => (POLICY_METHODS as readonly unknown[]).includes(m));
    const hoursText = ctx.form.get('session_hours');
    const hours = typeof hoursText === 'string' && hoursText ? Number(hoursText) : null;
    const rangesText = ctx.form.get('ip_ranges');
    const { ranges, invalid } = parseRanges(typeof rangesText === 'string' ? rangesText : '');
    const refuse = (error: string) => showDirectory(c, ctx.orgId, { error }, 400);
    if (hours !== null && !(SESSION_HOURS as readonly number[]).includes(hours)) {
      return refuse('Choose a session length from the list.');
    }
    if (invalid.length > 0) {
      return refuse(
        `These aren’t network ranges (or are wider than /8 or /16): ${invalid.slice(0, 5).join(', ')}.`,
      );
    }
    if (ranges.length > MAX_RANGES) return refuse(`Up to ${String(MAX_RANGES)} ranges.`);
    if (methods.length === 0 && !(await ssoOn(c.env.DB, ctx.orgId))) {
      return refuse('Allow at least one way to sign in, or turn on single sign-on first.');
    }
    const policy = {
      requireFactor: ctx.form.get('require_factor') === '1',
      passkeysOnly: ctx.form.get('passkeys_only') === '1',
      sessionHours: hours,
      methods,
      ipRanges: ranges,
    };
    await savePolicy(c.env.DB, now, ctx.orgId, policy);
    await record(c, ctx.session, 'org.policy_changed', {
      org: ctx.orgId,
      requireFactor: policy.requireFactor || policy.passkeysOnly,
      passkeysOnly: policy.passkeysOnly,
      sessionHours: hours,
      methods: methods.join(','),
      ranges: ranges.length,
    });
    return c.redirect(directory(ctx.orgId, 'policy'), 303);
  });

  app.post('/orgs/:org/require-sso', async (c) => {
    const ctx = await ownerChange(c);
    if (ctx instanceof Response) return ctx;
    const redirect = changeCheck(ctx.session, deps.now(), `/orgs/${ctx.orgId}/directory`);
    if (redirect) return c.redirect(redirect, 303);
    const on = ctx.form.get('on') === '1';
    if (on) {
      if (!(await ssoOn(c.env.DB, ctx.orgId))) {
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
