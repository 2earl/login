import type { Hono } from 'hono';
import { deleteAccount, revokeAllGrants } from './account';
import {
  LOG_FILTERS,
  adminAppsPage,
  adminInvitationsPage,
  adminLogPage,
  adminNeedsFactorPage,
  adminOrgsPage,
  adminUsersPage,
  type AdminInvitation,
  type AdminOrg,
  type AdminRegisteredApp,
  type AdminUser,
} from './admin-pages';
import type { Deps } from './app';
import { audit, type AuditEvent } from './audit';
import {
  clientIp,
  isSameOrigin,
  underRateLimit,
  workerCtx,
  type AppContext,
  type AppEnv,
} from './http';
import { deliverDeletionNotices, pendingNotices } from './deletion-notices';
import { createResourceServer, deleteResourceServer, listResourceServers } from './introspection';
import { allResources, serviceForResource } from './services';
import { isStepUpFresh } from './mfa';
import { setSignupMode, signupMode } from './settings';
import { authorizationServer } from './oauth';
import { notFoundPage } from './pages';
import type { Session } from './sessions';
import { tellNewOwners } from './sign-in';
import { deleteOrganization } from './orgs';

/**
 * /admin (DESIGN §4.6): only the user whose Google account is OWNER_GOOGLE_SUB, and only with a
 * second factor (D11, whatever MFA_REQUIRED says). Changes need the second factor from the last
 * 15 minutes. Everyone else gets the same 404 as a page that doesn't exist.
 */

export const ADMIN_STEP_UP_MAX_AGE_SECONDS = 15 * 60;
const LOG_LIMIT = 200;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const NOTICES: Record<string, string> = {
  suspended: 'User suspended, signed out and disconnected from their apps.',
  reactivated: 'User reactivated.',
  mfa_reset: 'Second factor reset. The user sets up a new one at their next sign-in.',
  deleted: 'Account deleted.',
  invited: 'Invitation added.',
  already_invited: 'That address is already invited.',
  withdrawn: 'Invitation withdrawn.',
  trusted: 'App marked as verified.',
  untrusted: 'Verification removed.',
  unregistered: 'App deleted and its access revoked.',
  rs_deleted: 'Resource server credentials revoked.',
  signup_open: 'Sign-up is open. Anyone can create an account.',
  signup_invite: 'Sign-up is closed. New accounts need an invitation.',
  org_suspended: 'Organization suspended.',
  org_reactivated: 'Organization reactivated.',
  org_deleted: 'Organization deleted.',
};

function isLoopback(url: URL): boolean {
  return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

/** Redirect URIs for a registered public client: https, or http on a loopback address. */
function parseRedirectUris(text: string): string[] | null {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.length > 10) return null;
  for (const line of lines) {
    let url: URL;
    try {
      url = new URL(line);
    } catch {
      return null;
    }
    const ok =
      (url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback(url))) &&
      !url.hash &&
      !url.username &&
      !url.password;
    if (!ok) return null;
  }
  return lines;
}

/** Whether `userId` is the owner: the account whose Google identity is OWNER_GOOGLE_SUB. */
export async function isOwnerUser(env: Env, userId: string): Promise<boolean> {
  const ownerSub: string = env.OWNER_GOOGLE_SUB;
  if (ownerSub.length === 0) return false;
  const row = await env.DB.prepare(
    "SELECT 1 AS ok FROM identities WHERE user_id = ? AND provider = 'google' AND subject = ?",
  )
    .bind(userId, ownerSub)
    .first<{ ok: number }>();
  return row !== null;
}

export function registerAdminRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /** The owner's session, or a response that ends the request. */
  async function owner(c: AppContext): Promise<Session | Response> {
    const session = c.get('session');
    if (!session) {
      const url = new URL(c.req.url);
      return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
    }
    if (!(await isOwnerUser(c.env, session.user.id))) return c.html(notFoundPage(), 404);
    if (!session.hasFactor) return c.html(adminNeedsFactorPage(), 403);
    // An aal1 session never gets here (the second-factor gate sends it to /mfa), but don't rely on it.
    if (session.aal !== 'aal2') return c.redirect('/mfa?return_to=%2Fadmin', 303);
    return session;
  }

  /** Owner check for changes: same-origin, rate-limited, fresh second factor. */
  async function ownerForChange(c: AppContext, back: string): Promise<Session | Response> {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'admin'))) return c.json({ error: 'rate_limited' }, 429);
    const result = await owner(c);
    if (result instanceof Response) return result;
    if (!isStepUpFresh(result, deps.now(), ADMIN_STEP_UP_MAX_AGE_SECONDS)) {
      return c.redirect(`/mfa?step_up=1&return_to=${encodeURIComponent(back)}`, 303);
    }
    return result;
  }

  async function record(
    c: AppContext,
    session: Session,
    event: AuditEvent,
    detail: Record<string, string | number | boolean | null>,
  ) {
    await audit(c.env.DB, deps.now(), event, {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail,
    });
  }

  const flash = (c: AppContext) => ({ notice: NOTICES[c.req.query('done') ?? ''] });
  const oauth = (c: AppContext) => authorizationServer(c.env).getOAuthApi(c.env);

  app.get('/admin', (c) => c.redirect('/admin/users', 303));

  // ---- Users --------------------------------------------------------------------------------

  async function listUsers(c: AppContext): Promise<AdminUser[]> {
    const { results } = await c.env.DB.prepare(
      `SELECT u.id, u.status, u.display_name, u.primary_email, u.created_at,
              (SELECT subject FROM identities WHERE user_id = u.id AND provider = 'google') AS subject,
              (SELECT MAX(last_login_at) FROM identities WHERE user_id = u.id) AS last_login_at,
              (SELECT GROUP_CONCAT(provider) FROM identities WHERE user_id = u.id) AS methods,
              (SELECT COUNT(*) FROM mfa_factors f WHERE f.user_id = u.id) AS factors
       FROM users u
       ORDER BY u.created_at LIMIT 1000`,
    ).all<{
      id: string;
      status: string;
      display_name: string | null;
      primary_email: string | null;
      created_at: number;
      subject: string | null;
      last_login_at: number | null;
      methods: string | null;
      factors: number;
    }>();
    return results.map((row) => ({
      id: row.id,
      email: row.primary_email,
      name: row.display_name,
      status: row.status,
      createdAt: row.created_at,
      lastSignInAt: row.last_login_at,
      factors: row.factors,
      methods: (row.methods ?? '').split(',').filter(Boolean).sort(),
      isOwner: row.subject === c.env.OWNER_GOOGLE_SUB,
    }));
  }

  app.get('/admin/users', async (c) => {
    const session = await owner(c);
    if (session instanceof Response) return session;
    return c.html(
      adminUsersPage({
        users: await listUsers(c),
        pending: await pendingNotices(c.env.DB),
        ...flash(c),
      }),
    );
  });

  app.post('/admin/users', async (c) => {
    const session = await ownerForChange(c, '/admin/users');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const userId = form.get('user');
    const fail = async (error: string) =>
      c.html(
        adminUsersPage({
          users: await listUsers(c),
          pending: await pendingNotices(c.env.DB),
          error,
        }),
        400,
      );

    if (typeof userId !== 'string') return fail('No user given.');
    if (userId === session.user.id) return fail('You can’t change your own account here.');
    const exists = await c.env.DB.prepare('SELECT 1 AS ok FROM users WHERE id = ?')
      .bind(userId)
      .first<{ ok: number }>();
    if (!exists) return fail('That user no longer exists.');
    const now = deps.now();

    switch (action) {
      case 'suspend': {
        await c.env.DB.batch([
          c.env.DB.prepare(
            // 2earl's own suspension: an organization can't lift it (DESIGN §4.18).
            `UPDATE users SET status = 'suspended', deactivated_at = NULL, delete_after = NULL,
               updated_at = ? WHERE id = ?`,
          ).bind(now, userId),
          c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId),
        ]);
        const grants = await revokeAllGrants(oauth(c), userId);
        await record(c, session, 'admin.user_suspended', { target: userId, grants });
        return c.redirect('/admin/users?done=suspended', 303);
      }
      case 'reactivate':
        await c.env.DB.prepare(
          `UPDATE users SET status = 'active', deactivated_at = NULL, delete_after = NULL,
             updated_at = ? WHERE id = ?`,
        )
          .bind(now, userId)
          .run();
        await record(c, session, 'admin.user_reactivated', { target: userId });
        return c.redirect('/admin/users?done=reactivated', 303);
      case 'reset_mfa':
        // For a user who lost every factor and every recovery code (DESIGN §4.7). Their sessions
        // end, so the next sign-in starts from Google and, if required, a new enrolment.
        await c.env.DB.batch([
          c.env.DB.prepare('DELETE FROM mfa_factors WHERE user_id = ?').bind(userId),
          c.env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(userId),
          c.env.DB.prepare(
            'UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?',
          ).bind(userId),
          c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId),
        ]);
        await record(c, session, 'admin.mfa_reset', { target: userId });
        return c.redirect('/admin/users?done=mfa_reset', 303);
      case 'delete':
        if (form.get('confirm') !== 'on') return fail('Tick the box to confirm the deletion.');
        tellNewOwners(c, await deleteAccount(c.env.DB, oauth(c), userId, now, clientIp(c)));
        workerCtx(c).waitUntil(deliverDeletionNotices(c.env, now));
        // The target's own events were re-keyed by deleteAccount; this one names no one.
        await record(c, session, 'admin.user_deleted', {});
        return c.redirect('/admin/users?done=deleted', 303);
      default:
        return fail('Unknown action.');
    }
  });

  // ---- Invitations ----------------------------------------------------------------------------

  async function listInvitations(c: AppContext): Promise<AdminInvitation[]> {
    const { results } = await c.env.DB.prepare(
      `SELECT a.id, a.kind, a.value, a.created_at, u.primary_email
       FROM allowlist a
       LEFT JOIN identities i ON (a.kind = 'google_sub' AND i.provider = 'google' AND i.subject = a.value)
                              OR (a.kind = 'email' AND i.provider = 'email' AND i.subject = a.value)
       LEFT JOIN users u ON u.id = i.user_id
       ORDER BY a.created_at`,
    ).all<{
      id: string;
      kind: 'email' | 'google_sub';
      value: string;
      created_at: number;
      primary_email: string | null;
    }>();
    return results.map((row) => ({
      id: row.id,
      kind: row.kind,
      value: row.value,
      accountEmail: row.primary_email,
      used: row.primary_email !== null,
      createdAt: row.created_at,
      isOwner: row.kind === 'google_sub' && row.value === c.env.OWNER_GOOGLE_SUB,
    }));
  }

  const invitationsHtml = async (c: AppContext, extra: { notice?: string; error?: string }) =>
    adminInvitationsPage({
      invitations: await listInvitations(c),
      locked: (await signupMode(c.env)) === 'invite',
      ...extra,
    });

  app.get('/admin/invitations', async (c) => {
    const session = await owner(c);
    if (session instanceof Response) return session;
    const { notice } = flash(c);
    return c.html(await invitationsHtml(c, notice ? { notice } : {}));
  });

  app.post('/admin/invitations', async (c) => {
    const session = await ownerForChange(c, '/admin/invitations');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const action = form.get('action');

    // The sign-up switch (DESIGN §4.9): takes effect at the next sign-in, no deploy needed.
    if (action === 'signup') {
      const mode = form.get('mode');
      if (mode !== 'open' && mode !== 'invite') return c.redirect('/admin/invitations', 303);
      await setSignupMode(c.env.DB, deps.now(), mode);
      await record(c, session, 'admin.signup_changed', { mode });
      return c.redirect(`/admin/invitations?done=signup_${mode}`, 303);
    }

    if (action === 'add') {
      const raw = form.get('email');
      const email = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
      if (email.length > 254 || !EMAIL.test(email)) {
        return c.html(await invitationsHtml(c, { error: 'Enter a valid email address.' }), 400);
      }
      const result = await c.env.DB.prepare(
        `INSERT INTO allowlist (id, kind, value, added_by, created_at)
         VALUES (?, 'email', ?, 'admin', ?) ON CONFLICT (kind, value) DO NOTHING`,
      )
        .bind(crypto.randomUUID(), email, deps.now())
        .run();
      if (result.meta.changes === 0)
        return c.redirect('/admin/invitations?done=already_invited', 303);
      await record(c, session, 'admin.invitation_added', {});
      return c.redirect('/admin/invitations?done=invited', 303);
    }

    if (action === 'remove') {
      const id = form.get('id');
      if (typeof id !== 'string') return c.redirect('/admin/invitations', 303);
      // The owner's own invitation can't be withdrawn here: it would lock the owner out.
      const result = await c.env.DB.prepare(
        "DELETE FROM allowlist WHERE id = ? AND NOT (kind = 'google_sub' AND value = ?)",
      )
        .bind(id, c.env.OWNER_GOOGLE_SUB)
        .run();
      if (result.meta.changes > 0) {
        await record(c, session, 'admin.invitation_removed', { invitation: id });
      }
      return c.redirect('/admin/invitations?done=withdrawn', 303);
    }
    return c.redirect('/admin/invitations', 303);
  });

  // ---- Apps ---------------------------------------------------------------------------------

  async function appsHtml(
    c: AppContext,
    extra: { notice?: string; error?: string; created?: { id: string; secret: string } },
  ) {
    const { results } = await c.env.DB.prepare(
      'SELECT client_id, note, created_at FROM trusted_clients ORDER BY created_at',
    ).all<{ client_id: string; note: string | null; created_at: number }>();
    const registered: AdminRegisteredApp[] = [];
    let cursor: string | undefined;
    do {
      const pageOfClients = await oauth(c).listClients({
        limit: 100,
        ...(cursor ? { cursor } : {}),
      });
      for (const client of pageOfClients.items) {
        // Clients identified by a metadata URL (CIMD) are fetched on demand, not registered.
        if (client.clientId.startsWith('https://')) continue;
        registered.push({
          clientId: client.clientId,
          name: client.clientName ?? null,
          redirectUris: client.redirectUris,
          createdAt: client.registrationDate ?? null,
        });
      }
      cursor = pageOfClients.cursor;
    } while (cursor && registered.length < 500);
    return adminAppsPage({
      resourceServers: await listResourceServers(c.env.DB),
      resources: allResources(c.env).map((resource) => {
        const service = serviceForResource(c.env, resource);
        return { resource, label: `${service?.name ?? 'Unknown'} (${resource})` };
      }),
      trusted: results.map((r) => ({
        clientId: r.client_id,
        note: r.note,
        createdAt: r.created_at,
      })),
      registered,
      ...extra,
    });
  }

  // ---- Organizations (DESIGN §4.14) --------------------------------------------------------

  async function listOrgs(c: AppContext): Promise<AdminOrg[]> {
    const { results } = await c.env.DB.prepare(
      `SELECT o.id, o.name, o.status, o.created_at,
              (SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id) AS members,
              (SELECT COUNT(*) FROM org_invitations i WHERE i.org_id = o.id AND i.expires_at > ?) AS invitations,
              (SELECT GROUP_CONCAT(COALESCE(u.primary_email, u.id), ', ') FROM org_members m
                 JOIN users u ON u.id = m.user_id WHERE m.org_id = o.id AND m.role = 'owner') AS owners
       FROM organizations o ORDER BY o.created_at LIMIT 1000`,
    )
      .bind(deps.now())
      .all<{
        id: string;
        name: string;
        status: 'active' | 'suspended';
        created_at: number;
        members: number;
        invitations: number;
        owners: string | null;
      }>();
    return results.map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      members: r.members,
      invitations: r.invitations,
      owners: r.owners ? r.owners.split(', ') : [],
      createdAt: r.created_at,
    }));
  }

  app.get('/admin/orgs', async (c) => {
    const session = await owner(c);
    if (session instanceof Response) return session;
    return c.html(adminOrgsPage({ orgs: await listOrgs(c), ...flash(c) }));
  });

  app.post('/admin/orgs', async (c) => {
    const session = await ownerForChange(c, '/admin/orgs');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const orgId = form.get('org');
    const fail = async (error: string) =>
      c.html(adminOrgsPage({ orgs: await listOrgs(c), error }), 400);
    if (typeof orgId !== 'string') return fail('No organization given.');
    const exists = await c.env.DB.prepare('SELECT 1 AS ok FROM organizations WHERE id = ?')
      .bind(orgId)
      .first<{ ok: number }>();
    if (!exists) return fail('That organization no longer exists.');
    const now = deps.now();
    switch (form.get('action')) {
      case 'suspend':
      case 'reactivate': {
        const suspend = form.get('action') === 'suspend';
        await c.env.DB.prepare('UPDATE organizations SET status = ?, updated_at = ? WHERE id = ?')
          .bind(suspend ? 'suspended' : 'active', now, orgId)
          .run();
        await record(c, session, suspend ? 'admin.org_suspended' : 'admin.org_reactivated', {
          org: orgId,
        });
        return c.redirect(`/admin/orgs?done=${suspend ? 'org_suspended' : 'org_reactivated'}`, 303);
      }
      case 'delete':
        if (form.get('confirm') !== 'on') return fail('Tick the box to confirm the deletion.');
        await deleteOrganization(c.env.DB, now, orgId);
        workerCtx(c).waitUntil(deliverDeletionNotices(c.env, now));
        await record(c, session, 'admin.org_deleted', { org: orgId });
        return c.redirect('/admin/orgs?done=org_deleted', 303);
      default:
        return fail('Unknown action.');
    }
  });

  app.get('/admin/apps', async (c) => {
    const session = await owner(c);
    if (session instanceof Response) return session;
    const { notice } = flash(c);
    return c.html(await appsHtml(c, notice ? { notice } : {}));
  });

  app.post('/admin/apps', async (c) => {
    const session = await ownerForChange(c, '/admin/apps');
    if (session instanceof Response) return session;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const field = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };
    const fail = async (error: string) => c.html(await appsHtml(c, { error }), 400);
    const now = deps.now();

    switch (action) {
      case 'trust': {
        const clientId = field('client_id');
        if (!clientId || clientId.length > 2000) return fail('Enter a client ID.');
        const known = await oauth(c)
          .lookupClient(clientId)
          .then((client) => client !== null)
          .catch(() => false);
        if (!known) {
          return fail(
            'No app with that client ID: it isn’t registered, and no valid metadata document could be fetched from it.',
          );
        }
        await c.env.DB.prepare(
          `INSERT INTO trusted_clients (client_id, note, created_at) VALUES (?, ?, ?)
           ON CONFLICT (client_id) DO UPDATE SET note = excluded.note`,
        )
          .bind(clientId, field('note').slice(0, 200) || null, now)
          .run();
        await record(c, session, 'admin.client_trusted', { client: clientId });
        return c.redirect('/admin/apps?done=trusted', 303);
      }
      case 'untrust': {
        const clientId = field('client_id');
        await c.env.DB.prepare('DELETE FROM trusted_clients WHERE client_id = ?')
          .bind(clientId)
          .run();
        await record(c, session, 'admin.client_untrusted', { client: clientId });
        return c.redirect('/admin/apps?done=untrusted', 303);
      }
      case 'register': {
        const name = field('name').slice(0, 100);
        const redirectUris = parseRedirectUris(field('redirect_uris'));
        if (!name) return fail('Enter the app’s name.');
        if (!redirectUris) {
          return fail(
            'Enter 1 to 10 redirect URIs, one per line: https, or http on localhost, 127.0.0.1 or [::1], without a fragment.',
          );
        }
        const client = await oauth(c).createClient({
          clientName: name,
          redirectUris,
          tokenEndpointAuthMethod: 'none',
          grantTypes: ['authorization_code', 'refresh_token'],
          responseTypes: ['code'],
        });
        await record(c, session, 'admin.client_registered', { client: client.clientId });
        return c.html(
          await appsHtml(c, {
            notice: `App registered. Its client ID is ${client.clientId}.`,
          }),
        );
      }
      case 'unregister': {
        const clientId = field('client_id');
        if (!clientId || clientId.startsWith('https://')) return fail('Not a registered app.');
        await oauth(c).deleteClient(clientId);
        await c.env.DB.prepare('DELETE FROM trusted_clients WHERE client_id = ?')
          .bind(clientId)
          .run();
        await record(c, session, 'admin.client_deleted', { client: clientId });
        return c.redirect('/admin/apps?done=unregistered', 303);
      }
      case 'rs_create': {
        const name = field('name').slice(0, 100);
        const resource = field('resource');
        if (!name) return fail('Enter a name for the resource server.');
        if (!allResources(c.env).includes(resource)) return fail('Choose a resource.');
        const created = await createResourceServer(c.env.DB, now, name, resource);
        await record(c, session, 'admin.resource_server_created', {
          resource_server: created.id,
          resource,
        });
        return c.html(await appsHtml(c, { created }));
      }
      case 'rs_delete': {
        const id = field('id');
        if (await deleteResourceServer(c.env.DB, id)) {
          await record(c, session, 'admin.resource_server_deleted', { resource_server: id });
        }
        return c.redirect('/admin/apps?done=rs_deleted', 303);
      }
      default:
        return fail('Unknown action.');
    }
  });

  // ---- Security log ---------------------------------------------------------------------------

  app.get('/admin/log', async (c) => {
    const session = await owner(c);
    if (session instanceof Response) return session;
    const requested = c.req.query('event') ?? '';
    const filter = LOG_FILTERS.some(([value]) => value === requested) ? requested : '';
    const { results } = await c.env.DB.prepare(
      `SELECT e.at, e.event, e.client_id, e.ip_prefix, e.detail, e.actor_user_id, u.primary_email
       FROM audit_events e LEFT JOIN users u ON u.id = e.actor_user_id
       WHERE e.event LIKE ? ORDER BY e.at DESC, e.id LIMIT ?`,
    )
      .bind(`${filter}%`, LOG_LIMIT)
      .all<{
        at: number;
        event: string;
        client_id: string | null;
        ip_prefix: string | null;
        detail: string | null;
        actor_user_id: string | null;
        primary_email: string | null;
      }>();
    return c.html(
      adminLogPage({
        filter,
        limit: LOG_LIMIT,
        events: results.map((row) => ({
          at: row.at,
          event: row.event,
          account:
            row.primary_email ??
            (row.actor_user_id?.startsWith('deleted:') ? 'deleted account' : row.actor_user_id),
          clientId: row.client_id,
          ipPrefix: row.ip_prefix,
          detail: row.detail,
        })),
      }),
    );
  });
}
