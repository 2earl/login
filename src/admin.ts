import { ASSIGNABLE_SERVICES } from './authz/grant';
import { NEVER_ASSIGNABLE } from './authz/login-manifest';
import { assignRole, listAssignments, revokeAssignment } from './authz/store';
import type { Hono } from 'hono';
import { deleteAccount, revokeAllGrants } from './account';
import {
  LOG_FILTERS,
  adminAppsPage,
  adminInvitationsPage,
  adminLogPage,
  adminNeedsFactorPage,
  adminOrgPage,
  adminOrgsPage,
  adminTeamPage,
  adminUsersPage,
  type AdminOrgDetail,
  type AdminView,
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
import { allResources, serviceForResource, systemRole } from './services';
import { isStepUpFresh } from './mfa';
import { setSignupMode, signupMode } from './settings';
import { clientScopePolicy, setClientScopePolicy } from './authz/client-policy';
import { authorizationServer } from './oauth';
import { notFoundPage } from './pages';
import type { Session } from './sessions';
import { tellNewOwners } from './sign-in';
import { deleteOrganization } from './orgs';
import { ssoOnSql } from './managed';
import { notify, orgSetupMail, sendMail } from './mail';
import {
  createSetupInvitation,
  listSetupInvitations,
  markResent,
  setupInvitation,
  withdrawSetupInvitation,
} from './org-setup';
import { noticeContext } from './sign-in';
import {
  grantStaff,
  isGrantableStaffRole,
  listStaff,
  revokeStaff,
  staffCan,
  staffRoleOf,
  type StaffRole,
} from './staff';

/**
 * /admin (DESIGN §4.6, §4.29): 2earl staff only (the owner, admins, support), and only with a
 * second factor (D11, whatever MFA_REQUIRED says). Changes need the second factor from the last
 * 15 minutes. Each page and action asks `staffCan` what the role may do. Everyone else, and staff
 * asking for what their role can't do, get the same 404 as a page that doesn't exist.
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
  scope_policy_enforce:
    'First-party permissions are enforced: other apps asking for them are refused.',
  scope_policy_report: 'First-party permissions are reported, not refused.',
  signup_open: 'Sign-up is open. Anyone can create an account.',
  signup_invite: 'Sign-up is closed. New accounts need an invitation.',
  org_suspended: 'Organization suspended.',
  org_reactivated: 'Organization reactivated.',
  org_deleted: 'Organization deleted.',
  signed_out: 'Signed out everywhere and disconnected from their apps. They were told by email.',
  setup_sent: 'Invitation sent. It works for 14 days.',
  setup_resent: 'Invitation sent again. It works for another 14 days.',
  setup_withdrawn: 'Invitation withdrawn.',
  staff_granted: 'Role given. They were told by email.',
  staff_revoked: 'Removed from staff. They were told by email.',
  platform_given: 'Role given. It applies from their next request.',
  platform_taken: 'Role taken back.',
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

export { isOwnerUser } from './staff';

interface Staff {
  session: Session;
  role: StaffRole;
}

export function registerAdminRoutes(app: Hono<AppEnv>, deps: Deps): void {
  /** A staff member allowed `need`, or a response that ends the request. */
  async function staff(
    c: AppContext,
    need: (role: StaffRole) => boolean = staffCan.view,
  ): Promise<Staff | Response> {
    const session = c.get('session');
    if (!session) {
      const url = new URL(c.req.url);
      return c.redirect(`/login?return_to=${encodeURIComponent(url.pathname + url.search)}`, 303);
    }
    const role = await staffRoleOf(c.env, session.user.id);
    if (!role) return c.html(notFoundPage(), 404);
    if (!session.hasFactor) return c.html(adminNeedsFactorPage(), 403);
    // An aal1 session never gets here (the second-factor gate sends it to /mfa), but don't rely on it.
    if (session.aal !== 'aal2') return c.redirect('/mfa?return_to=%2Fadmin', 303);
    if (!need(role)) return c.html(notFoundPage(), 404);
    return { session, role };
  }

  /** Staff check for changes: same-origin, rate-limited, fresh second factor. */
  async function staffForChange(
    c: AppContext,
    back: string,
    need: (role: StaffRole) => boolean,
  ): Promise<Staff | Response> {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    if (!(await underRateLimit(c, 'admin'))) return c.json({ error: 'rate_limited' }, 429);
    const result = await staff(c, need);
    if (result instanceof Response) return result;
    if (!isStepUpFresh(result.session, deps.now(), ADMIN_STEP_UP_MAX_AGE_SECONDS)) {
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

  const flash = (c: AppContext, role: StaffRole): AdminView => ({
    role,
    notice: NOTICES[c.req.query('done') ?? ''],
  });
  const oauth = (c: AppContext) => authorizationServer(c.env).getOAuthApi(c.env);

  app.get('/admin', (c) => c.redirect('/admin/users', 303));

  // ---- Users --------------------------------------------------------------------------------

  /** Accounts, oldest first; with `query`, those whose address or name contains it. */
  async function listUsers(c: AppContext, query = ''): Promise<AdminUser[]> {
    const like = `%${query.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
    const { results } = await c.env.DB.prepare(
      `SELECT u.id, u.status, u.display_name, u.primary_email, u.created_at,
              (SELECT subject FROM identities WHERE user_id = u.id AND provider = 'google') AS subject,
              (SELECT MAX(last_login_at) FROM identities WHERE user_id = u.id) AS last_login_at,
              (SELECT GROUP_CONCAT(provider) FROM identities WHERE user_id = u.id) AS methods,
              (SELECT COUNT(*) FROM mfa_factors f WHERE f.user_id = u.id) AS factors,
              (SELECT name FROM organizations WHERE id = u.managed_by) AS managed_by,
              u.deactivated_at,
              (SELECT role FROM staff s WHERE s.user_id = u.id) AS staff_role
       FROM users u
       WHERE ?1 = '' OR u.primary_email LIKE ?2 ESCAPE '\\' OR u.display_name LIKE ?2 ESCAPE '\\'
          OR u.id = ?1
          OR u.id IN (SELECT user_id FROM identities WHERE email LIKE ?2 ESCAPE '\\')
       ORDER BY u.created_at LIMIT 1000`,
    )
      .bind(query, like)
      .all<{
        id: string;
        status: string;
        display_name: string | null;
        primary_email: string | null;
        created_at: number;
        subject: string | null;
        last_login_at: number | null;
        methods: string | null;
        factors: number;
        managed_by: string | null;
        deactivated_at: number | null;
        staff_role: 'admin' | 'support' | null;
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
      staff:
        c.env.OWNER_GOOGLE_SUB.length > 0 && row.subject === c.env.OWNER_GOOGLE_SUB
          ? 'owner'
          : row.staff_role,
      managedBy: row.managed_by,
      deactivatedByOrg: row.deactivated_at !== null,
    }));
  }

  app.get('/admin/users', async (c) => {
    const who = await staff(c);
    if (who instanceof Response) return who;
    const query = (c.req.query('q') ?? '').trim().slice(0, 254);
    return c.html(
      adminUsersPage({
        users: await listUsers(c, query),
        pending: await pendingNotices(c.env.DB),
        query,
        ...flash(c, who.role),
      }),
    );
  });

  app.post('/admin/users', async (c) => {
    const who = await staffForChange(c, '/admin/users', staffCan.signOutUsers);
    if (who instanceof Response) return who;
    const { session, role } = who;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const userId = form.get('user');
    const fail = async (error: string) =>
      c.html(
        adminUsersPage({
          role,
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
    if (!staffCan.actOn(role, await staffRoleOf(c.env, userId))) {
      return fail('Staff accounts are managed by the owner.');
    }
    if (action !== 'sign_out' && !staffCan.manageUsers(role)) {
      return fail('Your role can’t do that. Ask an admin.');
    }
    const now = deps.now();

    switch (action) {
      case 'sign_out': {
        // For someone who lost a device or fears a session was taken: every session and app
        // grant ends; the account stays as it is, and they can sign in again at once.
        await c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
        const grants = await revokeAllGrants(oauth(c), userId);
        await record(c, session, 'admin.user_signed_out', { target: userId, grants });
        workerCtx(c).waitUntil(
          notify(c.env, userId, { kind: 'staff_signed_out' }, noticeContext(c, now)),
        );
        return c.redirect('/admin/users?done=signed_out', 303);
      }
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

  const invitationsHtml = async (c: AppContext, view: AdminView) =>
    adminInvitationsPage({
      invitations: await listInvitations(c),
      locked: (await signupMode(c.env)) === 'invite',
      ...view,
    });

  app.get('/admin/invitations', async (c) => {
    const who = await staff(c, staffCan.manageSignUp);
    if (who instanceof Response) return who;
    return c.html(await invitationsHtml(c, flash(c, who.role)));
  });

  app.post('/admin/invitations', async (c) => {
    const who = await staffForChange(c, '/admin/invitations', staffCan.manageSignUp);
    if (who instanceof Response) return who;
    const { session, role } = who;
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
        return c.html(
          await invitationsHtml(c, { role, error: 'Enter a valid email address.' }),
          400,
        );
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
    extra: AdminView & { created?: { id: string; secret: string } },
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
    const { results: reports } = await c.env.DB.prepare(
      `SELECT client_id, json_extract(detail, '$.scope') AS scope, COUNT(*) AS count
       FROM audit_events
       WHERE event = 'authz.scope_policy_would_refuse' AND at > ? AND client_id IS NOT NULL
       GROUP BY client_id, scope ORDER BY count DESC LIMIT 50`,
    )
      .bind(deps.now() - 7 * 24 * 60 * 60)
      .all<{ client_id: string; scope: string | null; count: number }>();
    return adminAppsPage({
      scopePolicy: {
        mode: await clientScopePolicy(c.env.DB),
        reports: reports.map((r) => ({
          clientId: r.client_id,
          scope: r.scope ?? '',
          count: r.count,
        })),
      },
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

  async function listOrgs(c: AppContext, onlyId?: string): Promise<AdminOrg[]> {
    const { results } = await c.env.DB.prepare(
      `SELECT o.id, o.name, o.status, o.created_at,
              (SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id) AS members,
              (SELECT COUNT(*) FROM org_invitations i WHERE i.org_id = o.id AND i.expires_at > ?1) AS invitations,
              (SELECT GROUP_CONCAT(COALESCE(u.primary_email, u.id), ', ') FROM org_members m
                 JOIN users u ON u.id = m.user_id WHERE m.org_id = o.id AND m.role = 'owner') AS owners,
              (SELECT COUNT(*) FROM org_domains d WHERE d.org_id = o.id) AS domains,
              (SELECT COUNT(*) FROM org_domains d WHERE d.org_id = o.id AND d.verified_at IS NOT NULL) AS verified_domains,
              (SELECT COUNT(*) FROM org_domains d WHERE d.org_id = o.id AND d.managed_at IS NOT NULL) AS managed_domains,
              (SELECT COUNT(*) FROM users u WHERE u.managed_by = o.id) AS managed_accounts,
              ${ssoOnSql('o.id')} AS sso,
              o.require_sso,
              (SELECT COUNT(*) FROM scim_tokens t WHERE t.org_id = o.id) AS directory_tokens,
              (SELECT require_factor || passkeys_only || COALESCE(session_hours, '') || methods || ip_ranges
                 FROM org_policies p WHERE p.org_id = o.id) AS rules
       FROM organizations o WHERE ?2 IS NULL OR o.id = ?2 ORDER BY o.created_at LIMIT 1000`,
    )
      .bind(deps.now(), onlyId ?? null)
      .all<{
        id: string;
        name: string;
        status: 'active' | 'suspended';
        created_at: number;
        members: number;
        invitations: number;
        owners: string | null;
        domains: number;
        verified_domains: number;
        managed_domains: number;
        managed_accounts: number;
        sso: number;
        require_sso: number;
        directory_tokens: number;
        rules: string | null;
      }>();
    return results.map((r) => ({
      id: r.id,
      name: r.name,
      status: r.status,
      members: r.members,
      invitations: r.invitations,
      owners: r.owners ? r.owners.split(', ') : [],
      createdAt: r.created_at,
      domains: r.domains,
      verifiedDomains: r.verified_domains,
      managedDomains: r.managed_domains,
      managedAccounts: r.managed_accounts,
      sso: r.sso === 1 ? (r.require_sso === 1 ? 'required' : 'on') : 'off',
      directoryTokens: r.directory_tokens,
      // Rules saved and different from the defaults (DESIGN §4.19).
      rules: r.rules !== null && r.rules !== '00google,email,passkey',
    }));
  }

  const orgsHtml = async (c: AppContext, view: AdminView, form?: { email: string; name: string }) =>
    adminOrgsPage({
      orgs: await listOrgs(c),
      setup: await listSetupInvitations(c.env.DB, deps.now()),
      now: deps.now(),
      ...(form ? { form } : {}),
      ...view,
    });

  app.get('/admin/orgs', async (c) => {
    const who = await staff(c);
    if (who instanceof Response) return who;
    return c.html(await orgsHtml(c, flash(c, who.role)));
  });

  app.post('/admin/orgs', async (c) => {
    // Support may only send a setup invitation again; the rest is checked per action below.
    const who = await staffForChange(c, '/admin/orgs', staffCan.resendOrgInvitations);
    if (who instanceof Response) return who;
    const { session, role } = who;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const field = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };
    const fail = async (error: string, status: 400 | 404 | 409 | 429 = 400) =>
      c.html(
        await orgsHtml(
          c,
          { role, error },
          action === 'setup_invite'
            ? { email: field('email'), name: field('name').slice(0, 60) }
            : undefined,
        ),
        status,
      );
    const now = deps.now();

    // ---- Setup invitations (DESIGN §4.30) ----
    if (action === 'setup_invite' || action === 'setup_resend' || action === 'setup_withdraw') {
      if (action !== 'setup_resend' && !staffCan.createOrgs(role)) {
        return fail('Your role can’t do that. Ask an admin.');
      }
      if (action === 'setup_invite') {
        const email = field('email').toLowerCase();
        const name = field('name').replace(/\s+/g, ' ').slice(0, 60) || null;
        if (email.length > 254 || !EMAIL.test(email)) return fail('Enter a valid email address.');
        const result = await createSetupInvitation(c.env.DB, now, {
          email,
          orgName: name,
          invitedBy: session.user.id,
        });
        if (!result.ok) {
          return fail(
            result.reason === 'pending'
              ? 'That address already has an invitation waiting. Send it again instead.'
              : 'Too many invitations are waiting (200). Withdraw some first.',
            409,
          );
        }
        const invitation = await setupInvitation(c.env.DB, result.id);
        if (invitation) {
          workerCtx(c).waitUntil(
            sendMail(
              c.env,
              email,
              orgSetupMail({
                orgName: name,
                link: `${c.env.ISSUER}/orgs/setup/${result.id}`,
                expiresAt: invitation.expiresAt,
              }),
            ),
          );
        }
        await record(c, session, 'admin.org_setup_invited', { invitation: result.id });
        return c.redirect('/admin/orgs?done=setup_sent', 303);
      }
      const invitation = await setupInvitation(c.env.DB, field('invitation'));
      if (!invitation) return fail('That invitation no longer exists.', 404);
      if (action === 'setup_resend') {
        if (!(await markResent(c.env.DB, now, invitation.id))) {
          return fail(
            'That invitation was sent in the last 10 minutes, or isn’t waiting any more.',
            429,
          );
        }
        workerCtx(c).waitUntil(
          sendMail(
            c.env,
            invitation.email,
            orgSetupMail({
              orgName: invitation.orgName,
              link: `${c.env.ISSUER}/orgs/setup/${invitation.id}`,
              expiresAt: now + (invitation.expiresAt - invitation.sentAt),
            }),
          ),
        );
        await record(c, session, 'admin.org_setup_resent', { invitation: invitation.id });
        return c.redirect('/admin/orgs?done=setup_resent', 303);
      }
      if (await withdrawSetupInvitation(c.env.DB, now, invitation.id)) {
        await record(c, session, 'admin.org_setup_withdrawn', { invitation: invitation.id });
      }
      return c.redirect('/admin/orgs?done=setup_withdrawn', 303);
    }

    // ---- Suspend, reactivate, delete ----
    if (!staffCan.manageOrgs(role)) return fail('Your role can’t do that. Ask an admin.');
    const orgId = form.get('org');
    if (typeof orgId !== 'string') return fail('No organization given.');
    const exists = await c.env.DB.prepare('SELECT 1 AS ok FROM organizations WHERE id = ?')
      .bind(orgId)
      .first<{ ok: number }>();
    if (!exists) return fail('That organization no longer exists.');
    switch (action) {
      case 'suspend':
      case 'reactivate': {
        const suspend = action === 'suspend';
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

  /** One organization in detail, for helping it. Recorded where the organization sees it. */
  app.get('/admin/orgs/:id', async (c) => {
    const who = await staff(c);
    if (who instanceof Response) return who;
    const orgId = c.req.param('id');
    const org = (await listOrgs(c, orgId))[0];
    if (!org) return c.html(notFoundPage(), 404);
    const now = deps.now();
    const db = c.env.DB;
    const [members, invitations, domains, activity] = await Promise.all([
      db
        .prepare(
          `SELECT m.user_id, m.role, m.joined_at, u.primary_email, u.display_name, u.managed_by
           FROM org_members m JOIN users u ON u.id = m.user_id WHERE m.org_id = ?
           ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'auditor' THEN 2 ELSE 3 END,
                    m.joined_at LIMIT 1000`,
        )
        .bind(orgId)
        .all<{
          user_id: string;
          role: string;
          joined_at: number;
          primary_email: string | null;
          display_name: string | null;
          managed_by: string | null;
        }>(),
      db
        .prepare(
          `SELECT email, role, expires_at FROM org_invitations
           WHERE org_id = ? AND expires_at > ? ORDER BY created_at LIMIT 100`,
        )
        .bind(orgId, now)
        .all<{ email: string; role: string; expires_at: number }>(),
      db
        .prepare(
          `SELECT domain, verified_at, managed_at FROM org_domains WHERE org_id = ? ORDER BY domain`,
        )
        .bind(orgId)
        .all<{ domain: string; verified_at: number | null; managed_at: number | null }>(),
      db
        .prepare(
          `SELECT e.at, e.event, u.primary_email FROM audit_events e
           LEFT JOIN users u ON u.id = e.actor_user_id
           WHERE json_extract(e.detail, '$.org') = ? ORDER BY e.at DESC, e.id LIMIT 50`,
        )
        .bind(orgId)
        .all<{ at: number; event: string; primary_email: string | null }>(),
    ]);
    // The organization sees that 2earl looked, at most once an hour per staff member (§4.29).
    const seen = await db
      .prepare(
        `SELECT 1 AS ok FROM audit_events WHERE event = 'admin.org_viewed' AND actor_user_id = ?
           AND at > ? AND json_extract(detail, '$.org') = ? LIMIT 1`,
      )
      .bind(who.session.user.id, now - 3600, orgId)
      .first<{ ok: number }>();
    if (!seen) await record(c, who.session, 'admin.org_viewed', { org: orgId });
    const detail: AdminOrgDetail = {
      org,
      members: members.results.map((m) => ({
        userId: m.user_id,
        email: m.primary_email,
        name: m.display_name,
        role: m.role,
        joinedAt: m.joined_at,
        managed: m.managed_by === orgId,
      })),
      invitations: invitations.results.map((i) => ({
        email: i.email,
        role: i.role,
        expiresAt: i.expires_at,
      })),
      domains: domains.results.map((d) => ({
        domain: d.domain,
        verified: d.verified_at !== null,
        managed: d.managed_at !== null,
      })),
      activity: activity.results.map((e) => ({
        at: e.at,
        event: e.event,
        actor: e.event.startsWith('admin.') ? '2earl' : e.primary_email,
      })),
    };
    return c.html(adminOrgPage({ detail, ...flash(c, who.role) }));
  });

  // ---- Staff (DESIGN §4.29) -----------------------------------------------------------------

  const teamHtml = async (c: AppContext, view: AdminView, form?: { email: string }) => {
    const members = await listStaff(c.env.DB);
    const session = c.get('session');
    const label = new Map<string, string>(members.map((m) => [m.userId, m.email ?? m.userId]));
    if (session) label.set(session.user.id, `${session.user.primaryEmail ?? 'You'} (owner)`);
    const held = await listAssignments(c.env.DB, null, deps.now());
    return adminTeamPage({
      staff: members,
      platform: {
        roles: ASSIGNABLE_SERVICES.flatMap((service) =>
          Object.entries(service.authz.roles)
            .filter(([, r]) => r.assignable === 'platform')
            .filter(([, r]) => !r.permissions.some((p) => NEVER_ASSIGNABLE.has(p)))
            .map(([id, r]) => ({
              id,
              name: r.name,
              service: service.name,
              permissions: [...r.permissions],
            })),
        ),
        held: held.map((a) => ({
          id: a.id,
          person: label.get(a.principal.id) ?? a.principal.id,
          role: systemRole(a.role)?.name ?? a.role,
          service: ASSIGNABLE_SERVICES.find((s) => s.id === a.service)?.name ?? a.service,
          expiresAt: a.expiresAt,
          reason: a.reason,
        })),
        people: [...label].map(([id, l]) => ({ id, label: l })),
      },
      ...(form ? { form } : {}),
      ...view,
    });
  };

  app.get('/admin/team', async (c) => {
    const who = await staff(c, staffCan.manageStaff);
    if (who instanceof Response) return who;
    return c.html(await teamHtml(c, flash(c, who.role)));
  });

  app.post('/admin/team', async (c) => {
    const who = await staffForChange(c, '/admin/team', staffCan.manageStaff);
    if (who instanceof Response) return who;
    const { session, role } = who;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const field = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };
    const fail = async (error: string, status: 400 | 404 | 409 = 400) =>
      c.html(await teamHtml(c, { role, error }, { email: field('email') }), status);
    const now = deps.now();
    const context = noticeContext(c, now);

    if (action === 'grant' || action === 'grant_user') {
      const staffRole = form.get('role');
      if (!isGrantableStaffRole(staffRole)) return fail('Choose admin or support.');
      let email = field('email').toLowerCase();
      if (action === 'grant_user') {
        // Changing the role of someone already on staff: by account, not address.
        const row = await c.env.DB.prepare(
          'SELECT u.primary_email FROM staff s JOIN users u ON u.id = s.user_id WHERE s.user_id = ?',
        )
          .bind(field('user'))
          .first<{ primary_email: string | null }>();
        if (!row?.primary_email) return fail('That person is no longer on staff.', 404);
        email = row.primary_email.toLowerCase();
      }
      if (email.length > 254 || !EMAIL.test(email)) return fail('Enter a valid email address.');
      const result = await grantStaff(
        c.env.DB,
        now,
        email,
        staffRole,
        session.user.id,
        session.user.id,
      );
      if (!result.ok) {
        const error = {
          no_account:
            'No 2earl account signs in with that address. Ask them to create one first (add a sign-up invitation if sign-up is closed).',
          owner: 'That’s you: the owner already has every permission.',
          managed:
            'That account is managed by an organization. Staff need an account of their own.',
          suspended: 'That account is suspended. Reactivate it first.',
          same: 'They already have that role.',
        }[result.reason];
        return fail(error, result.reason === 'no_account' ? 404 : 409);
      }
      // A role change applies to the sessions they already have; the email says what changed.
      await record(c, session, 'admin.staff_granted', {
        target: result.userId,
        role: staffRole,
        previous: result.previous,
      });
      workerCtx(c).waitUntil(
        notify(c.env, result.userId, { kind: 'staff_role', role: staffRole }, context),
      );
      return c.redirect('/admin/team?done=staff_granted', 303);
    }

    // App roles across 2earl (DESIGN §4.32): the owner gives them to staff, for one app.
    if (action === 'platform_grant') {
      const roleId = field('role');
      const system = systemRole(roleId);
      if (
        system?.assignable !== 'platform' ||
        !ASSIGNABLE_SERVICES.some((s) => s.authz.roles[roleId] === system)
      ) {
        return fail('Choose a role.');
      }
      const daysText = field('days');
      const days = daysText === '' ? null : Number(daysText);
      if (days !== null && (!Number.isInteger(days) || days < 1 || days > 365)) {
        return fail('Enter a number of days from 1 to 365, or leave it empty.');
      }
      const result = await assignRole(c.env, now, {
        orgId: null,
        principal: { kind: 'user', id: field('user') },
        role: roleId,
        expiresAt: days === null ? null : now + days * 24 * 60 * 60,
        grantedBy: session.user.id,
        reason: field('reason'),
      });
      if (!result.ok) {
        const error =
          {
            unknown_principal: 'Only the owner and staff can be given app roles.',
            duplicate: 'They already have that role.',
            exclusive: 'They hold a role that can’t be combined with this one.',
            not_assignable: 'That role can’t be given.',
          }[result.reason as string] ?? 'Nothing changed.';
        return fail(error, 409);
      }
      await record(c, session, 'admin.platform_role_given', {
        target: field('user'),
        role: roleId,
        days,
      });
      return c.redirect('/admin/team?done=platform_given', 303);
    }

    if (action === 'platform_revoke') {
      const gone = await revokeAssignment(c.env.DB, null, field('id'));
      if (gone) {
        await record(c, session, 'admin.platform_role_taken', {
          target: gone.principal.id,
          role: gone.role,
        });
      }
      return c.redirect('/admin/team?done=platform_taken', 303);
    }

    if (action === 'revoke') {
      const userId = field('user');
      const previous = await revokeStaff(c.env.DB, userId);
      if (previous) {
        await record(c, session, 'admin.staff_revoked', { target: userId, previous });
        workerCtx(c).waitUntil(notify(c.env, userId, { kind: 'staff_role', role: null }, context));
      }
      return c.redirect('/admin/team?done=staff_revoked', 303);
    }
    return fail('Unknown action.');
  });

  app.get('/admin/apps', async (c) => {
    const who = await staff(c, staffCan.manageApps);
    if (who instanceof Response) return who;
    return c.html(await appsHtml(c, flash(c, who.role)));
  });

  app.post('/admin/apps', async (c) => {
    const who = await staffForChange(c, '/admin/apps', staffCan.manageApps);
    if (who instanceof Response) return who;
    const { session, role } = who;
    const form = await c.req.raw.formData();
    const action = form.get('action');
    const field = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };
    const fail = async (error: string) => c.html(await appsHtml(c, { role, error }), 400);
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
            role,
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
      case 'scope_policy': {
        const mode = field('mode');
        if (mode !== 'report' && mode !== 'enforce') return fail('Choose a rule.');
        await setClientScopePolicy(c.env.DB, now, mode);
        await record(c, session, 'admin.scope_policy_changed', { mode });
        return c.redirect(`/admin/apps?done=scope_policy_${mode}`, 303);
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
        return c.html(await appsHtml(c, { role, created }));
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
    const who = await staff(c);
    if (who instanceof Response) return who;
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
        role: who.role,
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
