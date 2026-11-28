import type { AuditEvent } from './audit';
import { notify, type NoticeContext } from './mail';

/**
 * Security alerts for organization owners (DESIGN §4.27). The changes that would let someone
 * take over the organization's accounts, or hide that they did, are emailed to every owner the
 * moment they happen: single sign-on, owners and admins, keys and tokens, managed domains, the
 * security rules and where the activity log goes. If an owner's or admin's account is misused,
 * the other owners hear of it at once instead of finding it in the activity later.
 */

type Detail = Record<string, unknown>;

/** What happened, as the rest of a sentence after who did it; null when it isn't alerted. */
const ALERTS: Partial<Record<AuditEvent, (detail: Detail) => string | null>> = {
  'org.saml_saved': (d) =>
    d.enabled === false
      ? 'turned SAML single sign-on off'
      : 'changed the SAML single sign-on settings (who can sign in as your people)',
  'org.oidc_saved': (d) =>
    d.enabled === false
      ? 'turned OpenID Connect single sign-on off'
      : 'changed the OpenID Connect single sign-on settings (who can sign in as your people)',
  'org.saml_metadata_refreshed': () =>
    'took new SAML signing certificates from your identity provider’s metadata URL',
  'org.require_sso_changed': (d) =>
    d.on === false ? 'stopped requiring single sign-on for managed accounts' : null,
  'org.role_changed': (d) =>
    d.role === 'owner' || d.role === 'admin' || d.role === 'auditor'
      ? `made {target} ${d.role === 'owner' ? 'an owner' : d.role === 'admin' ? 'an admin' : 'an auditor (reads the activity)'}`
      : d.from === 'owner' || d.from === 'admin'
        ? `changed {target} from ${d.from} to ${String(d.role)}`
        : null,
  'org.group_role_changed': (d) =>
    d.role === 'admin' || d.role === 'auditor'
      ? `made the directory group “${String(d.name)}” ${d.role === 'admin' ? 'admins' : 'auditors'}`
      : null,
  'org.api_key_created': (d) =>
    `created an API key “${String(d.name)}” with ${d.access === 'write' ? 'read and write' : 'read'} access`,
  'org.scim_token_created': () => 'created a directory sync (SCIM) token',
  'org.service_account_created': (d) =>
    `created a service account with ${String(d.scope)} for ${String(d.resource)}`,
  'org.domain_unmanaged': (d) => `stopped managing accounts at ${String(d.domain)}`,
  'org.domain_removed': (d) => `removed the domain ${String(d.domain)}`,
  'org.policy_changed': () => 'changed the security rules for managed accounts',
  'org.audit_stream_changed': (d) =>
    d.removed === true
      ? 'stopped streaming the activity log'
      : 'changed where the activity log is streamed',
};

/** The sentence for an alerted event, or null. */
export function alertFor(event: AuditEvent, detail: Detail): string | null {
  return ALERTS[event]?.(detail) ?? null;
}

/** "Ada Lovelace (ada@example.com)", or the address alone, or the fallback. */
async function personLabel(db: D1Database, userId: string, fallback: string): Promise<string> {
  const user = await db
    .prepare('SELECT display_name, primary_email FROM users WHERE id = ?')
    .bind(userId)
    .first<{ display_name: string | null; primary_email: string | null }>();
  const label = [user?.display_name, user?.primary_email ? `(${user.primary_email})` : null]
    .filter(Boolean)
    .join(' ');
  return label || fallback;
}

/** Who made a change: a person, an API key, or 2earl itself. */
export type Actor = { userId: string } | { apiKey: string } | { system: true };

/**
 * Emails every owner of the organization about the change, if it is one that's alerted. The
 * owner who made it gets it too: if their account is the one misused, that's how they learn.
 */
export async function alertOwners(
  env: Env,
  orgId: string,
  event: AuditEvent,
  detail: Detail,
  actor: Actor,
  context?: NoticeContext,
): Promise<number> {
  let what = alertFor(event, detail);
  if (!what) return 0;
  if (what.includes('{target}')) {
    const target =
      typeof detail.target === 'string'
        ? await personLabel(env.DB, detail.target, 'a member')
        : 'a member';
    what = what.replace('{target}', target);
  }
  const org = await env.DB.prepare(
    "SELECT name FROM organizations WHERE id = ? AND status = 'active'",
  )
    .bind(orgId)
    .first<{ name: string }>();
  if (!org) return 0;
  let who: string;
  if ('userId' in actor) {
    who = await personLabel(env.DB, actor.userId, 'A member');
  } else if ('apiKey' in actor) {
    const key = await env.DB.prepare('SELECT name FROM org_api_keys WHERE id = ?')
      .bind(actor.apiKey)
      .first<{ name: string }>();
    who = `The API key “${key?.name ?? 'unknown'}”`;
  } else {
    who = '2earl';
  }
  const { results: owners } = await env.DB.prepare(
    "SELECT user_id FROM org_members WHERE org_id = ? AND role = 'owner'",
  )
    .bind(orgId)
    .all<{ user_id: string }>();
  await Promise.allSettled(
    owners.map((owner) =>
      notify(
        env,
        owner.user_id,
        { kind: 'org_security_change', org: org.name, orgId, who, what },
        context,
      ),
    ),
  );
  return owners.length;
}
