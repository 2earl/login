import type { Service } from '../services';

/**
 * Which client may ask for which scope (DESIGN §4.32, phase 13c). A first-party app's own
 * sign-in scope (`emanet:control`, `promptshare:account`) belongs to that app: any other client
 * asking for it is refused, even with the person's consent.
 *
 * The owner switches the rule on in two steps, without a deploy (`settings`,
 * `client_scope_policy`):
 * - `report` (the default): nothing is refused; each sign-in that would be is recorded as
 *   `authz.scope_policy_would_refuse`, so a wrong client ID shows up before it locks an app out;
 * - `enforce`: refused at /authorize, and at every code exchange and refresh.
 */

export type ClientScopePolicy = 'report' | 'enforce';

export async function clientScopePolicy(db: D1Database): Promise<ClientScopePolicy> {
  const row = await db
    .prepare("SELECT value FROM settings WHERE key = 'client_scope_policy'")
    .first<{ value: string }>();
  return row?.value === 'enforce' ? 'enforce' : 'report';
}

export async function setClientScopePolicy(
  db: D1Database,
  now: number,
  policy: ClientScopePolicy,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO settings (key, value, updated_at) VALUES ('client_scope_policy', ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .bind(policy, now)
    .run();
}

/** The scopes in `scopes` this client may not ask for. */
export function refusedScopes(
  env: Env,
  service: Service,
  clientId: string,
  scopes: readonly string[],
): string[] {
  const rules = service.firstPartyClients;
  if (!rules) return [];
  return scopes.filter((scope) => {
    const allowed = rules[scope];
    return allowed !== undefined && !allowed(env).includes(clientId);
  });
}
