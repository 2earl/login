import { WorkerEntrypoint } from 'cloudflare:workers';
import { createRemoteJWKSet } from 'jose';
import { createApp } from './app';
import { GOOGLE_JWKS_URL } from './google';
import { authorizationServer, type GrantProps } from './oauth';
import { deliverDeletionNotices } from './deletion-notices';
import { deleteAccount } from './account';
import { audit } from './audit';
import { dueDeletions } from './managed';
import { deliverStreams } from './org-audit';
import { serviceForResource } from './services';
import { boundKey, challenge, checkAccessToken } from './token-check';

export { PromptshareDirectory } from './directory';
export { OrganizationDirectory } from './org-directory';

const app = createApp({
  fetch: (input, init) => fetch(input, init),
  googleJwks: createRemoteJWKSet(new URL(GOOGLE_JWKS_URL)),
  now: () => Math.floor(Date.now() / 1000),
});

const AUDIT_RETENTION_SECONDS = 90 * 24 * 60 * 60;
const PURGE_CURSOR_KEY = 'purge-cursor';
/** The daily clean-up trigger; must match wrangler.jsonc. */
export const DAILY_CRON = '17 3 * * *';

/**
 * The login Worker. Public HTTP goes to `fetch`. `validateToken` is an RPC method for the MCP
 * gateway's Service Binding only: it is never reachable from the Internet (DESIGN §4.4).
 */
export default class LoginWorker extends WorkerEntrypoint<Env> {
  override fetch(request: Request): Response | Promise<Response> {
    return app.fetch(request, this.env, this.ctx);
  }

  /**
   * Validates an access token for one resource. The gateway passes its own canonical resource;
   * a token issued for any other audience is rejected by the library.
   */
  async validateToken(resource: string, token: string) {
    // A resource this server doesn't issue tokens for is a misconfigured gateway, not a bad token:
    // fail closed with an error (the gateway answers 503) rather than null (a 401 the client would
    // answer by signing in again, forever). Checked here, so the error is an ordinary RPC exception.
    if (!serviceForResource(this.env, resource)) {
      throw new Error('resource must name one registered protected resource');
    }
    const validated = await authorizationServer(this.env).validateToken<GrantProps>(
      resource,
      token,
      this.env,
    );
    // A DPoP-bound token is never accepted as a bearer token: validateRequest checks its proof.
    if (!validated || boundKey(validated.props)) return null;
    return validated as {
      props: GrantProps;
      audience: string;
      expiresAt: number;
      scope: string[];
      userId: string;
      clientId: string;
    };
  }

  /**
   * Validates the access token of one request to a resource (DESIGN §4.15): `Authorization` with
   * `Bearer` or `DPoP`, and the `DPoP` proof header. For resources that check DPoP proofs
   * (`dpop: true` in src/services.ts). The answer names the error and the `WWW-Authenticate` value
   * to send, so the resource needs no DPoP code of its own.
   */
  async validateRequest(
    resource: string,
    request: { authorization: string | null; dpop: string | null; method: string; url: string },
  ) {
    if (!serviceForResource(this.env, resource)) {
      throw new Error('resource must name one registered protected resource');
    }
    const checked = await checkAccessToken(
      this.env,
      Math.floor(Date.now() / 1000),
      resource,
      request,
    );
    return checked.ok
      ? { ok: true as const, token: checked.token }
      : {
          ok: false as const,
          error: checked.error,
          description: checked.description,
          wwwAuthenticate: challenge(checked.error),
        };
  }

  /**
   * Cron triggers (wrangler.jsonc). Every 15 minutes: deliver account-deletion notices to the
   * services. Daily: clean-up. Each part runs even if another fails.
   */
  override async scheduled(controller: ScheduledController): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    // Every minute: organizations' audit streams (DESIGN §4.23).
    const streams = await deliverStreams(this.env, fetch, now).catch((error: unknown) => {
      console.error('audit streams failed', error instanceof Error ? error.name : 'unknown');
      return null;
    });
    if (streams && streams.failed > 0) console.warn('audit streams failing', streams.failed);
    // Every 15 minutes: deletion notices to services.
    const minute = new Date(controller.scheduledTime).getUTCMinutes();
    if (controller.cron === DAILY_CRON || minute % 15 === 0) {
      const notices = await deliverDeletionNotices(this.env, now).catch((error: unknown) => {
        console.error('deletion notices failed', error instanceof Error ? error.name : 'unknown');
        return null;
      });
      if (notices && (notices.failed > 0 || notices.waiting > 0)) {
        console.warn('deletion notices pending', notices.failed, notices.waiting);
      }
    }
    if (controller.cron !== DAILY_CRON) return;

    const results = await Promise.allSettled([
      this.env.DB.batch([
        this.env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM login_tx WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM device_codes WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM org_invitations WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM pushed_requests WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM dpop_proofs WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM saml_states WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM saml_cache WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM audit_events WHERE at < ?').bind(
          now - AUDIT_RETENTION_SECONDS,
        ),
      ]),
      (async () => {
        const cursor = (await this.env.OAUTH_KV.get(PURGE_CURSOR_KEY)) ?? undefined;
        const result = await authorizationServer(this.env).purgeExpiredData(this.env, {
          batchSize: 100,
          ...(cursor ? { cursor } : {}),
        });
        if (result.cursor) await this.env.OAUTH_KV.put(PURGE_CURSOR_KEY, result.cursor);
        else await this.env.OAUTH_KV.delete(PURGE_CURSOR_KEY);
      })(),
      deleteDueManagedAccounts(this.env, now),
    ]);
    for (const result of results) {
      if (result.status === 'rejected') {
        console.error(
          'scheduled clean-up failed',
          result.reason instanceof Error ? result.reason.name : 'unknown',
        );
      }
    }
  }
}

/**
 * Managed accounts a directory removed 30 days ago and nobody reactivated (DESIGN §4.18): deleted
 * like any account, and every service is told.
 */
async function deleteDueManagedAccounts(env: Env, now: number): Promise<void> {
  const oauth = authorizationServer(env).getOAuthApi(env);
  for (const userId of await dueDeletions(env.DB, now)) {
    const org = await env.DB.prepare('SELECT managed_by FROM users WHERE id = ?')
      .bind(userId)
      .first<{ managed_by: string | null }>();
    await deleteAccount(env.DB, oauth, userId, now, null);
    await audit(env.DB, now, 'org.account_deletion_due', {
      detail: { org: org?.managed_by ?? null },
    });
  }
  await deliverDeletionNotices(env, now);
}
