import { WorkerEntrypoint } from 'cloudflare:workers';
import { createRemoteJWKSet } from 'jose';
import { createApp } from './app';
import { GOOGLE_JWKS_URL } from './google';
import { authorizationServer, type GrantProps } from './oauth';
import { deliverDeletionNotices } from './deletion-notices';
import { serviceForResource } from './services';

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
    return authorizationServer(this.env).validateToken(resource, token, this.env) as Promise<{
      props: GrantProps;
      audience: string;
      expiresAt: number;
      scope: string[];
      userId: string;
      clientId: string;
    } | null>;
  }

  /**
   * Cron triggers (wrangler.jsonc). Every 15 minutes: deliver account-deletion notices to the
   * services. Daily: clean-up. Each part runs even if another fails.
   */
  override async scheduled(controller: ScheduledController): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const notices = await deliverDeletionNotices(this.env, now).catch((error: unknown) => {
      console.error('deletion notices failed', error instanceof Error ? error.name : 'unknown');
      return null;
    });
    if (notices && (notices.failed > 0 || notices.waiting > 0)) {
      console.warn('deletion notices pending', notices.failed, notices.waiting);
    }
    if (controller.cron !== DAILY_CRON) return;

    const results = await Promise.allSettled([
      this.env.DB.batch([
        this.env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now),
        this.env.DB.prepare('DELETE FROM login_tx WHERE expires_at <= ?').bind(now),
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
