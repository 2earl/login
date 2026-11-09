import { WorkerEntrypoint } from 'cloudflare:workers';

/**
 * Prompt share's lookup of an account by email address, for sharing a prompt with someone
 * (DESIGN §4.8). A named entrypoint bound only by Prompt share (its wrangler.jsonc); the MCP
 * gateway and the public Internet can't reach it.
 *
 * Only active accounts and only addresses Google verified count. An address shared by more than
 * one account answers none, so a prompt never goes to the wrong person.
 */
export class PromptshareDirectory extends WorkerEntrypoint<Env> {
  async uidForEmail(email: string): Promise<string | null> {
    const address = normaliseEmail(email);
    if (!address) return null;
    const { results } = await this.env.DB.prepare(
      `SELECT DISTINCT u.id FROM identities i JOIN users u ON u.id = i.user_id
       WHERE i.email = ? COLLATE NOCASE AND i.email_verified = 1 AND u.status = 'active'
       LIMIT 2`,
    )
      .bind(address)
      .all<{ id: string }>();
    return results.length === 1 && results[0] ? results[0].id : null;
  }
}

/** Trimmed and lower-cased; null unless it looks like one address (no spaces, one @). */
export function normaliseEmail(email: string): string | null {
  const address = email.trim().toLowerCase();
  if (address.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) return null;
  return address;
}
