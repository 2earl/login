import { deleteAccount } from './account';
import type { OwnershipPlan } from './orgs';
import { claimProvisioned } from './scim';
import { audit } from './audit';
import { sha256Hex } from './crypto';
import { deliverDeletionNotices } from './deletion-notices';
import {
  CONSENT_APPROVALS_COOKIE,
  SESSION_COOKIE,
  clearCookie,
  clientIp,
  setCookie,
  workerCtx,
  type AppContext,
} from './http';
import { notify, sendMail, noticeMail, type Notice, type NoticeContext } from './mail';
import { authorizationServer } from './oauth';
import { MESSAGES, messagePage, type Message } from './pages';
import { safeReturnTo } from './return-to';
import { createSession, deleteSession, type SignInMethod } from './sessions';
import { deviceLabel } from './devices';

/**
 * What every way of signing in shares (DESIGN §4.2, §4.9): a fresh session, and the end of a
 * deletion once the user has proved it's them.
 */

/**
 * Opens a fresh session for `userId` and sets its cookie; any session the browser already had is
 * ended. Returns nothing to redirect to: `startSession` does that for form flows, the passkey
 * flow answers with JSON.
 */
export async function openSession(
  c: AppContext,
  now: number,
  userId: string,
  meta: { method: SignInMethod; aal2?: boolean },
): Promise<void> {
  const ip = clientIp(c);
  const previous = c.get('session');
  if (previous) await deleteSession(c.env.DB, previous.idHash);
  const userAgent = c.req.header('User-Agent');
  const session = await createSession(c.env.DB, c.env.SESSION_PEPPER, now, userId, {
    ipPrefix: ip,
    userAgentHash: userAgent ? (await sha256Hex(userAgent)).slice(0, 16) : null,
    device: deviceLabel(userAgent),
    method: meta.method,
    aal2: meta.aal2 ?? false,
  });
  setCookie(c, SESSION_COOKIE, session.cookieValue, session.expiresAt - now);
  // Organizations whose directory provisioned this account's address (DESIGN §4.16).
  await claimProvisioned(c.env.DB, now, userId);
  await audit(c.env.DB, now, 'login.succeeded', {
    actorUserId: userId,
    ipPrefix: ip,
    detail: { method: meta.method },
  });
}

/** A fresh session for `userId`, then on to `returnTo` (or the welcome page for a new account). */
export async function startSession(
  c: AppContext,
  now: number,
  userId: string,
  returnTo: string | null,
  options: { welcome?: boolean; method: SignInMethod },
): Promise<Response> {
  await openSession(c, now, userId, { method: options.method });
  // A new account stops at the welcome page first (a name, a second factor), then goes on.
  return c.redirect(
    options.welcome
      ? `/welcome?return_to=${encodeURIComponent(safeReturnTo(returnTo))}`
      : safeReturnTo(returnTo),
    303,
  );
}

/** Deletes the signed-in account after the user confirmed it (DESIGN §6.3). */
export async function finishDeletion(
  c: AppContext,
  now: number,
  userId: string,
  stop: (reason: string, message?: Message, status?: 400 | 403 | 500) => Promise<Response>,
): Promise<Response> {
  const address = await c.env.DB.prepare('SELECT primary_email FROM users WHERE id = ?')
    .bind(userId)
    .first<{ primary_email: string | null }>();
  const oauth = authorizationServer(c.env).getOAuthApi(c.env);
  try {
    const plan = await deleteAccount(c.env.DB, oauth, userId, now, clientIp(c));
    tellNewOwners(c, plan);
    // Tell every service now; the cron retries whatever doesn't go through.
    workerCtx(c).waitUntil(deliverDeletionNotices(c.env, now));
  } catch (error) {
    console.error('account deletion failed', error instanceof Error ? error.name : 'unknown');
    return stop('deletion_error', MESSAGES.deletionFailed, 500);
  }
  // The account is gone, so the address is taken from before; this is the last email.
  if (address?.primary_email) {
    const mail = noticeMail({ kind: 'account_deleted' }, noticeContext(c, now));
    workerCtx(c).waitUntil(sendMail(c.env, address.primary_email, mail));
  }
  clearCookie(c, SESSION_COOKIE);
  clearCookie(c, CONSENT_APPROVALS_COOKIE);
  return c.redirect('/account/deleted', 303);
}

/** Sends a security notice after the response. */
export function notifyLater(c: AppContext, userId: string, notice: Notice): void {
  workerCtx(c).waitUntil(notify(c.env, userId, notice, noticeContext(c)));
}

/** When the change happened, and the device and network it came from (DESIGN §4.9). */
export function noticeContext(c: AppContext, now = Math.floor(Date.now() / 1000)): NoticeContext {
  return {
    at: now,
    device: deviceLabel(c.req.header('User-Agent')),
    network: clientIp(c),
  };
}

/** A message page with its status, for the many ways sign-in can stop. */
export function stopped(c: AppContext, message: Message, status: 400 | 403 | 429 | 500 = 400) {
  return c.html(messagePage(message), status);
}

/** Tells each person who became an owner because the only owner deleted their account. */
export function tellNewOwners(c: AppContext, plan: OwnershipPlan): void {
  for (const passed of plan.passed)
    notifyLater(c, passed.to, { kind: 'org_owner', org: passed.name });
}
