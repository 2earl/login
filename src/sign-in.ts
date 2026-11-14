import { deleteAccount } from './account';
import type { OwnershipPlan } from './orgs';
import { claimProvisioned } from './scim';
import { managerOf, ssoRequiredBy } from './managed';
import { methodAllowed, networkAllowed, policyFor, type PolicyMethod } from './org-policy';

const METHOD_LABEL: Record<PolicyMethod, string> = {
  google: 'Google',
  email: 'a code by email',
  passkey: 'a passkey',
};
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

/**
 * Why this account can't sign in this way, if it can't: its organization requires single sign-on
 * (DESIGN §4.18), or its rules don't allow this way in or this network (§4.19). Checked before
 * every sign-in, SAML included for networks; sessions are checked again on every request.
 */
export async function signInRefusal(
  c: AppContext,
  userId: string,
  method: SignInMethod,
): Promise<Message | null> {
  // The organization's rules (DESIGN §4.19): which networks, which ways in.
  const policy = await policyFor(c.env.DB, userId);
  if (policy && !networkAllowed(policy, c.req.header('CF-Connecting-IP') ?? null)) {
    return {
      title: 'Not from this network',
      body: `${policy.orgName} manages this account and allows it only from its own networks. Connect to one of them (for example your company’s VPN), then sign in again.`,
      action: { href: '/login', label: 'Back to sign-in' },
    };
  }
  if (method === 'saml' || method === 'oidc') return null;
  const org = await ssoRequiredBy(c.env.DB, userId);
  if (!org) {
    if (policy && !methodAllowed(policy, method)) {
      return {
        title: 'Sign in another way',
        body: `${policy.orgName} manages this account and doesn’t allow signing in this way. Use one it allows${policy.methods.length > 0 ? ` (${policy.methods.map((m) => METHOD_LABEL[m]).join(', ')})` : ''}, or its single sign-on.`,
        action: { href: '/login', label: 'Back to sign-in' },
      };
    }
    return null;
  }
  return {
    title: 'Sign in with single sign-on',
    body: `${org.name} manages this account and asks you to sign in through its single sign-on. Choose “Sign in with your organization (SSO)” and enter your work address.`,
    action: { href: '/login/sso', label: 'Sign in with SSO' },
  };
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
  // A managed account is deleted by its organization, not by the person (DESIGN §4.18).
  const manager = await managerOf(c.env.DB, userId);
  if (manager) return stop('managed_account', managedDeletion(manager.name), 403);
  return deleteAndTell(c, now, userId, stop);
}

/** What a managed account sees instead of deleting itself. */
export function managedDeletion(org: string): Message {
  return {
    title: 'Your organization manages this account',
    body: `“${org}” manages this account, so only it can delete it. Ask its admins. You can still download your data.`,
    action: { href: '/account/data', label: 'Your data' },
  };
}

/**
 * Deletes the account and tells everyone who needs to know: services, new owners of its
 * organizations, and the person, at the address it had. False if the deletion failed.
 */
export async function removeAccount(c: AppContext, now: number, userId: string): Promise<boolean> {
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
    return false;
  }
  // The account is gone, so the address is taken from before; this is the last email.
  if (address?.primary_email) {
    const mail = noticeMail({ kind: 'account_deleted' }, noticeContext(c, now));
    workerCtx(c).waitUntil(sendMail(c.env, address.primary_email, mail));
  }
  return true;
}

/** The person's own deletion: the account goes, and so does this browser's session. */
async function deleteAndTell(
  c: AppContext,
  now: number,
  userId: string,
  stop: (reason: string, message?: Message, status?: 400 | 403 | 500) => Promise<Response>,
): Promise<Response> {
  if (!(await removeAccount(c, now, userId))) {
    return stop('deletion_error', MESSAGES.deletionFailed, 500);
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
