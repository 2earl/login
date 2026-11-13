import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Hono } from 'hono';
import { renderSVG } from 'uqr';
import type { Deps } from './app';
import { audit } from './audit';
import { notifyLater } from './sign-in';
import { base64url } from './crypto';
import { clientIp, isSameOrigin, underRateLimit, type AppContext, type AppEnv } from './http';
import {
  FIRST_FACTOR_MAX_SESSION_AGE_SECONDS,
  addPasskey,
  addTotp,
  clearFailures,
  decryptSecret,
  encryptSecret,
  getTotp,
  isStepUpFresh,
  listFactors,
  listPasskeys,
  lockedUntil,
  markSessionAal2,
  mfaGate,
  mfaRequired,
  peekPending,
  putPending,
  recordFailure,
  regenerateRecoveryCodes,
  remainingRecoveryCodes,
  removeFactor,
  takePending,
  useRecoveryCode,
} from './mfa';
import {
  MESSAGES,
  challengePage,
  messagePage,
  recoveryCodesPage,
  securityPage,
  totpSetupPage,
} from './pages';
import { safeReturnTo } from './return-to';
import { MFA_CSP } from './security-headers';
import { listIdentities } from './users';
import type { Session } from './sessions';
import { generateTotpSecret, otpauthUri, verifyTotp } from './totp';

/** Second-factor routes (DESIGN §4.7): /account/security for factors, /mfa for the challenge. */

const encoder = new TextEncoder();

const NOTICES: Record<string, string> = {
  added: 'Second factor added.',
  removed: 'Second factor removed.',
};

export function relyingParty(env: Env): { rpID: string; origin: string } {
  const url = new URL(env.ISSUER);
  return { rpID: url.hostname, origin: url.origin };
}

export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** A page allowed to run /passkey.js: second-factor pages and the sign-in page. */
export function mfaHtml(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': MFA_CSP },
  });
}

function cleanLabel(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const label = value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, 60);
  return label.length > 0 ? label : fallback;
}

/**
 * May this session add or remove factors now? With a factor: only with a second-factor proof at
 * most 5 minutes old. Without one: only within 10 minutes of signing in with Google, so a session
 * cookie stolen later can't attach the thief's own factor.
 */
/** "A passkey", "An authenticator app": how a notice names a factor kind. */
function factorName(kind: string): string {
  return kind === 'webauthn'
    ? 'A passkey'
    : kind === 'totp'
      ? 'An authenticator app'
      : 'A second factor';
}

export function changeCheck(session: Session, now: number, returnTo: string): string | null {
  if (session.hasFactor) {
    return isStepUpFresh(session, now)
      ? null
      : `/mfa?step_up=1&return_to=${encodeURIComponent(returnTo)}`;
  }
  return now - session.createdAt <= FIRST_FACTOR_MAX_SESSION_AGE_SECONDS
    ? null
    : `/login?reauth=1&return_to=${encodeURIComponent(returnTo)}`;
}

export function registerMfaRoutes(app: Hono<AppEnv>, deps: Deps): void {
  const signedIn = (c: AppContext): Session | null => c.get('session');

  /**
   * After a factor is added. The first one also proves possession (the session becomes aal2) and
   * creates recovery codes, shown once on the next page.
   */
  async function factorAdded(c: AppContext, session: Session, kind: string, next: string) {
    const now = deps.now();
    await audit(c.env.DB, now, 'mfa.enrolled', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail: { kind },
    });
    notifyLater(c, session.user.id, { kind: 'factor_added', factor: factorName(kind) });
    if (session.hasFactor) return '/account/security?done=added';
    await markSessionAal2(c.env.DB, session.idHash, now);
    const codes = await regenerateRecoveryCodes(
      c.env.DB,
      c.env.MFA_ENCRYPTION_KEY,
      session.user.id,
    );
    await putPending(
      c.env.DB,
      session.idHash,
      'recovery_codes',
      await encryptSecret(
        c.env.MFA_ENCRYPTION_KEY,
        session.idHash,
        JSON.stringify({ codes, next }),
      ),
      now,
    );
    await audit(c.env.DB, now, 'mfa.recovery_codes_created', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
    });
    return '/account/security/recovery-codes';
  }

  async function securityHtml(c: AppContext, session: Session, extra: { error?: string } = {}) {
    const notice = NOTICES[c.req.query('done') ?? ''];
    const returnTo = c.req.query('return_to');
    return securityPage({
      factors: await listFactors(c.env.DB, session.user.id),
      methods: await listIdentities(c.env, session.user.id),
      recoveryRemaining: await remainingRecoveryCodes(c.env.DB, session.user.id),
      mfaRequired: mfaRequired(c.env),
      mustEnrol: mfaGate(c.env, session) === 'enrol',
      next: returnTo ? safeReturnTo(returnTo) : '/account',
      ...(notice ? { notice } : {}),
      ...extra,
    });
  }

  // ---- Managing factors ----------------------------------------------------------------------

  app.get('/account/security', async (c) => {
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    return mfaHtml(await securityHtml(c, session));
  });

  app.post('/account/security/passkeys/options', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    const session = signedIn(c);
    if (!session) return c.json({ message: 'Sign in again.' }, 401);
    const redirect = changeCheck(session, deps.now(), '/account/security');
    if (redirect) return c.json({ redirect });

    const { rpID } = relyingParty(c.env);
    const passkeys = await listPasskeys(c.env.DB, session.user.id);
    const options = await generateRegistrationOptions({
      rpName: '2earl',
      rpID,
      userName: session.user.primaryEmail ?? session.user.id,
      userDisplayName: session.user.displayName ?? '',
      userID: new Uint8Array(encoder.encode(session.user.id)),
      attestationType: 'none',
      excludeCredentials: passkeys.map((p) => ({ id: p.credentialId, transports: p.transports })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      timeout: 120_000,
    });
    await putPending(c.env.DB, session.idHash, 'webauthn_register', options.challenge, deps.now());
    return c.json(options);
  });

  app.post('/account/security/passkeys', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    const session = signedIn(c);
    if (!session) return c.json({ message: 'Sign in again.' }, 401);
    const now = deps.now();
    if (changeCheck(session, now, '/account/security')) {
      return c.json({ message: 'Confirm it’s you again, then add the passkey.' }, 403);
    }
    const body = await c.req
      .json<{ label?: unknown; next?: unknown; response?: unknown }>()
      .catch(() => null);
    const challenge = await takePending(c.env.DB, session.idHash, 'webauthn_register', now);
    if (!body || !challenge) return c.json({ message: 'This request expired. Try again.' }, 400);

    const { rpID, origin } = relyingParty(c.env);
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });
    } catch {
      return c.json({ message: 'The passkey couldn’t be verified. Try again.' }, 400);
    }
    if (!verification.verified) {
      return c.json({ message: 'The passkey couldn’t be verified. Try again.' }, 400);
    }

    const { credential } = verification.registrationInfo;
    try {
      await addPasskey(c.env.DB, session.user.id, now, {
        credentialId: credential.id,
        publicKey: base64url(credential.publicKey),
        signCount: credential.counter,
        transports: credential.transports ?? [],
        label: cleanLabel(body.label, 'Passkey'),
      });
    } catch {
      return c.json({ message: 'This passkey is already registered.' }, 409);
    }
    const next = typeof body.next === 'string' ? safeReturnTo(body.next) : '/account';
    return c.json({ redirect: await factorAdded(c, session, 'webauthn', next) });
  });

  app.get('/account/security/totp', async (c) => {
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    const now = deps.now();
    const redirect = changeCheck(session, now, '/account/security/totp');
    if (redirect) return c.redirect(redirect, 303);
    if (await getTotp(c.env.DB, session.user.id)) return c.redirect('/account/security', 303);

    // A new secret every time the page is opened; it is kept, encrypted, until confirmed.
    const secret = generateTotpSecret();
    await putPending(
      c.env.DB,
      session.idHash,
      'totp_enrol',
      await encryptSecret(c.env.MFA_ENCRYPTION_KEY, session.idHash, secret),
      now,
    );
    return c.html(totpPage(session, secret, safeReturnTo(c.req.query('return_to'))));
  });

  function totpPage(session: Session, secret: string, next: string, error?: string): string {
    const uri = otpauthUri(secret, session.user.primaryEmail ?? 'account');
    const qrSvg = renderSVG(uri, {
      ecc: 'M',
      border: 2,
      pixelSize: 6,
      blackColor: '#1c1b1f',
      whiteColor: '#ffffff',
    });
    return totpSetupPage({ qrSvg, secret, next, ...(error ? { error } : {}) });
  }

  app.post('/account/security/totp', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    const now = deps.now();
    const redirect = changeCheck(session, now, '/account/security/totp');
    if (redirect) return c.redirect(redirect, 303);
    if (!(await underRateLimit(c, 'mfa'))) {
      return c.html(messagePage(MESSAGES.tooManyAttempts, 'Setup paused'), 429);
    }

    const sealed = await peekPending(c.env.DB, session.idHash, 'totp_enrol', now);
    if (!sealed) return c.redirect('/account/security/totp', 303);
    const secret = await decryptSecret(c.env.MFA_ENCRYPTION_KEY, session.idHash, sealed);
    const form = await c.req.raw.formData();
    const next = safeReturnTo(stringField(form, 'next'));
    const step = await verifyTotp(secret, stringField(form, 'code') ?? '', now, null);
    if (step === null) {
      return c.html(
        totpPage(
          session,
          secret,
          next,
          'That code didn’t match. Check the app shows 2earl and enter its current code.',
        ),
        400,
      );
    }

    await takePending(c.env.DB, session.idHash, 'totp_enrol', now);
    try {
      await addTotp(
        c.env.DB,
        session.user.id,
        now,
        await encryptSecret(c.env.MFA_ENCRYPTION_KEY, session.user.id, secret),
        step,
      );
    } catch {
      return c.redirect('/account/security', 303); // already has one (another tab)
    }
    return c.redirect(await factorAdded(c, session, 'totp', next), 303);
  });

  app.post('/account/security/factors/remove', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    const now = deps.now();
    if (!isStepUpFresh(session, now)) {
      return c.redirect('/mfa?step_up=1&return_to=%2Faccount%2Fsecurity', 303);
    }
    const factorId = (await c.req.raw.formData()).get('factor');
    if (typeof factorId !== 'string') return c.redirect('/account/security', 303);

    const factors = await listFactors(c.env.DB, session.user.id);
    if (mfaRequired(c.env) && factors.length === 1 && factors[0]?.id === factorId) {
      return mfaHtml(
        await securityHtml(c, session, {
          error: '2earl requires a second factor. Add another one before removing this one.',
        }),
        400,
      );
    }
    const kind = factors.find((f) => f.id === factorId)?.kind;
    if (await removeFactor(c.env.DB, session.user.id, factorId)) {
      await audit(c.env.DB, now, 'mfa.removed', {
        actorUserId: session.user.id,
        ipPrefix: clientIp(c),
        detail: { kind: kind ?? null },
      });
      notifyLater(c, session.user.id, { kind: 'factor_removed', factor: factorName(kind ?? '') });
    }
    return c.redirect('/account/security?done=removed', 303);
  });

  app.post('/account/security/recovery-codes', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    const now = deps.now();
    if (!session.hasFactor) return c.redirect('/account/security', 303);
    if (!isStepUpFresh(session, now)) {
      return c.redirect('/mfa?step_up=1&return_to=%2Faccount%2Fsecurity', 303);
    }
    const codes = await regenerateRecoveryCodes(
      c.env.DB,
      c.env.MFA_ENCRYPTION_KEY,
      session.user.id,
    );
    await putPending(
      c.env.DB,
      session.idHash,
      'recovery_codes',
      await encryptSecret(
        c.env.MFA_ENCRYPTION_KEY,
        session.idHash,
        JSON.stringify({ codes, next: '/account/security' }),
      ),
      now,
    );
    await audit(c.env.DB, now, 'mfa.recovery_codes_created', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
    });
    notifyLater(c, session.user.id, { kind: 'recovery_codes' });
    return c.redirect('/account/security/recovery-codes', 303);
  });

  app.get('/account/security/recovery-codes', async (c) => {
    const session = signedIn(c);
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fsecurity', 303);
    // Shown once: reading them deletes the only plaintext copy.
    const sealed = await takePending(c.env.DB, session.idHash, 'recovery_codes', deps.now());
    if (!sealed) return c.redirect('/account/security', 303);
    const { codes, next } = JSON.parse(
      await decryptSecret(c.env.MFA_ENCRYPTION_KEY, session.idHash, sealed),
    ) as { codes: string[]; next: string };
    return c.html(recoveryCodesPage({ codes, next: safeReturnTo(next) }));
  });

  // ---- The challenge ----------------------------------------------------------------------------

  /** A passed challenge: the session becomes aal2 and the failure count resets. */
  async function verified(c: AppContext, session: Session, method: string): Promise<void> {
    const now = deps.now();
    await markSessionAal2(c.env.DB, session.idHash, now);
    await clearFailures(c.env.DB, session.user.id);
    await audit(c.env.DB, now, 'mfa.verified', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail: { method },
    });
  }

  /** A failed attempt. Returns the lock expiry if this attempt locked the step. */
  async function failed(c: AppContext, session: Session, method: string): Promise<number | null> {
    const now = deps.now();
    const locked = await recordFailure(c.env.DB, session.user.id, now);
    await audit(c.env.DB, now, locked ? 'mfa.locked' : 'mfa.failed', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail: { method },
    });
    return locked ? lockedUntil(c.env.DB, session.user.id, now) : null;
  }

  async function challengeHtml(
    c: AppContext,
    session: Session,
    returnTo: string,
    stepUp: boolean,
    extra: { error?: string; lockedUntil?: number | null } = {},
  ): Promise<string> {
    const factors = await listFactors(c.env.DB, session.user.id);
    return challengePage({
      hasPasskey: factors.some((f) => f.kind === 'webauthn'),
      hasTotp: factors.some((f) => f.kind === 'totp'),
      returnTo,
      stepUp,
      lockedUntil: extra.lockedUntil ?? (await lockedUntil(c.env.DB, session.user.id, deps.now())),
      ...(extra.error ? { error: extra.error } : {}),
    });
  }

  app.get('/mfa', async (c) => {
    const session = signedIn(c);
    if (!session) return c.redirect('/login', 303);
    const returnTo = safeReturnTo(c.req.query('return_to'));
    const stepUp = c.req.query('step_up') === '1';
    const gate = mfaGate(c.env, session);
    if (gate === 'enrol')
      return c.redirect(`/account/security?return_to=${encodeURIComponent(returnTo)}`, 303);
    if (!session.hasFactor || (gate === null && !stepUp)) return c.redirect(returnTo, 303);
    return mfaHtml(await challengeHtml(c, session, returnTo, stepUp));
  });

  app.post('/mfa/passkey/options', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    const session = signedIn(c);
    if (!session) return c.json({ message: 'Sign in again.' }, 401);
    const now = deps.now();
    if (await lockedUntil(c.env.DB, session.user.id, now)) {
      return c.json({ message: 'Too many failed attempts. Try again later.' }, 429);
    }
    const passkeys = await listPasskeys(c.env.DB, session.user.id);
    if (passkeys.length === 0) return c.json({ message: 'No passkey on this account.' }, 400);
    const options = await generateAuthenticationOptions({
      rpID: relyingParty(c.env).rpID,
      allowCredentials: passkeys.map((p) => ({ id: p.credentialId, transports: p.transports })),
      userVerification: 'preferred',
      timeout: 120_000,
    });
    await putPending(c.env.DB, session.idHash, 'webauthn_authenticate', options.challenge, now);
    return c.json(options);
  });

  app.post('/mfa/passkey', async (c) => {
    if (!isSameOrigin(c)) return c.json({ message: 'Forbidden.' }, 403);
    if (!(await underRateLimit(c, 'mfa'))) {
      return c.json({ message: 'Too many attempts from this network. Wait a minute.' }, 429);
    }
    const session = signedIn(c);
    if (!session) return c.json({ message: 'Sign in again.' }, 401);
    const now = deps.now();
    if (await lockedUntil(c.env.DB, session.user.id, now)) {
      return c.json({ message: 'Too many failed attempts. Try again later.' }, 429);
    }
    const body = await c.req.json<{ returnTo?: unknown; response?: unknown }>().catch(() => null);
    const challenge = await takePending(c.env.DB, session.idHash, 'webauthn_authenticate', now);
    if (!body || !challenge) return c.json({ message: 'This request expired. Try again.' }, 400);

    const response = body.response as AuthenticationResponseJSON | undefined;
    // Only the signed-in user's own passkeys count.
    const passkey = (await listPasskeys(c.env.DB, session.user.id)).find(
      (p) => p.credentialId === response?.id,
    );
    let ok = false;
    let newCounter = 0;
    if (passkey && response) {
      try {
        const { rpID, origin } = relyingParty(c.env);
        const result = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          credential: {
            id: passkey.credentialId,
            publicKey: fromBase64url(passkey.publicKey),
            counter: passkey.signCount,
            transports: passkey.transports,
          },
          requireUserVerification: false,
        });
        ok = result.verified;
        newCounter = result.authenticationInfo.newCounter;
      } catch {
        ok = false;
      }
    }
    if (!ok || !passkey) {
      const until = await failed(c, session, 'webauthn');
      return c.json(
        {
          message: until
            ? 'Too many failed attempts. Try again later.'
            : 'That passkey didn’t work. Try again.',
        },
        until ? 429 : 400,
      );
    }

    await c.env.DB.prepare(
      'UPDATE mfa_factors SET webauthn_sign_count = ?, last_used_at = ? WHERE id = ?',
    )
      .bind(newCounter, now, passkey.id)
      .run();
    await verified(c, session, 'webauthn');
    return c.json({
      redirect: safeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : null),
    });
  });

  app.post('/mfa/totp', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = signedIn(c);
    if (!session) return c.redirect('/login', 303);
    const form = await c.req.raw.formData();
    const returnTo = safeReturnTo(stringField(form, 'return_to'));
    const stepUp = session.aal === 'aal2';
    if (!(await underRateLimit(c, 'mfa'))) {
      return mfaHtml(
        await challengeHtml(c, session, returnTo, stepUp, {
          error: 'Too many attempts from this network. Wait a minute, then try again.',
        }),
        429,
      );
    }
    const now = deps.now();
    if (await lockedUntil(c.env.DB, session.user.id, now)) {
      return mfaHtml(await challengeHtml(c, session, returnTo, stepUp), 429);
    }

    const totp = await getTotp(c.env.DB, session.user.id);
    const step = totp
      ? await verifyTotp(
          await decryptSecret(c.env.MFA_ENCRYPTION_KEY, session.user.id, totp.secretEnc),
          stringField(form, 'code') ?? '',
          now,
          totp.lastStep,
        )
      : null;
    // The step is recorded only if it is still newer than the last one: a code can't be used twice,
    // even by two requests at once.
    const recorded =
      totp && step !== null
        ? (
            await c.env.DB.prepare(
              `UPDATE mfa_factors SET totp_last_step = ?, last_used_at = ?
               WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)`,
            )
              .bind(step, now, totp.id, step)
              .run()
          ).meta.changes === 1
        : false;

    if (!recorded) {
      const until = await failed(c, session, 'totp');
      return mfaHtml(
        await challengeHtml(c, session, returnTo, stepUp, {
          lockedUntil: until,
          ...(until
            ? {}
            : { error: 'That code didn’t work. Enter the current code from your app.' }),
        }),
        until ? 429 : 400,
      );
    }
    await verified(c, session, 'totp');
    return c.redirect(returnTo, 303);
  });

  app.post('/mfa/recovery', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = signedIn(c);
    if (!session) return c.redirect('/login', 303);
    const form = await c.req.raw.formData();
    const returnTo = safeReturnTo(stringField(form, 'return_to'));
    const stepUp = session.aal === 'aal2';
    const now = deps.now();
    if (!(await underRateLimit(c, 'mfa')) || (await lockedUntil(c.env.DB, session.user.id, now))) {
      return mfaHtml(await challengeHtml(c, session, returnTo, stepUp), 429);
    }

    const remaining = await useRecoveryCode(
      c.env.DB,
      c.env.MFA_ENCRYPTION_KEY,
      session.user.id,
      stringField(form, 'code') ?? '',
      now,
    );
    if (remaining === null) {
      const until = await failed(c, session, 'recovery_code');
      return mfaHtml(
        await challengeHtml(c, session, returnTo, stepUp, {
          lockedUntil: until,
          ...(until ? {} : { error: 'That recovery code didn’t work, or was already used.' }),
        }),
        until ? 429 : 400,
      );
    }
    await verified(c, session, 'recovery_code');
    await audit(c.env.DB, now, 'mfa.recovery_code_used', {
      actorUserId: session.user.id,
      ipPrefix: clientIp(c),
      detail: { remaining },
    });
    // Send the user to their codes when they are running out.
    return c.redirect(remaining <= 3 ? '/account/security' : returnTo, 303);
  });
}

function stringField(form: FormData, name: string): string | null {
  const value = form.get(name);
  return typeof value === 'string' ? value : null;
}
