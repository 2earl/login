import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { SEND_LIMITS, maskEmail, newCode } from '../src/email-codes';
import { codeMail, mailHtml, noticeMail } from '../src/mail';
import { setOAuthClock } from '../src/oauth';
import {
  FakeGoogle,
  NOW,
  ORIGIN,
  OWNER_EMAIL,
  call,
  count,
  freshIp,
  makeApp,
  resetDatabase,
  setCookies,
  signIdToken,
  signIn,
} from './helpers';

const FORM = {
  'Content-Type': 'application/x-www-form-urlencoded',
  Origin: ORIGIN,
  'Sec-Fetch-Site': 'same-origin',
};

interface Sent {
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
}

let google: FakeGoogle;
let now: number;
let ip: string;
let app: ReturnType<typeof makeApp>;
let sent: Sent[];
let mailFails: boolean;

/** A stand-in for Cloudflare Email Service that keeps what was sent. */
const mailer = {
  send: (message: Sent) => {
    if (mailFails) return Promise.reject(Object.assign(new Error('x'), { code: 'E_INTERNAL' }));
    sent.push(message);
    return Promise.resolve({ messageId: 'm' });
  },
};

const vars = (extra: Record<string, unknown> = {}) => ({ MAILER: mailer, ...extra });
const open = { LOGIN_LOCKED: 'false' };

async function post(
  path: string,
  body: Record<string, string>,
  cookies: Record<string, string> = {},
  extra: Record<string, unknown> = {},
) {
  return call(app, path, {
    method: 'POST',
    headers: FORM,
    body: new URLSearchParams(body),
    cookies,
    ip,
    vars: vars(extra),
  });
}

const lastCode = () => /^\s+(\d{6})$/m.exec(sent.at(-1)?.text ?? '')?.[1] ?? '';
const lastLink = () => /token=([A-Za-z0-9_-]+)/.exec(sent.at(-1)?.text ?? '')?.[1] ?? '';

/** Asks for a code; returns the browser's code cookie. */
async function askCode(email: string, extra: Record<string, unknown> = open, cookies = {}) {
  const response = await post('/login/email', { email }, cookies, extra);
  return { response, cookie: setCookies(response)['__Host-email_code'] ?? '' };
}

async function typeCode(
  cookie: string,
  code: string,
  extra: Record<string, unknown> = open,
  session?: string,
) {
  return post(
    '/login/email/code',
    { code },
    { '__Host-email_code': cookie, ...(session ? { '__Host-session': session } : {}) },
    extra,
  );
}

/** Signs up or in with email; returns the session cookie. */
async function emailSignIn(email: string, extra: Record<string, unknown> = open) {
  const { cookie } = await askCode(email, extra);
  const response = await typeCode(cookie, lastCode(), extra);
  return { response, session: setCookies(response)['__Host-session'] ?? '' };
}

beforeEach(async () => {
  now = NOW;
  ip = freshIp();
  setOAuthClock(() => now);
  await resetDatabase();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM email_codes'),
    env.DB.prepare('DELETE FROM settings'),
  ]);
  google = new FakeGoogle();
  app = makeApp(google, () => now);
  sent = [];
  mailFails = false;
});

describe('signing up and in with an email code', () => {
  it('creates an account from a code, and signs in with the next one', async () => {
    const page = await (await call(app, '/login', { vars: vars(open) })).text();
    expect(page).toContain('Continue with Google');
    expect(page).toContain('action="/login/email"');

    const { response, cookie } = await askCode('New@Example.com ');
    expect(response.headers.get('Location')).toBe('/login/email/code');
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe('new@example.com');
    expect(sent[0]?.subject).toBe(`${lastCode()} is your 2earl code`);
    const codePage = await (
      await call(app, '/login/email/code', {
        cookies: { '__Host-email_code': cookie },
        vars: vars(),
      })
    ).text();
    expect(codePage).toContain('<strong>new@example.com</strong>');

    const done = await typeCode(cookie, lastCode());
    expect(done.headers.get('Location')).toBe('/welcome?return_to=%2Faccount');
    expect(setCookies(done)['__Host-session']).toBeTruthy();
    expect(setCookies(done)['__Host-email_code']).toBe('');
    expect(await count('identities', "provider = 'email' AND subject = 'new@example.com'")).toBe(1);

    // Signing in again: the same account, straight to where it was going.
    const again = await emailSignIn('new@example.com');
    expect(again.response.headers.get('Location')).toBe('/account');
    expect(await count('users')).toBe(1);
  });

  it('answers the same for an address with and without an account', async () => {
    await emailSignIn('known@example.com');
    const known = await askCode('known@example.com');
    const unknown = await askCode('unknown@example.com');
    expect(known.response.status).toBe(unknown.response.status);
    expect(known.response.headers.get('Location')).toBe(unknown.response.headers.get('Location'));
    expect(sent.at(-1)?.subject).toBe(sent.at(-2)?.subject.replace(/^\d{6}/, lastCode()));
  });

  it('allows five wrong tries, then the code stops working', async () => {
    const { cookie } = await askCode('a@example.com');
    const right = lastCode();
    const wrong = right === '000000' ? '111111' : '000000';
    const first = await typeCode(cookie, wrong);
    expect(first.status).toBe(400);
    expect(await first.text()).toContain('4 tries left');
    for (let i = 0; i < 4; i++) await typeCode(cookie, wrong);
    const late = await typeCode(cookie, right);
    expect(await late.text()).toContain('That code no longer works');
    expect(await count('users')).toBe(0);
  });

  it('works once, for 10 minutes, and only in the browser that asked', async () => {
    const { cookie } = await askCode('a@example.com');
    const code = lastCode();
    const elsewhere = await askCode('b@example.com');
    expect(await (await typeCode(elsewhere.cookie, code)).text()).toContain(
      'That code isn’t right',
    );

    now += 11 * 60;
    expect(await (await typeCode(cookie, code)).text()).toContain('That code no longer works');

    now = NOW;
    const fresh = await askCode('c@example.com');
    const used = lastCode();
    expect((await typeCode(fresh.cookie, used)).status).toBe(303);
    expect(await (await typeCode(fresh.cookie, used)).text()).toContain('no longer works');
  });

  it('stores neither the code nor the link, only their HMACs', async () => {
    const { cookie } = await askCode('a@example.com');
    const row = await env.DB.prepare('SELECT * FROM email_codes').first<Record<string, string>>();
    expect(JSON.stringify(row)).not.toContain(lastCode());
    expect(JSON.stringify(row)).not.toContain(lastLink());
    expect(JSON.stringify(row)).not.toContain(cookie);
  });

  it('signs in from the link after a button, and only in the same browser', async () => {
    const { cookie } = await askCode('link@example.com');
    const token = lastLink();
    const opened = await call(app, `/login/email/link?token=${token}`, {
      cookies: { '__Host-email_code': cookie },
      vars: vars(open),
    });
    // Opening it (as mail scanners do) changes nothing.
    expect(opened.status).toBe(200);
    expect(await opened.text()).toContain('action="/login/email/link"');
    expect(await count('users')).toBe(0);

    const otherBrowser = await call(app, `/login/email/link?token=${token}`, { vars: vars(open) });
    expect(await otherBrowser.text()).toContain('Open the link where you asked for it');

    const done = await post('/login/email/link', { token }, { '__Host-email_code': cookie }, open);
    expect(done.headers.get('Location')).toBe('/welcome?return_to=%2Faccount');
    expect(await count('users')).toBe(1);
  });

  it('limits codes per address, so the form can’t flood an inbox', async () => {
    for (let i = 0; i < SEND_LIMITS.perAddressPerHour; i++) {
      expect((await askCode('target@example.com')).response.status).toBe(303);
    }
    const refused = await askCode('target@example.com');
    expect(refused.response.status).toBe(429);
    expect(await refused.response.text()).toContain('Too many codes for now');
    expect(sent).toHaveLength(SEND_LIMITS.perAddressPerHour);
    expect(await count('audit_events', "event = 'login.code_refused'")).toBe(1);
    now += 3601;
    expect((await askCode('target@example.com')).response.status).toBe(303);
  });

  it('says so when the email can’t be sent, and keeps no code', async () => {
    mailFails = true;
    const { response } = await askCode('a@example.com');
    expect(response.status).toBe(502);
    expect(await count('email_codes')).toBe(0);
  });

  it('refuses an address that isn’t one, keeping what was typed', async () => {
    const response = await post('/login/email', { email: 'nope' }, {}, open);
    expect(response.status).toBe(400);
    const html = await response.text();
    expect(html).toContain('Enter an email address like name@example.com.');
    expect(html).toContain('value="nope"');
  });

  it('asks for an invitation while sign-up is closed', async () => {
    const closed = { LOGIN_LOCKED: 'true' };
    const stranger = await emailSignIn('stranger@example.com', closed);
    expect(stranger.response.status).toBe(403);
    expect(await count('users')).toBe(0);
    // The owner's invitation (resetDatabase) is an address: it can sign up with email.
    const invited = await emailSignIn(OWNER_EMAIL, closed);
    expect(invited.response.headers.get('Location')).toBe('/welcome?return_to=%2Faccount');
  });
});

describe('one account per address', () => {
  it('sends someone whose address signs in with Google to Google', async () => {
    await signIn(app, google); // the owner, with Google
    const attempt = await emailSignIn(OWNER_EMAIL);
    expect(attempt.response.status).toBe(409);
    expect(await attempt.response.text()).toContain('Continue with Google');
    expect(await count('identities', "provider = 'email'")).toBe(0);
  });

  it('sends someone whose address signs in with email to email', async () => {
    await emailSignIn('mail@example.com');
    const result = await signIn(app, google, {
      claims: { sub: 'google-sub-mail', email: 'mail@example.com', name: 'M' },
    });
    expect(result.callback.status).toBe(409);
    expect(await count('identities', "provider = 'google'")).toBe(0);
  });
});

describe('sign-in methods on the account page', () => {
  it('adds an address to a Google account after a code, and tells the account', async () => {
    const { session } = await signIn(app, google);
    const cookies = { '__Host-session': session ?? '' };
    const asked = await post('/account/methods/email', { email: 'second@example.com' }, cookies);
    expect(asked.headers.get('Location')).toBe('/login/email/code');
    expect(sent.at(-1)?.to).toBe('second@example.com');
    const code = setCookies(asked)['__Host-email_code'] ?? '';
    const done = await typeCode(code, lastCode(), {}, session);
    expect(done.headers.get('Location')).toBe('/account?added=email');
    expect(await count('identities', "provider = 'email' AND subject = 'second@example.com'")).toBe(
      1,
    );
    // The notice goes to the account's address, the Google one.
    expect(sent.at(-1)?.to).toBe(OWNER_EMAIL);
    expect(sent.at(-1)?.subject).toBe('A sign-in method was added to your 2earl account');

    const page = await (await call(app, '/account/security', { cookies, vars: vars() })).text();
    expect(page).toContain('Email code');
    expect(page).toContain('second@example.com');
  });

  it('adds Google to an email account, unless its address is another account’s', async () => {
    const linkGoogle = async (session: string, claims: Record<string, string>) => {
      const cookies = { '__Host-session': session };
      const start = await post('/account/methods/google', {}, cookies);
      const location = new URL(start.headers.get('Location') ?? 'about:blank');
      google.nextIdToken = await signIdToken({
        nonce: location.searchParams.get('nonce') ?? '',
        ...claims,
      });
      const state = encodeURIComponent(location.searchParams.get('state') ?? '');
      return call(app, `/callback/google?code=auth-code&state=${state}`, {
        ip,
        cookies: { ...cookies, '__Host-login_tx': setCookies(start)['__Host-login_tx'] ?? '' },
        vars: vars(),
      });
    };

    await emailSignIn('taken@example.com');
    const { session } = await emailSignIn('mine@example.com');
    const refused = await linkGoogle(session, { sub: 'g-taken', email: 'taken@example.com' });
    expect(refused.status).toBe(409);
    expect(await count('identities', "provider = 'google'")).toBe(0);

    const added = await linkGoogle(session, { sub: 'g-mine', email: 'mine.g@example.com' });
    expect(added.headers.get('Location')).toBe('/account?added=google');
    expect(await count('identities', "provider = 'google' AND subject = 'g-mine'")).toBe(1);
  });

  it('never removes the last method, nor the owner’s Google account', async () => {
    const { session } = await emailSignIn('solo@example.com');
    const cookies = { '__Host-session': session };
    const only = await env.DB.prepare('SELECT id FROM identities').first<{ id: string }>();
    await post('/account/methods/remove', { identity: only?.id ?? '' }, cookies);
    expect(await count('identities')).toBe(1);

    const owner = (await signIn(app, google)).session ?? '';
    const ownerCookies = { '__Host-session': owner };
    const asked = await post('/account/methods/email', { email: 'o2@example.com' }, ownerCookies);
    await typeCode(setCookies(asked)['__Host-email_code'] ?? '', lastCode(), {}, owner);
    const googleRow = await env.DB.prepare(
      "SELECT id FROM identities WHERE provider = 'google'",
    ).first<{ id: string }>();
    await post('/account/methods/remove', { identity: googleRow?.id ?? '' }, ownerCookies);
    expect(await count('identities', "provider = 'google'")).toBe(1);
  });

  it('removes a method and moves the account’s address to the one left', async () => {
    const { session } = await emailSignIn('first@example.com');
    const cookies = { '__Host-session': session };
    const asked = await post('/account/methods/email', { email: 'second@example.com' }, cookies);
    await typeCode(setCookies(asked)['__Host-email_code'] ?? '', lastCode(), {}, session);
    const first = await env.DB.prepare(
      "SELECT id FROM identities WHERE subject = 'first@example.com'",
    ).first<{ id: string }>();
    const removed = await post('/account/methods/remove', { identity: first?.id ?? '' }, cookies);
    expect(removed.headers.get('Location')).toBe('/account?removed=1');
    const user = await env.DB.prepare('SELECT primary_email FROM users').first<{
      primary_email: string;
    }>();
    expect(user?.primary_email).toBe('second@example.com');
  });

  it('needs a recent sign-in to change methods', async () => {
    const { session } = await emailSignIn('late@example.com');
    now += 11 * 60;
    const response = await post(
      '/account/methods/email',
      { email: 'x@example.com' },
      { '__Host-session': session },
    );
    expect(response.headers.get('Location')).toBe(
      '/login?reauth=1&return_to=%2Faccount%2Fmethods%2Femail',
    );
    const reauth = await (
      await call(app, '/login?reauth=1&return_to=%2Faccount', {
        cookies: { '__Host-session': session },
        vars: vars(open),
      })
    ).text();
    expect(reauth).toContain('We’ll send a code to <strong>late@example.com</strong>');
    expect(reauth).not.toContain('Continue with Google');
  });

  it('keeps a name the user chose when Google signs in again', async () => {
    const { session } = await signIn(app, google);
    await post('/account/name', { name: '  Ferhat   D. ' }, { '__Host-session': session ?? '' });
    await signIn(app, google);
    const user = await env.DB.prepare('SELECT display_name FROM users').first<{
      display_name: string;
    }>();
    expect(user?.display_name).toBe('Ferhat D.');
  });
});

describe('welcome, and deleting an account that signs in with email', () => {
  it('saves a name on the welcome page and goes on', async () => {
    const { session } = await emailSignIn('w@example.com');
    const cookies = { '__Host-session': session };
    const page = await (
      await call(app, '/welcome?return_to=%2Faccount', { cookies, vars: vars() })
    ).text();
    expect(page).toContain('Your account is ready');
    expect(page).toContain('href="/account/security"');
    const saved = await post('/welcome', { name: 'Wil', return_to: '/account' }, cookies);
    expect(saved.headers.get('Location')).toBe('/account');
    expect(
      (await env.DB.prepare('SELECT display_name FROM users').first<{ display_name: string }>())
        ?.display_name,
    ).toBe('Wil');
  });

  it('deletes after a code sent to the account’s address, and says goodbye', async () => {
    const { session } = await emailSignIn('bye@example.com');
    const cookies = { '__Host-session': session };
    const page = await (await call(app, '/account/delete', { cookies, vars: vars() })).text();
    expect(page).toContain('Confirm with an email code');
    expect(page).not.toContain('Confirm with Google');

    const asked = await post('/account/delete', { confirm: 'on', method: 'email' }, cookies);
    expect(asked.headers.get('Location')).toBe('/login/email/code');
    expect(sent.at(-1)?.subject).toBe(`${lastCode()} confirms deleting your 2earl account`);
    const code = setCookies(asked)['__Host-email_code'] ?? '';
    const deleted = await typeCode(code, lastCode(), {}, session);
    expect(deleted.headers.get('Location')).toBe('/account/deleted');
    expect(await count('users')).toBe(0);
    expect(await count('email_codes')).toBe(0);
    expect(sent.at(-1)?.subject).toBe('Your 2earl account was deleted');
  });

  it('won’t delete with a code from another browser session', async () => {
    const { session } = await emailSignIn('keep@example.com');
    const asked = await post('/account/delete', { confirm: 'on' }, { '__Host-session': session });
    const code = setCookies(asked)['__Host-email_code'] ?? '';
    const response = await typeCode(code, lastCode(), {});
    expect(response.status).toBe(400);
    expect(await count('users')).toBe(1);
  });
});

describe('emails', () => {
  it('carry a plain and a matching HTML part, and replies reach a person', async () => {
    await askCode('parts@example.com');
    const mail = sent.at(-1);
    expect(mail?.replyTo).toBe('legal@2earl.com');
    expect(mail?.html).toContain(`>${lastCode()}</p>`);
    expect(mail?.html).toContain('<a href="https://login.2earl.com/login/email/link?token=');
    expect(mail?.html).not.toMatch(/<img|<script|https?:\/\/(?!([a-z0-9-]+\.)*2earl\.com)/);
  });

  it('escape what an app calls itself, and link only our own addresses', () => {
    const notice = noticeMail({ kind: 'app_connected', app: '<b>Evil</b> https://evil.example' });
    const html = mailHtml(notice.lines);
    expect(html).toContain('&lt;b&gt;Evil&lt;/b&gt;');
    expect(html).not.toContain('href="https://evil.example');
    expect(mailHtml(codeMail('sign_in', '123456', 'https://login.2earl.com/x').lines)).toContain(
      'letter-spacing:4px;margin:8px 0 16px">123456</p>',
    );
  });
});

describe('codes', () => {
  it('are six digits and look random', () => {
    const codes = new Set(Array.from({ length: 200 }, () => newCode()));
    for (const code of codes) expect(code).toMatch(/^\d{6}$/);
    expect(codes.size).toBeGreaterThan(190);
  });

  it('mask an address for the screen', () => {
    expect(maskEmail('ferhat@example.com')).toBe('fe•••@example.com');
    expect(maskEmail('a@b.co')).toBe('•••@b.co');
  });
});
