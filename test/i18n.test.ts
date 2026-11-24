import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { collectMissing, fromPreferences, localizeHtml, pickLocale } from '../src/i18n';
import { codeMail, sendMail } from '../src/mail';
import { setOAuthClock } from '../src/oauth';
import { FakeGoogle, NOW, call, freshIp, resetDatabase, signIn, testJwks } from './helpers';

/** DESIGN §4.31: languages. */

interface Sent {
  to: string;
  subject: string;
  text: string;
  html: string;
}

let google: FakeGoogle;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  setOAuthClock(() => NOW);
  await resetDatabase();
  google = new FakeGoogle();
  app = createApp({
    fetch: (input, init) => google.fetch(input, init),
    googleJwks: testJwks,
    now: () => NOW,
  });
});

describe('choosing the language', () => {
  it('reads Accept-Language and ui_locales by preference', () => {
    expect(fromPreferences('de-DE,tr;q=0.8,en;q=0.5')).toBe('tr');
    expect(fromPreferences('en-GB,tr;q=0.9')).toBe('en');
    expect(fromPreferences('tr-TR')).toBe('tr');
    expect(fromPreferences('fr, de')).toBeNull();
    expect(fromPreferences('tr en')).toBe('tr');
  });

  it('prefers an explicit choice, then the cookie, the account, the browser', () => {
    expect(pickLocale({ query: 'en', acceptLanguage: 'tr' })).toBe('en');
    expect(pickLocale({ uiLocales: 'tr', cookie: 'en' })).toBe('tr');
    expect(pickLocale({ cookie: 'tr', account: 'en', acceptLanguage: 'en' })).toBe('tr');
    expect(pickLocale({ account: 'tr', acceptLanguage: 'en' })).toBe('tr');
    expect(pickLocale({ acceptLanguage: 'tr-TR,tr;q=0.9' })).toBe('tr');
    expect(pickLocale({ query: 'xx', acceptLanguage: 'fr' })).toBe('en');
  });

  it('serves the sign-in page in Turkish to a Turkish browser', async () => {
    const response = await call(app, '/login', { headers: { 'Accept-Language': 'tr-TR,tr' } });
    const html = await response.text();
    expect(response.headers.get('Content-Language')).toBe('tr');
    expect(html).toContain('<html lang="tr">');
    expect(html).toContain('Google ile devam et');
    expect(html).toContain('href="https://2earl.com/tr/privacy"');
    // The switcher names every language in its own words, and keeps the page's address.
    expect(html).toContain('lang="en" translate="no" hreflang="en">English</a>');
    expect(html).toContain('aria-current="true">Türkçe</a>');
  });

  it('remembers ?lang= in a cookie', async () => {
    const chosen = await call(app, '/login?lang=tr');
    const cookie = chosen.headers.get('Set-Cookie') ?? '';
    expect(cookie).toContain('__Host-lang=tr');
    expect(cookie).toContain('Secure');
    const later = await call(app, '/login', { cookies: { '__Host-lang': 'tr' } });
    expect(await later.text()).toContain('Google ile devam et');
    const english = await call(app, '/login?lang=en', { headers: { 'Accept-Language': 'tr' } });
    expect(await english.text()).toContain('Continue with Google');
  });

  it('saves the language on the account, for its emails', async () => {
    const { session } = await signIn(app, google);
    await call(app, '/account?lang=tr', {
      cookies: { '__Host-session': session ?? '' },
      ip: freshIp(),
    });
    const row = await env.DB.prepare('SELECT locale FROM users').first<{ locale: string }>();
    expect(row?.locale).toBe('tr');
  });
});

describe('translating', () => {
  it('moves inline elements with the words, and keeps what isn’t to be translated', () => {
    const html =
      '<!doctype html><html lang="en"><head><title>Delete account · 2earl</title></head><body>' +
      '<p>By continuing, you agree to the <a href="https://2earl.com/terms">Terms of service</a> and acknowledge the <a href="https://2earl.com/privacy">Privacy policy</a>.</p>' +
      '<input placeholder="Email address"><span translate="no">Delete</span>' +
      '<p>Reference: <code>Delete</code></p></body></html>';
    const out = localizeHtml(html, 'tr');
    expect(out).toContain('<html lang="tr">');
    expect(out).toContain('<title>Hesabı sil · 2earl</title>');
    expect(out).toContain(
      '<p>Devam ederek <a href="https://2earl.com/tr/terms">Kullanım koşullarını</a> kabul etmiş ve <a href="https://2earl.com/tr/privacy">Gizlilik politikasını</a> okumuş olursunuz.</p>',
    );
    expect(out).toContain('placeholder="E-posta adresi"');
    expect(out).toContain('<span translate="no">Delete</span>');
    expect(out).toContain('<p>Referans: <code>Delete</code></p>');
  });

  it('fills placeholders and translates month names', () => {
    const out = localizeHtml('<p>Joined 9 November 2025</p><p>Ada <span>Owner</span></p>', 'tr');
    expect(out).toContain('<p>9 Kasım 2025 tarihinde katıldı</p>');
    expect(out).toContain('<p>Ada <span>Sahip</span></p>');
  });

  it('sends emails in the recipient’s language', async () => {
    const sent: Sent[] = [];
    const mailer = {
      send: (m: Sent) => {
        sent.push(m);
        return Promise.resolve({ messageId: 'm' });
      },
    };
    const mailEnv = { ...env, MAILER: mailer } as unknown as Env;
    await sendMail(
      mailEnv,
      'someone@example.org',
      codeMail('sign_in', '123456', 'https://login.2earl.com/login/email/x'),
      'tr',
    );
    expect(sent[0]?.subject).toBe('2earl kodunuz: 123456');
    expect(sent[0]?.text).toContain('2earl’e giriş yapmak ya da hesabınızı oluşturmak için');
    expect(sent[0]?.html).toContain('<html lang="tr">');
    expect(sent[0]?.html).toContain('https://2earl.com/tr/privacy');
  });
});

describe('coverage', () => {
  it('has every sentence of the pages people use most', async () => {
    const missing = collectMissing();
    const { session } = await signIn(app, google);
    const cookies = { '__Host-session': session ?? '', '__Host-lang': 'tr' };
    for (const path of [
      '/account',
      '/account/security',
      '/account/sessions',
      '/account/apps',
      '/account/orgs',
      '/account/data',
      '/account/delete',
    ]) {
      const response = await call(app, path, { cookies, ip: freshIp() });
      expect(response.status, path).toBeLessThan(400);
    }
    for (const path of ['/login', '/login/sso', '/device', '/not-a-page']) {
      await call(app, path, { cookies: { '__Host-lang': 'tr' }, ip: freshIp() });
    }
    // Names from the test data are the person's own words, not ours.
    const ours = [...missing].filter((m) => !/^(Owner Example)$/.test(m));
    expect(ours).toEqual([]);
  });
});
