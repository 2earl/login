import { createHash, randomBytes } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';

/**
 * One owner's whole journey, in a real browser, against the real app (e2e/worker/index.ts):
 * sign-in, passkey, sign-out, second step, admin, app consent and tokens, disconnect, export,
 * deletion. Google's sign-in page is intercepted; everything on login.2earl.com's side is real.
 */

const OWNER = { sub: 'e2e-owner-sub', email: 'ffrhtd@gmail.com', name: 'E2E Owner' };
const STRANGER = { sub: 'e2e-stranger', email: 'stranger@example.com', name: 'Stranger' };
const APP_REDIRECT = 'http://127.0.0.1:9/callback';
const RESOURCE = 'https://mcp.2earl.com/mcp';

const b64url = (data: Buffer | string) => Buffer.from(data).toString('base64url');

let googleIdentity = OWNER;

/** Who "Google" signs in as on the next trip there. */
function googleSignsInAs(identity: typeof OWNER): void {
  googleIdentity = identity;
}

/**
 * Stands in for Google's sign-in page. Playwright can't intercept a request the browser makes by
 * following a redirect, so the two app requests that redirect to Google (/login and the deletion
 * form) are fetched here as the browser would send them, and Google's answer is put in place of
 * the redirect: straight back to the callback with a code naming `googleIdentity`.
 */
async function interceptGoogle(page: Page): Promise<void> {
  await page.route(/^http:\/\/localhost:8788\/(login|account\/delete)(\?|$)/, async (route) => {
    const response = await route.fetch({
      maxRedirects: 0,
      headers: await route.request().allHeaders(),
    });
    const location = response.headers().location ?? '';
    if (!location.startsWith('https://accounts.google.com/')) {
      await route.fulfill({ response });
      return;
    }
    const auth = new URL(location);
    const code = b64url(
      JSON.stringify({
        ...googleIdentity,
        nonce: auth.searchParams.get('nonce'),
        codeChallenge: auth.searchParams.get('code_challenge'),
      }),
    );
    const back = new URL(auth.searchParams.get('redirect_uri') ?? '');
    back.searchParams.set('code', code);
    back.searchParams.set('state', auth.searchParams.get('state') ?? '');
    await route.fulfill({
      response,
      headers: { ...response.headers(), location: back.toString() },
    });
  });
}

/** Chromium's built-in virtual authenticator: a platform passkey that always says yes. */
async function addVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

test('the owner’s whole journey', async ({ page }) => {
  // No page may break its Content-Security-Policy, and no script may fail.
  const problems: string[] = [];
  page.on('console', (message) => {
    // HTTP error pages (the 403 for an uninvited account) are expected; script and CSP errors aren't.
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource')) {
      problems.push(message.text());
    }
  });
  page.on('pageerror', (error) => problems.push(error.message));
  await addVirtualAuthenticator(page);
  await interceptGoogle(page);

  await test.step('an uninvited Google account is turned away', async () => {
    googleSignsInAs(STRANGER);
    await page.goto('/');
    await page.getByRole('link', { name: 'Continue with Google' }).click();
    await expect(page.getByRole('heading', { level: 1 })).toContainText('can’t sign in yet');
  });

  await test.step('the owner signs in', async () => {
    googleSignsInAs(OWNER);
    await page.goto('/');
    await page.getByRole('link', { name: 'Continue with Google' }).click();
    await expect(page).toHaveURL('/account');
    await expect(page.getByText(OWNER.email).first()).toBeVisible();
    await expect(page.getByText('Second factor: off')).toBeVisible();
  });

  await test.step('adds a passkey and is shown recovery codes once', async () => {
    await page.getByRole('link', { name: 'Manage second factor' }).click();
    await page.getByLabel('Name (optional)').fill('Virtual key');
    await page.getByRole('button', { name: 'Add a passkey' }).click();
    await expect(page).toHaveURL('/account/security/recovery-codes');
    await expect(page.locator('.codes li')).toHaveCount(10);
    await page.getByRole('link', { name: 'I’ve saved them' }).click();
    await expect(page).toHaveURL('/account');
    await expect(page.getByText('Second factor: on, with 1 passkey')).toBeVisible();
    await page.goto('/account/security/recovery-codes');
    await expect(page).toHaveURL('/account/security'); // shown once
  });

  await test.step('signs out', async () => {
    await page.goto('/account');
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByRole('link', { name: 'Continue with Google' })).toBeVisible();
    // The session is gone on the server: /account now sends the browser to sign in.
    const account = await page.request.get('/account', { maxRedirects: 0 });
    expect(account.status()).toBe(303);
    expect(account.headers().location).toBe('/login?return_to=%2Faccount');
  });

  await test.step('signs in again and passes the second step with the passkey', async () => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Continue with Google' }).click();
    await expect(page).toHaveURL(/\/mfa\?return_to=/);
    await page.getByRole('button', { name: 'Use a passkey' }).click();
    await expect(page).toHaveURL('/account');
  });

  let clientId = '';
  await test.step('registers an app in the admin area', async () => {
    await page.goto('/admin/apps');
    await page.getByLabel('App name').fill('E2E client');
    await page.getByLabel(/Redirect URIs/).fill(APP_REDIRECT);
    await page.getByRole('button', { name: 'Register app' }).click();
    const notice = await page.getByRole('status').innerText();
    clientId = /client ID is (\S+)\./.exec(notice)?.[1] ?? '';
    expect(clientId).not.toBe('');
  });

  let tokens: { access_token: string; refresh_token: string } = {
    access_token: '',
    refresh_token: '',
  };
  await test.step('connects the app through the consent page', async () => {
    const verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const authorize = new URL('/authorize', 'http://localhost:8788');
    authorize.search = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: APP_REDIRECT,
      scope: 'mcp:tools.read mcp:tools.invoke',
      state: 'app-state',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: RESOURCE,
    }).toString();

    // Allow answers with a redirect to the app; the redirect is read here, where the app would.
    const captured: { url: URL | null } = { url: null };
    await page.route('http://localhost:8788/authorize', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.continue();
        return;
      }
      const response = await route.fetch({
        maxRedirects: 0,
        headers: await route.request().allHeaders(),
      });
      captured.url = new URL(response.headers().location ?? 'about:blank');
      await route.fulfill({
        status: 200,
        contentType: 'text/plain',
        body: 'app received the code',
      });
    });
    await page.goto(authorize.toString());
    await expect(page.getByRole('heading', { level: 1 })).toContainText('E2E client');
    await page.getByRole('button', { name: 'Allow' }).click();
    await expect(page.getByText('app received the code')).toBeVisible();
    const back = captured.url;
    expect(`${back?.origin ?? ''}${back?.pathname ?? ''}`).toBe(APP_REDIRECT);

    expect(back?.searchParams.get('state')).toBe('app-state');
    expect(back?.searchParams.get('iss')).toBe('http://localhost:8788');
    const response = await page.request.post('/oauth/token', {
      form: {
        grant_type: 'authorization_code',
        code: back?.searchParams.get('code') ?? '',
        redirect_uri: APP_REDIRECT,
        client_id: clientId,
        code_verifier: verifier,
        resource: RESOURCE,
      },
    });
    expect(response.status()).toBe(200);
    tokens = (await response.json()) as typeof tokens;
    expect(tokens.access_token).toBeTruthy();
  });

  await test.step('downloads a copy of the account data', async () => {
    await page.goto('/account');
    const download = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download your data' }).click();
    const file = await download;
    expect(file.suggestedFilename()).toMatch(/^2earl-account-\d{4}-\d{2}-\d{2}\.json$/);
    const stream = await file.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      account: { email: string };
      connectedApps: { name: string }[];
    };
    expect(data.account.email).toBe(OWNER.email);
    expect(data.connectedApps.map((a) => a.name)).toEqual(['E2E client']);
  });

  await test.step('disconnects the app, which can no longer refresh', async () => {
    await page.goto('/account');
    await page.getByRole('button', { name: /Disconnect/ }).click();
    await expect(page.getByText('E2E client')).toHaveCount(0);
    const refresh = await page.request.post('/oauth/token', {
      form: {
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_id: clientId,
      },
    });
    expect(refresh.status()).toBe(400);
  });

  await test.step('deletes the account after confirming with Google', async () => {
    await page.goto('/account');
    await page.getByRole('link', { name: 'Delete account' }).click();
    await page.getByLabel(/can’t be restored/).check();
    await page.getByRole('button', { name: 'Confirm with Google' }).click();
    await expect(page).toHaveURL('/account/deleted');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Your account is deleted');
    // The invitation went with it: signing in again is refused.
    await page.goto('/');
    await page.getByRole('link', { name: 'Continue with Google' }).click();
    await expect(page.getByRole('heading', { level: 1 })).toContainText('can’t sign in yet');
  });

  expect(problems).toEqual([]);
});
