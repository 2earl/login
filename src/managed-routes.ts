import type { Hono } from 'hono';
import type { Deps } from './app';
import { isSameOrigin, type AppEnv } from './http';
import { joinManaged, keepPersonal, pendingChoice } from './managed';
import { managedChoicePage } from './managed-pages';
import { changeCheck } from './mfa-routes';
import { safeReturnTo } from './return-to';
import { notifyLater } from './sign-in';

/**
 * The person's side of managed accounts (DESIGN §4.18): an organization now manages a domain
 * where the account has an address, and the person chooses before going on.
 */
export function registerManagedRoutes(app: Hono<AppEnv>, deps: Deps): void {
  app.get('/account/managed', async (c) => {
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fmanaged', 303);
    const returnTo = c.req.query('return_to') ?? null;
    const choice = await pendingChoice(c.env.DB, session.user.id);
    if (!choice) return c.redirect(safeReturnTo(returnTo), 303);
    return c.html(managedChoicePage({ choice, returnTo }));
  });

  app.post('/account/managed', async (c) => {
    if (!isSameOrigin(c)) return c.json({ error: 'forbidden' }, 403);
    const session = c.get('session');
    if (!session) return c.redirect('/login?return_to=%2Faccount%2Fmanaged', 303);
    const form = await c.req.raw.formData();
    const orgId = form.get('org');
    const choice = form.get('choice');
    const raw = form.get('return_to');
    const returnTo = typeof raw === 'string' ? raw : null;
    const here = `/account/managed${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`;
    if (typeof orgId !== 'string') return c.redirect(here, 303);
    const now = deps.now();
    const again = async (error: string) => {
      const pending = await pendingChoice(c.env.DB, session.user.id);
      return pending
        ? c.html(managedChoicePage({ choice: pending, returnTo, error }), 409)
        : c.redirect(safeReturnTo(returnTo), 303);
    };

    if (choice === 'join') {
      const result = await joinManaged(c.env.DB, now, session.user.id, orgId);
      if (result === 'too_many')
        return again('You’re in 50 organizations, the most an account can be in. Leave one first.');
      // Another organization may still be waiting for an answer; the gate shows it next.
      return c.redirect(safeReturnTo(returnTo), 303);
    }
    if (choice === 'personal') {
      // Taking sign-in methods off the account: a recent proof it's you, as for any method.
      const redirect = changeCheck(session, now, here);
      if (redirect) return c.redirect(redirect, 303);
      const pending = await pendingChoice(c.env.DB, session.user.id);
      const result = await keepPersonal(c.env.DB, now, session.user.id, orgId);
      if (result === 'no_other_way')
        return again('Add another way to sign in first, then remove the address.');
      if (result === 'kept' && pending) {
        notifyLater(c, session.user.id, {
          kind: 'method_removed',
          method: `sign-in with ${pending.addresses.join(', ')}`,
        });
      }
      return c.redirect(safeReturnTo(returnTo), 303);
    }
    return c.redirect(here, 303);
  });
}
