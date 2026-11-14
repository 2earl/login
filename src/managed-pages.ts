import type { PendingChoice } from './managed';
import { escapeHtml, page } from './pages';

/** The choice an account at a newly managed domain makes (DESIGN §4.18). Every value is escaped. */
export function managedChoicePage(params: {
  choice: PendingChoice;
  returnTo: string | null;
  error?: string;
}): string {
  const { choice } = params;
  const org = escapeHtml(choice.orgName);
  const list = choice.addresses.map((a) => `<strong>${escapeHtml(a)}</strong>`).join(', ');
  const fields = (value: string) =>
    `<input type="hidden" name="org" value="${escapeHtml(choice.orgId)}">` +
    `<input type="hidden" name="choice" value="${value}">` +
    (params.returnTo
      ? `<input type="hidden" name="return_to" value="${escapeHtml(params.returnTo)}">`
      : '');
  return page(
    'Your account and your organization',
    `<h1>“${org}” manages accounts at your address’s domain</h1>` +
      `<p class="lede">Your account signs in with ${list || 'an address at that domain'}. “${org}” proved it controls that domain. Choose what happens to your account.</p>` +
      (params.error ? `<p class="warning" role="alert">${escapeHtml(params.error)}</p>` : '') +
      (choice.canJoin
        ? '<section class="section choice" aria-labelledby="join-heading">' +
          '<h2 id="join-heading">Let the organization manage it</h2>' +
          '<ul class="plain-list">' +
          `<li>You become a member of “${org}”, which sees your name and address.</li>` +
          '<li>It can require you to sign in through its single sign-on.</li>' +
          '<li>It can deactivate or delete this account.</li>' +
          '<li>You can’t remove that address, leave the organization or delete the account yourself. You can still download your data.</li>' +
          '</ul>' +
          '<form method="post" action="/account/managed">' +
          fields('join') +
          '<button class="button primary" type="submit">Let it manage my account</button></form>' +
          '</section>'
        : '<p class="section-text">Another organization already manages your account, so this address can only be removed from it.</p>') +
      '<section class="section choice" aria-labelledby="keep-heading">' +
      `<h2 id="keep-heading">${choice.canJoin ? 'Keep it your own' : 'Remove the address'}</h2>` +
      `<p class="section-text">We remove ${list || 'the address'} from your account. Everything else stays, and you sign in another way.</p>` +
      (choice.hasOtherWay
        ? '<form method="post" action="/account/managed">' +
          fields('personal') +
          `<button class="button secondary" type="submit">${choice.canJoin ? 'Keep it my own' : 'Remove the address'}</button></form>`
        : '<p class="note">That address is your only way to sign in. Add another one first: a different email address, or a Google account.</p>' +
          '<div class="data-actions">' +
          '<a class="button secondary" href="/account/methods/email">Add an email address</a>' +
          '<form method="post" action="/account/methods/google"><button class="button secondary" type="submit">Add Google</button></form>' +
          '</div>') +
      '</section>' +
      '<p class="fine">Until you choose, your account works only for this. You can also <a href="/account/export">download your data</a> or <a href="/account/delete">delete your account</a>.</p>',
  );
}
