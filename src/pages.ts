/** Server-rendered HTML. Every dynamic value goes through `escapeHtml`. No scripts. */

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const LEGAL_FOOTER =
  '<footer><a href="https://2earl.com/privacy">Privacy</a> · ' +
  '<a href="https://2earl.com/terms">Terms</a> · ' +
  '<a href="https://2earl.com/imprint">Imprint</a></footer>';

export function page(title: string, body: string): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    `<title>${escapeHtml(title)} · 2earl</title>` +
    '<link rel="stylesheet" href="/app.css"></head><body><main>' +
    '<p class="brand"><a href="/">2earl</a></p>' +
    body +
    '</main>' +
    LEGAL_FOOTER +
    '</body></html>'
  );
}

export function homePage(signedInEmail: string | null): string {
  if (signedInEmail) {
    return page(
      'Account',
      '<h1>2earl account</h1>' +
        `<p>Signed in as <strong>${escapeHtml(signedInEmail)}</strong>.</p>` +
        '<p><a class="button" href="/account">Go to your account</a></p>',
    );
  }
  return page(
    'Sign in',
    '<h1>2earl account</h1>' +
      '<p>Sign in to manage your account and the apps that may act for you.</p>' +
      '<p><a class="button" href="/login">Sign in with Google</a></p>' +
      '<p class="muted">The service is not open to the public yet.</p>',
  );
}

export function accountPage(params: {
  email: string | null;
  name: string | null;
  memberSince: number;
}): string {
  const since = new Date(params.memberSince * 1000).toISOString().slice(0, 10);
  return page(
    'Your account',
    '<h1>Your account</h1>' +
      '<dl>' +
      (params.name ? `<dt>Name</dt><dd>${escapeHtml(params.name)}</dd>` : '') +
      `<dt>Email</dt><dd>${escapeHtml(params.email ?? '')}</dd>` +
      `<dt>Member since</dt><dd>${since}</dd>` +
      '</dl>' +
      '<form method="post" action="/logout"><button type="submit">Sign out</button></form>',
  );
}

export function messagePage(title: string, message: string, retry = true): string {
  return page(
    title,
    `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>` +
      (retry ? '<p><a class="button" href="/login">Try again</a></p>' : ''),
  );
}

export const APP_CSS = `
:root{--bg:#fbfaf8;--fg:#1d1c1a;--muted:#5f5b55;--rule:#e4e0da;--link:#1f4fbf;--btn:#1d1c1a;--btn-fg:#fbfaf8;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#151514;--fg:#ecebe8;--muted:#a8a49d;--rule:#2e2d2a;--link:#8fb0ff;--btn:#ecebe8;--btn-fg:#151514}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:1.0625rem/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main,footer{max-width:32rem;margin:0 auto;padding:2.5rem 1rem 1rem}
footer{padding-top:0;color:var(--muted);font-size:.9rem}
footer a{color:var(--muted)}
.brand a{font-weight:700;font-size:1.2rem;color:var(--fg);text-decoration:none}
h1{font-size:1.7rem;line-height:1.2;margin:1.5rem 0 1rem}
a{color:var(--link)}
.muted{color:var(--muted);font-size:.95rem}
.button,button{display:inline-block;background:var(--btn);color:var(--btn-fg);border:0;border-radius:.5rem;padding:.65rem 1.1rem;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.4rem 1rem;margin:0 0 1.5rem}
dt{color:var(--muted)}
dd{margin:0;overflow-wrap:anywhere}
`;
