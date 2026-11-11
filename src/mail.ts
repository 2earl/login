/**
 * Email from login.2earl.com (DESIGN §4.9): sign-in codes and security notices. Sent with
 * Cloudflare Email Service (the MAILER binding, wrangler.jsonc) as plain text with a matching,
 * minimal HTML part, as Cloudflare's deliverability guidance asks: no images, no remote content,
 * nothing to track. Replies reach a person. Sending never throws; a failure is logged by its
 * code only.
 */

const SENDER = { email: 'noreply@2earl.com', name: '2earl' };
const REPLY_TO = 'legal@2earl.com';
const FOOTER = [
  '',
  '—',
  '2earl · https://2earl.com',
  'Your account: https://login.2earl.com/account',
];

const escapeHtml = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** Our own https links become links; everything else is text. */
const linkify = (escaped: string) =>
  escaped.replace(
    /https:\/\/(?:[a-z0-9-]+\.)*2earl\.com[^\s<]*/g,
    (url) => `<a href="${url}" style="color:#b23a0c">${url}</a>`,
  );

/** The same lines as HTML: paragraphs, the code (an indented line) set large. */
export function mailHtml(lines: string[]): string {
  const body = lines
    .map((line) => {
      if (line === '') return '';
      if (line === '—') return '<hr style="border:0;border-top:1px solid #e2e1e5;margin:24px 0">';
      if (/^\s{4}\S+$/.test(line)) {
        return `<p style="font-size:28px;font-weight:600;letter-spacing:4px;margin:8px 0 16px">${escapeHtml(line.trim())}</p>`;
      }
      return `<p style="margin:0 0 12px">${linkify(escapeHtml(line))}</p>`;
    })
    .join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#ffffff;font:16px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#1c1b1f"><div style="max-width:560px">\n${body}\n</div></body></html>`;
}

export async function sendMail(
  env: Env,
  to: string,
  subject: string,
  lines: string[],
): Promise<boolean> {
  const all = [...lines, ...FOOTER];
  try {
    await env.MAILER.send({
      to,
      from: SENDER,
      replyTo: REPLY_TO,
      subject,
      text: all.join('\n'),
      html: mailHtml(all),
    });
    return true;
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    console.error('email failed', typeof code === 'string' ? code : 'unknown');
    return false;
  }
}

export type CodePurpose = 'sign_in' | 'delete_account' | 'link_email';

const CODE_INTRO: Record<CodePurpose, string> = {
  sign_in: 'Your code to sign in to 2earl, or to create your account:',
  delete_account: 'Your code to confirm deleting your 2earl account:',
  link_email: 'Your code to add this address to your 2earl account:',
};

/** The code, and a link that does the same in the browser that asked for it. */
export function codeMail(
  purpose: CodePurpose,
  code: string,
  link: string,
): { subject: string; lines: string[] } {
  return {
    subject:
      purpose === 'delete_account'
        ? `${code} confirms deleting your 2earl account`
        : `${code} is your 2earl code`,
    lines: [
      CODE_INTRO[purpose],
      '',
      `    ${code}`,
      '',
      'Or open this link in the same browser:',
      link,
      '',
      'The code works once, for 10 minutes.',
      purpose === 'delete_account'
        ? 'If you didn’t ask to delete your account, sign in and add a second factor: someone may be using your account.'
        : 'If you didn’t ask for it, you can ignore this email. Nobody can use it without access to your inbox.',
    ],
  };
}

/** Security notices: what changed, when, and what to do if it wasn't you. */
export type Notice =
  | { kind: 'method_added'; method: string }
  | { kind: 'method_removed'; method: string }
  | { kind: 'factor_added'; factor: string }
  | { kind: 'factor_removed'; factor: string }
  | { kind: 'recovery_codes' }
  | { kind: 'app_connected'; app: string }
  | { kind: 'account_deleted' };

export function noticeMail(notice: Notice): { subject: string; lines: string[] } {
  const notYou =
    'If this wasn’t you, sign in at https://login.2earl.com, check your sign-in methods and connected apps, and add a second factor.';
  switch (notice.kind) {
    case 'method_added':
      return {
        subject: 'A sign-in method was added to your 2earl account',
        lines: [`You can now sign in to 2earl with ${notice.method}.`, '', notYou],
      };
    case 'method_removed':
      return {
        subject: 'A sign-in method was removed from your 2earl account',
        lines: [`You can no longer sign in to 2earl with ${notice.method}.`, '', notYou],
      };
    case 'factor_added':
      return {
        subject: 'A second factor was added to your 2earl account',
        lines: [`${notice.factor} now protects your 2earl account.`, '', notYou],
      };
    case 'factor_removed':
      return {
        subject: 'A second factor was removed from your 2earl account',
        lines: [`${notice.factor} no longer protects your 2earl account.`, '', notYou],
      };
    case 'recovery_codes':
      return {
        subject: 'New recovery codes for your 2earl account',
        lines: ['New recovery codes were created. The earlier ones no longer work.', '', notYou],
      };
    case 'app_connected':
      return {
        subject: `${notice.app} can now act for you`,
        lines: [
          `You allowed ${notice.app} to use your 2earl account.`,
          'You can see what it may do, and disconnect it, at https://login.2earl.com/account.',
          '',
          notYou,
        ],
      };
    case 'account_deleted':
      return {
        subject: 'Your 2earl account was deleted',
        lines: [
          'Your 2earl account and everything in it were deleted, and every connected app was disconnected.',
          'You can create a new account at any time. This is the last email you get from us about this account.',
        ],
      };
  }
}

/**
 * Sends a security notice to the account's address, after the response (waitUntil). Accounts
 * without an address get none.
 */
export async function notify(env: Env, userId: string, notice: Notice): Promise<void> {
  const row = await env.DB.prepare('SELECT primary_email FROM users WHERE id = ?')
    .bind(userId)
    .first<{ primary_email: string | null }>();
  if (!row?.primary_email) return;
  const mail = noticeMail(notice);
  await sendMail(env, row.primary_email, mail.subject, mail.lines);
}
