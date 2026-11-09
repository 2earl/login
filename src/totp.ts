/**
 * Authenticator-app codes: RFC 6238 TOTP with the defaults every app supports (HMAC-SHA-1,
 * 6 digits, 30-second steps), and RFC 4648 base32 for the secret.
 */

export const TOTP_PERIOD_SECONDS = 30;
const DIGITS = 6;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32.charAt((value << (5 - bits)) & 31);
  return out;
}

export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error('invalid base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** A new 160-bit secret, as RFC 4226 recommends, base32-encoded. */
export function generateTotpSecret(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export function totpStep(nowSeconds: number): number {
  return Math.floor(nowSeconds / TOTP_PERIOD_SECONDS);
}

export async function totpCode(secret: string, step: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) |
    ((mac[offset + 1] ?? 0) << 16) |
    ((mac[offset + 2] ?? 0) << 8) |
    (mac[offset + 3] ?? 0);
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Checks a code against the current step and one step either side (clock drift). Returns the
 * matching step, which must be later than `lastStep`: a code is accepted once, and never an
 * older one after a newer one.
 */
export async function verifyTotp(
  secret: string,
  code: string,
  nowSeconds: number,
  lastStep: number | null,
): Promise<number | null> {
  const digits = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(digits)) return null;
  const current = totpStep(nowSeconds);
  let matched: number | null = null;
  // Check every candidate, so timing doesn't reveal which step matched.
  for (const step of [current - 1, current, current + 1]) {
    if ((await totpCode(secret, step)) === digits && (lastStep === null || step > lastStep)) {
      matched = step;
    }
  }
  return matched;
}

export function otpauthUri(secret: string, accountName: string): string {
  const label = encodeURIComponent(`2earl:${accountName}`);
  const params = new URLSearchParams({
    secret,
    issuer: '2earl',
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
