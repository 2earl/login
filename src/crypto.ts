/** Small Web Crypto helpers. No secrets are logged or returned from here. */

const encoder = new TextEncoder();

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A URL-safe random string with `bytes` bytes of entropy (default 256 bits). */
export function randomToken(bytes = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64url(buffer);
}

export async function sha256(data: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(data)));
}

export async function sha256Hex(data: string): Promise<string> {
  return toHex(await sha256(data));
}

/** RFC 7636 S256 code challenge for a PKCE verifier. */
export async function pkceChallenge(verifier: string): Promise<string> {
  return base64url(await sha256(verifier));
}

const hmacKeys = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (!key) {
    key = crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    hmacKeys.set(secret, key);
  }
  return key;
}

/**
 * HMAC-SHA-256 as hex. Used to store only a keyed hash of cookie values, so a database dump
 * cannot be turned back into working session cookies.
 */
export async function hmacHex(secret: string, message: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    'HMAC',
    await hmacKey(secret),
    encoder.encode(message),
  );
  return toHex(new Uint8Array(signature));
}

/** Constant-time comparison for equal-length strings. */
export function timingSafeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
