// Makes a new ID-token signing key for OpenID Connect (DESIGN §4.11): an ES256 (P-256) private
// JSON Web Key, printed as one line for the GitHub `production` secret OIDC_SIGNING_KEY.
// `--public` reads a private key on stdin and prints its public half, for OIDC_NEXT_PUBLIC_KEY.
// Nothing is written to disk.

/** @returns {Promise<string>} */
export async function newSigningKey() {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', privateKey);
  return JSON.stringify({ kty, crv, x, y, d });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.includes('--public')) {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const { kty, crv, x, y } = JSON.parse(input);
    process.stdout.write(`${JSON.stringify({ kty, crv, x, y })}\n`);
  } else {
    process.stdout.write(`${await newSigningKey()}\n`);
  }
}
