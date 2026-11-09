import { base64url } from '../src/crypto';

/**
 * A software passkey authenticator for tests: ES256, "none" attestation. It builds the same
 * bytes a browser and authenticator would send, so the server's real WebAuthn verification runs.
 */

const encoder = new TextEncoder();

// ---- Minimal CBOR encoder (the subset WebAuthn needs) -----------------------------------------

type Cbor = number | string | Uint8Array | Map<number | string, Cbor>;

function head(major: number, length: number): number[] {
  if (length < 24) return [(major << 5) | length];
  if (length < 256) return [(major << 5) | 24, length];
  if (length < 65536) return [(major << 5) | 25, length >> 8, length & 255];
  throw new Error('too long');
}

export function cbor(value: Cbor): Uint8Array {
  const out: number[] = [];
  const write = (v: Cbor): void => {
    if (typeof v === 'number') {
      out.push(...(v >= 0 ? head(0, v) : head(1, -1 - v)));
    } else if (typeof v === 'string') {
      const bytes = encoder.encode(v);
      out.push(...head(3, bytes.length), ...bytes);
    } else if (v instanceof Uint8Array) {
      out.push(...head(2, v.length), ...v);
    } else {
      out.push(...head(5, v.size));
      for (const [k, item] of v) {
        write(k);
        write(item);
      }
    }
  };
  write(value);
  return new Uint8Array(out);
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data)));
}

function fromB64url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)), (c) =>
    c.charCodeAt(0),
  );
}

/** WebCrypto signs ECDSA as raw r‖s; WebAuthn carries DER. */
function derSignature(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let body = bytes.slice(start);
    if ((body[0] ?? 0) & 0x80) body = concat(new Uint8Array([0]), body);
    return concat(new Uint8Array([0x02, body.length]), body);
  };
  const seq = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat(new Uint8Array([0x30, seq.length]), seq);
}

export class SoftAuthenticator {
  readonly credentialId = crypto.getRandomValues(new Uint8Array(32));
  private counter = 0;
  private keys: CryptoKeyPair | null = null;

  constructor(
    private readonly rpId = 'login.2earl.com',
    private readonly origin = 'https://login.2earl.com',
  ) {}

  get id(): string {
    return base64url(this.credentialId);
  }

  private async keyPair(): Promise<CryptoKeyPair> {
    this.keys ??= (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    return this.keys;
  }

  private clientData(type: string, challenge: string): Uint8Array {
    return encoder.encode(
      JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }),
    );
  }

  /** The browser's answer to navigator.credentials.create(), as JSON. */
  async register(options: { challenge: string }): Promise<Record<string, unknown>> {
    const jwk = (await crypto.subtle.exportKey(
      'jwk',
      (await this.keyPair()).publicKey,
    )) as JsonWebKey;
    const coseKey = cbor(
      new Map<number, Cbor>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, fromB64url(jwk.x ?? '')],
        [-3, fromB64url(jwk.y ?? '')],
      ]),
    );
    const idLength = new Uint8Array([0, this.credentialId.length]);
    const authData = concat(
      await sha256(encoder.encode(this.rpId)),
      new Uint8Array([0x45]), // UP | UV | AT
      new Uint8Array(4), // counter 0
      new Uint8Array(16), // AAGUID
      idLength,
      this.credentialId,
      coseKey,
    );
    const attestationObject = cbor(
      new Map<string, Cbor>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64url(this.clientData('webauthn.create', options.challenge)),
        attestationObject: base64url(attestationObject),
        transports: ['internal'],
      },
    };
  }

  /** The browser's answer to navigator.credentials.get(), as JSON. */
  async authenticate(options: { challenge: string }): Promise<Record<string, unknown>> {
    this.counter += 1;
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, this.counter);
    const authData = concat(
      await sha256(encoder.encode(this.rpId)),
      new Uint8Array([0x05]), // UP | UV
      counter,
    );
    const clientData = this.clientData('webauthn.get', options.challenge);
    const signed = concat(authData, await sha256(clientData));
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        (await this.keyPair()).privateKey,
        signed,
      ),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64url(clientData),
        authenticatorData: base64url(authData),
        signature: base64url(derSignature(raw)),
      },
    };
  }
}
