import { DPOP_ALGS, DpopError, readAuthorization, verifyDpopProof } from './dpop';
import { authorizationServer, type GrantProps } from './oauth';

/**
 * Checking an access token presented to a resource (DESIGN §4.15): with `Bearer`, or with `DPoP`
 * and a proof when the token is bound to a key. A bound token is never accepted as a bearer token,
 * and an unbound one never with the DPoP scheme (RFC 9449 §7).
 */

export interface CheckedToken {
  props: GrantProps;
  audience: string;
  expiresAt: number;
  scope: string[];
  userId: string;
  clientId: string;
  /** The key's thumbprint, for a DPoP-bound token. */
  jkt: string | null;
}

export type TokenCheck =
  | { ok: true; token: CheckedToken }
  | {
      ok: false;
      error: 'invalid_request' | 'invalid_token' | 'invalid_dpop_proof';
      description: string;
    };

/** The key a token is bound to (`cnf.jkt`, RFC 9449 §6.1), if any. */
export function boundKey(props: unknown): string | null {
  const cnf = (props as { cnf?: { jkt?: unknown } } | null)?.cnf;
  return typeof cnf?.jkt === 'string' ? cnf.jkt : null;
}

export async function checkAccessToken(
  env: Env,
  now: number,
  resource: string,
  request: { authorization: string | null; dpop: string | null; method: string; url: string },
): Promise<TokenCheck> {
  const presented = readAuthorization(request.authorization);
  if (!presented) return { ok: false, error: 'invalid_token', description: 'No access token' };
  const validated = await authorizationServer(env).validateToken(resource, presented.token, env);
  if (!validated)
    return { ok: false, error: 'invalid_token', description: 'Unknown or expired token' };
  const props = validated.props as GrantProps;
  const jkt = boundKey(props);
  if (!jkt) {
    if (presented.scheme === 'dpop') {
      return { ok: false, error: 'invalid_token', description: 'This token is a bearer token' };
    }
  } else {
    if (presented.scheme !== 'dpop') {
      return { ok: false, error: 'invalid_token', description: 'This token needs a DPoP proof' };
    }
    try {
      const proof = await verifyDpopProof(env.DB, now, {
        proof: request.dpop,
        method: request.method,
        url: request.url,
        accessToken: presented.token,
      });
      if (proof.jkt !== jkt) {
        return {
          ok: false,
          error: 'invalid_dpop_proof',
          description: 'The proof is from another key',
        };
      }
    } catch (error) {
      if (error instanceof DpopError) {
        return { ok: false, error: 'invalid_dpop_proof', description: error.description };
      }
      throw error;
    }
  }
  return {
    ok: true,
    token: {
      props,
      audience: validated.audience,
      expiresAt: validated.expiresAt,
      scope: validated.scope,
      userId: validated.userId,
      clientId: validated.clientId,
      jkt,
    },
  };
}

/** The `WWW-Authenticate` value for a failed check: both schemes, the error on the right one. */
export function challenge(error?: string, scope?: string): string {
  const algs = `algs="${DPOP_ALGS.join(' ')}"`;
  const scopePart = scope ? `, scope="${scope}"` : '';
  if (error === 'invalid_dpop_proof') return `DPoP error="${error}", ${algs}`;
  if (error) return `Bearer error="${error}"${scopePart}, DPoP ${algs}`;
  return `Bearer, DPoP ${algs}`;
}
