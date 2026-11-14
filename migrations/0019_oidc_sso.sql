-- Phase 10c: single sign-on with OpenID Connect (DESIGN §4.20).

CREATE TABLE org_oidc (
  org_id            TEXT    PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  -- The provider's issuer, exactly as its discovery document names it (https).
  issuer            TEXT    NOT NULL,
  client_id         TEXT    NOT NULL,
  -- AES-GCM with MFA_ENCRYPTION_KEY, bound to the organization.
  client_secret_enc TEXT    NOT NULL,
  enabled           INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;

-- A sign-in at the provider in progress: what the way back must match.
CREATE TABLE oidc_states (
  state_hash   TEXT    PRIMARY KEY, -- HMAC of the state parameter
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  browser_hash TEXT    NOT NULL,    -- HMAC of the browser cookie
  nonce        TEXT    NOT NULL,
  verifier     TEXT    NOT NULL,    -- PKCE code verifier
  return_to    TEXT,
  expires_at   INTEGER NOT NULL
) STRICT;

-- Sessions can start with OpenID Connect too: widen the check as 0015 did, keeping every value.
ALTER TABLE sessions ADD COLUMN sign_in_method TEXT
  CHECK (sign_in_method IN ('google', 'email', 'passkey', 'saml', 'oidc'));
UPDATE sessions SET sign_in_method = method;
ALTER TABLE sessions DROP COLUMN method;
ALTER TABLE sessions RENAME COLUMN sign_in_method TO method;
