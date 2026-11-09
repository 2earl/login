-- Second factor (docs/DESIGN.md §4.7): passkeys, an authenticator app, recovery codes.

CREATE TABLE mfa_factors (
  id                     TEXT PRIMARY KEY,
  user_id                TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind                   TEXT    NOT NULL CHECK (kind IN ('webauthn', 'totp')),
  label                  TEXT    NOT NULL,
  created_at             INTEGER NOT NULL,
  last_used_at           INTEGER,
  -- Passkeys: credential ID and COSE public key (base64url), signature counter, transports (JSON).
  webauthn_credential_id TEXT UNIQUE,
  webauthn_public_key    TEXT,
  webauthn_sign_count    INTEGER,
  webauthn_transports    TEXT,
  -- Authenticator app: secret encrypted with MFA_ENCRYPTION_KEY (AES-GCM, bound to user_id), and
  -- the last accepted 30-second step, so a code can't be used twice.
  totp_secret_enc        TEXT,
  totp_last_step         INTEGER,
  CHECK (kind <> 'webauthn' OR (webauthn_credential_id IS NOT NULL AND webauthn_public_key IS NOT NULL)),
  CHECK (kind <> 'totp' OR totp_secret_enc IS NOT NULL)
) STRICT;
CREATE INDEX mfa_factors_user_id ON mfa_factors (user_id);
-- One authenticator app per account.
CREATE UNIQUE INDEX mfa_factors_one_totp ON mfa_factors (user_id) WHERE kind = 'totp';

-- Ten single-use codes per account, stored as keyed hashes only.
CREATE TABLE recovery_codes (
  id        TEXT PRIMARY KEY,
  user_id   TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash TEXT    NOT NULL,
  used_at   INTEGER
) STRICT;
CREATE INDEX recovery_codes_user_id ON recovery_codes (user_id);

-- Short-lived state of a second-factor step (≤ 10 minutes), bound to the browser session:
-- a passkey challenge, an authenticator-app secret being set up, or new recovery codes waiting to
-- be shown once. Secrets are encrypted.
CREATE TABLE mfa_pending (
  session_hash TEXT    NOT NULL REFERENCES sessions (id_hash) ON DELETE CASCADE,
  purpose      TEXT    NOT NULL
    CHECK (purpose IN ('webauthn_register', 'webauthn_authenticate', 'totp_enrol', 'recovery_codes')),
  value        TEXT    NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (session_hash, purpose)
) STRICT;

-- Wrong codes lock the second-factor step for 15 minutes after 5 attempts in a row.
ALTER TABLE users ADD COLUMN mfa_failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_locked_until INTEGER;
