-- Phase 8e (DESIGN §4.14): sign in with Microsoft, GitHub or Apple too.

-- Tables are rebuilt below to widen CHECK constraints; foreign keys are checked at the end.
PRAGMA defer_foreign_keys = true;

-- identities: three more providers. As with Google, the subject is the provider's stable account
-- ID, never the email address; accounts are never joined by address (THREAT_MODEL B3).
CREATE TABLE identities_new (
  id             TEXT PRIMARY KEY,
  user_id        TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider       TEXT    NOT NULL
    CHECK (provider IN ('google', 'email', 'microsoft', 'github', 'apple')),
  subject        TEXT    NOT NULL,
  email          TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER NOT NULL,
  UNIQUE (provider, subject),
  CHECK (provider <> 'email' OR (subject = lower(subject) AND email = subject AND email_verified = 1))
) STRICT;
INSERT INTO identities_new
  SELECT id, user_id, provider, subject, email, email_verified, created_at, last_login_at
  FROM identities;
DROP TABLE identities;
ALTER TABLE identities_new RENAME TO identities;
CREATE INDEX identities_user_id ON identities (user_id);
CREATE INDEX identities_verified_email ON identities (email COLLATE NOCASE) WHERE email_verified = 1;

-- login_tx: which provider the trip goes to, and 'link' for adding any provider to an account.
CREATE TABLE login_tx_new (
  id_hash       TEXT PRIMARY KEY,
  state         TEXT    NOT NULL UNIQUE,
  nonce         TEXT    NOT NULL,
  pkce_verifier TEXT    NOT NULL,
  auth_request  TEXT,
  return_to     TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  purpose       TEXT    NOT NULL DEFAULT 'sign_in'
    CHECK (purpose IN ('sign_in', 'delete_account', 'link_google', 'link')),
  user_id       TEXT,
  provider      TEXT    NOT NULL DEFAULT 'google'
    CHECK (provider IN ('google', 'microsoft', 'github', 'apple'))
) STRICT;
INSERT INTO login_tx_new
  SELECT id_hash, state, nonce, pkce_verifier, auth_request, return_to, created_at, expires_at,
         purpose, user_id, 'google'
  FROM login_tx;
DROP TABLE login_tx;
ALTER TABLE login_tx_new RENAME TO login_tx;
CREATE INDEX login_tx_expires_at ON login_tx (expires_at);

-- Apple answers with a cross-site POST (response_mode=form_post), which carries no SameSite=Lax
-- cookie, so the browser can't be checked there. The answer waits here for a few minutes under a
-- random ticket, and the browser is sent on to a same-site GET that has the login_tx cookie.
CREATE TABLE callback_tickets (
  id_hash    TEXT PRIMARY KEY,
  provider   TEXT    NOT NULL CHECK (provider IN ('apple')),
  state      TEXT    NOT NULL,
  code       TEXT,
  error      TEXT,
  name       TEXT,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX callback_tickets_expires_at ON callback_tickets (expires_at);

-- sessions: record the new providers as how a session signed in. Rebuilt to widen the CHECK on
-- `method`; every session is kept. Dropping the old table clears mfa_pending through its cascade:
-- those are second-factor challenges that live a few minutes, and the person just starts again.
CREATE TABLE sessions_new (
  id_hash         TEXT PRIMARY KEY,
  user_id         TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  aal             TEXT    NOT NULL DEFAULT 'aal1' CHECK (aal IN ('aal1', 'aal2')),
  aal2_at         INTEGER,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  ip_prefix       TEXT,
  user_agent_hash TEXT,
  device          TEXT,
  method          TEXT CHECK (method IN ('google', 'email', 'passkey', 'microsoft', 'github', 'apple'))
) STRICT;
INSERT INTO sessions_new
  SELECT id_hash, user_id, aal, aal2_at, created_at, last_seen_at, expires_at, ip_prefix,
         user_agent_hash, device, method
  FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);
