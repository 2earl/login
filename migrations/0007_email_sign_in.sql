-- Open sign-up with email (docs/DESIGN.md §4.9): sign in with a one-time code sent by email,
-- sign-in methods added and removed by the user, and a sign-up switch the owner can flip.

-- Tables are rebuilt below to widen CHECK constraints; foreign keys are checked at the end.
PRAGMA defer_foreign_keys = true;

-- identities: a second provider, 'email', whose subject is the address in lower case.
CREATE TABLE identities_new (
  id             TEXT PRIMARY KEY,
  user_id        TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider       TEXT    NOT NULL CHECK (provider IN ('google', 'email')),
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

-- login_tx: a trip to Google can also add Google to a signed-in account ('link_google').
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
    CHECK (purpose IN ('sign_in', 'delete_account', 'link_google')),
  user_id       TEXT
) STRICT;
INSERT INTO login_tx_new
  SELECT id_hash, state, nonce, pkce_verifier, auth_request, return_to, created_at, expires_at,
         purpose, user_id
  FROM login_tx;
DROP TABLE login_tx;
ALTER TABLE login_tx_new RENAME TO login_tx;
CREATE INDEX login_tx_expires_at ON login_tx (expires_at);

-- A code sent by email, waiting to be typed. Bound to the browser that asked by a cookie
-- (__Host-email_code) whose HMAC is the ID. The code and the link token are stored only as
-- HMACs. Lives 10 minutes, allows 5 wrong tries, is used once.
CREATE TABLE email_codes (
  id_hash     TEXT PRIMARY KEY,
  email       TEXT    NOT NULL,
  code_hash   TEXT    NOT NULL,
  link_hash   TEXT    NOT NULL UNIQUE,
  purpose     TEXT    NOT NULL CHECK (purpose IN ('sign_in', 'delete_account', 'link_email')),
  user_id     TEXT,  -- delete_account, link_email: the signed-in account it is for
  return_to   TEXT,
  attempts    INTEGER NOT NULL DEFAULT 0,
  ip_prefix   TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
) STRICT;
CREATE INDEX email_codes_email ON email_codes (email, created_at);
CREATE INDEX email_codes_ip ON email_codes (ip_prefix, created_at);
CREATE INDEX email_codes_created ON email_codes (created_at);

-- Settings the owner changes on /admin without a deploy. 'signup': 'open' | 'invite'.
CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT    NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
