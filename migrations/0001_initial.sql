-- Initial schema for login.2earl.com. See docs/DESIGN.md §6.1.
-- Conventions: IDs are text (ULIDs or random IDs generated in the Worker); times are integer
-- Unix seconds (UTC); booleans are 0/1 integers with CHECK constraints.

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  status        TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  display_name  TEXT,
  primary_email TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
) STRICT;

-- One row per login method. Users are found by (provider, subject), never by email.
CREATE TABLE identities (
  id             TEXT PRIMARY KEY,
  user_id        TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider       TEXT    NOT NULL CHECK (provider IN ('google')),
  subject        TEXT    NOT NULL,
  email          TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER NOT NULL,
  UNIQUE (provider, subject)
) STRICT;
CREATE INDEX identities_user_id ON identities (user_id);

-- Browser sessions. Only an HMAC of the cookie value is stored.
CREATE TABLE sessions (
  id_hash         TEXT PRIMARY KEY,
  user_id         TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  aal             TEXT    NOT NULL DEFAULT 'aal1' CHECK (aal IN ('aal1', 'aal2')),
  aal2_at         INTEGER,
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  ip_prefix       TEXT,
  user_agent_hash TEXT
) STRICT;
CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

-- In-flight Google sign-ins (≤ 10 minutes). Only an HMAC of the cookie value is stored.
CREATE TABLE login_tx (
  id_hash       TEXT PRIMARY KEY,
  state         TEXT    NOT NULL UNIQUE,
  nonce         TEXT    NOT NULL,
  pkce_verifier TEXT    NOT NULL,
  auth_request  TEXT,  -- JSON of the parsed OAuth request to resume, if any
  return_to     TEXT,  -- local path to return to when not resuming an OAuth request
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX login_tx_expires_at ON login_tx (expires_at);

-- Who may sign in while the service is locked (DESIGN D9).
CREATE TABLE allowlist (
  id         TEXT PRIMARY KEY,
  kind       TEXT    NOT NULL CHECK (kind IN ('google_sub', 'email')),
  value      TEXT    NOT NULL,
  added_by   TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE (kind, value)
) STRICT;

-- CIMD clients the owner has marked as verified on the consent page.
CREATE TABLE trusted_clients (
  client_id  TEXT PRIMARY KEY,
  note       TEXT,
  created_at INTEGER NOT NULL
) STRICT;

-- Security audit trail. No tokens, codes or full URLs; IP addresses truncated.
-- user_id is intentionally not a foreign key: events must survive account deletion, which
-- replaces it with a random correlation ID (DESIGN §6.3).
CREATE TABLE audit_events (
  id            TEXT PRIMARY KEY,
  at            INTEGER NOT NULL,
  event         TEXT    NOT NULL,
  actor_user_id TEXT,
  client_id     TEXT,
  ip_prefix     TEXT,
  detail        TEXT   -- JSON
) STRICT;
CREATE INDEX audit_events_at ON audit_events (at);
CREATE INDEX audit_events_actor ON audit_events (actor_user_id);
