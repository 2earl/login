-- Phase 13c (DESIGN §4.33): service accounts, the machine identities of organizations' backends.
-- They get access tokens with the client credentials grant (RFC 6749 §4.4), authenticated with a
-- secret (kept only as its SHA-256) or a JWT signed with a key whose public part is stored here
-- (RFC 7523). Each has its own client in the OAuth library (`client_id`), so its tokens are
-- validated like everyone else's.
CREATE TABLE service_accounts (
  id          TEXT    PRIMARY KEY, -- 'sa_…', what the backend sends as client_id
  org_id      TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  status      TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  -- The library's client for this account.
  client_id   TEXT    NOT NULL UNIQUE,
  -- Space-separated scopes the owner allowed, all of one resource.
  resource    TEXT    NOT NULL,
  scopes      TEXT    NOT NULL,
  secret_hash TEXT,
  -- A public JWK set for private_key_jwt; NULL when it authenticates with a secret.
  jwks        TEXT,
  created_by  TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  last_used_at INTEGER,
  CHECK ((secret_hash IS NULL) != (jwks IS NULL))
) STRICT;
CREATE INDEX service_accounts_org ON service_accounts (org_id);

-- JWTs a service account authenticated with, so none works twice (RFC 7523 §3). Minutes only.
CREATE TABLE client_assertion_jti (
  id_hash    TEXT    PRIMARY KEY, -- SHA-256 of the account and the jti
  expires_at INTEGER NOT NULL
) STRICT;

-- What's left to do in the OAuth library (KV) once an account is gone: revoke its tokens and
-- delete its client. An outbox, so it happens however the row went (an owner deleting it, the
-- organization's deletion cascading), and is retried until done (src/service-accounts.ts).
CREATE TABLE service_account_cleanup (
  id         TEXT    PRIMARY KEY, -- the account's 'sa_…'
  client_id  TEXT    NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER service_account_deleted AFTER DELETE ON service_accounts
BEGIN
  DELETE FROM authz_assignments
  WHERE principal_kind = 'service_account' AND principal_id = OLD.id;
  INSERT INTO service_account_cleanup (id, client_id, created_at)
  VALUES (OLD.id, OLD.client_id, CAST(strftime('%s', 'now') AS INTEGER))
  ON CONFLICT (id) DO NOTHING;
END;
