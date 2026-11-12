-- Phase 9b: an organization's own directory manages its members over SCIM 2.0 (DESIGN §4.16).

-- Domains an organization proved it controls, with a DNS TXT record. Only addresses at a
-- verified domain can be provisioned; a domain is verified for one organization at a time.
CREATE TABLE org_domains (
  org_id      TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  domain      TEXT    NOT NULL COLLATE NOCASE,
  -- The value to publish at _2earl-challenge.<domain>; public, not a secret.
  challenge   TEXT    NOT NULL,
  verified_at INTEGER,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (org_id, domain)
) STRICT;
CREATE UNIQUE INDEX org_domains_verified ON org_domains (domain) WHERE verified_at IS NOT NULL;

-- The directory's credentials: bearer tokens stored as SHA-256 (256 random bits, shown once).
CREATE TABLE scim_tokens (
  id           TEXT    PRIMARY KEY,
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  token_hash   TEXT    NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
) STRICT;

-- People the directory provisioned. Linked to the 2earl account that signs in with the address
-- (user_id) once there is one; active ones are members of the organization.
CREATE TABLE scim_users (
  id           TEXT    PRIMARY KEY,
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_name    TEXT    NOT NULL COLLATE NOCASE,
  external_id  TEXT,
  display_name TEXT,
  given_name   TEXT,
  family_name  TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  user_id      TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  UNIQUE (org_id, user_name)
) STRICT;
CREATE INDEX scim_users_user ON scim_users (user_id);
CREATE INDEX scim_users_pending ON scim_users (user_name) WHERE user_id IS NULL;
