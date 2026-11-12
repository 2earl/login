-- Phase 9c: an organization's members sign in through its own SAML 2.0 identity provider
-- (DESIGN §4.17). login is the service provider.

-- One identity provider per organization. The certificate is the IdP's public signing
-- certificate; nothing here is secret.
CREATE TABLE org_saml (
  org_id        TEXT    PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  idp_entity_id TEXT    NOT NULL,
  sso_url       TEXT    NOT NULL,
  certificate   TEXT    NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
) STRICT;

-- A sign-in on its way to the IdP: bound to the browser (HMAC of the __Host-saml_tx cookie) and
-- to its RelayState (stored as an HMAC). The IdP's response is parked here between its
-- cross-site POST and the same-site GET that finishes the sign-in. At most 10 minutes.
CREATE TABLE saml_states (
  state_hash   TEXT    PRIMARY KEY,
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  browser_hash TEXT    NOT NULL,
  return_to    TEXT,
  response     TEXT,
  expires_at   INTEGER NOT NULL
) STRICT;

-- node-saml's cache: request IDs (each response must answer one we sent, once) and assertion IDs
-- (each assertion is accepted once). Keys are prefixed with the organization.
CREATE TABLE saml_cache (
  key        TEXT    PRIMARY KEY,
  value      TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

-- Sessions can start with SAML: widen the sign-in method's check without rebuilding the table
-- (which would end second-factor steps in progress), keeping every session's value.
ALTER TABLE sessions ADD COLUMN sign_in_method TEXT
  CHECK (sign_in_method IN ('google', 'email', 'passkey', 'saml'));
UPDATE sessions SET sign_in_method = method;
ALTER TABLE sessions DROP COLUMN method;
ALTER TABLE sessions RENAME COLUMN sign_in_method TO method;
