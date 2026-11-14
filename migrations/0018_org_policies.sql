-- Phase 10b: security rules an organization sets for the accounts it manages (DESIGN §4.19).
CREATE TABLE org_policies (
  org_id         TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  -- A second factor is required (1 also when passkeys_only is 1).
  require_factor INTEGER NOT NULL DEFAULT 0,
  -- The second factor must be a passkey.
  passkeys_only  INTEGER NOT NULL DEFAULT 0,
  -- Sessions end this many hours after sign-in; NULL keeps the default (7 days).
  session_hours  INTEGER,
  -- Ways to sign in, comma-separated: google, email, passkey. SSO is decided by require_sso.
  methods        TEXT NOT NULL DEFAULT 'google,email,passkey',
  -- Networks the accounts may be used from, CIDR, one per line; empty means anywhere.
  ip_ranges      TEXT NOT NULL DEFAULT '',
  updated_at     INTEGER NOT NULL
);
