-- Phase 8c: token introspection (RFC 7662; DESIGN §4.12).
--
-- A resource server that can't use a Service Binding (a 2earl service outside Cloudflare, or a
-- partner) checks tokens at /oauth/introspect with its own credentials. It sees only tokens
-- issued for its resource. The secret is stored as its SHA-256 (it is 256 random bits, shown once
-- at creation); deleting the row revokes it.
CREATE TABLE resource_servers (
  id           TEXT PRIMARY KEY,
  name         TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  secret_hash  TEXT    NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
) STRICT;
