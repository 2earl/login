-- Phase 9d: DPoP and pushed authorization requests (DESIGN §4.15).

-- RFC 9126: an authorization request a client sent straight to login. The browser then carries
-- only `request_uri`, whose random part is stored as an HMAC. At most 10 minutes; deleted daily.
CREATE TABLE pushed_requests (
  id_hash    TEXT    PRIMARY KEY,
  client_id  TEXT    NOT NULL,
  params     TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

-- RFC 9449 §11.1: DPoP proofs already seen (hash of the key's thumbprint and the proof's `jti`),
-- so a captured proof can't be replayed while it is fresh. Kept 2 minutes; deleted daily.
CREATE TABLE dpop_proofs (
  id_hash    TEXT    PRIMARY KEY,
  expires_at INTEGER NOT NULL
) STRICT;
