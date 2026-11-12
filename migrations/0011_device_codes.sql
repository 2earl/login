-- Phase 8d: the device authorization grant (RFC 8628; DESIGN §4.13).
--
-- A device without a browser (the 2earl CLI) asks for a code, the person approves it on another
-- device through the ordinary authorization page, and the device collects its tokens by polling.
-- The device code itself is never stored, only its HMAC. The authorization code waits here at
-- most until the device collects it (10 minutes); exchanging it also needs a PKCE verifier that
-- is derived from the device code and SESSION_PEPPER, never stored.
CREATE TABLE device_codes (
  id_hash        TEXT PRIMARY KEY,
  user_code      TEXT    NOT NULL UNIQUE,
  state          TEXT    NOT NULL UNIQUE,
  client_id      TEXT    NOT NULL,
  scope          TEXT    NOT NULL,
  resource       TEXT,
  status         TEXT    NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'denied')),
  code           TEXT,
  interval       INTEGER NOT NULL DEFAULT 5,
  last_polled_at INTEGER,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX device_codes_expires_at ON device_codes (expires_at);
