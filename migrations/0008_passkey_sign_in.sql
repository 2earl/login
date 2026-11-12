-- Phase 8a (DESIGN §4.10, §7).

-- Sign-in with a passkey: one pending WebAuthn challenge per browser, keyed by the HMAC of the
-- __Host-passkey_tx cookie, for at most 5 minutes. user_id is set only when someone signed in
-- confirms it's them, so only that account's passkeys count.
CREATE TABLE passkey_challenges (
  id_hash    TEXT PRIMARY KEY,
  challenge  TEXT    NOT NULL,
  user_id    TEXT    REFERENCES users (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX passkey_challenges_expires_at ON passkey_challenges (expires_at);

-- Signed-in devices: a coarse device name ("Firefox on Windows", never the full user agent) and
-- how the session started, so people can tell their sessions apart and end the ones they don't
-- recognise.
ALTER TABLE sessions ADD COLUMN device TEXT;
ALTER TABLE sessions ADD COLUMN method TEXT CHECK (method IN ('google', 'email', 'passkey'));
