-- Phase 8b: login as an OpenID Connect provider (DESIGN §4.11).

-- Pairwise subject identifiers (OIDC Core §8.1): each site knows a user by its own random ID,
-- so two sites can't link one person by comparing IDs. One row per account and sector (the
-- host the site redirects to, or the client ID for apps on this device).
CREATE TABLE oidc_subjects (
  sub        TEXT PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  sector     TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, sector)
) STRICT;
