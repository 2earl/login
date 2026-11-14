-- Phase 10g: the organization's API (DESIGN §4.24).
CREATE TABLE org_api_keys (
  id           TEXT    PRIMARY KEY, -- 'oak_…'
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name         TEXT    NOT NULL,
  key_hash     TEXT    NOT NULL UNIQUE, -- SHA-256 of the key; the key itself is shown once
  -- 'read', or 'write' (read and write).
  access       TEXT    NOT NULL CHECK (access IN ('read', 'write')),
  created_by   TEXT,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
) STRICT;
CREATE INDEX org_api_keys_org ON org_api_keys (org_id);
