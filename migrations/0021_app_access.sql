-- Phase 10e: which apps the accounts an organization manages may use (DESIGN §4.22).
ALTER TABLE organizations ADD COLUMN restrict_apps INTEGER NOT NULL DEFAULT 0;

CREATE TABLE org_app_access (
  org_id     TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  client_id  TEXT    NOT NULL,
  -- '' for everyone the organization manages; otherwise a directory group (scim_groups.id).
  group_id   TEXT    NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, client_id, group_id)
) STRICT;
