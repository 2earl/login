-- Phase 10k: the auditor role (DESIGN §4.28). Auditors see an organization's members, activity
-- and settings and can download its activity, but change nothing. Directory groups can carry
-- the role too.
--
-- Tables are rebuilt below to widen CHECK constraints; foreign keys are checked at the end.
-- scim_group_members references scim_groups with ON DELETE CASCADE, and dropping a table deletes
-- its rows first, so it is copied and rebuilt before scim_groups is dropped.
PRAGMA defer_foreign_keys = true;

CREATE TABLE org_members_new (
  org_id    TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role      TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'auditor', 'member')),
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, user_id)
) STRICT;
INSERT INTO org_members_new (org_id, user_id, role, joined_at)
  SELECT org_id, user_id, role, joined_at FROM org_members;
DROP TABLE org_members;
ALTER TABLE org_members_new RENAME TO org_members;
CREATE INDEX org_members_user ON org_members (user_id);

CREATE TABLE org_invitations_new (
  id         TEXT    PRIMARY KEY,
  token_hash TEXT    NOT NULL UNIQUE,
  org_id     TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  email      TEXT    NOT NULL COLLATE NOCASE,
  role       TEXT    NOT NULL CHECK (role IN ('admin', 'auditor', 'member')),
  invited_by TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (org_id, email)
) STRICT;
INSERT INTO org_invitations_new (id, token_hash, org_id, email, role, invited_by, created_at, expires_at)
  SELECT id, token_hash, org_id, email, role, invited_by, created_at, expires_at FROM org_invitations;
DROP TABLE org_invitations;
ALTER TABLE org_invitations_new RENAME TO org_invitations;

CREATE TABLE scim_groups_new (
  id           TEXT    PRIMARY KEY, -- 'scg_…'
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  display_name TEXT    NOT NULL,
  external_id  TEXT,
  -- The role the group's members get in the organization: NULL (no say), 'admin' or 'auditor'.
  role         TEXT    CHECK (role IN ('admin', 'auditor')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  UNIQUE (org_id, display_name COLLATE NOCASE)
) STRICT;
INSERT INTO scim_groups_new (id, org_id, display_name, external_id, role, created_at, updated_at)
  SELECT id, org_id, display_name, external_id, role, created_at, updated_at FROM scim_groups;

CREATE TABLE scim_group_members_new (
  group_id     TEXT NOT NULL REFERENCES scim_groups_new (id) ON DELETE CASCADE,
  scim_user_id TEXT NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, scim_user_id)
) STRICT;
INSERT INTO scim_group_members_new (group_id, scim_user_id)
  SELECT group_id, scim_user_id FROM scim_group_members;

DROP TABLE scim_group_members;
DROP TABLE scim_groups;
ALTER TABLE scim_groups_new RENAME TO scim_groups;
ALTER TABLE scim_group_members_new RENAME TO scim_group_members;
CREATE INDEX scim_group_members_user ON scim_group_members (scim_user_id);
