-- Phase 10d: groups from the organization's directory, mapped to roles (DESIGN §4.21).
CREATE TABLE scim_groups (
  id           TEXT    PRIMARY KEY, -- 'scg_…'
  org_id       TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  display_name TEXT    NOT NULL,
  external_id  TEXT,
  -- The role the group's members get in the organization: NULL (no say) or 'admin'.
  role         TEXT    CHECK (role IN ('admin')),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  UNIQUE (org_id, display_name COLLATE NOCASE)
) STRICT;

CREATE TABLE scim_group_members (
  group_id     TEXT NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
  scim_user_id TEXT NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, scim_user_id)
) STRICT;

CREATE INDEX scim_group_members_user ON scim_group_members (scim_user_id);
