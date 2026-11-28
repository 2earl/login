-- Phase 13 (DESIGN §4.32): custom roles and scoped role assignments. Permissions and system roles
-- are in code (src/services.ts, src/authz/login-manifest.ts); only what organizations and 2earl
-- staff decide is stored here.

-- An organization's own role in one service: a name and a set of that service's permissions.
CREATE TABLE authz_roles (
  id          TEXT    PRIMARY KEY, -- 'rol_…'
  org_id      TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  service     TEXT    NOT NULL,
  name        TEXT    NOT NULL,
  description TEXT    NOT NULL DEFAULT '',
  created_by  TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (org_id, service, name COLLATE NOCASE)
) STRICT;

CREATE TABLE authz_role_permissions (
  role_id    TEXT NOT NULL REFERENCES authz_roles (id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  PRIMARY KEY (role_id, permission)
) STRICT;

-- A role held by a principal, across 2earl (platform, staff only) or in one organization,
-- optionally for one resource of it ('<type>:<id>'; '' for all of them).
CREATE TABLE authz_assignments (
  id             TEXT    PRIMARY KEY, -- 'asg_…'
  scope_kind     TEXT    NOT NULL CHECK (scope_kind IN ('platform', 'org')),
  org_id         TEXT    REFERENCES organizations (id) ON DELETE CASCADE,
  resource       TEXT    NOT NULL DEFAULT '',
  principal_kind TEXT    NOT NULL CHECK (principal_kind IN ('user', 'group', 'service_account')),
  principal_id   TEXT    NOT NULL,
  -- '<service>:<system role>' or a custom role's 'rol_…'.
  role           TEXT    NOT NULL,
  service        TEXT    NOT NULL,
  -- Conditions come in phase 13e; until then a row with one never grants anything.
  condition      TEXT    NOT NULL DEFAULT '',
  expires_at     INTEGER,
  granted_by     TEXT,
  granted_at     INTEGER NOT NULL,
  reason         TEXT    NOT NULL DEFAULT '',
  CHECK ((scope_kind = 'platform') = (org_id IS NULL)),
  CHECK (scope_kind = 'org' OR resource = ''),
  UNIQUE (scope_kind, org_id, resource, principal_kind, principal_id, role)
) STRICT;

CREATE INDEX authz_assignments_principal ON authz_assignments (principal_kind, principal_id);
CREATE INDEX authz_assignments_org ON authz_assignments (org_id, service);
CREATE INDEX authz_assignments_role ON authz_assignments (role);

-- Whoever goes, their assignments go with them, on every path (account deletion, SCIM, an
-- organization's deletion cascading into its groups). A principal can be one of three tables, so
-- there is no foreign key; these triggers do its work.
CREATE TRIGGER authz_user_deleted AFTER DELETE ON users
BEGIN
  DELETE FROM authz_assignments WHERE principal_kind = 'user' AND principal_id = OLD.id;
END;

CREATE TRIGGER authz_group_deleted AFTER DELETE ON scim_groups
BEGIN
  DELETE FROM authz_assignments WHERE principal_kind = 'group' AND principal_id = OLD.id;
END;

-- A custom role's assignments go with the role.
CREATE TRIGGER authz_role_deleted AFTER DELETE ON authz_roles
BEGIN
  DELETE FROM authz_assignments WHERE role = OLD.id;
END;

-- Platform roles are for 2earl staff: losing the staff role ends them. (The owner isn't a row
-- in `staff`, so the owner's platform roles end only with the account.)
CREATE TRIGGER authz_staff_removed AFTER DELETE ON staff
BEGIN
  DELETE FROM authz_assignments
  WHERE scope_kind = 'platform' AND principal_kind = 'user' AND principal_id = OLD.user_id;
END;

-- Leaving an organization ends the roles held in it. A migration that rebuilds org_members,
-- users, staff or scim_groups (DROP and CREATE) drops the trigger with it: create it again.
CREATE TRIGGER authz_member_removed AFTER DELETE ON org_members
BEGIN
  DELETE FROM authz_assignments
  WHERE scope_kind = 'org' AND org_id = OLD.org_id
    AND principal_kind = 'user' AND principal_id = OLD.user_id;
END;
