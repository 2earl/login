-- Phase 9a: organizations and roles (DESIGN §4.14).
--
-- An organization is a team of 2earl accounts. Each member has one role: owner (everything,
-- including deleting the organization), admin (members and invitations) or member. An
-- organization always has at least one owner; the routes keep it so, and account deletion passes
-- ownership on (src/orgs.ts).
CREATE TABLE organizations (
  id         TEXT    PRIMARY KEY,
  name       TEXT    NOT NULL,
  -- 'suspended' by the 2earl owner in /admin: members can't change it, services don't see it.
  status     TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE org_members (
  org_id    TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role      TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (org_id, user_id)
) STRICT;
CREATE INDEX org_members_user ON org_members (user_id);

-- Invitations by email address. The link's token is stored only as an HMAC; the address is the
-- invitee's, kept until the invitation is accepted, declined, revoked or expires (7 days), then
-- deleted by the daily clean-up.
CREATE TABLE org_invitations (
  id         TEXT    PRIMARY KEY,
  token_hash TEXT    NOT NULL UNIQUE,
  org_id     TEXT    NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  email      TEXT    NOT NULL COLLATE NOCASE,
  role       TEXT    NOT NULL CHECK (role IN ('admin', 'member')),
  invited_by TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE (org_id, email)
) STRICT;

-- Deleting an organization reaches every service that keeps data for organizations
-- (`organizationEvents` in src/services.ts), like account deletion (0005).
CREATE TABLE org_deletion_notices (
  service         TEXT    NOT NULL,
  org_id          TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER,
  last_error      TEXT,
  PRIMARY KEY (service, org_id)
) STRICT;
