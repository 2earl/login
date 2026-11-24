-- Phase 11 (DESIGN §4.29–§4.30): 2earl's own staff, and organizations set up by invitation.

-- 2earl staff besides the owner (OWNER_GOOGLE_SUB, who is never stored here). Admins run 2earl
-- but can't give or take staff roles; support helps people and organizations, mostly reading.
CREATE TABLE staff (
  user_id    TEXT    PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  role       TEXT    NOT NULL CHECK (role IN ('admin', 'support')),
  granted_by TEXT    REFERENCES users (id) ON DELETE SET NULL,
  granted_at INTEGER NOT NULL
) STRICT;

-- An invitation from 2earl to set up a new organization. The person who signs in with the
-- address names it and becomes its owner. Only owners and admins of 2earl send them.
CREATE TABLE org_setup_invitations (
  id         TEXT    PRIMARY KEY, -- 'osi_…'
  email      TEXT    NOT NULL COLLATE NOCASE,
  org_name   TEXT,                -- suggested; the invited person can change it
  invited_by TEXT    REFERENCES users (id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  sent_at    INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,
  org_id     TEXT    REFERENCES organizations (id) ON DELETE SET NULL
) STRICT;
CREATE INDEX org_setup_invitations_email ON org_setup_invitations (email);
