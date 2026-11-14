-- Phase 10a: accounts an organization manages (DESIGN §4.18).

-- An owner can manage the accounts at a verified domain.
ALTER TABLE org_domains ADD COLUMN managed_at INTEGER;

-- Managed accounts sign in only through the organization's SSO (owners exempt, only while SSO is on).
ALTER TABLE organizations ADD COLUMN require_sso INTEGER NOT NULL DEFAULT 0;

-- The organization that manages the account, and since when. Deleting the organization releases
-- its accounts; the release statements also clear the columns below (src/managed.ts).
ALTER TABLE users ADD COLUMN managed_by TEXT REFERENCES organizations (id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN managed_since INTEGER;
-- Set when the organization (or its directory) deactivated the account. status is 'suspended'
-- then too; this marks the suspension as the organization's, so it can lift only its own.
ALTER TABLE users ADD COLUMN deactivated_at INTEGER;
-- A directory's DELETE: deactivated now, deleted by the daily clean-up after this time.
ALTER TABLE users ADD COLUMN delete_after INTEGER;

CREATE INDEX users_managed_by ON users (managed_by) WHERE managed_by IS NOT NULL;
CREATE INDEX users_delete_after ON users (delete_after) WHERE delete_after IS NOT NULL;
