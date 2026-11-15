-- Phase 10i: SAML settings from the identity provider's metadata URL, read again daily
-- (DESIGN §4.26).
ALTER TABLE org_saml ADD COLUMN metadata_url TEXT;
ALTER TABLE org_saml ADD COLUMN metadata_checked_at INTEGER;
-- Why the last read failed or wasn't applied, in words for the owner; NULL when it worked.
ALTER TABLE org_saml ADD COLUMN metadata_error TEXT;
