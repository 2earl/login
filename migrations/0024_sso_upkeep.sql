-- Phase 10h: single sign-on that keeps working (DESIGN §4.25).

-- The identity provider's next signing certificate, accepted alongside the current one, so a
-- certificate change at the provider doesn't stop sign-in. Expiry times are read from the
-- certificates when they're saved (NULL for a bare public key).
ALTER TABLE org_saml ADD COLUMN certificate_next TEXT;
ALTER TABLE org_saml ADD COLUMN certificate_expires_at INTEGER;
ALTER TABLE org_saml ADD COLUMN certificate_next_expires_at INTEGER;
-- The last expiry warning sent to owners, as '<expires_at>:<days>'; reset when saved.
ALTER TABLE org_saml ADD COLUMN expiry_notice TEXT;

-- When the client secret expires, if the owner says (Entra ID's secrets do).
ALTER TABLE org_oidc ADD COLUMN secret_expires_at INTEGER;
ALTER TABLE org_oidc ADD COLUMN expiry_notice TEXT;
