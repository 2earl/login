-- Prompt share's sharing by email (DESIGN §4.8): looking an account up by a verified address.
CREATE INDEX identities_verified_email ON identities (email COLLATE NOCASE) WHERE email_verified = 1;
