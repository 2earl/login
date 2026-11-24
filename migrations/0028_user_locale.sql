-- The language an account chose or last used (DESIGN §4.31): 'en', 'tr', … or NULL (not known
-- yet). Emails to the account use it. No CHECK, so adding a language needs no table rebuild; the
-- code accepts only the languages it has.
ALTER TABLE users ADD COLUMN locale TEXT;
