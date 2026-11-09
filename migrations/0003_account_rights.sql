-- Account deletion re-authenticates with Google first (docs/DESIGN.md §4.5, §6.3). A sign-in
-- transaction now records why it was started, and for a deletion, whose account it is for.
ALTER TABLE login_tx ADD COLUMN purpose TEXT NOT NULL DEFAULT 'sign_in'
  CHECK (purpose IN ('sign_in', 'delete_account'));
ALTER TABLE login_tx ADD COLUMN user_id TEXT;
