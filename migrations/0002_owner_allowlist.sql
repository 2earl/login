-- Locked launch (DESIGN D9): the owner's Google account may sign in. This email entry is
-- replaced by the account's Google subject on the first successful sign-in
-- (src/users.ts pinAllowlistToSubject). The address is already public on 2earl.com/imprint.
INSERT INTO allowlist (id, kind, value, added_by, created_at)
VALUES ('owner-initial', 'email', 'ffrhtd@gmail.com', 'migration-0002', 1762628400);
