-- Account deletion reaches every 2earl service (DESIGN §4.8). Written in the same transaction as
-- the deletion, one row per service in src/services.ts, and deleted once that service confirms
-- it has deleted its data. Holds only the deleted account's internal ID: nothing else about the
-- person remains to link it to.
CREATE TABLE deletion_notices (
  service         TEXT    NOT NULL,
  user_id         TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER,
  -- The error's name only (e.g. "TypeError"), never its message.
  last_error      TEXT,
  PRIMARY KEY (service, user_id)
) STRICT;
