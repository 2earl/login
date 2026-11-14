-- Phase 10f: the organization's audit log, downloaded or streamed (DESIGN §4.23).
CREATE TABLE org_audit_streams (
  org_id            TEXT    PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  -- Where events are sent: the organization's own https endpoint.
  url               TEXT    NOT NULL,
  -- The signing secret, AES-GCM with MFA_ENCRYPTION_KEY bound to the organization.
  secret_enc        TEXT    NOT NULL,
  enabled           INTEGER NOT NULL DEFAULT 1,
  -- The last event delivered: (at, id), in the order events are read.
  cursor_at         INTEGER NOT NULL,
  cursor_id         TEXT    NOT NULL DEFAULT '',
  failures          INTEGER NOT NULL DEFAULT 0,
  next_attempt_at   INTEGER NOT NULL DEFAULT 0,
  last_status       TEXT,
  last_delivered_at INTEGER,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;

-- The organization's sign-ins: events by the accounts it manages, in time order.
CREATE INDEX audit_events_actor_at ON audit_events (actor_user_id, at);
