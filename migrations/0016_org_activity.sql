-- An organization's activity page (DESIGN §4.14) reads the audit log by organization: index the
-- `org` its events carry, newest first. Only events about an organization have one.
CREATE INDEX audit_events_org ON audit_events (json_extract(detail, '$.org'), at)
  WHERE json_extract(detail, '$.org') IS NOT NULL;
