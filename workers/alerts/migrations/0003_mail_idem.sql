-- One replay key per mail occurrence; the alerts table is keyed by event code.
CREATE TABLE mail_idem (
  key TEXT PRIMARY KEY,
  at INTEGER NOT NULL
);
CREATE INDEX mail_idem_at ON mail_idem(at);
