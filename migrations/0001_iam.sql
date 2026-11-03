PRAGMA foreign_keys = ON;
CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE oidc_providers (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id),
  issuer TEXT NOT NULL, client_id TEXT NOT NULL
);
CREATE TABLE users (
  id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
  UNIQUE (issuer, subject)
);
-- Memberships are explicitly provisioned; signing in never grants organization access.
CREATE TABLE memberships (
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK (role IN ('admin','member')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE login_transactions (
  state_hash TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
  verifier TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
  user_id TEXT NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL,
  FOREIGN KEY (organization_id, user_id) REFERENCES memberships(organization_id, user_id)
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE audit_events (
  id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
  user_id TEXT, action TEXT NOT NULL, created_at INTEGER NOT NULL
);
