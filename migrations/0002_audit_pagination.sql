CREATE INDEX audit_events_organization_order ON audit_events(organization_id, created_at DESC, id DESC);
