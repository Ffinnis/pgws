SET LOCAL search_path=pgws_control,pg_catalog;
ALTER TABLE credentials ADD COLUMN host_revoked_at timestamptz;
ALTER TABLE credentials ADD CONSTRAINT credential_revocation_delivery
 CHECK (host_revoked_at IS NULL OR revoked_at IS NOT NULL);
CREATE INDEX credentials_pending_revocation ON credentials(tenant_id,project_id,workspace_id,generation)
 WHERE host_revoked_at IS NULL;
