SET LOCAL search_path=pgws_control,pg_catalog;
ALTER TABLE api_tokens ADD COLUMN id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
CREATE UNIQUE INDEX api_tokens_id ON api_tokens(id);
CREATE INDEX api_tokens_project_list ON api_tokens(tenant_id,project_id,id);
