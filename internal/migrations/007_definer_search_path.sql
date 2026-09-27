-- Explicit pg_temp placement prevents a caller's temporary table from
-- shadowing authority or grants inside the narrowly scoped definer functions.
ALTER FUNCTION pgws_control.lock_authority(uuid) SET search_path=pgws_control,pg_catalog,pg_temp;
ALTER FUNCTION pgws_control.lock_execution_grant(uuid,uuid,uuid) SET search_path=pgws_control,pg_catalog,pg_temp;
ALTER FUNCTION pgws_control.lock_source_reference(uuid,uuid,text,text) SET search_path=pgws_control,pg_catalog,pg_temp;
