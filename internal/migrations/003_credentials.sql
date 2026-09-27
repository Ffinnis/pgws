-- Only encrypted operation receipts contain credential material. RLS still
-- restricts credential metadata to the authenticated project.
GRANT SELECT ON pgws_control.credentials TO pgws_runtime;
