ALTER TABLE repositories ADD COLUMN connection_id TEXT NOT NULL DEFAULT '';
UPDATE repositories SET connection_id=md5(random()::text || clock_timestamp()::text || full_name);
ALTER TABLE jobs ADD COLUMN connection_id TEXT;
ALTER TABLE jobs ADD COLUMN organization_id TEXT;
ALTER TABLE jobs ADD COLUMN installation_id BIGINT;
ALTER TABLE jobs ADD COLUMN claim_token TEXT;
UPDATE jobs SET state='cancelled',lease_until=NULL,last_error='Connection snapshot required'
 WHERE state IN ('pending','running');
-- Ownership changes serialize with guarded writes holding the repository row lock.
CREATE FUNCTION vf_security.rotate_repository_connection() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' OR TG_OP='UPDATE' THEN
  UPDATE public.repositories SET connection_id=md5(random()::text || clock_timestamp()::text || full_name)
   WHERE full_name=OLD.repo;
 END IF;
 IF TG_OP='INSERT' OR TG_OP='UPDATE' THEN
  UPDATE public.repositories SET connection_id=md5(random()::text || clock_timestamp()::text || full_name)
   WHERE full_name=NEW.repo;
 END IF;
 RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION vf_security.rotate_repository_connection() FROM PUBLIC;
CREATE TRIGGER repository_connection_ownership AFTER INSERT OR UPDATE OR DELETE ON repository_ownership
 FOR EACH ROW EXECUTE FUNCTION vf_security.rotate_repository_connection();
