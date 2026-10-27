-- Existing jobs lack a verified connection snapshot and must not be replayed.
ALTER TABLE repositories ADD COLUMN connection_id TEXT NOT NULL DEFAULT '';
UPDATE repositories SET connection_id=lower(hex(randomblob(16)));
ALTER TABLE jobs ADD COLUMN connection_id TEXT;
ALTER TABLE jobs ADD COLUMN organization_id TEXT;
ALTER TABLE jobs ADD COLUMN installation_id INTEGER;
ALTER TABLE jobs ADD COLUMN claim_token TEXT;
UPDATE jobs SET state='cancelled',lease_until=NULL,last_error='Connection snapshot required'
 WHERE state IN ('pending','running');
CREATE TRIGGER repository_connection_insert AFTER INSERT ON repository_ownership BEGIN
 UPDATE repositories SET connection_id=lower(hex(randomblob(16))) WHERE full_name=NEW.repo;
END;
CREATE TRIGGER repository_connection_update AFTER UPDATE ON repository_ownership BEGIN
 UPDATE repositories SET connection_id=lower(hex(randomblob(16))) WHERE full_name IN (OLD.repo,NEW.repo);
END;
CREATE TRIGGER repository_connection_delete AFTER DELETE ON repository_ownership BEGIN
 UPDATE repositories SET connection_id=lower(hex(randomblob(16))) WHERE full_name=OLD.repo;
END;
