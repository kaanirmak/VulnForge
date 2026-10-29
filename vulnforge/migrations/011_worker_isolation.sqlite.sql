ALTER TABLE advisories ADD COLUMN catalog_scope TEXT NOT NULL DEFAULT 'public';
UPDATE advisories SET catalog_scope='quarantined_legacy' WHERE source NOT IN ('OSV','GitHub webhook');
ALTER TABLE advisory_aliases ADD COLUMN catalog_scope TEXT NOT NULL DEFAULT 'public';
UPDATE advisory_aliases SET catalog_scope='quarantined_legacy'
 WHERE advisory_id IN (SELECT id FROM advisories WHERE catalog_scope='quarantined_legacy');
CREATE INDEX IF NOT EXISTS advisories_scope_idx ON advisories(catalog_scope,updated_at DESC);
CREATE INDEX IF NOT EXISTS advisory_aliases_scope_idx ON advisory_aliases(catalog_scope,alias);

