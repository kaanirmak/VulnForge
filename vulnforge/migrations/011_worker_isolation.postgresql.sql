ALTER TABLE public.advisories ADD COLUMN catalog_scope TEXT NOT NULL DEFAULT 'public';

UPDATE public.advisories SET catalog_scope='quarantined_legacy' WHERE source NOT IN ('OSV','GitHub webhook');

ALTER TABLE public.advisory_aliases ADD COLUMN catalog_scope TEXT NOT NULL DEFAULT 'public';

UPDATE public.advisory_aliases SET catalog_scope='quarantined_legacy'
 WHERE advisory_id IN (SELECT id FROM public.advisories WHERE catalog_scope='quarantined_legacy');

CREATE INDEX IF NOT EXISTS advisories_scope_idx ON public.advisories(catalog_scope,updated_at DESC);

CREATE INDEX IF NOT EXISTS advisory_aliases_scope_idx ON public.advisory_aliases(catalog_scope,alias);

ALTER TABLE vf_security.runtime_roles DROP CONSTRAINT runtime_roles_mode_check;

ALTER TABLE vf_security.runtime_roles ADD CONSTRAINT runtime_roles_mode_check CHECK (mode IN ('operator','customer','worker'));

CREATE FUNCTION vf_security.is_worker() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM vf_security.runtime_roles r WHERE r.role_name=session_user AND r.mode='worker') $vf$;

CREATE FUNCTION vf_security.job_id() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT CASE
    WHEN COALESCE(pg_catalog.current_setting('vulnforge.job_id',true),'') ~ '^[1-9][0-9]{0,17}$'
    THEN pg_catalog.current_setting('vulnforge.job_id',true)::bigint
    ELSE NULL END $vf$;

CREATE FUNCTION vf_security.job_catalog_scope() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT CASE
    WHEN vf_security.is_worker() AND COALESCE(pg_catalog.current_setting('vulnforge.catalog_scope',true),'')='private_osv'
      AND COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')<>''
    THEN 'org:'||pg_catalog.current_setting('vulnforge.organization_id',true)
    WHEN vf_security.is_worker() AND COALESCE(pg_catalog.current_setting('vulnforge.catalog_scope',true),'public')='public'
    THEN 'public'
    ELSE '' END $vf$;

CREATE OR REPLACE FUNCTION vf_security.can_advisory(advisory text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (
    SELECT 1 FROM public.advisory_impacts i
    WHERE i.advisory_id=advisory AND vf_security.can_repo(i.repo)
      AND (pg_catalog.left(advisory,4)<>'org:' OR pg_catalog.left(advisory,pg_catalog.length('org:'||vf_security.org_id()||':'))='org:'||vf_security.org_id()||':')) $vf$;

DROP POLICY vf_customer_read ON public.advisories;

CREATE POLICY vf_customer_read ON public.advisories FOR SELECT USING (
  vf_security.is_customer()
  AND catalog_scope IN ('public','org:'||vf_security.org_id())
  AND vf_security.can_advisory(id));

DROP POLICY vf_customer_read ON public.advisory_aliases;

CREATE POLICY vf_customer_read ON public.advisory_aliases FOR SELECT USING (
  vf_security.is_customer()
  AND catalog_scope IN ('public','org:'||vf_security.org_id())
  AND vf_security.can_advisory(advisory_id));

CREATE POLICY vf_worker_read ON public.jobs FOR SELECT USING (
  vf_security.is_worker()
  AND id=vf_security.job_id()
  AND state='running'
  AND claim_token IS NOT NULL
  AND claim_token=COALESCE(pg_catalog.current_setting('vulnforge.claim_token',true),'')
  AND connection_id IS NOT NULL
  AND connection_id=COALESCE(pg_catalog.current_setting('vulnforge.connection_id',true),'')
  AND COALESCE(organization_id,'')=COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')
  AND lease_until>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp()));

CREATE FUNCTION vf_security.can_worker_ownership(repo_name text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_worker() AND EXISTS (
    SELECT 1 FROM public.jobs j
    WHERE j.id=vf_security.job_id()
      AND j.repo=repo_name
      AND j.state='running'
      AND j.claim_token IS NOT NULL
      AND j.claim_token=COALESCE(pg_catalog.current_setting('vulnforge.claim_token',true),'')
      AND j.connection_id IS NOT NULL
      AND j.connection_id=COALESCE(pg_catalog.current_setting('vulnforge.connection_id',true),'')
      AND COALESCE(j.organization_id,'')=COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')
      AND j.lease_until>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())) $vf$;

CREATE POLICY vf_worker_read ON public.repository_ownership FOR SELECT USING (
  vf_security.can_worker_ownership(repo));

CREATE FUNCTION vf_security.can_worker_repository_row(name text, conn text, inst bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_worker()
    AND conn<>''
    AND conn=COALESCE(pg_catalog.current_setting('vulnforge.connection_id',true),'')
    AND EXISTS (
      SELECT 1 FROM public.jobs j
      WHERE j.id=vf_security.job_id()
        AND j.repo=name
        AND j.connection_id=conn
        AND j.installation_id=inst
        AND j.state='running'
        AND j.claim_token IS NOT NULL
        AND j.claim_token=COALESCE(pg_catalog.current_setting('vulnforge.claim_token',true),'')
        AND COALESCE(j.organization_id,'')=COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')
        AND j.lease_until>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp()))
    AND COALESCE((SELECT o.organization_id FROM public.repository_ownership o WHERE o.repo=name),'')
        =COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')
    AND (
      COALESCE(pg_catalog.current_setting('vulnforge.catalog_scope',true),'public')='public'
      OR (pg_catalog.current_setting('vulnforge.catalog_scope',true)='private_osv'
          AND COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')<>'')) $vf$;

CREATE POLICY vf_worker_read ON public.repositories FOR SELECT USING (
  vf_security.can_worker_repository_row(full_name,connection_id,installation_id));

CREATE FUNCTION vf_security.can_worker_repo(name text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_worker() AND EXISTS (
    SELECT 1 FROM public.repositories r
    WHERE r.full_name=name
      AND vf_security.can_worker_repository_row(r.full_name,r.connection_id,r.installation_id)) $vf$;

CREATE FUNCTION vf_security.can_worker_job_insert(repo_name text, inst bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.can_worker_repo(repo_name) AND EXISTS (
    SELECT 1 FROM public.repositories r
    WHERE r.full_name=repo_name AND r.installation_id=inst
      AND vf_security.can_worker_repository_row(r.full_name,r.connection_id,r.installation_id)) $vf$;

CREATE FUNCTION vf_security.can_worker_membership(org text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_worker()
    AND org<>''
    AND org=COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'')
    AND vf_security.can_worker_repo(COALESCE((SELECT j.repo FROM public.jobs j WHERE j.id=vf_security.job_id()),'')) $vf$;

CREATE FUNCTION vf_security.can_worker_scan(scan text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (
    SELECT 1 FROM public.scans s WHERE s.id=scan AND vf_security.can_worker_repo(s.repo)) $vf$;

CREATE FUNCTION vf_security.can_worker_finding(finding bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (
    SELECT 1 FROM public.findings f WHERE f.id=finding AND vf_security.can_worker_repo(f.repo)) $vf$;

CREATE FUNCTION vf_security.can_worker_advisory(advisory text, scope text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_worker()
    AND vf_security.can_worker_repo(COALESCE((SELECT j.repo FROM public.jobs j WHERE j.id=vf_security.job_id()),''))
    AND scope=vf_security.job_catalog_scope()
    AND ((scope='public' AND pg_catalog.left(advisory,4)<>'org:')
      OR (pg_catalog.left(scope,4)='org:' AND pg_catalog.left(advisory,pg_catalog.length(scope)+1)=scope||':')) $vf$;

CREATE POLICY vf_worker_update ON public.repositories FOR UPDATE
  USING (vf_security.can_worker_repository_row(full_name,connection_id,installation_id))
  WITH CHECK (vf_security.can_worker_repository_row(full_name,connection_id,installation_id));

CREATE POLICY vf_worker_update ON public.jobs FOR UPDATE
  USING (vf_security.is_worker() AND id=vf_security.job_id() AND vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.is_worker() AND id=vf_security.job_id() AND vf_security.can_worker_repo(repo)
    AND lease_until>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
    AND lease_until<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())+305);

CREATE POLICY vf_worker_insert ON public.jobs FOR INSERT WITH CHECK (
  vf_security.can_worker_job_insert(repo,installation_id)
  AND state='pending' AND attempts=0 AND claim_token IS NULL AND lease_until IS NULL AND finished_at IS NULL
  AND connection_id=COALESCE(pg_catalog.current_setting('vulnforge.connection_id',true),'')
  AND COALESCE(organization_id,'')=COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),''));

CREATE POLICY vf_worker_read ON public.remediation_policies FOR SELECT USING (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_read ON public.memberships FOR SELECT USING (
  vf_security.can_worker_membership(organization_id));

CREATE POLICY vf_worker_all ON public.findings FOR ALL
  USING (vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_read ON public.suppressions FOR SELECT USING (vf_security.can_worker_finding(finding_id));

CREATE POLICY vf_worker_all ON public.dependency_inventory FOR ALL
  USING (vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_all ON public.scans FOR ALL
  USING (vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_all ON public.scan_findings FOR ALL
  USING (vf_security.can_worker_scan(scan_id))
  WITH CHECK (vf_security.can_worker_scan(scan_id));

CREATE POLICY vf_worker_all ON public.advisory_impacts FOR ALL
  USING (vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_all ON public.advisories FOR ALL
  USING (vf_security.can_worker_advisory(id,catalog_scope))
  WITH CHECK (vf_security.can_worker_advisory(id,catalog_scope));

CREATE POLICY vf_worker_all ON public.advisory_aliases FOR ALL
  USING (vf_security.can_worker_advisory(advisory_id,catalog_scope))
  WITH CHECK (vf_security.can_worker_advisory(advisory_id,catalog_scope));

CREATE POLICY vf_worker_all ON public.remediations FOR ALL
  USING (vf_security.can_worker_repo(repo))
  WITH CHECK (vf_security.can_worker_repo(repo));

CREATE POLICY vf_worker_insert ON public.audit_events FOR INSERT WITH CHECK (
  vf_security.can_worker_repo(repo) AND actor IN ('scanner','system','intelligence'));

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vf_security FROM PUBLIC;
