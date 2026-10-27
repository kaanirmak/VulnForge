-- Dedicated VulnForge database only. Customer role grants are provisioned separately.

CREATE SCHEMA vf_security;

REVOKE ALL ON SCHEMA vf_security FROM PUBLIC;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE vf_security.runtime_roles (role_name TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK(mode IN ('operator','customer')));

INSERT INTO vf_security.runtime_roles VALUES(current_user,'operator');

CREATE FUNCTION vf_security.is_internal() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM vf_security.runtime_roles r WHERE r.role_name=session_user AND r.mode='operator') $vf$;

CREATE FUNCTION vf_security.is_customer() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM vf_security.runtime_roles r WHERE r.role_name=session_user AND r.mode='customer') $vf$;

CREATE FUNCTION vf_security.org_id() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT COALESCE(pg_catalog.current_setting('vulnforge.organization_id',true),'') $vf$;

CREATE FUNCTION vf_security.actor_id() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT (SELECT s.user_id FROM public.user_sessions s WHERE vf_security.is_customer()
    AND s.token_hash=pg_catalog.current_setting('vulnforge.session_hash',true)
    AND s.expires_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
    AND s.last_seen_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())-1800) $vf$;

CREATE FUNCTION vf_security.member_of(org text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_customer() AND (vf_security.org_id()='' OR vf_security.org_id()=org)
    AND EXISTS (SELECT 1 FROM public.memberships m WHERE m.organization_id=org AND m.user_id=vf_security.actor_id()) $vf$;

CREATE FUNCTION vf_security.org_role() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT (SELECT m.role FROM public.memberships m WHERE m.organization_id=vf_security.org_id()
    AND m.user_id=vf_security.actor_id()) $vf$;

CREATE FUNCTION vf_security.permits(action text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT COALESCE(CASE
    WHEN action IN ('project.read','finding.read','scan.read','impact.read','export.read')
      THEN vf_security.org_role() IN ('org_admin','maintainer','analyst','viewer','auditor')
    WHEN action='finding.triage' THEN vf_security.org_role() IN ('org_admin','maintainer','analyst')
    WHEN action='finding.suppress' THEN vf_security.org_role() IN ('org_admin','maintainer')
    WHEN action='audit.read' THEN vf_security.org_role() IN ('org_admin','auditor')
    ELSE false END,false) $vf$;

CREATE FUNCTION vf_security.can_repo(name text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT vf_security.is_customer() AND vf_security.org_id()<>'' AND EXISTS (
    SELECT 1 FROM public.repository_ownership o JOIN public.memberships m ON m.organization_id=o.organization_id
    WHERE o.repo=name AND o.organization_id=vf_security.org_id() AND m.user_id=vf_security.actor_id()) $vf$;

CREATE FUNCTION vf_security.can_finding(finding bigint) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM public.findings f WHERE f.id=finding AND vf_security.can_repo(f.repo)) $vf$;

CREATE FUNCTION vf_security.can_scan(scan text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM public.scans s WHERE s.id=scan AND vf_security.can_repo(s.repo)) $vf$;

CREATE FUNCTION vf_security.can_advisory(advisory text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT EXISTS (SELECT 1 FROM public.advisory_impacts i WHERE i.advisory_id=advisory AND vf_security.can_repo(i.repo)) $vf$;

CREATE FUNCTION vf_security.migration_history() RETURNS TABLE(version integer,checksum text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$
 SELECT s.version,s.checksum FROM public.schema_migrations s $vf$;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.users FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.users FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.users FOR SELECT USING (vf_security.is_customer() AND (id=vf_security.actor_id()));

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.organizations FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.organizations FOR SELECT USING (vf_security.is_customer() AND (vf_security.member_of(id)));

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.memberships FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.memberships FOR SELECT USING (vf_security.is_customer() AND (user_id=vf_security.actor_id() AND (vf_security.org_id()='' OR organization_id=vf_security.org_id())));

ALTER TABLE public.repository_ownership ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.repository_ownership FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.repository_ownership FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.repository_ownership FOR SELECT USING (vf_security.is_customer() AND (organization_id=vf_security.org_id() AND vf_security.member_of(organization_id)));

ALTER TABLE public.repositories ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.repositories FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.repositories FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.repositories FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(full_name)));

ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.findings FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.findings FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.findings FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(repo)));

ALTER TABLE public.dependency_inventory ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.dependency_inventory FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.dependency_inventory FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.dependency_inventory FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(repo)));

ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.remediations FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.remediations FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.remediations FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(repo)));

ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.scans FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.scans FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.scans FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(repo)));

ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.scan_findings FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.scan_findings FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.scan_findings FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_scan(scan_id)));

ALTER TABLE public.advisory_impacts ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.advisory_impacts FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.advisory_impacts FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.advisory_impacts FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_repo(repo)));

ALTER TABLE public.advisories ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.advisories FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.advisories FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.advisories FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_advisory(id)));

ALTER TABLE public.advisory_aliases ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.advisory_aliases FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.advisory_aliases FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.advisory_aliases FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_advisory(advisory_id)));

ALTER TABLE public.suppressions ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.suppressions FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.suppressions FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.suppressions FOR SELECT USING (vf_security.is_customer() AND (vf_security.can_finding(finding_id)));

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.audit_events FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_read ON public.audit_events FOR SELECT USING (vf_security.is_customer() AND (vf_security.permits('audit.read') AND (vf_security.can_repo(repo) OR repo='organization:'||vf_security.org_id())));

ALTER TABLE public.jobs ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.jobs FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

ALTER TABLE public.deliveries ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.deliveries FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

ALTER TABLE public.runner_reports ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.runner_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY vf_internal ON public.runner_reports FOR ALL USING (vf_security.is_internal()) WITH CHECK (vf_security.is_internal());

CREATE POLICY vf_customer_triage ON public.findings FOR UPDATE
 USING (vf_security.can_repo(repo) AND (vf_security.permits('finding.triage') OR (status='suppressed' AND EXISTS (SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())))))
 WITH CHECK (vf_security.can_repo(repo) AND (
 (vf_security.permits('finding.triage') AND status IN ('open','resolved')) OR
 (vf_security.permits('finding.suppress') AND status='suppressed' AND EXISTS (
  SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id
  AND s.expires_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
  AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())+31622400)) OR (status='open' AND EXISTS (SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())))));

CREATE POLICY vf_customer_suppress ON public.suppressions FOR INSERT WITH CHECK (
  vf_security.permits('finding.suppress') AND vf_security.can_finding(finding_id)
  AND expires_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
  AND expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())+31622400
  AND pg_catalog.length(reason) BETWEEN 5 AND 2000);

CREATE POLICY vf_customer_unsuppress ON public.suppressions FOR DELETE USING (vf_security.permits('finding.triage') AND vf_security.can_finding(finding_id));

CREATE POLICY vf_customer_audit ON public.audit_events FOR INSERT WITH CHECK (
  vf_security.can_repo(repo) AND details::jsonb->>'organization_id'=vf_security.org_id() AND (
   (actor=vf_security.actor_id() AND action='triage' AND vf_security.permits('finding.triage')
    AND EXISTS (SELECT 1 FROM public.findings f WHERE f.id=finding_id AND f.repo=audit_events.repo)) OR
   (actor=vf_security.actor_id() AND action='scan_export_requested' AND finding_id IS NULL
    AND EXISTS (SELECT 1 FROM public.scans s WHERE s.id=details::jsonb->>'scan_id' AND s.repo=audit_events.repo)) OR
   (actor='system' AND action='suppression_expired' AND EXISTS (
    SELECT 1 FROM public.findings f JOIN public.suppressions s ON s.finding_id=f.id
    WHERE f.id=audit_events.finding_id AND f.repo=audit_events.repo AND f.status='open'
    AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())))));

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vf_security FROM PUBLIC;

REVOKE ALL ON public.users,public.organizations,public.memberships,public.repository_ownership,public.repositories,public.findings,public.dependency_inventory,public.remediations,public.scans,public.scan_findings,public.advisory_impacts,public.advisories,public.advisory_aliases,public.suppressions,public.audit_events,public.jobs,public.deliveries,public.runner_reports,public.auth_states,public.user_sessions,public.schema_migrations FROM PUBLIC;
