CREATE OR REPLACE FUNCTION vf_security.permits(action text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $vf$ SELECT COALESCE(CASE
    WHEN action IN ('project.read','finding.read','scan.read','impact.read','export.read')
      THEN vf_security.org_role() IN ('org_admin','maintainer','analyst','viewer','auditor')
    WHEN action='finding.triage' THEN vf_security.org_role() IN ('org_admin','maintainer','analyst')
    WHEN action IN ('finding.suppress','finding.accept_risk') THEN vf_security.org_role() IN ('org_admin','maintainer')
    WHEN action='audit.read' THEN vf_security.org_role() IN ('org_admin','auditor')
    ELSE false END,false) $vf$;

DROP POLICY vf_customer_triage ON public.findings;

CREATE POLICY vf_customer_triage ON public.findings FOR UPDATE
 USING (vf_security.can_repo(repo) AND (vf_security.permits('finding.triage') OR (status IN ('suppressed','risk_accepted') AND EXISTS (SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())))))
 WITH CHECK (vf_security.can_repo(repo) AND (
 (vf_security.permits('finding.triage') AND status IN ('open','resolved','false_positive') AND NOT EXISTS (
  SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id)) OR
 (((vf_security.permits('finding.suppress') AND status='suppressed') OR
   (vf_security.permits('finding.accept_risk') AND status='risk_accepted')) AND EXISTS (
  SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id
  AND s.expires_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
  AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())+31622400)) OR (status='open' AND EXISTS (SELECT 1 FROM public.suppressions s WHERE s.finding_id=findings.id AND s.expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())))));

DROP POLICY vf_customer_suppress ON public.suppressions;

CREATE POLICY vf_customer_suppress ON public.suppressions FOR INSERT WITH CHECK (
  (vf_security.permits('finding.suppress') OR vf_security.permits('finding.accept_risk'))
  AND vf_security.can_finding(finding_id)
  AND expires_at>EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())
  AND expires_at<=EXTRACT(EPOCH FROM pg_catalog.statement_timestamp())+31622400
  AND pg_catalog.length(reason) BETWEEN 5 AND 2000);

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vf_security FROM PUBLIC;
