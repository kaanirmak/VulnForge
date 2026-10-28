"""Expiry, invalidation and tenant-safe snapshot evidence, with no provider traffic."""
import asyncio
import copy
import json
import time

import pytest

from test_database import pg_store,pg_customer
from test_organization import seed,config,client_for,ROOT
from test_agent import FakeOSV
from test_requirements import LockGitHub
from support import managed_config
from vulnforge.api import create_app
from vulnforge.auth import AuthSessions,digest
from vulnforge.db import Store
from vulnforge.freshness import (age_state,assess_scan,repository_evidence,
                                recommendation_view,INVENTORY_MAX_AGE,INTELLIGENCE_MAX_AGE)
from vulnforge.organization import OrganizationData
from vulnforge.reports import sbom,sarif
from vulnforge.worker import Agent


def complete_scan(now=None):
    now=time.time() if now is None else now
    return {'id':'a'*32,'repo':'o/r','kind':'dependencies','commit_sha':'a'*40,'state':'complete',
            'started_at':now-20,'finished_at':now-5,'coverage':{
                'scope':'dependency_manifests','default_branch':'main','files_total':1,
                'files_scanned':1,'files_skipped':0,'issues':[],
                'manifests':[{'path':'package-lock.json','sha256':'b'*64}],
                'intelligence_checked_at':now-10,'intelligence_source':'public_osv'},
            'dependencies':[],'findings':[]}


def write_scan(store,repo='o/r'):
    data=complete_scan();data['repo']=repo
    id_=store.start_scan(repo,'dependencies',data['commit_sha'])
    data['coverage']['intelligence_checked_at']=time.time()
    store.finish_scan(id_,'complete',data['coverage'])
    return store.scan(id_)


def record(store,scan):
    id_=store.save_advisory({'id':'GHSA-FRESHNESS','summary':'Synthetic issue','modified':'2026-01-01T00:00:00Z'})
    rec={'package':'demo','ecosystem':'npm','current_version':'1.0.0','recommended_version':'1.0.1',
         'status':'update_available','verified_at':scan['coverage']['intelligence_checked_at'],
         'release_verified':False,'tests_verified':False}
    evidence={'advisory_sha256':store.advisory(id_)['source_sha256'],'coverage_complete':True}
    store.save_impact(scan['repo'],id_,'not_affected',scan['id'],evidence,[rec])
    return id_,rec


@pytest.mark.parametrize('value,expected',[(None,'unknown'),(True,'unknown'),('1','unknown'),
    (float('nan'),'unknown'),(float('inf'),'unknown'),(-1,'unknown'),(0,'unknown'),
    (1001,'unknown'),(999,'fresh'),(900,'stale'),(901,'fresh')])
def test_age_boundaries_and_untrusted_timestamp_types(value,expected):
    assert age_state(value,1000,100)==expected


def test_fresh_complete_snapshot_is_never_history_head_or_safety_proof():
    result=assess_scan(complete_scan(1000),1000,'main')
    assert result['status']=='fresh_snapshot' and result['reasons']==[]
    assert result['history']=='not_verified' and result['snapshot_only']
    assert not result['safe'] and not result['current_head_verified']


@pytest.mark.parametrize('key,value,reason',[
    ('kind','pr_dependencies','not_default_branch_inventory'),
    ('kind','commit','not_default_branch_inventory'),
    ('state','running','scan_running'),('state','failed','scan_failed'),
    ('state','incomplete','scan_incomplete'),('commit_sha',None,'snapshot_sha_unverified'),
    ('finished_at',None,'inventory_unknown'),('finished_at',1001,'inventory_unknown'),
])
def test_incomplete_or_unbound_scan_cannot_be_fresh(key,value,reason):
    scan=complete_scan(1000);scan[key]=value
    result=assess_scan(scan,1000,'main')
    assert result['status']=='needs_review' and reason in result['reasons']


@pytest.mark.parametrize('key,value,reason',[
    ('scope','changed_files','snapshot_scope_unverified'),
    ('issues',[{'reason':'transitive_graph_unavailable'}],'incomplete_coverage'),
    ('files_skipped',1,'incomplete_coverage'),('files_total',0,'manifest_coverage_unverified'),
    ('files_total',True,'manifest_coverage_unverified'),('files_scanned',None,'manifest_coverage_unverified'),
    ('manifests',[],'manifest_coverage_unverified'),('default_branch','old','default_branch_unverified'),
    ('intelligence_checked_at',1,'intelligence_stale'),
    ('intelligence_checked_at',99999,'intelligence_unknown'),
    ('intelligence_source','disabled','intelligence_source_unverified'),
])
def test_coverage_and_source_proof_fail_closed(key,value,reason):
    scan=complete_scan(10000);scan['coverage'][key]=value
    result=assess_scan(scan,10000,'main')
    assert result['status']=='needs_review' and reason in result['reasons']


def test_inventory_and_feed_expire_independently_and_without_mutating_history():
    scan=complete_scan(100000);original=copy.deepcopy(scan)
    assert assess_scan(scan,100000+INTELLIGENCE_MAX_AGE)['intelligence_age']=='stale'
    expired=assess_scan(scan,100000+INVENTORY_MAX_AGE)
    assert expired['inventory_age']=='stale' and expired['intelligence_age']=='stale'
    assert scan==original


def test_recommendation_expiry_retains_prior_version_but_removes_current_candidate():
    rec={'status':'update_available','recommended_version':'1.0.1','verified_at':999}
    original=copy.deepcopy(rec)
    view=recommendation_view(rec,{'status':'fresh_snapshot'},1000)
    assert view['recommended_version']=='1.0.1'
    for timestamp in (None,0,True,1001,1000-INTELLIGENCE_MAX_AGE):
        stale=recommendation_view({**rec,'verified_at':timestamp},{'status':'fresh_snapshot'},1000)
        assert stale['recommended_version'] is None and stale['previous_recommended_version']=='1.0.1'
        assert stale['status']=='needs_reverification'
    assert rec==original


@pytest.fixture(params=['sqlite','postgresql'])
def evidence_store(request,tmp_path):
    return (Store(str(tmp_path/'db')) if request.param=='sqlite' else request.getfixturevalue('pg_store'))


def test_empty_and_pr_scans_are_not_default_inventory(evidence_store):
    store=evidence_store;store.upsert_repo('o/r',1,'main')
    scan=store.start_scan('o/r','pr_dependencies','a'*40)
    store.finish_scan(scan,'complete',complete_scan()['coverage'])
    with store.conn() as c: assert repository_evidence(c,'o/r')['status']=='missing'


@pytest.mark.parametrize('state',['incomplete','failed','running'])
def test_latest_failure_or_running_scan_invalidates_previous_success(evidence_store,state):
    store=evidence_store;store.upsert_repo('o/r',1,'main');write_scan(store)
    scan=store.start_scan('o/r','dependencies','b'*40)
    if state!='running': store.finish_scan(scan,state,{'issues':[{'reason':'provider_error'}]})
    with store.conn() as c:
        result=repository_evidence(c,'o/r')
        assert result['scan_id']==scan and result['status']=='needs_review'


def test_push_invalidation_and_branch_change_require_a_new_snapshot(evidence_store):
    store=evidence_store;store.upsert_repo('o/r',1,'main');write_scan(store)
    with store.conn() as c: assert repository_evidence(c,'o/r')['status']=='fresh_snapshot'
    store.invalidate_repository_evidence('o/r')
    with store.conn() as c:
        assert 'default_branch_push_since_snapshot' in repository_evidence(c,'o/r')['reasons']
        # Even a scan that began before the push and finished afterwards is conservatively invalid.
        c.execute('UPDATE scans SET finished_at=?',(time.time(),))
        assert repository_evidence(c,'o/r')['status']=='needs_review'
    store.upsert_repo('o/r',1,'new-main')
    with store.conn() as c: assert 'default_branch_unverified' in repository_evidence(c,'o/r')['reasons']


def test_revision_expiry_and_superseded_impact_never_claim_current_negative(evidence_store):
    store=evidence_store;store.upsert_repo('o/r',1,'main');scan=write_scan(store)
    id_,rec=record(store,scan)
    assert store.list_impacts()['items'][0]['assessment_state']=='not_affected'
    store.save_advisory({'id':id_,'summary':'Changed range','modified':'2026-02-01T00:00:00Z'})
    view=store.list_impacts()['items'][0]
    assert view['observed_state']=='not_affected' and view['state']==view['assessment_state']=='under_investigation'
    assert 'advisory_revision_unverified' in view['freshness']['reasons']
    assert view['recommendations'][0]['recommended_version'] is None
    # Read-time expiry does not rewrite the stored recommendation or old observation.
    with store.conn() as c:
        stored=c.execute('SELECT recommendations,state FROM advisory_impacts').fetchone()
        assert json.loads(stored['recommendations'])[0]==rec and stored['state']=='not_affected'
    write_scan(store)
    assert 'impact_snapshot_superseded' in store.list_impacts()['items'][0]['freshness']['reasons']


def test_timestamp_tie_cannot_choose_a_successful_baseline_arbitrarily(evidence_store):
    store=evidence_store;store.upsert_repo('o/r',1,'main');scan=write_scan(store)
    another=store.start_scan('o/r','dependencies','b'*40)
    with store.conn() as c:
        c.execute('UPDATE scans SET started_at=? WHERE id=?',(scan['started_at'],another))
        result=repository_evidence(c,'o/r')
    assert result['status']=='needs_review' and 'scan_order_ambiguous' in result['reasons']


@pytest.mark.parametrize('ref,deleted,invalidated',[
    ('refs/heads/main',False,True),('refs/heads/main',True,True),('refs/heads/feature',False,False)])
def test_customer_runner_default_push_invalidates_without_creating_source_jobs(tmp_path,ref,deleted,invalidated):
    from fastapi.testclient import TestClient
    store=Store(str(tmp_path/'db'))
    from vulnforge.config import Config
    client=TestClient(create_app(Config(webhook_secret='test-secret',admin_token='test-admin'),store))
    store.upsert_repo('o/r',1,'main');write_scan(store)
    data={'installation':{'id':1},'repository':{'full_name':'o/r','default_branch':'main'},
          'ref':ref,'deleted':deleted,'before':'a'*40,'after':'b'*40,'commits':[]}
    body=json.dumps(data).encode()
    # Use the configured fixture secret through an explicit local signature.
    import hmac,hashlib
    headers={'X-GitHub-Event':'push','X-GitHub-Delivery':'freshness-push',
             'X-Hub-Signature-256':'sha256='+hmac.new(b'test-secret',body,hashlib.sha256).hexdigest()}
    assert client.post('/github/webhook',content=body,headers=headers).status_code==202
    assert store.list_rows('jobs')==[]
    with store.conn() as c:
        assert repository_evidence(c,'o/r')['status']==('needs_review' if invalidated else 'fresh_snapshot')


@pytest.mark.parametrize('role',['org_admin','maintainer','analyst','viewer','auditor'])
def test_pg_all_roles_see_invalidation_without_reading_operator_audit(pg_store,pg_customer,role):
    members,orgs,repos,scans,findings=seed(pg_store)
    write_scan(pg_store,repos['alpha'])
    cfg=config(pg_store);token,_=AuthSessions(pg_store,cfg).create(members['alpha_'+role]['id'])
    customer=OrganizationData(pg_customer,orgs['alpha'],members['alpha_'+role]['id'],digest(token))
    assert customer.rows('repositories')['items'][0]['evidence_status']['status']=='fresh_snapshot'
    pg_store.invalidate_repository_evidence(repos['alpha'])
    result=customer.rows('repositories')['items']
    assert len(result)==1 and result[0]['full_name']==repos['alpha']
    assert result[0]['evidence_status']['status']=='needs_review'
    assert 'bravo' not in json.dumps(result)


def test_exports_explicitly_preserve_snapshot_and_history_limits(tmp_path):
    store=Store(str(tmp_path/'db'));store.upsert_repo('o/r',1,'main');data=write_scan(store)
    scan=store.scan(data['id'])
    properties=sbom(scan)['metadata']['properties']
    status=json.loads(next(p['value'] for p in properties if p['name']=='vulnforge:evidence_status'))
    assert status['history']=='not_verified' and not status['safe']
    assert sarif(scan)['runs'][0]['properties']['evidence_status']==status
    store.invalidate_repository_evidence('o/r')
    changed=store.scan(data['id'])
    assert changed['evidence_status']['status']=='needs_review'
    assert 'default_branch_push_since_snapshot' in changed['evidence_status']['reasons']


def test_worker_records_checked_source_branch_and_timestamp_without_real_provider(tmp_path):
    store=Store(str(tmp_path/'db'));store.upsert_repo('o/r',1,'main')
    cfg=managed_config(intelligence_mode='public_osv',allow_external_package_metadata=True,
                       osv_allowed_packages=('npm:demo',))
    asyncio.run(Agent(cfg,store,LockGitHub(),FakeOSV()).audit('o/r',1,'main'))
    scan=store.scan(store.list_rows('scans')[0]['id'])
    assert scan['coverage']['intelligence_source']=='public_osv'
    assert scan['coverage']['default_branch']=='main'
    assert scan['started_at']<=scan['coverage']['intelligence_checked_at']<=scan['finished_at']
    assert scan['evidence_status']['status']=='fresh_snapshot'


def test_customer_and_operator_views_suppress_expired_candidate_without_erasing_history(tmp_path):
    store=Store(str(tmp_path/'db'));members,orgs,repos,scans,findings=seed(store)
    scan=write_scan(store,repos['alpha']);advisory,rec=record(store,scan)
    details={'update_recommendation':rec,'advisory_id':advisory,'scan_id':scan['id'],
             'advisory_sha256':store.advisory(advisory)['source_sha256']}
    finding={'key':'snapshot-finding','title':'Synthetic finding','severity':'high',
             'category':'dependency','file_path':'package-lock.json','details':details}
    store.record_scan_finding(scan['id'],finding)
    store.save_finding(repos['alpha'],'snapshot-finding','dependency','high','Synthetic finding',
                       'package-lock.json','a'*40,details)
    # Keep the report timeline consistent while expiring only the intelligence window.
    coverage=copy.deepcopy(scan['coverage']);coverage['intelligence_checked_at']-=4000
    with store.conn() as c:
        c.execute('UPDATE scans SET started_at=started_at-4000,finished_at=finished_at-4000,coverage=? WHERE id=?',
                  (json.dumps(coverage),scan['id']))
    cfg=config(store);app=create_app(cfg,store)
    client,_=client_for(app,store,cfg,members['alpha_viewer'])
    root=ROOT+'/'+orgs['alpha']
    candidate=next(i for i in client.get(root+'/impacts').json()['items'] if i['advisory_id']==advisory)
    assert candidate['assessment_state']=='under_investigation'
    assert candidate['recommendations'][0]['recommended_version'] is None
    assert candidate['recommendations'][0]['previous_recommended_version']=='1.0.1'
    assert 'bravo' not in json.dumps(candidate)
    rows=client.get(root+'/findings').json()['items']
    current=next(i for i in rows if i['key']=='snapshot-finding')
    assert current['details']['update_recommendation']['recommended_version'] is None
    for suffix in ('','/sarif','/sbom'):
        response=client.get(root+'/scans/'+scan['id']+suffix)
        assert response.status_code==200 and 'needs_review' in response.text
    headers={'Authorization':'Bearer operator-only'}
    for path in ('/api/findings','/api/v1/findings'):
        response=client.get(path,headers=headers);assert response.status_code==200
        rows=response.json() if isinstance(response.json(),list) else response.json()['items']
        current=next(i for i in rows if i['key']=='snapshot-finding')
        details=json.loads(current['details']) if isinstance(current['details'],str) else current['details']
        assert details['update_recommendation']['recommended_version'] is None
    with store.conn() as c:
        stored=json.loads(c.execute('SELECT recommendations FROM advisory_impacts WHERE advisory_id=?',
                                    (advisory,)).fetchone()[0])
    assert stored[0]['recommended_version']=='1.0.1'


def test_push_invalidation_timestamp_survives_database_transfer(tmp_path,pg_store):
    from vulnforge.migrate import import_sqlite
    source=Store(str(tmp_path/'source.db'));source.upsert_repo('o/r',1,'main');write_scan(source)
    source.invalidate_repository_evidence('o/r')
    assert import_sqlite(source.path,pg_store.path)['verified']
    assert source.repository('o/r')['evidence_invalidated_at']==pg_store.repository('o/r')['evidence_invalidated_at']
    with pg_store.conn() as c:
        assert 'default_branch_push_since_snapshot' in repository_evidence(c,'o/r')['reasons']
