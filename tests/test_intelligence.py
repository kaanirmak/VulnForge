"""New advisory -> project impact -> reviewed upgrade recommendation acceptance tests."""
import asyncio
import json

import pytest

from support import managed_config as Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.intelligence import in_github_range, recommend_updates
from vulnforge.worker import Agent
from test_agent import FakeGitHub, FakeOSV
from test_requirements import LockGitHub, CleanOSV
from test_webhook import setup, signed

AUTH={'Authorization':'Bearer test-admin'}

def intelligence_config(**kwargs):
    return Config(intelligence_mode='public_osv',allow_external_package_metadata=True,
                  osv_allowed_packages=('npm:demo','PyPI:requests'),**kwargs)



def advisory(eco='PyPI',name='demo',target='1.0.1',id_='GHSA-FIXTURE'):
    return {'id':id_,'aliases':['CVE-2099-12345'],'summary':'Fictional test advisory',
            'affected':[{'package':{'name':name,'ecosystem':eco},
                         'ranges':[{'type':'ECOSYSTEM' if eco=='PyPI' else 'SEMVER',
                                    'events':[{'introduced':'0'},{'fixed':target}]}]}]}


@pytest.mark.parametrize('eco,current,target',[
    ('PyPI','1.0.0','1.0.1'),('npm','1.0.0','1.0.1'),('crates.io','1.0.0','1.0.1'),
    ('Packagist','1.0.0','1.0.1'),('Go','v1.0.0','v1.0.1')])
def test_upgrade_recommendations_are_verified_across_supported_ecosystems(eco,current,target):
    calls=[]
    class OSV:
        async def check(self,deps): calls.extend(deps); return []
    async def run():
        dep=Dependency('demo',current,eco,'lock')
        result=(await recommend_updates({dep:[advisory(eco,target=target)]},OSV()))[dep]
        assert result['recommended_version']==target
        assert result['status']=='update_available' and result['upgrade_class']=='patch'
        assert result['requires_review'] and not result['tests_verified'] and not result['release_verified']
        assert result['verified_at']
    asyncio.run(run())
    assert calls[0].version==target


def test_target_with_another_advisory_is_not_recommended():
    class OSV:
        async def check(self,deps): return [(deps[0],{'id':'OTHER'})]
    async def run():
        dep=Dependency('demo','1.0.0','npm','package-lock.json')
        result=(await recommend_updates({dep:[advisory('npm')]},OSV()))[dep]
        assert result['recommended_version'] is None
        assert result['status']=='target_still_affected'
    asyncio.run(run())


def test_next_documented_fix_is_tried_when_first_is_still_affected():
    class OSV:
        async def check(self,deps): return [(deps[0],{'id':'OTHER'})] if deps[0].version=='1.0.1' else []
    async def run():
        dep=Dependency('demo','1.0.0','npm','package-lock.json')
        record=advisory('npm')
        record['affected'][0]['ranges'][0]['events'] += [{'introduced':'2.0.0'},{'fixed':'2.0.1'}]
        result=(await recommend_updates({dep:[record]},OSV()))[dep]
        assert result['recommended_version']=='2.0.1' and result['upgrade_class']=='major'
    asyncio.run(run())


def test_no_fix_and_failed_target_query_stay_explicit():
    class OSV:
        async def check(self,deps): raise RuntimeError('fixture timeout')
    async def run():
        dep=Dependency('demo','1.0.0','PyPI','requirements.txt')
        nofix=advisory();nofix['affected'][0]['ranges'][0]['events']=[{'introduced':'0'}]
        missing=(await recommend_updates({dep:[nofix]},OSV()))[dep]
        failed=(await recommend_updates({dep:[advisory()]},OSV()))[dep]
        assert missing['status']=='no_known_fix' and missing['recommended_version'] is None
        assert failed['status']=='verification_failed' and failed['recommended_version'] is None
    asyncio.run(run())


def test_current_version_unstable_or_unsupported_is_not_guessed():
    async def run():
        dep=Dependency('demo','1.0.0-beta.1','npm','package-lock.json')
        result=(await recommend_updates({dep:[advisory('npm')]},CleanOSV()))[dep]
        assert result['status']=='unsupported_version'
        assert result['recommended_version'] is None
    asyncio.run(run())


def test_periodic_audit_persists_project_impact_and_suggestion_without_auto_pr(tmp_path):
    async def run():
        store=Store(str(tmp_path/'db'))
        store.upsert_repo('o/r',1,'main')
        gh=FakeGitHub()
        await Agent(intelligence_config(enable_auto_pr=False),store,gh,FakeOSV()).audit('o/r',1,'main')
        impact=store.list_impacts()['items'][0]
        assert impact['repo']=='o/r' and impact['state']=='affected'
        assert impact['evidence']['dependencies'][0]['version']=='2.27.0'
        assert not impact['evidence']['coverage_complete']
        assert impact['recommendations'][0]['recommended_version'] is None
        assert impact['recommendations'][0]['previous_recommended_version']=='2.31.0'
        assert impact['recommendations'][0]['status']=='needs_reverification'
        assert gh.prs==[]
        assert store.list_advisories()[0]['affected_projects']==1
        assert store.list_impacts(advisory_id='GHSA-TEST')['items'][0]['id']==impact['id']
    asyncio.run(run())


def test_impacts_follow_upgrade_and_failed_audit_does_not_look_safe(tmp_path):
    class MutableOSV:
        affected=True
        fail=False
        async def check(self,deps):
            if self.fail: raise RuntimeError('fixture timeout')
            return [(d,advisory('npm')) for d in deps if self.affected and d.version=='1.0.0']
    async def run():
        store=Store(str(tmp_path/'db'));osv=MutableOSV()
        store.upsert_repo('o/r',1,'main')
        agent=Agent(intelligence_config(),store,LockGitHub(),osv)
        await agent.audit('o/r',1,'main')
        assert store.list_impacts()['items'][0]['state']=='affected'
        osv.fail=True
        with pytest.raises(RuntimeError): await agent.audit('o/r',1,'main')
        impact=store.list_impacts()['items'][0]
        assert impact['state']=='under_investigation' and impact['recommendations']==[]
        osv.fail=False;osv.affected=False
        await agent.audit('o/r',1,'main')
        assert store.list_impacts()['items'][0]['state']=='not_affected'
    asyncio.run(run())


def ghsa_body(action='published',target='1.0.1',range_='>= 1.0.0, < 1.0.1'):
    return json.dumps({'action':action,'security_advisory':{
        'ghsa_id':'GHSA-NEW-FIXTURE','cve_id':'CVE-2099-54321','summary':'Synthetic new advisory',
        'updated_at':'2099-01-01T00:00:00Z',
        'vulnerabilities':[{'package':{'ecosystem':'npm','name':'demo'},
                            'vulnerable_version_range':range_,
                            'first_patched_version':{'identifier':target}}]}}).encode()


def test_new_advisory_is_matched_before_osv_index_update_and_rechecked(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/affected',1,'main');store.upsert_repo('o/unrelated',2,'main')
    store.replace_inventory('o/affected',[Dependency('demo','1.0.0','npm','package-lock.json')])
    store.replace_inventory('o/unrelated',[Dependency('other','1.0.0','npm','package-lock.json')])
    body=ghsa_body()
    response=client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    assert response.json()['queued']==1
    pending=client.get('/api/v1/impacts',headers=AUTH).json()['items'][0]
    assert pending['state']=='under_investigation'
    async def run():
        agent=Agent(intelligence_config(),store,LockGitHub(),CleanOSV())
        await agent.process(store.claim())
        await agent.audit('o/affected',1,'main')  # OSV still hasn't indexed the new event.
    asyncio.run(run())
    result=client.get('/api/v1/impacts?advisory_id=CVE-2099-54321',headers=AUTH).json()['items'][0]
    assert result['repo']=='o/affected' and result['state']=='affected'
    assert result['evidence']['source']=='GitHub webhook'
    assert result['recommendations'][0]['recommended_version']=='1.0.1'
    assert client.get('/api/v1/advisories',headers=AUTH).json()[0]['affected_projects']==1


def test_ghsa_fix_still_inside_new_range_is_rejected_even_if_osv_has_no_record(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    body=ghsa_body(target='1.0.1',range_='>= 1.0.0, < 1.0.2')
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    asyncio.run(Agent(intelligence_config(),store,LockGitHub(),CleanOSV()).process(store.claim()))
    result=store.list_impacts()['items'][0]['recommendations'][0]
    assert result['recommended_version'] is None and result['previous_status']=='target_still_affected'


def test_unknown_range_is_never_declared_not_affected(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    body=ghsa_body(range_='^1.0.0')
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    asyncio.run(Agent(intelligence_config(),store,LockGitHub(),CleanOSV()).process(store.claim()))
    impact=store.list_impacts()['items'][0]
    assert impact['state']=='under_investigation' and impact['recommendations']==[]


def test_same_package_with_nonaffected_version_is_not_an_affected_project(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    body=ghsa_body()
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    gh=LockGitHub('{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.2"}}}')
    asyncio.run(Agent(intelligence_config(),store,gh,CleanOSV()).process(store.claim()))
    assert store.list_impacts()['items'][0]['state']=='not_affected'
    assert store.list_advisories()[0]['affected_projects']==0


def test_withdrawal_invalidates_suggestions_and_stale_osv_cannot_resurrect_it(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    first=ghsa_body()
    client.post('/github/webhook',content=first,headers=signed('security_advisory',first))
    agent=Agent(intelligence_config(),store,LockGitHub(),CleanOSV())
    asyncio.run(agent.process(store.claim()))
    withdrawn=ghsa_body(action='withdrawn')
    client.post('/github/webhook',content=withdrawn,headers=signed('security_advisory',withdrawn))
    assert store.list_impacts()['items'][0]['state']=='withdrawn'
    store.save_advisory(advisory('npm',id_='GHSA-NEW-FIXTURE'))
    assert store.advisory('GHSA-NEW-FIXTURE')['withdrawn']
    assert store.list_impacts()['items'][0]['recommendations']==[]


def test_intelligence_api_auth_filters_pagination_and_refresh_idempotency(tmp_path):
    client,store=setup(tmp_path)
    for i in range(3):
        repo=f'o/r{i}';store.upsert_repo(repo,1,'main')
        id_=store.save_advisory(advisory(id_=f'GHSA-{i}'))
        store.save_impact(repo,id_,'affected',None,{},[])
    for path in ('/api/v1/impacts','/api/v1/advisories'):
        assert client.get(path).status_code==401
    assert client.post('/api/v1/intelligence/refresh').status_code==401
    first=client.get('/api/v1/impacts?limit=2',headers=AUTH).json()
    assert len(first['items'])==2 and first['next_cursor']
    second=client.get('/api/v1/impacts',params={'cursor':first['next_cursor']},headers=AUTH).json()
    assert len(second['items'])==1 and second['next_cursor'] is None
    assert len(client.get('/api/v1/impacts?repo=o/r1',headers=AUTH).json()['items'])==1
    assert client.post('/api/v1/intelligence/refresh',headers=AUTH).json()['queued']==3
    assert client.post('/api/v1/intelligence/refresh',headers=AUTH).json()['queued']==0
    assert client.post('/api/v1/intelligence/refresh?repo=missing/repo',headers=AUTH).status_code==404


@pytest.mark.parametrize('expression,expected',[
    ('>= 1.0.0, < 1.0.1',True),('< 1.0.0',False),('<= 1.0.0',True),
    ('< 0.9.0 || >= 1.0.0, < 2.0.0',True),('^1.0.0',None),('>= 1.0.0-beta.1',None)])
def test_explicit_github_range_comparisons(expression,expected):
    assert in_github_range('1.0.0','npm',expression) is expected


def test_older_webhook_cannot_override_a_newer_range_and_aliases_are_retained(tmp_path):
    store=Store(str(tmp_path/'db'))
    newer={'id':'GHSA-EXAMPLE','aliases':[],'summary':'new','modified':'2099-02-01T00:00:00Z',
           'vulnerabilities':[]}
    store.save_advisory(newer,'GitHub webhook')
    store.save_advisory({**newer,'summary':'old','aliases':['CVE-2099-12345'],
                         'modified':'2099-01-01T00:00:00Z'},'GitHub webhook')
    assert store.advisory('GHSA-EXAMPLE')['summary']=='new'
    assert 'CVE-2099-12345' in store.advisory('GHSA-EXAMPLE')['aliases']


def test_withdrawal_closes_only_related_findings_and_records_history(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    body=ghsa_body()
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    asyncio.run(Agent(intelligence_config(),store,LockGitHub(),CleanOSV()).process(store.claim()))
    store.save_finding('o/r','other','dependency','high','Other',None,'a'*40,{'advisory_id':'UNRELATED'})
    body=ghsa_body(action='withdrawn')
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    rows=store.list_rows('findings')
    assert next(r for r in rows if r['key']=='other')['status']=='open'
    assert next(r for r in rows if r['key']!='other')['status']=='resolved'
    assert any(e['action']=='advisory_withdrawn' for e in store.list_rows('audit_events'))


def test_newer_explicit_github_event_can_reinstate_withdrawn_advisory(tmp_path):
    store=Store(str(tmp_path/'db'))
    store.save_advisory({'id':'GHSA-EXAMPLE','withdrawn':'2099-01-01T00:00:00Z',
                         'modified':'2099-01-01T00:00:00Z'},'GitHub webhook')
    store.save_advisory({'id':'GHSA-EXAMPLE','modified':'2099-02-01T00:00:00Z'},'GitHub webhook')
    assert not store.advisory('GHSA-EXAMPLE')['withdrawn']


def test_github_first_patched_version_string_contract(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    data=json.loads(ghsa_body())
    data['security_advisory']['vulnerabilities'][0]['first_patched_version']='1.0.1'
    body=json.dumps(data).encode()
    client.post('/github/webhook',content=body,headers=signed('security_advisory',body))
    asyncio.run(Agent(intelligence_config(),store,LockGitHub(),CleanOSV()).process(store.claim()))
    recommendation=store.list_impacts()['items'][0]['recommendations'][0]
    assert recommendation['recommended_version']=='1.0.1'


def test_candidate_queries_are_batched_and_duplicate_manifest_targets_coalesced():
    calls=[]
    class OSV:
        async def check(self,deps):
            calls.append(deps)
            return [(d,{'id':'OTHER'}) for d in deps if d.name=='vulnerable-target']
    async def run():
        deps=[Dependency('demo','1.0.0','npm','a/package-lock.json'),
              Dependency('demo','1.0.0','npm','b/package-lock.json'),
              Dependency('vulnerable-target','1.0.0','npm','c/package-lock.json')]
        output=await recommend_updates({d:[advisory('npm',name=d.name)] for d in deps},OSV())
        assert output[deps[0]]['recommended_version']=='1.0.1'
        assert output[deps[1]]['recommended_version']=='1.0.1'
        assert output[deps[2]]['recommended_version'] is None
    asyncio.run(run())
    assert len(calls)==1 and len(calls[0])==2


def test_ghsa_and_osv_cross_alias_linking_and_revision_history(tmp_path):
    client,store=setup(tmp_path)
    store.upsert_repo('o/r',1,'main')
    # 1. OSV advisory arrives first under PYSEC ID with a CVE alias (no GHSA yet)
    first_id=store.save_advisory({
        'id':'PYSEC-2026-42',
        'aliases':['CVE-2026-4242'],
        'summary':'Initial PYSEC report',
        'modified':'2026-01-10T00:00:00Z',
    },source='OSV')
    assert first_id=='PYSEC-2026-42'
    store.save_impact('o/r',first_id,'affected',None,{'advisory_sha256':store.advisory(first_id)['source_sha256']},[])
    store.save_finding('o/r','dep:pysec42','dependency','high','requests affected','requirements.txt','a'*40,
                       {'advisory_id':'PYSEC-2026-42','osv_id':'PYSEC-2026-42','aliases':['CVE-2026-4242']})

    # 2. Signed GitHub security_advisory webhook arrives with GHSA ID and the same CVE in identifiers
    webhook_payload=json.dumps({
        'action':'updated',
        'security_advisory':{
            'ghsa_id':'GHSA-4242-xxxx-yyyy',
            'cve_id':None,
            'identifiers':[{'type':'GHSA','value':'GHSA-4242-xxxx-yyyy'},{'type':'CVE','value':'CVE-2026-4242'}],
            'summary':'Updated GHSA range',
            'updated_at':'2026-02-01T00:00:00Z',
            'vulnerabilities':[{'package':{'ecosystem':'pip','name':'requests'},'vulnerable_version_range':'< 2.31.0'}],
        }
    }).encode()
    res=client.post('/github/webhook',content=webhook_payload,headers=signed('security_advisory',webhook_payload))
    assert res.status_code==202

    # Both aliases resolve to the canonical GHSA record and preserve revision history
    by_ghsa=store.advisory('GHSA-4242-xxxx-yyyy')
    by_cve=store.advisory('CVE-2026-4242')
    by_pysec=store.advisory('PYSEC-2026-42')
    assert by_ghsa is not None and by_cve['id']=='GHSA-4242-xxxx-yyyy' and by_pysec['id']=='GHSA-4242-xxxx-yyyy'
    assert set(by_ghsa['aliases'])>={'GHSA-4242-xxxx-yyyy','CVE-2026-4242','PYSEC-2026-42'}
    assert by_ghsa['revision_count']==2
    assert [r['source'] for r in by_ghsa['revisions']]==['OSV','GitHub webhook']

    # 3. Subsequent OSV record without GHSA in its payload still resolves to GHSA-4242-xxxx-yyyy via CVE alias
    merged_id=store.save_advisory({
        'id':'PYSEC-2026-42',
        'aliases':['CVE-2026-4242'],
        'summary':'Lagging OSV sync',
        'modified':'2026-01-15T00:00:00Z',
    },source='OSV')
    assert merged_id=='GHSA-4242-xxxx-yyyy'
    after_lag=store.advisory('GHSA-4242-xxxx-yyyy')
    assert after_lag['summary']=='Updated GHSA range'
    assert after_lag['revision_count']==3
    assert after_lag['revisions'][-1]['superseded'] is True

    # 4. Withdrawing GHSA also withdraws linked PYSEC finding and impact
    withdrawn_payload=json.dumps({
        'action':'withdrawn',
        'security_advisory':{
            'ghsa_id':'GHSA-4242-xxxx-yyyy',
            'cve_id':'CVE-2026-4242',
            'summary':'Withdrawn advisory',
            'updated_at':'2026-03-01T00:00:00Z',
            'withdrawn_at':'2026-03-01T00:00:00Z',
            'vulnerabilities':[],
        }
    }).encode()
    client.post('/github/webhook',content=withdrawn_payload,headers=signed('security_advisory',withdrawn_payload))
    assert store.advisory('CVE-2026-4242')['withdrawn']==1
    assert store.list_rows('findings')[0]['status']=='resolved'
    assert all(i['state']=='withdrawn' for i in store.list_impacts(advisory_id='CVE-2026-4242')['items'])
