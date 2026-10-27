"""Privacy acceptance: no network by default, no raw code accepted, no trust by upload."""
import asyncio
import copy
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.db import Store
from vulnforge.dependencies import Dependency
from vulnforge.github import GitHub
from vulnforge.osv import OSV
from vulnforge.privacy import MetadataPolicy, PrivacyError, path_id
from vulnforge.runner_report import RunnerReport, parse_report
from vulnforge.worker import Agent
from test_webhook import signed
from support import managed_config


def report_fixture():
    path=path_id('backend/package-lock.json')
    return {'report_version':'1','scan_mode':'customer_runner','repo':'org/service',
            'commit_sha':'a'*40,'scan_kind':'dependencies',
            'coverage':{'state':'complete','files_total':1,'files_scanned':1,'files_skipped':0,
                        'dependency_scope':'resolved'},
            'manifests':[{'path_id':path,'sha256':'b'*64}],
            'dependencies':[{'name':'demo','version':'1.2.3','ecosystem':'npm','path_id':path}]}


def report_client(tmp_path):
    cfg=Config(webhook_secret='test-webhook-secret',admin_token='admin',operator_report_token='report-operator',
               database_path=str(tmp_path/'db'))
    store=Store(cfg.database_path);store.upsert_repo('org/service',1,'main')
    return TestClient(create_app(cfg,store)),store


OPERATOR={'Authorization':'Bearer report-operator'}
REPORT_PATH='/api/v1/operator/runner-reports'


def test_config_defaults_and_environment_are_private(monkeypatch):
    for key in ('SCAN_MODE','ALLOW_MANAGED_SOURCE_ACCESS','MANAGED_SCAN_CONSENT_ID','INTELLIGENCE_MODE',
                'ALLOW_EXTERNAL_PACKAGE_METADATA','ENABLE_AUTO_PR','ENABLE_KEV','ENABLE_CHECKS',
                'OSV_ALLOWED_PACKAGES','PRIVATE_PACKAGE_PATTERNS','OPERATOR_REPORT_TOKEN','ADMIN_TOKEN'):
        monkeypatch.delenv(key,raising=False)
    cfg=Config.from_env()
    assert cfg.scan_mode=='customer_runner' and not cfg.source_access_allowed
    assert cfg.intelligence_mode=='disabled' and not cfg.allow_external_package_metadata
    with pytest.raises(PrivacyError): cfg.require_source_access()


@pytest.mark.parametrize('kwargs',[
    {'scan_mode':'managed'},
    {'scan_mode':'managed','allow_managed_source_access':True},
    {'scan_mode':'managed','allow_managed_source_access':True,'managed_scan_consent_id':'bad\nreference'},
    {'enable_auto_pr':True}, {'scan_mode':'silent-fallback'},
    {'allow_managed_source_access':'false'},
    {'intelligence_mode':'public_osv'},
    {'intelligence_mode':'private_osv'},
    {'operator_report_token':'same','admin_token':'same'},
    {'enable_kev':True},
])
def test_invalid_or_incomplete_consent_fails_closed(kwargs):
    with pytest.raises((ValueError,PrivacyError)): Config(**kwargs)


def test_managed_mode_requires_every_explicit_setting():
    cfg=managed_config()
    cfg.require_source_access()
    assert cfg.source_access_allowed


def test_default_github_cannot_issue_tokens_or_read_files_even_with_cached_credentials():
    calls=[]
    def handler(req): calls.append(req);raise AssertionError('Network must remain unused')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(Config(app_id='1',private_key_path='/must/not/be/read'),client)
            gh.tokens[1]=('cached-token',time.time()+3600)
            for operation in (gh.token(1),gh.get_file('org/service',1,'app.py','a'*40)):
                with pytest.raises(PrivacyError): await operation
            with pytest.raises(PrivacyError): gh.app_jwt()
    asyncio.run(run())
    assert calls==[]


def test_managed_token_permissions_are_read_only_by_default():
    payloads=[]
    def handler(req):
        payloads.append(json.loads(req.content))
        return httpx.Response(200,json={'token':'fixture-token','expires_at':'2099-01-01T00:00:00Z'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            gh=GitHub(managed_config(),client);gh.app_jwt=lambda:'fixture-jwt'
            await gh.token(1)
    asyncio.run(run())
    assert payloads==[{'permissions':{'metadata':'read','contents':'read','pull_requests':'read'}}]


def test_default_osv_and_disabled_advisory_query_send_nothing():
    calls=[]
    def handler(req): calls.append(req);raise AssertionError('No external request expected')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            osv=OSV(client=client)
            with pytest.raises(PrivacyError): await osv.check([Dependency('private','1','PyPI','requirements.txt')])
            with pytest.raises(PrivacyError): await osv.advisory('GHSA-FIXTURE')
    asyncio.run(run())
    assert calls==[]


def test_whole_inventory_is_preflighted_before_first_osv_batch():
    calls=[]
    def handler(req): calls.append(req);raise AssertionError('A later private package must block earlier batches')
    async def run():
        deps=[Dependency(f'public-{n}','1.0.0','npm','lock') for n in range(101)]
        deps.append(Dependency('private','1.0.0','npm','lock'))
        policy=MetadataPolicy('public_osv',True,tuple('npm:'+d.name for d in deps[:-1]))
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(PrivacyError): await OSV(client=client,policy=policy).check(deps)
    asyncio.run(run())
    assert calls==[]


def test_explicit_allowlist_is_normalized_and_private_patterns_override_it():
    dep=Dependency('My_Package','1.0.0','PyPI','requirements.txt')
    policy=MetadataPolicy('public_osv',True,('PyPI:My.Package',))
    policy.require_packages([dep],'https://api.osv.dev')
    denied=MetadataPolicy('public_osv',True,('PyPI:My.Package',),('PyPI:my_*',))
    with pytest.raises(PrivacyError): denied.require_packages([dep],'https://api.osv.dev')
    with pytest.raises(ValueError): MetadataPolicy('public_osv',True,('PyPI:*',))


@pytest.mark.parametrize('url',[
    'http://api.osv.dev','https://api.osv.dev.attacker.invalid','https://api.osv.dev@attacker.invalid',
    'https://api.osv.dev?secret=token','https://api.osv.dev/#fragment','https://api.osv.dev/v1/other',
])
def test_public_provider_cannot_be_redirected_by_configuration(url):
    policy=MetadataPolicy('public_osv',True,('npm:demo',))
    with pytest.raises(PrivacyError): policy.require_packages([Dependency('demo','1.0.0','npm','lock')],url)


def test_private_osv_endpoint_contract():
    policy=MetadataPolicy('private_osv')
    policy.require_packages([Dependency('internal','1','PyPI','lock')],'https://osv.internal.example')
    with pytest.raises(PrivacyError): policy.require_endpoint('https://api.osv.dev')
    with pytest.raises(PrivacyError): policy.require_endpoint('http://osv.internal.example')


def test_default_push_does_not_queue_source_fetch_or_store_commit_messages(tmp_path):
    client,store=report_client(tmp_path)
    source='confidential source code'
    body=json.dumps({'installation':{'id':1},'repository':{'full_name':'org/service'},
        'before':'a'*40,'after':'b'*40,'ref':'refs/heads/main','commits':[{'id':'b'*40,'message':source}]}).encode()
    response=client.post('/github/webhook',content=body,headers=signed('push',body))
    assert response.json()['queued']==0
    assert store.list_rows('jobs')==[]
    assert source not in json.dumps(store.list_rows('repositories'))


def test_legacy_dependency_job_is_failed_without_source_fallback(tmp_path):
    class NoSource:
        async def default_branch(self,*args): raise AssertionError('No source API call permitted')
    async def run():
        store=Store(str(tmp_path/'db'));store.upsert_repo('org/service',1,'main')
        agent=Agent(Config(),store,NoSource(),None)
        with pytest.raises(PrivacyError): await agent.audit('org/service',1,'main')
        assert store.list_rows('scans')[0]['state']=='failed'
    asyncio.run(run())


def test_valid_report_is_quarantined_and_idempotent_never_promoted_to_inventory(tmp_path):
    client,store=report_client(tmp_path)
    response=client.post(REPORT_PATH,json=report_fixture(),headers=OPERATOR)
    assert response.status_code==202 and response.json()['trust_state']=='quarantined'
    duplicate=client.post(REPORT_PATH,json=report_fixture(),headers=OPERATOR)
    assert duplicate.json()['duplicate']
    assert store.list_rows('dependency_inventory')==[] and store.list_rows('scans')==[]
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM runner_reports').fetchone()[0]==1
        data=c.execute('SELECT report FROM runner_reports').fetchone()[0]
        assert 'backend/package-lock.json' not in data
    assert any(e['action']=='runner_report_quarantined' for e in store.list_rows('audit_events'))
    assert 'dependencies' not in response.json()


def test_report_requires_separate_operator_token_and_existing_repository(tmp_path):
    client,store=report_client(tmp_path)
    for headers in ({},{'Authorization':'Bearer admin'}):
        assert client.post(REPORT_PATH,json=report_fixture(),headers=headers).status_code==401
    unknown=report_fixture();unknown['repo']='org/missing'
    assert client.post(REPORT_PATH,json=unknown,headers=OPERATOR).status_code==404
    disabled=TestClient(create_app(Config(database_path=str(tmp_path/'other')),Store(str(tmp_path/'other'))))
    assert disabled.post(REPORT_PATH,json=report_fixture(),headers=OPERATOR).status_code==503


@pytest.mark.parametrize('field',['source','source_code','diff','snippet','evidence','contents','raw','stdout','token','tenant_id','installation_id'])
def test_unknown_report_fields_are_rejected_without_echo_or_storage(tmp_path,field,caplog):
    client,store=report_client(tmp_path)
    secret='ghp_'+'A'*36
    payload=report_fixture();payload[field]=secret
    response=client.post(REPORT_PATH,json=payload,headers=OPERATOR)
    assert response.status_code==422 and secret not in response.text and secret not in caplog.text
    with store.conn() as c:
        assert c.execute('SELECT COUNT(*) FROM runner_reports').fetchone()[0]==0


@pytest.mark.parametrize('location',['dependency','finding','manifest','coverage'])
def test_nested_source_fields_cannot_be_smuggled_into_metadata(tmp_path,location):
    client,_=report_client(tmp_path);payload=report_fixture()
    if location=='dependency': payload['dependencies'][0]['source']='eval(secret)'
    elif location=='manifest': payload['manifests'][0]['contents']='secret file'
    elif location=='finding':
        payload['findings']=[{'rule_id':'js-eval','severity':'high','path_id':path_id('app.js'),
                              'line':1,'fingerprint':'c'*64,'evidence':'secret file'}]
    else: payload['coverage']['reasons']={'secret file':1}
    assert client.post(REPORT_PATH,json=payload,headers=OPERATOR).status_code==422


def test_credential_disguised_as_package_name_is_rejected(tmp_path):
    client,_=report_client(tmp_path);payload=report_fixture()
    payload['dependencies'][0]['ecosystem']='PyPI'
    secret='ghp_'+'B'*36;payload['dependencies'][0]['name']=secret
    response=client.post(REPORT_PATH,json=payload,headers=OPERATOR)
    assert response.status_code==422 and secret not in response.text


@pytest.mark.parametrize('change',[
    {'files_scanned':0}, {'files_total':True}, {'files_total':'1'},
    {'files_total':2,'files_skipped':1}, {'unresolved_dependencies':1},
    {'dependency_scope':'declared'}, {'reasons':{'parse_error':1}},
])
def test_false_complete_coverage_claims_are_rejected(change):
    payload=report_fixture();payload['coverage'].update(change)
    with pytest.raises(ValidationError): RunnerReport.model_validate(payload)


def test_duplicate_json_keys_and_duplicate_observations_are_rejected(tmp_path):
    client,_=report_client(tmp_path)
    payload=json.dumps(report_fixture())
    duplicate=payload[:-1]+',"source":"secret","source":""}'
    assert client.post(REPORT_PATH,content=duplicate,headers=OPERATOR).status_code==422
    fixture=report_fixture();fixture['dependencies'].append(copy.deepcopy(fixture['dependencies'][0]))
    assert client.post(REPORT_PATH,json=fixture,headers=OPERATOR).status_code==422


def test_oversized_encoded_and_deep_json_are_rejected(tmp_path):
    client,_=report_client(tmp_path)
    assert client.post(REPORT_PATH,content=b' '*1_000_001,headers=OPERATOR).status_code==413
    assert client.post(REPORT_PATH,json=report_fixture(),headers={**OPERATOR,'Content-Encoding':'gzip'}).status_code==415
    assert client.post(REPORT_PATH,content='['*2000+']'*2000,headers=OPERATOR).status_code==422


def test_mutated_or_constructed_models_are_revalidated_at_storage_boundary(tmp_path):
    store=Store(str(tmp_path/'db'));store.upsert_repo('org/service',1,'main')
    report=RunnerReport.model_validate(report_fixture())
    report.dependencies.append({'name':'secret','source':'hidden source'})
    with pytest.raises(ValidationError): store.quarantine_runner_report(report)
    with pytest.raises(TypeError): store.quarantine_runner_report(report_fixture())


def test_uninstall_removes_quarantined_reports(tmp_path):
    client,store=report_client(tmp_path)
    client.post(REPORT_PATH,json=report_fixture(),headers=OPERATOR)
    store.remove_repo('org/service')
    with store.conn() as c: assert c.execute('SELECT COUNT(*) FROM runner_reports').fetchone()[0]==0


@pytest.mark.parametrize('unsafe',['/home/user/secret.py','../secret.py','a/../secret.py','a\\secret.py','a//file','https://example.invalid/file'])
def test_path_pseudonyms_require_relative_safe_paths(unsafe):
    with pytest.raises(ValueError): path_id(unsafe)


def test_privacy_status_is_authenticated_and_does_not_claim_customer_readiness(tmp_path):
    client,_=report_client(tmp_path)
    assert client.get('/api/v1/privacy').status_code==401
    data=client.get('/api/v1/privacy',headers={'Authorization':'Bearer admin'}).json()
    assert not data['server_source_access'] and not data['customer_ingestion_ready']
    assert not data['tenant_isolation_ready'] and not data['source_upload_allowed']
