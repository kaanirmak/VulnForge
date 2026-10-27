import asyncio
import json
from pathlib import Path

import httpx
import pytest

from vulnforge.runner_upload import upload,UploadError,token_endpoint,destination,main
from test_privacy import report_fixture

ENV={'GITHUB_ACTIONS':'true','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'fixture-runtime-token',
     'ACTIONS_ID_TOKEN_REQUEST_URL':'https://pipelines.actions.githubusercontent.com/job/oidctoken?api-version=2.0'}
SERVER='https://vulnforge.example'


def fixture(tmp_path):
    path=tmp_path/'report.json';path.write_text(json.dumps(report_fixture()));return path


def test_report_upload_uses_separate_credentials_and_only_canonical_metadata(tmp_path):
    path=fixture(tmp_path);calls=[]
    def handler(request):
        calls.append(request)
        if request.method=='GET':
            assert request.url.host=='pipelines.actions.githubusercontent.com'
            assert request.url.params['audience']==SERVER+'/api/v1/runner/reports'
            assert request.headers['authorization']=='Bearer fixture-runtime-token'
            return httpx.Response(200,json={'value':'header.payload.signature'},headers={'Set-Cookie':'private=value'})
        assert str(request.url)==SERVER+'/api/v1/runner/reports'
        assert request.headers['authorization']=='Bearer header.payload.signature'
        assert 'cookie' not in request.headers and b'fixture-runtime-token' not in request.content
        data=json.loads(request.content)
        assert data['repo']=='org/service' and 'source' not in data
        return httpx.Response(202,json={'receipt_id':'c'*64,'duplicate':False,
            'trust_state':'identity_verified_quarantined','baseline_ready':False,'ignored_private':'do-not-print'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result=await upload(path,SERVER,consent=True,client=client,environ=ENV)
            assert set(result)=={'receipt_id','duplicate','trust_state','baseline_ready'}
    asyncio.run(run());assert len(calls)==2


@pytest.mark.parametrize('url',[
    'http://pipelines.actions.githubusercontent.com/job/oidctoken?api-version=2.0',
    'https://attacker.example/oidctoken?api-version=2.0',
    'https://pipelines.actions.githubusercontent.com.attacker.example/oidctoken?api-version=2.0',
    'https://user:secret@pipelines.actions.githubusercontent.com/oidctoken?api-version=2.0',
    'https://pipelines.actions.githubusercontent.com:8443/oidctoken?api-version=2.0',
    'https://pipelines.actions.githubusercontent.com/arbitrary?api-version=2.0',
    'https://pipelines.actions.githubusercontent.com/job/oidctoken?api-version=2.0&audience=attacker',
    'https://pipelines.actions.githubusercontent.com/job/oidctoken?api-version=2.0#fragment',
])
def test_request_credential_never_goes_to_an_untrusted_endpoint(url):
    with pytest.raises(UploadError): token_endpoint(url,SERVER)


def test_no_consent_or_source_payload_never_causes_network_access(tmp_path):
    path=fixture(tmp_path)
    def handler(request): raise AssertionError('No request may leave')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(UploadError): await upload(path,SERVER,client=client,environ=ENV)
            path.write_text(json.dumps({**report_fixture(),'source':'private-code'}))
            with pytest.raises(ValueError): await upload(path,SERVER,consent=True,client=client,environ=ENV)
            path.unlink();path.symlink_to(tmp_path/'outside')
            with pytest.raises(OSError): await upload(path,SERVER,consent=True,client=client,environ=ENV)
    asyncio.run(run())


def test_loopback_upload_requires_explicit_preview_permission():
    with pytest.raises(UploadError): destination('http://127.0.0.1:8000')
    assert destination('http://127.0.0.1:8000',True).startswith('http://127.0.0.1:8000/')
    for invalid in ('https://user:secret@example.com','https://example.com/path','https://example.com?token=private'):
        with pytest.raises(UploadError): destination(invalid)


@pytest.mark.parametrize('response',[
    lambda request:httpx.Response(302,headers={'Location':'https://attacker.example'}),
    lambda request:httpx.Response(500,json={'error':'private-provider-marker'}),
    lambda request:httpx.Response(200,content=b'x'*32769),
])
def test_error_redirect_or_large_response_never_leaks_provider_details(tmp_path,response):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
            with pytest.raises(UploadError) as failure:
                await upload(fixture(tmp_path),SERVER,consent=True,client=client,environ=ENV)
            assert 'private-provider-marker' not in str(failure.value)
    asyncio.run(run())


def test_cli_failure_omits_private_paths_and_tokens(tmp_path,capsys,monkeypatch):
    monkeypatch.delenv('GITHUB_ACTIONS',raising=False)
    result=main(['--report',str(tmp_path/'private-file-name'),'--server',SERVER,'--consent-metadata-upload'])
    assert result==2 and 'private-file-name' not in capsys.readouterr().err


def test_malformed_hosts_are_rejected_before_http_or_credentials():
    for origin in ('https://example%zz.com','https://bad..example.com','https://-bad.example.com'):
        with pytest.raises(UploadError): destination(origin)
    with pytest.raises(UploadError):
        token_endpoint('https://bad%.actions.githubusercontent.com/job/oidctoken?api-version=2.0',SERVER)
