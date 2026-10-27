import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from vulnforge.api import create_app
from vulnforge.config import Config
from vulnforge.db import Store,StaleJob
from vulnforge.worker import run_leased_job
from test_job_scope import queue,claim
from test_database import pg_store


def test_heartbeat_renews_only_live_claim(queue):
    job=claim(queue)
    with queue.conn() as c:
        c.execute('UPDATE jobs SET lease_until=? WHERE id=?',(time.time()+2,job['id']))
    async def work(): await asyncio.sleep(.05);return 'finished'
    assert asyncio.run(run_leased_job(queue,job,work(),heartbeat=.01,timeout=2))=='finished'
    with queue.conn() as c:
        assert c.execute('SELECT lease_until FROM jobs WHERE id=?',(job['id'],)).fetchone()[0]>time.time()+250
    queue.finish(job)
    with pytest.raises(StaleJob): queue.renew_job(job)


def test_revocation_or_timeout_cancels_pending_work_and_cleans_up(queue):
    job=claim(queue);cleaned=[]
    async def work():
        try: await asyncio.sleep(10)
        finally: cleaned.append(True)
    async def revoke():
        await asyncio.sleep(.03)
        with queue.conn() as c: c.execute("UPDATE jobs SET claim_token='another-worker' WHERE id=?",(job['id'],))
    async def run():
        revoker=asyncio.create_task(revoke())
        try:
            with pytest.raises(StaleJob):
                await run_leased_job(queue,job,work(),heartbeat=.01,timeout=2)
        finally: await revoker
        with pytest.raises(TimeoutError):
            await run_leased_job(queue,job,work(),heartbeat=1,timeout=.01)
    asyncio.run(run())
    assert len(cleaned)==2


def fail_four_times(store):
    job=claim(store)
    for attempt in range(1,5):
        assert job['attempts']==attempt
        store.finish(job,'RuntimeError')
        if attempt<4:
            with store.conn() as c:
                row=c.execute('SELECT available_at FROM jobs WHERE id=?',(job['id'],)).fetchone()
                assert row[0]>time.time()+20
                c.execute('UPDATE jobs SET available_at=0 WHERE id=?',(job['id'],))
            job=store.claim()
    return job


def test_dead_letter_retry_is_scoped_audited_and_single_use(queue):
    failed=fail_four_times(queue)
    letters=queue.dead_letters()
    assert len(letters)==1 and letters[0]['finished_at'] and 'payload' not in letters[0]
    assert queue.claim() is None
    assert queue.retry_dead_letter(failed['id'])['state']=='pending'
    with pytest.raises(ValueError): queue.retry_dead_letter(failed['id'])
    new=queue.claim()
    assert new['id']!=failed['id'] and new['attempts']==1
    queue.check_job(new)
    assert any(a['action']=='dead_letter_retried' for a in queue.list_rows('audit_events'))


def test_old_organization_payload_is_not_replayed(queue):
    failed=fail_four_times(queue)
    from test_job_scope import own
    own(queue)
    with pytest.raises(StaleJob): queue.retry_dead_letter(failed['id'])
    assert queue.claim() is None


def test_dead_letter_operator_api_authentication(tmp_path):
    store=Store(str(tmp_path/'db'));store.upsert_repo('alpha/project',11,'main')
    failed=fail_four_times(store)
    with TestClient(create_app(Config(admin_token='operator-test'),store)) as client:
        path='/api/v1/operator/jobs/dead-letters'
        assert client.get(path).status_code==401
        headers={'Authorization':'Bearer operator-test'}
        assert client.get(path,headers=headers).json()['items'][0]['id']==failed['id']
        retry=f'/api/v1/operator/jobs/{failed["id"]}/retry'
        assert client.post(retry).status_code==401
        assert client.post(retry,headers=headers).status_code==202
        assert client.post(retry,headers=headers).status_code==409
