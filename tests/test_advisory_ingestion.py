import asyncio
import pytest
from vulnforge.db import Store
from vulnforge.intelligence import AdvisoryIngestionRunner


def test_advisory_ingestion_cursor_resume_and_retry(tmp_path):
    store = Store(str(tmp_path / 'db'))
    runner = AdvisoryIngestionRunner(store, 'OSV-PyPI')

    # 1. Initial state is None
    assert store.get_ingestion_state('OSV-PyPI') is None

    # Sample paginated data
    batch_1 = [
        {'id': 'GHSA-0001', 'summary': 'First vuln', 'modified': '2026-01-01T00:00:00Z',
         'affected': [{'package': {'name': 'demo-pkg', 'ecosystem': 'PyPI'}}]},
        {'id': 'GHSA-0002', 'summary': 'Second vuln', 'modified': '2026-01-02T00:00:00Z',
         'affected': [{'package': {'name': 'demo-pkg', 'ecosystem': 'PyPI'}}]}
    ]
    batch_2 = [
        {'id': 'GHSA-0003', 'summary': 'Third vuln', 'modified': '2026-01-03T00:00:00Z',
         'affected': [{'package': {'name': 'other-pkg', 'ecosystem': 'PyPI'}}]}
    ]

    async def fetcher_page_1(cursor):
        assert cursor is None
        return batch_1, 'cursor_token_page_2', True

    async def run_step_1():
        result = await runner.ingest_batch(fetcher_page_1)
        assert result['processed'] == 2
        assert result['cursor'] == 'cursor_token_page_2'
        assert result['has_more'] is True

    asyncio.run(run_step_1())

    # Verify state after step 1
    state = store.get_ingestion_state('OSV-PyPI')
    assert state['cursor'] == 'cursor_token_page_2'
    assert state['status'] == 'pending'
    assert state['processed_count'] == 2
    assert state['retry_count'] == 0
    assert state['error'] is None
    assert store.advisory('GHSA-0001') is not None
    assert store.advisory('GHSA-0002') is not None

    # 2. Simulate interruption and retry failure
    async def failing_fetcher(cursor):
        assert cursor == 'cursor_token_page_2'  # Properly resumed from saved cursor
        raise ConnectionError('Temporary OSV upstream timeout')

    async def run_failing_step():
        with pytest.raises(ConnectionError):
            await runner.ingest_batch(failing_fetcher)

    asyncio.run(run_failing_step())

    # Verify failed state and incremented retry count
    failed_state = store.get_ingestion_state('OSV-PyPI')
    assert failed_state['cursor'] == 'cursor_token_page_2'  # Cursor was NOT lost
    assert failed_state['status'] == 'failed'
    assert failed_state['retry_count'] == 1
    assert 'Temporary OSV upstream timeout' in failed_state['error']
    assert failed_state['processed_count'] == 2

    # 3. Successful resumption after retry
    async def fetcher_page_2(cursor):
        assert cursor == 'cursor_token_page_2'
        return batch_2, None, False

    async def run_step_2():
        result = await runner.ingest_batch(fetcher_page_2)
        assert result['processed'] == 1
        assert result['cursor'] is None
        assert result['has_more'] is False

    asyncio.run(run_step_2())

    # Verify final completed state
    final_state = store.get_ingestion_state('OSV-PyPI')
    assert final_state['cursor'] is None
    assert final_state['status'] == 'idle'
    assert final_state['processed_count'] == 3
    assert final_state['retry_count'] == 0  # Reset on success
    assert final_state['error'] is None
    assert final_state['last_success_at'] is not None
    assert store.advisory('GHSA-0003') is not None

