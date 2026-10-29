import time
from vulnforge.db import Store


def test_advisory_impact_versioned_history(tmp_path):
    store = Store(str(tmp_path / 'db'))
    store.upsert_repo('org/repo', 1, 'main')
    adv_id = store.save_advisory({
        'id': 'GHSA-TEST-0001',
        'summary': 'Test advisory',
        'modified': '2026-01-01T00:00:00Z'
    })

    # Step 1: Initial detection from scan 1 -> affected
    scan_1_id = store.start_scan('org/repo', 'dependencies', 'a' * 40)
    store.finish_scan(scan_1_id, 'complete', {'state': 'complete'})
    rec_1 = [{'package': 'foo', 'ecosystem': 'npm', 'recommended_version': '1.1.0'}]
    store.save_impact(
        'org/repo',
        adv_id,
        'affected',
        scan_1_id,
        {'source_sha256': '1111', 'coverage_complete': True},
        rec_1
    )

    history_1 = store.impact_history('org/repo', adv_id)
    assert len(history_1) == 1
    assert history_1[0]['revision'] == 1
    assert history_1[0]['state'] == 'affected'
    assert history_1[0]['scan_id'] == scan_1_id
    assert history_1[0]['recommendations'] == rec_1

    # Step 2: Rescan or patch applied -> scan 2 -> not_affected
    scan_2_id = store.start_scan('org/repo', 'dependencies', 'b' * 40)
    store.finish_scan(scan_2_id, 'complete', {'state': 'complete'})
    store.save_impact(
        'org/repo',
        adv_id,
        'not_affected',
        scan_2_id,
        {'source_sha256': '1111', 'coverage_complete': True, 'reason': 'patched'},
        []
    )

    history_2 = store.impact_history('org/repo', adv_id)
    assert len(history_2) == 2
    assert history_2[0]['revision'] == 1
    assert history_2[0]['state'] == 'affected'

    assert history_2[1]['revision'] == 2
    assert history_2[1]['state'] == 'not_affected'
    assert history_2[1]['scan_id'] == scan_2_id
    assert history_2[1]['evidence']['reason'] == 'patched'

    # Step 3: Advisory withdrawn -> pending_impact or withdrawn state
    store.pending_impact('org/repo', adv_id, delivery='deliv-123')
    history_3 = store.impact_history('org/repo', adv_id)
    assert len(history_3) == 3
    assert history_3[2]['revision'] == 3
    assert history_3[2]['state'] == 'under_investigation'
    assert history_3[2]['evidence']['delivery_id'] == 'deliv-123'

