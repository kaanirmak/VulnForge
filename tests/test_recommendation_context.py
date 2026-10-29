import asyncio
import pytest
from vulnforge.dependencies import Dependency
from vulnforge.intelligence import recommend_updates, enrich_recommendation_context


class MockOSV:
    async def check(self, deps):
        return []


def test_recommendation_context_parent_dependency_and_overrides():
    # Parent direct package: express
    parent = Dependency('express', '4.18.2', 'npm', 'package-lock.json',
                        direct=True, scope='runtime', dependency_edges=['cookie'])
    # Transitive child package: cookie
    child = Dependency('cookie', '0.4.0', 'npm', 'package-lock.json',
                       direct=False, scope='runtime', dependency_edges=[])

    advisory = {
        'id': 'GHSA-COOKIE-001',
        'affected': [
            {
                'package': {'name': 'cookie', 'ecosystem': 'npm'},
                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '0.7.0'}]}]
            }
        ]
    }

    async def run():
        output = await recommend_updates({parent: [], child: [advisory]}, MockOSV())
        child_rec = output[child]
        assert child_rec['status'] == 'update_available'
        assert child_rec['recommended_version'] == '0.7.0'
        assert child_rec['is_direct'] is False
        assert child_rec['parent_packages'] == ['express']
        assert child_rec['requires_override_or_parent_upgrade'] is True
        assert child_rec['override_strategy']['tool'] == 'npm/yarn'
        assert child_rec['override_strategy']['directive'] == 'overrides'
        assert child_rec['override_strategy']['snippet'] == {'cookie': '0.7.0'}

    asyncio.run(run())


def test_recommendation_context_major_upgrade_warning():
    direct_dep = Dependency('pydantic', '1.10.12', 'PyPI', 'requirements.txt', direct=True)
    advisory = {
        'id': 'GHSA-PYDANTIC-001',
        'affected': [
            {
                'package': {'name': 'pydantic', 'ecosystem': 'PyPI'},
                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.0.0'}]}]
            }
        ]
    }

    async def run():
        output = await recommend_updates({direct_dep: [advisory]}, MockOSV())
        rec = output[direct_dep]
        assert rec['status'] == 'update_available'
        assert rec['recommended_version'] == '2.0.0'
        assert rec['upgrade_class'] == 'major'
        assert rec['major_upgrade'] is True
        assert rec['breaking_change_risk'] == 'high'
        assert 'Major upgrade' in rec['major_upgrade_warning']
        assert rec['requires_manifest_change'] is True
        assert rec['requires_override_or_parent_upgrade'] is False

    asyncio.run(run())

