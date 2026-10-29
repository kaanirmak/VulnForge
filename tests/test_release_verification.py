import asyncio
import pytest
from vulnforge.dependencies import Dependency
from vulnforge.intelligence import recommend_updates, PackageRegistryVerifier


class MockOSV:
    async def check(self, deps):
        # All tested candidates have no OSV advisories
        return []


class MockRegistryVerifier:
    def __init__(self, data):
        self.data = data

    async def verify_release(self, package: str, version: str, ecosystem: str) -> dict:
        key = (ecosystem, package, version)
        if key in self.data:
            return self.data[key]
        return {'published': True, 'yanked': False, 'deprecated': False}


def test_recommend_updates_skips_yanked_and_deprecated_releases():
    dep = Dependency('demo-pkg', '1.0.0', 'PyPI', 'requirements.txt')
    advisory = {
        'id': 'GHSA-YANK-0001',
        'affected': [
            {
                'package': {'name': 'demo-pkg', 'ecosystem': 'PyPI'},
                'ranges': [
                    {
                        'type': 'ECOSYSTEM',
                        'events': [
                            {'introduced': '0'},
                            {'fixed': '1.0.1'},  # First fix (yanked in registry)
                            {'fixed': '1.0.2'}   # Second fix (clean and published)
                        ]
                    }
                ]
            }
        ]
    }

    # 1. First fix is yanked, second is published
    registry_data = {
        ('PyPI', 'demo-pkg', '1.0.1'): {
            'published': True,
            'yanked': True,
            'yanked_reason': 'Critical bug in 1.0.1',
            'deprecated': False
        },
        ('PyPI', 'demo-pkg', '1.0.2'): {
            'published': True,
            'yanked': False,
            'deprecated': False
        }
    }
    verifier = MockRegistryVerifier(registry_data)

    async def run_skip_yanked():
        output = await recommend_updates({dep: [advisory]}, MockOSV(), registry_verifier=verifier)
        rec = output[dep]
        assert rec['status'] == 'update_available'
        # Crucial: 1.0.1 was skipped because it was yanked; 1.0.2 was recommended instead!
        assert rec['recommended_version'] == '1.0.2'
        assert rec['release_verified'] is True
        assert rec['yanked'] is False
        assert rec['deprecated'] is False

    asyncio.run(run_skip_yanked())


def test_recommend_updates_marks_when_all_fixes_are_yanked_or_deprecated():
    dep = Dependency('old-lib', '2.0.0', 'npm', 'package-lock.json')
    advisory = {
        'id': 'GHSA-DEP-0002',
        'affected': [
            {
                'package': {'name': 'old-lib', 'ecosystem': 'npm'},
                'ranges': [
                    {
                        'type': 'ECOSYSTEM',
                        'events': [
                            {'introduced': '0'},
                            {'fixed': '2.1.0'}
                        ]
                    }
                ]
            }
        ]
    }

    # Fix is marked deprecated by maintainers
    registry_data = {
        ('npm', 'old-lib', '2.1.0'): {
            'published': True,
            'yanked': False,
            'deprecated': True,
            'deprecation_reason': 'This package has been abandoned.'
        }
    }
    verifier = MockRegistryVerifier(registry_data)

    async def run_all_deprecated():
        output = await recommend_updates({dep: [advisory]}, MockOSV(), registry_verifier=verifier)
        rec = output[dep]
        assert rec['status'] == 'release_deprecated'
        assert rec['recommended_version'] is None
        assert rec['deprecated'] is True
        assert rec['deprecation_reason'] == 'This package has been abandoned.'

    asyncio.run(run_all_deprecated())

