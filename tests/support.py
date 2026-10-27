"""Explicit legacy managed-mode fixtures; production defaults remain privacy-first."""
from vulnforge.config import Config as RuntimeConfig
from vulnforge.osv import OSV as RuntimeOSV
from vulnforge.privacy import MetadataPolicy


def managed_config(**kwargs):
    return RuntimeConfig(scan_mode='managed',allow_managed_source_access=True,
                         managed_scan_consent_id='unit-test-consent',**kwargs)


def fixture_osv(*args,**kwargs):
    kwargs['policy']=MetadataPolicy(mode='public_osv',external_consent=True,
        allowed_packages=('PyPI:requests','PyPI:test','npm:demo'))
    return RuntimeOSV(*args,**kwargs)
