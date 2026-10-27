"""Versioned, metadata-only runner report contract. No free-form source evidence."""
import json
import re
from typing import Annotated, Literal

from packaging.version import Version
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .privacy import safe_metadata

Hex64 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
PathID = Annotated[str, Field(pattern=r'^sha256:[0-9a-f]{64}$')]
Counter = Annotated[int, Field(ge=0,le=1_000_000)]
Ecosystem = Literal['PyPI','npm','Go','crates.io','Packagist']
RuleID = Literal['hardcoded-secret','dynamic-execution','subprocess-shell','js-eval','inner-html']
Reason = Literal['content_unavailable','unsupported_file_type','parse_error','scanner_limit',
                 'unresolved_dependency','transitive_graph_unavailable','no_supported_manifests']


class MetadataModel(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,hide_input_in_errors=True,frozen=True,
                           revalidate_instances='always')


class ReportDependency(MetadataModel):
    name: str = Field(min_length=1,max_length=214)
    version: str = Field(min_length=1,max_length=128)
    ecosystem: Ecosystem
    path_id: PathID

    @model_validator(mode='after')
    def identity(self):
        safe_metadata(self.name)
        safe_metadata(self.version)
        patterns={
            'PyPI':r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?',
            'npm':r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*',
            'crates.io':r'[A-Za-z0-9][A-Za-z0-9_-]*',
            'Go':r'[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~+-]+)+',
            'Packagist':r'[a-z0-9_.-]+/[a-z0-9_.-]+'
        }
        if not re.fullmatch(patterns[self.ecosystem],self.name):
            raise ValueError('Invalid package identity')
        if self.ecosystem=='PyPI':
            Version(self.version)
        elif not re.fullmatch(r'v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?',self.version):
            raise ValueError('An exact version is required')
        return self


class ReportFinding(MetadataModel):
    rule_id: RuleID
    severity: Literal['critical','high','medium','low','info']
    path_id: PathID
    line: int = Field(ge=1,le=10_000_000)
    fingerprint: Hex64


class ReportManifest(MetadataModel):
    path_id: PathID
    sha256: Hex64


class ReportCoverage(MetadataModel):
    state: Literal['complete','incomplete']
    files_total: Counter
    files_scanned: Counter
    files_skipped: Counter
    unresolved_dependencies: Counter = 0
    dependency_scope: Literal['resolved','declared','unknown'] = 'unknown'
    reasons: dict[Reason, Counter] = Field(default_factory=dict,max_length=7)

    @model_validator(mode='after')
    def accounting(self):
        if self.files_scanned+self.files_skipped!=self.files_total:
            raise ValueError('Coverage counts must account for every file')
        if self.state=='complete' and (self.files_skipped or self.unresolved_dependencies or self.reasons):
            raise ValueError('Incomplete analysis cannot be reported complete')
        return self


class RunnerReport(MetadataModel):
    report_version: Literal['1']
    scan_mode: Literal['customer_runner']
    repo: str = Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$',max_length=256)
    commit_sha: str = Field(pattern=r'^[0-9a-f]{40}$')
    scan_kind: Literal['code','dependencies']
    coverage: ReportCoverage
    manifests: list[ReportManifest] = Field(default_factory=list,max_length=80)
    dependencies: list[ReportDependency] = Field(default_factory=list,max_length=1500)
    findings: list[ReportFinding] = Field(default_factory=list,max_length=5000)

    @field_validator('repo')
    @classmethod
    def safe_repo(cls,value):
        safe_metadata(value)
        if '..' in value: raise ValueError('Invalid repository')
        return value

    @model_validator(mode='after')
    def consistency(self):
        if self.scan_kind=='dependencies' and self.coverage.state=='complete':
            if self.coverage.dependency_scope!='resolved' or not self.manifests:
                raise ValueError('Complete dependency reports require resolved manifest evidence')
        identities=[(d.ecosystem,d.name,d.version,d.path_id) for d in self.dependencies]
        if len(set(identities))!=len(identities):
            raise ValueError('Duplicate dependency observations')
        manifest_ids=[m.path_id for m in self.manifests]
        if len(set(manifest_ids))!=len(manifest_ids):
            raise ValueError('Duplicate manifest observations')
        if self.scan_kind=='dependencies' and any(dep.path_id not in manifest_ids for dep in self.dependencies):
            raise ValueError('Dependency observations require matching manifest evidence')
        if self.scan_kind=='code' and self.dependencies:
            raise ValueError('Dependency observations require a dependency report')
        return self


def parse_report(body: bytes) -> RunnerReport:
    def reject_duplicates(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError('Duplicate JSON fields are forbidden')
            value[key]=item
        return value
    data=json.loads(body,object_pairs_hook=reject_duplicates)
    return RunnerReport.model_validate(data)
