"""Extended ecosystem parsers for Java (Maven, Gradle), .NET (NuGet), and Container/Image SBOMs."""
import json
import re
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from vulnforge.dependencies import Dependency


def parse_maven_pom(content: str, file_path: str = "pom.xml") -> List[Dependency]:
    """Parse dependencies from a Maven pom.xml file."""
    deps: List[Dependency] = []
    if not content or not content.strip():
        return deps

    try:
        # Strip default namespace for clean tag lookup
        clean_xml = re.sub(r'\sxmlns="[^"]+"', '', content, count=1)
        root = ET.fromstring(clean_xml)
    except ET.ParseError:
        return deps

    # Search dependencies block
    for dep_elem in root.findall(".//dependency"):
        group = dep_elem.findtext("groupId", "").strip()
        artifact = dep_elem.findtext("artifactId", "").strip()
        version = dep_elem.findtext("version", "").strip()
        scope = dep_elem.findtext("scope", "runtime").strip().lower()

        if group and artifact and version and not version.startswith("${"):
            name = f"{group}:{artifact}"
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="Maven",
                file_path=file_path,
                direct=True,
                scope=scope if scope in ("runtime", "dev", "build", "test") else "runtime",
            ))

    return deps


def parse_gradle_build(content: str, file_path: str = "build.gradle") -> List[Dependency]:
    """Parse dependencies from a Gradle build file (Groovy or Kotlin DSL)."""
    deps: List[Dependency] = []
    if not content or not content.strip():
        return deps

    # Match patterns like: implementation 'org.springframework.boot:spring-boot-starter-web:2.7.0'
    # or: testImplementation("junit:junit:4.13.2")
    pattern = re.compile(
        r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s*(?:\(\s*)?['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)['"](?:\s*\))?"""
    )
    for match in pattern.finditer(content):
        group, artifact, version = match.groups()
        name = f"{group}:{artifact}"
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="Maven",
            file_path=file_path,
            direct=True,
            scope="runtime",
        ))

    return deps


def parse_nuget_csproj(content: str, file_path: str = "app.csproj") -> List[Dependency]:
    """Parse PackageReference items from a .NET C# project file."""
    deps: List[Dependency] = []
    if not content or not content.strip():
        return deps

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return deps

    for pkg_elem in root.findall(".//PackageReference"):
        pkg_name = pkg_elem.get("Include") or pkg_elem.get("Update")
        version = pkg_elem.get("Version") or pkg_elem.findtext("Version")

        if pkg_name and version and not version.startswith("$("):
            deps.append(Dependency(
                name=pkg_name.strip(),
                version=version.strip(),
                ecosystem="NuGet",
                file_path=file_path,
                direct=True,
                scope="runtime",
            ))

    return deps


def parse_cyclonedx_sbom(content: str, file_path: str = "bom.json") -> List[Dependency]:
    """Parse components and provenance hashes from a CycloneDX JSON SBOM."""
    deps: List[Dependency] = []
    if not content or not content.strip():
        return deps

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    components = data.get("components") or []
    for c in components:
        name = c.get("name")
        version = c.get("version") or "unknown"
        purl = c.get("purl") or ""

        # Infer ecosystem from purl (e.g. pkg:maven/..., pkg:nuget/..., pkg:npm/...)
        ecosystem = "generic"
        if purl.startswith("pkg:maven/"):
            ecosystem = "Maven"
        elif purl.startswith("pkg:nuget/"):
            ecosystem = "NuGet"
        elif purl.startswith("pkg:npm/"):
            ecosystem = "npm"
        elif purl.startswith("pkg:pypi/"):
            ecosystem = "PyPI"
        elif purl.startswith("pkg:golang/"):
            ecosystem = "Go"
        elif purl.startswith("pkg:cargo/"):
            ecosystem = "crates.io"

        # Extract component hash/digest
        digest = None
        hashes = c.get("hashes") or []
        for h in hashes:
            if h.get("alg") in ("SHA-256", "sha256"):
                digest = f"sha256:{h.get('content')}"
                break

        if name:
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem=ecosystem,
                file_path=file_path,
                direct=True,
                scope=c.get("scope", "runtime"),
                digest=digest,
            ))

    return deps


def parse_spdx_sbom(content: str, file_path: str = "spdx.json") -> List[Dependency]:
    """Parse packages and checksums from an SPDX JSON container SBOM."""
    deps: List[Dependency] = []
    if not content or not content.strip():
        return deps

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    packages = data.get("packages") or []
    for p in packages:
        name = p.get("name")
        version = p.get("versionInfo") or "unknown"

        digest = None
        for ck in p.get("checksums", []):
            if ck.get("algorithm") == "SHA256":
                digest = f"sha256:{ck.get('checksumValue')}"
                break

        if name and name != data.get("name"):
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="container_package",
                file_path=file_path,
                direct=True,
                digest=digest,
            ))

    return deps
