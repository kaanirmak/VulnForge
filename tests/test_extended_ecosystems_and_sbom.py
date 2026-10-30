import json
import pytest

from vulnforge.extended_ecosystems import (
    parse_cyclonedx_sbom,
    parse_gradle_build,
    parse_maven_pom,
    parse_nuget_csproj,
    parse_spdx_sbom,
)


def test_parse_maven_pom():
    pom_xml = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.mycompany.app</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.8.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>"""
    deps = parse_maven_pom(pom_xml, "pom.xml")
    assert len(deps) == 2

    d1 = next(d for d in deps if "commons-lang3" in d.name)
    assert d1.name == "org.apache.commons:commons-lang3"
    assert d1.version == "3.12.0"
    assert d1.ecosystem == "Maven"
    assert d1.scope == "runtime"

    d2 = next(d for d in deps if "junit-jupiter" in d.name)
    assert d2.scope == "test"


def test_parse_gradle_build():
    gradle_content = """
plugins {
    id 'java'
}
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:2.7.0'
    testImplementation("junit:junit:4.13.2")
}
"""
    deps = parse_gradle_build(gradle_content, "build.gradle")
    assert len(deps) == 2
    assert deps[0].name == "org.springframework.boot:spring-boot-starter-web"
    assert deps[0].version == "2.7.0"
    assert deps[0].ecosystem == "Maven"

    assert deps[1].name == "junit:junit"
    assert deps[1].version == "4.13.2"


def test_parse_nuget_csproj():
    csproj_content = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="2.10.0" />
  </ItemGroup>
</Project>"""
    deps = parse_nuget_csproj(csproj_content, "src/Backend.csproj")
    assert len(deps) == 2
    assert deps[0].name == "Newtonsoft.Json"
    assert deps[0].version == "13.0.1"
    assert deps[0].ecosystem == "NuGet"
    assert deps[1].name == "Serilog"


def test_parse_cyclonedx_sbom():
    cyclonedx_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.17.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
                "hashes": [
                    {"alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
                ]
            },
            {
                "type": "library",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2"
            }
        ]
    }
    deps = parse_cyclonedx_sbom(json.dumps(cyclonedx_json), "cyclonedx-bom.json")
    assert len(deps) == 2

    log4j = deps[0]
    assert log4j.name == "log4j-core"
    assert log4j.version == "2.17.1"
    assert log4j.ecosystem == "Maven"
    assert log4j.digest == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    express = deps[1]
    assert express.name == "express"
    assert express.ecosystem == "npm"


def test_parse_spdx_sbom():
    spdx_json = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "alpine-base-image",
        "packages": [
            {
                "name": "alpine-base-image",
                "SPDXID": "SPDXRef-RootPackage"
            },
            {
                "name": "openssl",
                "SPDXID": "SPDXRef-Package-openssl",
                "versionInfo": "3.0.8-r0",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": "abcdef1234567890"}
                ]
            }
        ]
    }
    deps = parse_spdx_sbom(json.dumps(spdx_json), "spdx.json")
    assert len(deps) == 1
    assert deps[0].name == "openssl"
    assert deps[0].version == "3.0.8-r0"
    assert deps[0].digest == "sha256:abcdef1234567890"
