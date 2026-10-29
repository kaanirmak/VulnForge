import json
import pytest
from pathlib import Path
from vulnforge.cli import scan
from vulnforge.scanner import scan_code
from vulnforge.dependencies import parse_manifest, inventory_manifest


# =========================================================================
# 1. Scanner Rule Fixtures: Positive and Negative Cases
# =========================================================================

def test_hardcoded_secret_positives_and_negatives():
    # Positives: should trigger hardcoded-secret
    positives = [
        ('key.py', 'gh_token = "ghp_123456789012345678901234567890123456"\n'),
        ('aws.py', 'aws_access = "AKIA1234567890ABCDEF"\n'),
        ('pkey.py', 'key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."\n')
    ]
    for filename, code in positives:
        findings = scan_code(filename, code)
        assert any(f['details']['rule'] == 'hardcoded-secret' for f in findings), f"Failed positive for {filename}"

    # Negatives: safe placeholders, variable definitions without secrets
    negatives = [
        ('safe1.py', '# Just a comment about tokens\n'),
        ('safe2.py', 'token = os.getenv("API_KEY")\n'),
        ('safe3.py', 'dummy_val = "YOUR_API_KEY_HERE"\n'),
        ('safe4.py', 'sample = "<INSERT_TOKEN>"\n')
    ]
    for filename, code in negatives:
        findings = scan_code(filename, code)
        assert not any(f['details']['rule'] == 'hardcoded-secret' for f in findings), f"False positive for {filename}"


def test_dynamic_execution_positives_and_negatives():
    # Positives: exec / eval
    positives = [
        ('app.py', 'eval(user_query)\n'),
        ('app2.py', 'exec("import " + module_name)\n')
    ]
    for filename, code in positives:
        findings = scan_code(filename, code)
        assert any(f['details']['rule'] == 'dynamic-execution' for f in findings), f"Failed positive for {filename}"

    # Negatives: safe method calls or non-calls
    negatives = [
        ('safe.py', 'class Evaluator:\n    def evaluate(self, x):\n        return x * 2\n'),
        ('safe2.py', '# eval(x) is dangerous\nresult = x + y\n')
    ]
    for filename, code in negatives:
        findings = scan_code(filename, code)
        assert not any(f['details']['rule'] == 'dynamic-execution' for f in findings), f"False positive for {filename}"


def test_subprocess_shell_positives_and_negatives():
    # Positives: shell=True
    positives = [
        ('proc1.py', 'import subprocess\nsubprocess.run(command, shell=True)\n'),
        ('proc2.py', 'import subprocess\nsubprocess.Popen("ls " + path, shell=True)\n')
    ]
    for filename, code in positives:
        findings = scan_code(filename, code)
        assert any(f['details']['rule'] == 'subprocess-shell' for f in findings), f"Failed positive for {filename}"

    # Negatives: safe subprocess calls without shell=True or shell=False
    negatives = [
        ('safe.py', 'import subprocess\nsubprocess.run(["ls", "-la"])\n'),
        ('safe2.py', 'subprocess.run(cmd, shell=False)\n')
    ]
    for filename, code in negatives:
        findings = scan_code(filename, code)
        assert not any(f['details']['rule'] == 'subprocess-shell' for f in findings), f"False positive for {filename}"


def test_js_eval_positives_and_negatives():
    positives = [
        ('eval1.js', 'const res = eval(payload);\n')
    ]
    for filename, code in positives:
        findings = scan_code(filename, code)
        assert any(f['details']['rule'] == 'js-eval' for f in findings), f"Failed positive for {filename}"

    negatives = [
        ('safe.js', 'const isEven = [1, 2, 3].every(x => x % 2 === 0);\n'),
        ('safe2.js', 'function evaluate(userCode) { return userCode.trim(); }\n')
    ]
    for filename, code in negatives:
        findings = scan_code(filename, code)
        assert not any(f['details']['rule'] == 'js-eval' for f in findings), f"False positive for {filename}"


def test_inner_html_positives_and_negatives():
    positives = [
        ('dom.js', 'document.getElementById("content").innerHTML = userInput;\n'),
        ('dom2.js', 'targetElement.innerHTML = `<p>${data}</p>`;\n')
    ]
    for filename, code in positives:
        findings = scan_code(filename, code)
        assert any(f['details']['rule'] == 'inner-html' for f in findings), f"Failed positive for {filename}"

    negatives = [
        ('safe.js', 'document.getElementById("content").textContent = userInput;\n')
    ]
    for filename, code in negatives:
        findings = scan_code(filename, code)
        assert not any(f['details']['rule'] == 'inner-html' for f in findings), f"False positive for {filename}"


# =========================================================================
# 2. Manifest Parser Fixtures: Positive, Negative, Corrupt & Boundary Cases
# =========================================================================

def test_corrupt_manifests_handled_gracefully():
    # Corrupt JSON in package-lock.json, composer.lock, Pipfile.lock
    corrupt_json = '{"packages": {'
    with pytest.raises(Exception):
        inventory_manifest('package-lock.json', corrupt_json)
    with pytest.raises(Exception):
        inventory_manifest('composer.lock', corrupt_json)
    with pytest.raises(Exception):
        inventory_manifest('Pipfile.lock', corrupt_json)

    # Corrupt TOML in Cargo.lock, poetry.lock, uv.lock
    corrupt_toml = '[[package]\nname = "broken'
    with pytest.raises(Exception):
        inventory_manifest('Cargo.lock', corrupt_toml)
    with pytest.raises(Exception):
        inventory_manifest('poetry.lock', corrupt_toml)
    with pytest.raises(Exception):
        inventory_manifest('uv.lock', corrupt_toml)


def test_recursive_include_loop_protection():
    # Mutual recursion in requirements include directives: a.txt -> b.txt -> a.txt
    files = {
        'requirements.txt': '-r extra.txt\nrequests==2.31.0\n',
        'extra.txt': '-r requirements.txt\nurllib3==2.2.3\n'
    }
    def resolver(path):
        return files.get(path)

    # Must terminate without infinite recursion or stack overflow
    deps = parse_manifest('requirements.txt', files['requirements.txt'], include_resolver=resolver)
    names = {d.name: d.version for d in deps}
    assert names['requests'] == '2.31.0'
    assert names['urllib3'] == '2.2.3'


def test_cli_scanner_handles_cyclical_symlinks_and_boundary_limits(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()

    # Cyclical directory symlinks: dir_a/link_b -> dir_b; dir_b/link_a -> dir_a
    dir_a = source / 'dir_a'
    dir_a.mkdir()
    dir_b = source / 'dir_b'
    dir_b.mkdir()
    (dir_a / 'loop_to_b').symlink_to(dir_b, target_is_directory=True)
    (dir_b / 'loop_to_a').symlink_to(dir_a, target_is_directory=True)

    # Broken symlink
    (source / 'broken_link.py').symlink_to(source / 'non_existent.py')

    # Valid code file
    (source / 'valid.py').write_text('token = "ghp_123456789012345678901234567890123456"\n')

    # Deep directory hierarchy exceeding limits
    deep = source
    for i in range(35):
        deep = deep / f'sub_{i}'
        deep.mkdir()
    (deep / 'deep_code.py').write_text('eval("safe")\n')

    # Scan should not hang, loop infinitely or crash
    report = scan(source, 'org/boundary-test', 'a' * 40)
    assert report.coverage.files_scanned >= 1
    # Secrets in valid.py are found
    assert any(f.rule_id == 'hardcoded-secret' for f in report.findings)
    # Symlinks/limits skipped safely
    assert report.coverage.files_skipped >= 1
    assert report.coverage.state == 'incomplete'
    assert 'content_unavailable' in report.coverage.reasons or 'scanner_limit' in report.coverage.reasons
