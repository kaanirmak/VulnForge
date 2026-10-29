"""Small, transparent static rule set and canonical finding/fingerprint normalizer."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess

FINDING_SCHEMA_VERSION = '1'
PINNED_SEMGREP_VERSION = '1.96.0'
SEMGREP_RULEPACK_ID = 'vulnforge-default-v1'
SEMGREP_RULEPACK_CONTENT = json.dumps({
    'rules': [
        {
            'id': 'vulnforge.python.dynamic-execution',
            'languages': ['python'],
            'severity': 'ERROR',
            'message': 'Dynamic Python evaluation can execute attacker-controlled input',
            'pattern-either': [{'pattern': 'eval(...)'}, {'pattern': 'exec(...)'}],
        },
        {
            'id': 'vulnforge.python.subprocess-shell',
            'languages': ['python'],
            'severity': 'WARNING',
            'message': 'Subprocess invoked with shell=True',
            'pattern': 'subprocess.$FUNC(..., shell=True, ...)',
        },
        {
            'id': 'vulnforge.javascript.js-eval',
            'languages': ['javascript', 'typescript'],
            'severity': 'ERROR',
            'message': 'JavaScript eval() usage',
            'pattern': 'eval(...)',
        },
        {
            'id': 'vulnforge.javascript.inner-html',
            'languages': ['javascript', 'typescript'],
            'severity': 'WARNING',
            'message': 'HTML sink; verify input escaping/sanitization',
            'pattern': '$EL.innerHTML = $VAL',
        },
    ]
}, sort_keys=True, separators=(',', ':'))
SEMGREP_RULEPACK_SHA256 = hashlib.sha256(SEMGREP_RULEPACK_CONTENT.encode()).hexdigest()

PINNED_GITLEAKS_VERSION = '8.21.2'
GITLEAKS_CONFIG_ID = 'vulnforge-gitleaks-v1'
GITLEAKS_CONFIG_CONTENT = (
    'title = "VulnForge Gitleaks Config v1"\n'
    '[[rules]]\nid = "github-pat"\ndescription = "GitHub Personal Access Token"\n'
    'regex = \'\'\'\\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{30,}\\b\'\'\'\n'
    '[[rules]]\nid = "github-fine-grained-pat"\ndescription = "GitHub Fine-Grained Personal Access Token"\n'
    'regex = \'\'\'github_pat_[A-Za-z0-9_]{22,}\'\'\'\n'
    '[[rules]]\nid = "aws-access-token"\ndescription = "AWS Access Key ID"\n'
    'regex = \'\'\'\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b\'\'\'\n'
    '[[rules]]\nid = "private-key"\ndescription = "Asymmetric Private Key"\n'
    'regex = \'\'\'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\'\'\'\n'
)
GITLEAKS_CONFIG_SHA256 = hashlib.sha256(GITLEAKS_CONFIG_CONTENT.encode()).hexdigest()

SEMGREP_CHECK_ID_MAP = {
    'vulnforge.python.dynamic-execution': 'dynamic-execution',
    'python.lang.security.audit.eval-detected': 'dynamic-execution',
    'vulnforge.python.subprocess-shell': 'subprocess-shell',
    'python.lang.security.audit.subprocess-shell-true': 'subprocess-shell',
    'vulnforge.javascript.js-eval': 'js-eval',
    'javascript.browser.security.eval-detected': 'js-eval',
    'vulnforge.javascript.inner-html': 'inner-html',
    'javascript.browser.security.innerhtml': 'inner-html',
}

SEVERITY_MAP = {
    'critical': 'critical',
    'high': 'high',
    'error': 'high',
    'medium': 'medium',
    'warning': 'medium',
    'warn': 'medium',
    'low': 'low',
    'info': 'info',
    'note': 'info',
}

VALID_CATEGORIES = frozenset(('code', 'dependency', 'coverage'))
VALID_SCANNERS = frozenset(('builtin', 'semgrep', 'gitleaks', 'osv', 'coverage'))

# Never store values that match a secret rule in evidence.
SECRETS = [
    ('GitHub token', re.compile(r'\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{30,}\b')),
    ('GitHub fine-grained token', re.compile(r'github_pat_[A-Za-z0-9_]{22,}')),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
]


def normalize_severity(severity: str) -> str:
    if not isinstance(severity, str):
        raise ValueError('Severity must be a string')
    mapped = SEVERITY_MAP.get(severity.strip().lower())
    if mapped is None:
        raise ValueError(f'Unsupported finding severity: {severity}')
    return mapped


def redact_evidence(rule: str | None, snippet: str) -> str:
    if not isinstance(snippet, str):
        return ''
    if rule in ('hardcoded-secret', 'gitleaks-secret') or any(rx.search(snippet) for _, rx in SECRETS):
        return '[REDACTED: possible secret]'
    return snippet[:140]


def scrub_secret_values(text: str, extra_secrets: list[str] | tuple[str, ...] = ()) -> str:
    if not isinstance(text, str) or not text:
        return ''
    out = text
    for item in extra_secrets:
        if isinstance(item, str) and item:
            out = out.replace(item, '[REDACTED]')
    for _, rx in SECRETS:
        out = rx.sub('[REDACTED]', out)
    return out


def runner_fingerprint(path_pseudonym: str, line: int, rule_id: str) -> str:
    if not isinstance(path_pseudonym, str) or not path_pseudonym.startswith('sha256:'):
        raise ValueError('Runner fingerprint requires a sha256 path pseudonym')
    if type(line) is not int or line < 1:
        raise ValueError('Runner fingerprint requires a positive integer line number')
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError('Runner fingerprint requires a non-empty rule_id')
    return hashlib.sha256(f'{path_pseudonym}:{line}:{rule_id}'.encode()).hexdigest()


def compute_fingerprint(category: str, *, file_path: str | None = None,
                        line: int | None = None, rule: str | None = None,
                        ecosystem: str | None = None, package: str | None = None,
                        version: str | None = None, advisory_id: str | None = None,
                        sha: str | None = None) -> tuple[str, str]:
    if category == 'code':
        if not file_path or type(line) is not int or line < 1 or not rule:
            raise ValueError('Code finding fingerprint requires file_path, positive line, and rule')
        digest = hashlib.sha256(f'{file_path}:{line}:{rule}'.encode()).hexdigest()
        return f'code:{digest[:24]}', digest
    if category == 'dependency':
        if not file_path or not ecosystem or not package or not version or not advisory_id:
            raise ValueError('Dependency finding fingerprint requires file_path, ecosystem, package, version, and advisory_id')
        digest = hashlib.sha256(f'{file_path}:{ecosystem}:{package}:{version}:{advisory_id}'.encode()).hexdigest()
        return f'dep:{digest[:32]}', digest
    if category == 'coverage':
        if not sha or file_path is None:
            raise ValueError('Coverage finding fingerprint requires sha and file_path')
        digest = hashlib.sha256(f'{sha}:{file_path}'.encode()).hexdigest()
        return f'coverage:{digest[:24]}', digest
    raise ValueError(f'Unsupported finding category: {category}')


def normalize_finding(*, category: str, severity: str, title: str,
                      file_path: str | None = None, line: int | None = None,
                      rule: str | None = None, snippet: str = '',
                      scanner: str = 'builtin', details: dict | None = None,
                      ecosystem: str | None = None, package: str | None = None,
                      version: str | None = None, advisory_id: str | None = None,
                      sha: str | None = None) -> dict:
    if category not in VALID_CATEGORIES:
        raise ValueError(f'Unsupported finding category: {category}')
    if scanner not in VALID_SCANNERS:
        raise ValueError(f'Unsupported scanner source: {scanner}')
    norm_severity = normalize_severity(severity)
    if not isinstance(title, str) or not title.strip():
        raise ValueError('Finding title is required')
    safe_title = redact_evidence(rule, title.strip()) if any(rx.search(title) for _, rx in SECRETS) else title.strip()[:500]
    key, fingerprint = compute_fingerprint(
        category, file_path=file_path, line=line, rule=rule,
        ecosystem=ecosystem, package=package, version=version,
        advisory_id=advisory_id, sha=sha)
    pseudonym = None
    if isinstance(file_path, str) and file_path:
        try:
            from .privacy import path_id
            pseudonym = path_id(file_path)
        except ValueError:
            pseudonym = None
    merged_details = dict(details or {})
    merged_details['schema_version'] = FINDING_SCHEMA_VERSION
    merged_details['scanner'] = scanner
    merged_details['fingerprint'] = fingerprint
    if pseudonym is not None:
        merged_details['path_id'] = pseudonym
    if category == 'code':
        merged_details['rule'] = rule
        merged_details['rule_id'] = rule
        merged_details['line'] = line
        merged_details['evidence'] = redact_evidence(rule, snippet)
        if pseudonym is not None:
            merged_details['runner_fingerprint'] = runner_fingerprint(pseudonym, line, rule)
    return {
        'schema_version': FINDING_SCHEMA_VERSION,
        'key': key,
        'fingerprint': fingerprint,
        'category': category,
        'scanner': scanner,
        'severity': norm_severity,
        'title': safe_title,
        'file_path': file_path,
        'details': merged_details,
    }


def to_runner_finding(normalized: dict, *, path_pseudonym: str | None = None) -> dict:
    from .privacy import path_id
    if normalized.get('category') != 'code':
        raise ValueError('Only code findings convert to runner code findings')
    details = normalized.get('details') or {}
    rule = details.get('rule_id') or details.get('rule')
    line = details.get('line')
    pseudonym = path_pseudonym or details.get('path_id') or path_id(normalized['file_path'])
    return {
        'rule_id': rule,
        'severity': normalize_severity(normalized['severity']),
        'path_id': pseudonym,
        'line': line,
        'fingerprint': runner_fingerprint(pseudonym, line, rule),
    }


def finding(path: str, line: int, rule: str, title: str, severity: str, snippet: str,
            *, scanner: str = 'builtin', line_signature: str | None = None):
    extra = {'line_signature': line_signature} if line_signature else None
    return normalize_finding(
        category='code',
        severity=severity,
        title=title,
        file_path=path,
        line=line,
        rule=rule,
        snippet=snippet,
        scanner=scanner,
        details=extra,
    )


def _line_sig(rule: str, title: str, raw_line: str = '', *, is_secret: bool = False) -> str:
    if is_secret or any(rx.search(raw_line) for _, rx in SECRETS):
        token = f'{rule}:{title}'
    else:
        normalized_line = ' '.join(raw_line.split())
        token = f'{rule}:{title}:{normalized_line}'
    return hashlib.sha256(token.encode()).hexdigest()[:32]


def classify_pr_code_findings(head_findings: list[dict], base_findings: list[dict],
                              *, base_sha: str | None = None) -> list[dict]:
    """Compare PR head code findings against base findings to separate new vs pre_existing."""
    remaining = list(base_findings)
    classified = []
    # Pass 1: exact key match (same path, line, rule)
    unmatched_indices = []
    for idx, item in enumerate(head_findings):
        copy = {**item, 'details': dict(item.get('details') or {})}
        if base_sha:
            copy['details']['base_sha'] = base_sha
        match_pos = next((i for i, b in enumerate(remaining) if b.get('key') == copy.get('key')), None)
        if match_pos is not None:
            matched = remaining.pop(match_pos)
            copy['details']['diff_status'] = 'pre_existing'
            copy['details']['base_line'] = (matched.get('details') or {}).get('line')
            classified.append(copy)
        else:
            classified.append(copy)
            unmatched_indices.append(idx)
    # Pass 2: line-shifted match by (rule, line_signature/title)
    for idx in unmatched_indices:
        copy = classified[idx]
        d = copy['details']
        rule = d.get('rule')
        sig = d.get('line_signature') or copy.get('title')
        match_pos = next(
            (i for i, b in enumerate(remaining)
             if (b.get('details') or {}).get('rule') == rule
             and ((b.get('details') or {}).get('line_signature') or b.get('title')) == sig),
            None,
        )
        if match_pos is not None:
            matched = remaining.pop(match_pos)
            d['diff_status'] = 'pre_existing'
            d['base_line'] = (matched.get('details') or {}).get('line')
        else:
            d['diff_status'] = 'new'
    return classified


def classify_pr_dependency_findings(head_findings: list[dict],
                                    *, base_keys: set[str] | None = None,
                                    base_packages: set[tuple[str, str, str, str]] | None = None,
                                    base_sha: str | None = None) -> list[dict]:
    """Compare PR head dependency findings against base inventory/keys."""
    keys = base_keys or set()
    packages = base_packages or set()
    classified = []
    for item in head_findings:
        copy = {**item, 'details': dict(item.get('details') or {})}
        d = copy['details']
        if base_sha:
            d['base_sha'] = base_sha
        pkg_tuple = (copy.get('file_path'), d.get('ecosystem'), d.get('package'), d.get('version'))
        if copy.get('key') in keys or pkg_tuple in packages:
            d['diff_status'] = 'pre_existing'
        else:
            d['diff_status'] = 'new'
        classified.append(copy)
    return classified


def scan_code(path: str, source: str):
    if len(source) > 300_000:
        return []
    results = []
    lines=source.splitlines()[:10000]
    for n, line in enumerate(lines,1):
        for name, regex in SECRETS:
            if regex.search(line):
                title = f'Possible {name} in source'
                results.append(finding(path,n,'hardcoded-secret',title,'high',
                                       '[REDACTED: possible secret]',
                                       line_signature=_line_sig('hardcoded-secret', title, is_secret=True)))
                break
    if path.endswith('.py'):
        try:
            root=ast.parse(source)
        except SyntaxError:
            return results
        for node in ast.walk(root):
            if not isinstance(node,ast.Call):
                continue
            call_name = ''
            if isinstance(node.func,ast.Name): call_name=node.func.id
            if isinstance(node.func,ast.Attribute): call_name=node.func.attr
            n=getattr(node,'lineno',0)
            snippet=(lines[n-1].strip() if 0 < n <= len(lines) else '')
            if call_name in ('eval','exec'):
                title = 'Dynamic Python evaluation can execute attacker-controlled input'
                results.append(finding(path,n,'dynamic-execution',
                    title,'high',
                    '[CODE OMITTED; inspect referenced line]',
                    line_signature=_line_sig('dynamic-execution', title, snippet)))
            if call_name in ('run','Popen','call','check_output','check_call') and any(
                kw.arg=='shell' and isinstance(kw.value,ast.Constant) and kw.value.value is True
                for kw in node.keywords):
                title = 'Subprocess invoked with shell=True'
                results.append(finding(path,n,'subprocess-shell',
                    title,'medium',
                    '[CODE OMITTED; inspect referenced line]',
                    line_signature=_line_sig('subprocess-shell', title, snippet)))
    if path.endswith(('.js','.ts','.jsx','.tsx')):
        for n,line in enumerate(lines,1):
            if re.search(r'\beval\s*\(', line):
                title = 'JavaScript eval() usage'
                results.append(finding(path,n,'js-eval',title,'high',
                                       '[CODE OMITTED; inspect referenced line]',
                                       line_signature=_line_sig('js-eval', title, line)))
            if re.search(r'\.innerHTML\s*=',line):
                title = 'HTML sink; verify input escaping/sanitization'
                results.append(finding(path,n,'inner-html',
                    title,'medium',
                    '[CODE OMITTED; inspect referenced line]',
                    line_signature=_line_sig('inner-html', title, line)))
    return results


def map_semgrep_rule_id(check_id: str) -> str:
    if not isinstance(check_id, str) or not check_id.strip():
        raise ValueError('Semgrep check_id is required')
    cleaned = check_id.strip()
    if cleaned in SEMGREP_CHECK_ID_MAP:
        return SEMGREP_CHECK_ID_MAP[cleaned]
    for suffix, canonical in SEMGREP_CHECK_ID_MAP.items():
        if cleaned.endswith('.' + suffix) or cleaned.endswith('/' + suffix):
            return canonical
    if cleaned in ('hardcoded-secret', 'dynamic-execution', 'subprocess-shell', 'js-eval', 'inner-html'):
        return cleaned
    raise ValueError(f'Unapproved Semgrep rule check_id: {cleaned}')


def verify_semgrep_contract(version_output: str, *, rulepack_path: str | Path | None = None,
                            expected_version: str = PINNED_SEMGREP_VERSION,
                            expected_rulepack_sha256: str = SEMGREP_RULEPACK_SHA256) -> dict:
    if not isinstance(version_output, str):
        raise ValueError('Semgrep version output is required')
    m = re.search(r'\b(\d+\.\d+\.\d+)\b', version_output.strip())
    if not m or m.group(1) != expected_version:
        raise ValueError(f'Semgrep version mismatch: expected {expected_version}')
    actual_sha = expected_rulepack_sha256
    if rulepack_path is not None:
        raw_path = str(rulepack_path)
        if '://' in raw_path or raw_path.startswith(('p/', 'r/')):
            raise ValueError('Remote Semgrep registry configs are forbidden; use a pinned local rulepack')
        resolved = Path(rulepack_path).resolve(strict=True)
        actual_sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_sha != expected_rulepack_sha256:
            raise ValueError('Semgrep rulepack SHA-256 checksum mismatch')
    return {
        'tool': 'semgrep',
        'version': expected_version,
        'rulepack_id': SEMGREP_RULEPACK_ID,
        'rulepack_sha256': actual_sha,
    }


def parse_semgrep_json(payload: dict | str | bytes, *,
                       expected_version: str = PINNED_SEMGREP_VERSION,
                       rulepack_sha256: str = SEMGREP_RULEPACK_SHA256) -> list[dict]:
    from .privacy import path_id
    if isinstance(payload, (str, bytes)):
        data = json.loads(payload)
    elif isinstance(payload, dict):
        data = payload
    else:
        raise ValueError('Invalid Semgrep JSON payload')
    version = data.get('version')
    if version is not None and str(version).strip() != expected_version:
        raise ValueError(f'Semgrep output version mismatch: expected {expected_version}')
    raw_results = data.get('results')
    if not isinstance(raw_results, list):
        raise ValueError('Semgrep JSON payload missing results list')
    findings = []
    for item in raw_results:
        if not isinstance(item, dict):
            raise ValueError('Invalid Semgrep result entry')
        rel_path = item.get('path')
        path_id(rel_path)
        start = item.get('start') or {}
        line = start.get('line')
        if type(line) is not int or line < 1:
            raise ValueError('Semgrep finding requires a positive integer start.line')
        extra = item.get('extra') or {}
        raw_check_id = item.get('check_id', '')
        rule = map_semgrep_rule_id(raw_check_id)
        severity = normalize_severity(str(extra.get('severity', 'WARNING')))
        message = str(extra.get('message') or f'Semgrep {rule} match').strip()
        findings.append(normalize_finding(
            category='code',
            severity=severity,
            title=message,
            file_path=rel_path,
            line=line,
            rule=rule,
            snippet='[CODE OMITTED; inspect referenced line]',
            scanner='semgrep',
            details={
                'semgrep_check_id': str(raw_check_id),
                'tool_version': expected_version,
                'rulepack_id': SEMGREP_RULEPACK_ID,
                'rulepack_sha256': rulepack_sha256,
                'line_signature': _line_sig(rule, message),
            },
        ))
    return findings


def run_semgrep_adapter(target_root: str | Path, *, semgrep_bin: str | Path,
                        rulepack_path: str | Path,
                        expected_version: str = PINNED_SEMGREP_VERSION,
                        expected_rulepack_sha256: str = SEMGREP_RULEPACK_SHA256,
                        runner=None) -> list[dict]:
    root = Path(target_root).resolve(strict=True)
    binary = Path(semgrep_bin)
    if not binary.is_absolute():
        raise ValueError('Semgrep binary path must be absolute')
    if str(binary).startswith(str(root) + '/'):
        raise ValueError('Semgrep binary must reside outside target checkout')
    exec_fn = runner or (lambda cmd: subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout)
    ver_out = exec_fn([str(binary), '--version'])
    contract = verify_semgrep_contract(
        ver_out,
        rulepack_path=rulepack_path,
        expected_version=expected_version,
        expected_rulepack_sha256=expected_rulepack_sha256,
    )
    scan_out = exec_fn([
        str(binary), 'scan', '--json', '--metrics=off', '--disable-version-check',
        '--config', str(Path(rulepack_path).resolve(strict=True)), str(root),
    ])
    return parse_semgrep_json(
        scan_out,
        expected_version=contract['version'],
        rulepack_sha256=contract['rulepack_sha256'],
    )


def verify_gitleaks_contract(version_output: str, *, config_path: str | Path | None = None,
                             expected_version: str = PINNED_GITLEAKS_VERSION,
                             expected_config_sha256: str = GITLEAKS_CONFIG_SHA256) -> dict:
    if not isinstance(version_output, str):
        raise ValueError('Gitleaks version output is required')
    m = re.search(r'\bv?(\d+\.\d+\.\d+)\b', version_output.strip())
    if not m or m.group(1) != expected_version:
        raise ValueError(f'Gitleaks version mismatch: expected {expected_version}')
    actual_sha = expected_config_sha256
    if config_path is not None:
        resolved = Path(config_path).resolve(strict=True)
        actual_sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_sha != expected_config_sha256:
            raise ValueError('Gitleaks config SHA-256 checksum mismatch')
    return {
        'tool': 'gitleaks',
        'version': expected_version,
        'config_id': GITLEAKS_CONFIG_ID,
        'config_sha256': actual_sha,
    }


def parse_gitleaks_json(payload: list | str | bytes, *,
                        expected_version: str = PINNED_GITLEAKS_VERSION,
                        config_sha256: str = GITLEAKS_CONFIG_SHA256) -> list[dict]:
    from .privacy import path_id
    if isinstance(payload, (str, bytes)):
        text = payload.decode('utf-8') if isinstance(payload, bytes) else payload
        data = json.loads(text) if text.strip() else []
    elif isinstance(payload, list):
        data = payload
    else:
        raise ValueError('Invalid Gitleaks JSON payload')
    if not isinstance(data, list):
        raise ValueError('Gitleaks JSON payload must be a list')
    findings = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError('Invalid Gitleaks finding entry')
        rel_path = item.get('File') or item.get('file')
        path_id(rel_path)
        line = item.get('StartLine') if 'StartLine' in item else item.get('line')
        if type(line) is not int or line < 1:
            raise ValueError('Gitleaks finding requires a positive integer StartLine')
        raw_rule = str(item.get('RuleID') or item.get('rule_id') or 'secret').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', raw_rule):
            raise ValueError('Invalid Gitleaks RuleID')
        raw_secret = str(item.get('Secret') or '')
        raw_match = str(item.get('Match') or '')
        desc = str(item.get('Description') or f'Secret detected ({raw_rule})').strip()
        safe_desc = scrub_secret_values(desc, extra_secrets=(raw_secret, raw_match))
        title = f'Possible {safe_desc} in source' if not safe_desc.lower().startswith('possible ') else safe_desc
        findings.append(normalize_finding(
            category='code',
            severity='high',
            title=title,
            file_path=rel_path,
            line=line,
            rule='hardcoded-secret',
            snippet='[REDACTED: possible secret]',
            scanner='gitleaks',
            details={
                'gitleaks_rule_id': raw_rule,
                'tool_version': expected_version,
                'config_id': GITLEAKS_CONFIG_ID,
                'config_sha256': config_sha256,
                'line_signature': _line_sig('hardcoded-secret', title, is_secret=True),
            },
        ))
    return findings


def run_gitleaks_adapter(target_root: str | Path, *, gitleaks_bin: str | Path,
                         config_path: str | Path,
                         expected_version: str = PINNED_GITLEAKS_VERSION,
                         expected_config_sha256: str = GITLEAKS_CONFIG_SHA256,
                         runner=None) -> list[dict]:
    root = Path(target_root).resolve(strict=True)
    binary = Path(gitleaks_bin)
    if not binary.is_absolute():
        raise ValueError('Gitleaks binary path must be absolute')
    if str(binary).startswith(str(root) + '/'):
        raise ValueError('Gitleaks binary must reside outside target checkout')
    exec_fn = runner or (lambda cmd: subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout)
    try:
        ver_out = exec_fn([str(binary), 'version'])
        contract = verify_gitleaks_contract(
            ver_out,
            config_path=config_path,
            expected_version=expected_version,
            expected_config_sha256=expected_config_sha256,
        )
        scan_out = exec_fn([
            str(binary), 'dir', str(root), '--no-banner', '--redact',
            '--exit-code', '0', '--config', str(Path(config_path).resolve(strict=True)),
            '--report-format', 'json', '--report-path', '-',
        ])
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(scrub_secret_values(str(exc.stderr or exc.stdout or 'Gitleaks execution failed'))) from None
    return parse_gitleaks_json(
        scan_out,
        expected_version=contract['version'],
        config_sha256=contract['config_sha256'],
    )
