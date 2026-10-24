"""Small, transparent static rule set. Not a substitute for Semgrep/CodeQL."""
import ast
import hashlib
import re

# Never store values that match a secret rule in evidence.
SECRETS = [
    ('GitHub token', re.compile(r'\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{30,}\b')),
    ('GitHub fine-grained token', re.compile(r'github_pat_[A-Za-z0-9_]{22,}')),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('Private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
]


def finding(path: str, line: int, rule: str, title: str, severity: str, snippet: str):
    fingerprint = hashlib.sha256(f'{path}:{line}:{rule}'.encode()).hexdigest()[:24]
    return {'key': f'code:{fingerprint}', 'category':'code', 'severity':severity,
            'title':title, 'file_path':path,
            'details':{'rule':rule, 'line':line, 'evidence':snippet[:140]}}


def scan_code(path: str, source: str):
    if len(source) > 300_000:
        return []
    results = []
    lines=source.splitlines()[:10000]
    for n, line in enumerate(lines,1):
        for name, regex in SECRETS:
            if regex.search(line):
                results.append(finding(path,n,'hardcoded-secret',f'Possible {name} in source','high',
                                       '[REDACTED: possible secret]'))
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
                results.append(finding(path,n,'dynamic-execution',
                    'Dynamic Python evaluation can execute attacker-controlled input','high',
                    '[CODE OMITTED; inspect referenced line]'))
            if call_name in ('run','Popen','call','check_output','check_call') and any(
                kw.arg=='shell' and isinstance(kw.value,ast.Constant) and kw.value.value is True
                for kw in node.keywords):
                results.append(finding(path,n,'subprocess-shell',
                    'Subprocess invoked with shell=True','medium',
                    '[CODE OMITTED; inspect referenced line]'))
    if path.endswith(('.js','.ts','.jsx','.tsx')):
        for n,line in enumerate(lines,1):
            if re.search(r'\beval\s*\(', line):
                results.append(finding(path,n,'js-eval','JavaScript eval() usage','high',
                                       '[CODE OMITTED; inspect referenced line]'))
            if re.search(r'\.innerHTML\s*=',line):
                results.append(finding(path,n,'inner-html',
                    'HTML sink; verify input escaping/sanitization','medium',
                    '[CODE OMITTED; inspect referenced line]'))
    return results
