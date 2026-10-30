"""Evidence-based reachability and runtime exposure signal analyzer."""
import ast
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple


ROUTE_DECORATOR_PATTERNS = (
    re.compile(r"^(app|router|bp|api)\.(get|post|put|delete|patch|route|api_route)$"),
    re.compile(r"^.*route.*$"),
)


@dataclass
class ReachabilityAssessment:
    package: str
    status: str  # 'reachable', 'unreachable', 'runtime_exposed', 'unknown'
    vulnerable_symbols: List[str]
    matched_symbols: List[str] = field(default_factory=list)
    callsites: List[Dict[str, Any]] = field(default_factory=list)
    is_runtime_exposed: bool = False
    base_severity: str = "medium"
    contextual_severity: str = "medium"
    confidence: float = 0.5
    evidence_rationale: str = ""


class ReachabilityVisitor(ast.NodeVisitor):
    """AST visitor tracking package imports, symbol calls, and route exposures."""

    def __init__(self, package_name: str, vulnerable_symbols: List[str], file_path: str):
        self.package_name = package_name.lower().replace("-", "_")
        self.vulnerable_symbols = set(vulnerable_symbols or [])
        self.file_path = file_path

        self.imported_names: Dict[str, str] = {}  # alias -> original symbol or module
        self.imported_package: bool = False
        self.callsites: List[Dict[str, Any]] = []
        self.matched_symbols: Set[str] = set()
        self.has_runtime_exposure: bool = False
        self._current_function_is_route: bool = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod_root = alias.name.split(".")[0].lower().replace("-", "_")
            if mod_root == self.package_name:
                self.imported_package = True
                local_name = alias.asname or alias.name
                self.imported_names[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            mod_root = node.module.split(".")[0].lower().replace("-", "_")
            if mod_root == self.package_name:
                self.imported_package = True
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    self.imported_names[local_name] = alias.name
                    if alias.name in self.vulnerable_symbols:
                        self.matched_symbols.add(alias.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_route = self._current_function_is_route
        # Check if function has a route decorator
        is_route = False
        for dec in node.decorator_list:
            dec_str = ""
            if isinstance(dec, ast.Name):
                dec_str = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_str = f"{getattr(dec.value, 'id', '')}.{dec.attr}"
            elif isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Attribute):
                    dec_str = f"{getattr(func.value, 'id', '')}.{func.attr}"
                elif isinstance(func, ast.Name):
                    dec_str = func.id

            if any(p.match(dec_str) for p in ROUTE_DECORATOR_PATTERNS):
                is_route = True
                break

        self._current_function_is_route = is_route
        self.generic_visit(node)
        self._current_function_is_route = prev_route

    def visit_Call(self, node: ast.Call):
        func_name = ""
        invoked_symbol = ""

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.imported_names:
                invoked_symbol = self.imported_names[func_name]
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            val = node.func.value
            if isinstance(val, ast.Name) and val.id in self.imported_names:
                invoked_symbol = attr_name

        if invoked_symbol:
            # Check if this symbol is in vulnerable list or package is invoked directly
            if not self.vulnerable_symbols or invoked_symbol in self.vulnerable_symbols:
                self.matched_symbols.add(invoked_symbol)
                callsite = {
                    "file": self.file_path,
                    "line": getattr(node, "lineno", 0),
                    "symbol": invoked_symbol,
                    "in_route": self._current_function_is_route,
                }
                self.callsites.append(callsite)
                if self._current_function_is_route:
                    self.has_runtime_exposure = True

        self.generic_visit(node)


def analyze_reachability(
    files: Dict[str, str],
    package_name: str,
    vulnerable_symbols: Optional[List[str]] = None,
    base_severity: str = "medium",
) -> ReachabilityAssessment:
    """Analyze AST call-graph across files to assess reachability and runtime exposure."""
    symbols = vulnerable_symbols or []
    total_callsites: List[Dict[str, Any]] = []
    total_matched_symbols: Set[str] = set()
    package_imported_anywhere = False
    runtime_exposed = False

    for file_path, content in files.items():
        if not file_path.endswith(".py"):
            continue

        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            continue

        visitor = ReachabilityVisitor(package_name, symbols, file_path)
        visitor.visit(tree)

        if visitor.imported_package:
            package_imported_anywhere = True
        total_matched_symbols.update(visitor.matched_symbols)
        total_callsites.extend(visitor.callsites)
        if visitor.has_runtime_exposure:
            runtime_exposed = True

    # Assess status and contextual severity
    base_sev = base_severity.lower()
    if not package_imported_anywhere:
        status = "unreachable"
        confidence = 0.95
        contextual_severity = "low" if base_sev in ("critical", "high") else "info"
        rationale = f"Package '{package_name}' is declared in inventory but never imported in application code."
    elif total_callsites and runtime_exposed:
        status = "runtime_exposed"
        confidence = 0.90
        contextual_severity = "critical" if base_sev in ("critical", "high") else base_sev
        rationale = f"Vulnerable symbol(s) {sorted(total_matched_symbols)} are invoked directly within public HTTP route handlers."
    elif total_callsites:
        status = "reachable"
        confidence = 0.85
        contextual_severity = base_sev
        rationale = f"Vulnerable symbol(s) {sorted(total_matched_symbols)} are imported and actively invoked in application call-graph."
    elif symbols and not total_matched_symbols:
        status = "unreachable"
        confidence = 0.80
        contextual_severity = "low"
        rationale = f"Package '{package_name}' is imported, but specific vulnerable symbols {symbols} are not referenced."
    else:
        status = "unknown"
        confidence = 0.50
        contextual_severity = base_sev
        rationale = f"Package '{package_name}' is imported, but symbol-level callgraph analysis is inconclusive."

    return ReachabilityAssessment(
        package=package_name,
        status=status,
        vulnerable_symbols=symbols,
        matched_symbols=sorted(total_matched_symbols),
        callsites=total_callsites,
        is_runtime_exposed=runtime_exposed,
        base_severity=base_sev,
        contextual_severity=contextual_severity,
        confidence=confidence,
        evidence_rationale=rationale,
    )

