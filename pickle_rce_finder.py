#!/usr/bin/env python3
# rce_scanner.py (robust version)
import argparse, ast, json, os, sys
from pathlib import Path

DEFAULT_RULES = {
    "pickle": {
        "imports": {"pickle"},
        # Focus on dangerous deserialization entrypoints
        "calls": {
            ("pickle", "load"),
            ("pickle", "loads"),
        },
    },
    "torch": {
        "imports": {"torch"},
        # torch.load() can deserialize pickled payloads depending on usage
        "calls": {
            ("torch", "load"),
        },
    },
}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", "env"}
MAX_FILE_BYTES = 10 * 1024 * 1024  # Max source file size to parse (bytes). 10 MiB.
MAX_AST_NODES = 100000  # Max AST nodes visited per file (DoS/anti-pathological guardrail).

# Optional tighter limits (useful for CI / scanning huge repos):
# MAX_FILE_BYTES = 2 * 1024 * 1024   # 2 MiB
# MAX_AST_NODES = 20000              # Lower AST node cap

# ASCII banner
def banner():
    b = r"""
  _____ _      _    _        _____   _____ ______   ______ _           _           
 |  __ (_)    | |  | |      |  __ \ / ____|  ____| |  ____(_)         | |          
 | |__) |  ___| | _| | ___  | |__) | |    | |__    | |__   _ _ __   __| | ___ _ __ 
 |  ___/ |/ __| |/ / |/ _ \ |  _  /| |    |  __|   |  __| | | '_ \ / _` |/ _ \ '__|
 | |   | | (__|   <| |  __/ | | \ \| |____| |____  | |    | | | | | (_| |  __/ |   
 |_|   |_|\___|_|\_\_|\___| |_|  \_\\_____|______| |_|    |_|_| |_|\__,_|\___|_|   
                                                                                                                                                                  
    Pickle Deserialization Parser for Python Source Code
            coded by @JoshuaProvoste (jp / kw0)

"""
    print(b)

def load_rules_json(path: str) -> dict:
    def warn(msg: str) -> None:
        print(f"[rules] {msg}", file=sys.stderr)

    try:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Failed to load rules JSON from {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"Rules JSON root must be an object/dict, got {type(data).__name__}")

    rules = {}
    for mod, spec in data.items():
        if not isinstance(mod, str) or not mod.strip():
            warn(f"Skipping rule with non-string/empty module key: {mod!r}")
            continue
        if not isinstance(spec, dict):
            warn(f"Skipping module '{mod}': spec must be an object/dict, got {type(spec).__name__}")
            continue

        # --- imports ---
        imports_raw = spec.get("imports", [])
        if not isinstance(imports_raw, list):
            warn(f"Module '{mod}': 'imports' must be a list, got {type(imports_raw).__name__}; treating as empty")
            imports_raw = []

        imports = set()
        for imp in imports_raw:
            if not isinstance(imp, str) or not imp.strip():
                warn(f"Module '{mod}': ignoring invalid import entry: {imp!r}")
                continue
            # Normalize to import root (same behavior as visitor)
            imports.add(imp.split(".")[0])

        # Heuristic typo/mismatch warning (e.g., pickle vs picle)
        if imports and mod not in imports:
            suggestion = None
            for imp in imports:
                if abs(len(imp) - len(mod)) <= 1 and imp[:3] == mod[:3]:
                    suggestion = imp
                    break
            if suggestion:
                warn(f"Module '{mod}': imports contains '{suggestion}' but not '{mod}' (typo?).")
            else:
                warn(f"Module '{mod}': imports does not include '{mod}' (current imports={sorted(imports)!r}).")

        # --- calls ---
        calls_raw = spec.get("calls", [])
        if not isinstance(calls_raw, list):
            warn(f"Module '{mod}': 'calls' must be a list, got {type(calls_raw).__name__}; treating as empty")
            calls_raw = []

        calls = set()
        for item in calls_raw:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], str)
                and item[0].strip()
                and item[1].strip()
            ):
                calls.add((item[0], item[1]))
            else:
                warn(f"Module '{mod}': ignoring malformed call entry (expected [module, func]): {item!r}")

        rules[mod] = {"imports": imports, "calls": calls}

    return rules

def iter_py_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield Path(dirpath) / fn

class AstNodeLimitExceeded(Exception):
    def __init__(self, count: int, limit: int):
        super().__init__(f"AST node limit exceeded: {count}>{limit}")
        self.count = count
        self.limit = limit

class RefVisitor(ast.NodeVisitor):
    def __init__(self, rules):
        self.rules = rules
        self.name_to_module = {}
        self.findings = []
        self.node_count = 0  # counts visited AST nodes

        # Precompute allowed import roots from the ruleset
        self.tracked_imports = set()
        for spec in self.rules.values():
            self.tracked_imports.update(spec.get("imports", set()))

    def generic_visit(self, node):
        self.node_count += 1
        if self.node_count > MAX_AST_NODES:
            raise AstNodeLimitExceeded(self.node_count, MAX_AST_NODES)
        return super().generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name.split(".")[0]
            asname = alias.asname or mod
            if mod in self.tracked_imports:
                # Keep alias/module mapping for later call resolution
                self.name_to_module[asname] = mod
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if not node.module:
            return
        base = node.module.split(".")[0]
        if base in self.tracked_imports:
            for alias in node.names:
                local = alias.asname or alias.name
                # Keep alias/module mapping for later call resolution
                self.name_to_module[local] = base
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        mod, func = self._resolve_call(node.func)
        if mod and func and self._is_tracked_call(mod, func):
            self._report(node, "call", mod, func)
        self.generic_visit(node)

    def _resolve_call(self, func_node):
        # Build a dotted path from nested attributes, e.g.:
        #   pkg.pickle.loads -> ["pkg", "pickle", "loads"]
        #   t.serialization.load -> ["t", "serialization", "load"]
        def _dotted_parts(node):
            if isinstance(node, ast.Name):
                return [node.id]
            if isinstance(node, ast.Attribute):
                left = _dotted_parts(node.value)
                if not left:
                    return None
                return left + [node.attr]
            return None

        parts = _dotted_parts(func_node)
        if not parts:
            return None, None

        # If the root name is an alias we track (e.g., "t" -> "torch"), rewrite it.
        root = parts[0]
        parts[0] = self.name_to_module.get(root, root)

        func = parts[-1]

        # Prefer the (possibly de-aliased) root module if it's tracked.
        if parts[0] in self.rules:
            return parts[0], func

        # Otherwise, support cases like pkg.pickle.loads where the tracked module
        # appears later in the chain.
        for p in parts[:-1]:
            if p in self.rules:
                return p, func

        return None, None


    def _is_tracked_call(self, mod, func):
        return mod in self.rules and (mod, func) in self.rules[mod]["calls"]

    def _report(self, node, kind, module, name, alias=None):
        self.findings.append(
            {
                "kind": kind,
                "module": module,
                "name": name,
                "alias": alias,
                "lineno": getattr(node, "lineno", None),
                "col_offset": getattr(node, "col_offset", None),
            }
        )

def scan_file(path: Path, rules):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [{"file": str(path), "error": f"skipped_large_file>{path.stat().st_size}B"}]
    except OSError as e:
        return [{"file": str(path), "error": f"stat_error:{e}"}]

    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [{"file": str(path), "error": f"read_error:{e}"}]

    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [{"file": str(path), "error": f"syntax_error:{e}"}]
    except RecursionError as e:
        return [{"file": str(path), "error": f"parse_recursion_error:{e}"}]

    v = RefVisitor(rules)
    try:
        v.visit(tree)
    except AstNodeLimitExceeded as e:
        return [{"file": str(path), "error": f"skipped_huge_ast>{e.count}nodes"}]
    except RecursionError as e:
        return [{"file": str(path), "error": f"visit_recursion_error:{e}"}]
    except Exception as e:
        return [{"file": str(path), "error": f"visit_error:{type(e).__name__}:{e}"}]

    return [{"file": str(path), **f} for f in v.findings]

def main():
    ap = argparse.ArgumentParser(
        description="Simple AST-based scanner for module/function references (pickle-focused, extensible)."
    )
    ap.add_argument("--path", default=".", help="Root directory to scan (default: .)")
    ap.add_argument("--rules-file", help="Path to rules JSON; if provided, overrides DEFAULT_RULES")
    ap.add_argument(
        "--out",
        default="-",
        help="Output JSONL file (use '-' for stdout; default: '-')",
    )
    ap.add_argument(
        "--no-banner",
        action="store_true",
        help="Do not print the banner (avoids polluting stdout when using --out -).",
    )
    args = ap.parse_args()

    if not args.no_banner:
        banner()

    rules = DEFAULT_RULES
    if args.rules_file:
        rules = load_rules_json(args.rules_file)

    root = Path(args.path).resolve()

    sink = sys.stdout if args.out == "-" else Path(args.out).expanduser().resolve().open("w", encoding="utf-8")
    try:
        for py in iter_py_files(root):
            for item in scan_file(py, rules):
                sink.write(json.dumps(item, ensure_ascii=False) + "\n")
    finally:
        if sink is not sys.stdout:
            sink.close()

if __name__ == "__main__":
    main()