#!/usr/bin/env python3
# rce_scanner.py  (versión robusta)
import argparse, ast, json, os, sys
from pathlib import Path

DEFAULT_RULES = {
    "pickle": {
        "imports": {"pickle"},
        "calls": {("pickle", "load"), ("pickle", "dump")},
    },
    "torch": {
        "imports": {"torch"},
        "calls": {("torch", "load"), ("torch", "save")},
    }
}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", "env"}
MAX_FILE_BYTES = 10 * 1024 * 1024 #10 mb allowed
MAX_AST_NODES = 100000 #10 MB allowed
# MAX_FILE_BYTES = 2 * 1024 * 1024      # 2 MB: evita archivos gigantes
# MAX_AST_NODES  = 20000                # corta árboles patológicos

# Banner ASCII
def banner():
    banner = r"""
  _____ _      _    _        _____   _____ ______   ______ _           _           
 |  __ (_)    | |  | |      |  __ \ / ____|  ____| |  ____(_)         | |          
 | |__) |  ___| | _| | ___  | |__) | |    | |__    | |__   _ _ __   __| | ___ _ __ 
 |  ___/ |/ __| |/ / |/ _ \ |  _  /| |    |  __|   |  __| | | '_ \ / _` |/ _ \ '__|
 | |   | | (__|   <| |  __/ | | \ \| |____| |____  | |    | | | | | (_| |  __/ |   
 |_|   |_|\___|_|\_\_|\___| |_|  \_\\_____|______| |_|    |_|_| |_|\__,_|\___|_|   
                                                                                                                                                                  
    Pickle Deserialization Parser for Python Source Code
                coded by @JoshuaProvoste (jp / kw0)

"""
    print(banner)
banner()

def load_rules_json(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = {}
    for mod, spec in data.items():
        imports = set(spec.get("imports", []))
        # "calls" en JSON como lista de pares: [["pickle","load"], ["pickle","dump"]]
        calls = { (m, f) for m, f in spec.get("calls", []) }
        rules[mod] = {"imports": imports, "calls": calls}
    return rules

def iter_py_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield Path(dirpath) / fn

class RefVisitor(ast.NodeVisitor):
    def __init__(self, rules):
        self.rules = rules
        self.name_to_module = {}
        self.findings = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name.split(".")[0]
            asname = alias.asname or mod
            if mod in self.rules and mod in self.rules[mod]["imports"]:
                self.name_to_module[asname] = mod
                self._report(node, "import", mod, None, asname)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if not node.module:
            return
        base = node.module.split(".")[0]
        if base in self.rules and base in self.rules[base]["imports"]:
            for alias in node.names:
                local = alias.asname or alias.name
                self.name_to_module[local] = base
                self._report(node, "importfrom", base, alias.name, local)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        mod, func = self._resolve_call(node.func)
        if mod and func and self._is_tracked_call(mod, func):
            self._report(node, "call", mod, func)
        self.generic_visit(node)

    def _resolve_call(self, func_node):
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            base = func_node.value.id
            attr = func_node.attr
            mod = self.name_to_module.get(base, base)
            return mod, attr
        if isinstance(func_node, ast.Name):
            name = func_node.id
            mod = self.name_to_module.get(name)
            if mod:
                return mod, name
        return None, None

    def _is_tracked_call(self, mod, func):
        return mod in self.rules and (mod, func) in self.rules[mod]["calls"]

    def _report(self, node, kind, module, name, alias=None):
        self.findings.append({
            "kind": kind, "module": module, "name": name, "alias": alias,
            "lineno": getattr(node, "lineno", None),
            "col_offset": getattr(node, "col_offset", None),
        })

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

    # Cota de complejidad del AST
    try:
        node_count = sum(1 for _ in ast.walk(tree))
    except RecursionError as e:
        return [{"file": str(path), "error": f"walk_recursion_error:{e}"}]
    if node_count > MAX_AST_NODES:
        return [{"file": str(path), "error": f"skipped_huge_ast>{node_count}nodes"}]

    v = RefVisitor(rules)
    try:
        v.visit(tree)
    except RecursionError as e:
        return [{"file": str(path), "error": f"visit_recursion_error:{e}"}]
    except Exception as e:
        return [{"file": str(path), "error": f"visit_error:{type(e).__name__}:{e}"}]

    return [{"file": str(path), **f} for f in v.findings]

def main():
    ap = argparse.ArgumentParser(description="Escáner simple de referencias a módulos/funciones (pickle, extensible).")
    ap.add_argument("--path", default=".", help="Directorio raíz a escanear (por defecto: .)")
    ap.add_argument("--rules-file", help="Ruta a JSON de reglas; si se provee, reemplaza RULES")
    ap.add_argument("--out", default="-", help="Archivo de salida JSONL (use '-' para stdout; por defecto: '-')")
    args = ap.parse_args()

    rules = DEFAULT_RULES
    if args.rules_file:
        rules = load_rules_json(args.rules_file)

    root = Path(args.path).resolve()
    outputs = []

    for py in iter_py_files(root):
        outputs.extend(scan_file(py, rules))

    sink = sys.stdout if args.out == "-" else Path(args.out).expanduser().resolve().open("w", encoding="utf-8")
    try:
        for item in outputs:
            sink.write(json.dumps(item, ensure_ascii=False) + "\n")
    finally:
        if sink is not sys.stdout:
            sink.close()

if __name__ == "__main__":
    main()
