#!/usr/bin/env python3
# rce_scanner.py (robust version)
import argparse, ast, json, os, sys
from pathlib import Path
import tokenize
import warnings

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
def banner(file=sys.stdout):
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
    print(b, file=file)

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

def iter_py_files(root: Path, skip_dirs):
    skip_dirs = set(skip_dirs)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
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
        mod, func, qualified = self._resolve_call(node.func)
        if mod and func and self._is_tracked_call(mod, func):
            # Simple classification for better triage/filtering (does not affect detection logic)
            if mod == "pickle" and func in ("load", "loads"):
                category, severity = "deserialize", "high"
            elif mod == "torch" and func == "load":
                category, severity = "model_load", "high"
            else:
                category, severity = "call", "medium"

            self._report(
                node,
                "call",
                mod,
                func,
                qualified_name=qualified,
                category=category,
                severity=severity,
            )
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
            return None, None, None

        # De-alias the root if we tracked it (e.g., "t" -> "torch")
        root = parts[0]
        parts[0] = self.name_to_module.get(root, root)

        func = parts[-1]
        qualified = ".".join(parts)

        # Prefer the (possibly de-aliased) root module if it's tracked.
        if parts[0] in self.rules:
            return parts[0], func, qualified

        # Otherwise, support cases like pkg.pickle.loads where the tracked module
        # appears later in the chain.
        for p in parts[:-1]:
            if p in self.rules:
                return p, func, qualified

        return None, None, None

    def _is_tracked_call(self, mod, func):
        return mod in self.rules and (mod, func) in self.rules[mod]["calls"]

    def _report(self, node, kind, module, name, alias=None, *, qualified_name=None, category=None, severity=None):
        item = {
            "kind": kind,
            "module": module,
            "name": name,
            "alias": alias,
            "lineno": getattr(node, "lineno", None),
            "col_offset": getattr(node, "col_offset", None),
        }
        # Enriched fields (backwards-compatible: just extra keys)
        if qualified_name is not None:
            item["qualified_name"] = qualified_name
        if category is not None:
            item["category"] = category
        if severity is not None:
            item["severity"] = severity

        self.findings.append(item)

def scan_tokens_fallback(src: str, path: Path, rules: dict) -> list[dict]:
    """
    Streaming fallback scanner for huge files (memory-safe):
    - Uses tokenize without materializing token list
    - Reconstructs import/alias mappings
    - Detects dotted call expressions followed by '('
    Preserves the same rules/alias intent as the AST visitor.
    """
    import io

    tracked_imports = set()
    for spec in rules.values():
        tracked_imports.update(spec.get("imports", set()))

    name_to_module: dict[str, str] = {}
    findings: list[dict] = []

    def is_tracked_call(mod: str, func: str) -> bool:
        return mod in rules and (mod, func) in rules[mod]["calls"]

    def classify(mod: str, func: str) -> tuple[str, str]:
        if mod == "pickle" and func in ("load", "loads"):
            return "deserialize", "high"
        if mod == "torch" and func == "load":
            return "model_load", "high"
        return "call", "medium"

    def resolve_dotted(parts: list[str]) -> tuple[str | None, str | None, str | None]:
        # De-alias root
        if parts:
            parts = parts[:]  # copy
            parts[0] = name_to_module.get(parts[0], parts[0])

        if not parts:
            return None, None, None

        func = parts[-1]
        qualified = ".".join(parts)

        # Prefer root module if tracked
        if parts[0] in rules:
            return parts[0], func, qualified

        # Support pkg.pickle.loads where tracked module is later
        for p in parts[:-1]:
            if p in rules:
                return p, func, qualified

        return None, None, None

    def emit_call(mod: str, func: str, qualified: str, lineno: int, col: int) -> None:
        category, severity = classify(mod, func)
        findings.append(
            {
                "kind": "call",
                "module": mod,
                "name": func,
                "alias": None,
                "lineno": lineno,
                "col_offset": col,
                "qualified_name": qualified,
                "category": category,
                "severity": severity,
                "parser": "tokenize_fallback",
            }
        )

    # Stream tokens (NO splitlines(), NO list())
    try:
        reader = io.StringIO(src).readline
        tok_iter = tokenize.generate_tokens(reader)
    except Exception:
        return [{"file": str(path), "error": "tokenize_error"}]

    # Skip trivia but keep NEWLINE/NL (they matter as statement boundaries)
    DROP = {
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.COMMENT,
        tokenize.ENCODING,
    }

    pending: list[tokenize.TokenInfo] = []

    def next_tok() -> tokenize.TokenInfo:
        if pending:
            return pending.pop()
        return next(tok_iter)

    def push_tok(t: tokenize.TokenInfo) -> None:
        pending.append(t)

    def next_nondrop() -> tokenize.TokenInfo:
        while True:
            t = next_tok()
            if t.type not in DROP:
                return t

    def parse_module_name(first: tokenize.TokenInfo) -> tuple[list[str], tokenize.TokenInfo | None]:
        # module := NAME ('.' NAME)*
        parts = [first.string]
        while True:
            try:
                t = next_nondrop()
            except StopIteration:
                return parts, None
            if t.type == tokenize.OP and t.string == ".":
                try:
                    t2 = next_nondrop()
                except StopIteration:
                    return parts, None
                if t2.type == tokenize.NAME:
                    parts.append(t2.string)
                    continue
                # unexpected token after dot -> push back and stop
                push_tok(t2)
                push_tok(t)
                return parts, t
            else:
                push_tok(t)
                return parts, t

    def parse_import_stmt() -> None:
        # after seeing NAME 'import'
        while True:
            try:
                t = next_nondrop()
            except StopIteration:
                return

            if t.type in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER):
                return
            if t.type == tokenize.OP and t.string == ",":
                continue
            if t.type != tokenize.NAME:
                continue

            mod_parts, _ = parse_module_name(t)
            mod_root = mod_parts[0]
            asname = mod_root

            # optional "as NAME"
            try:
                t2 = next_nondrop()
            except StopIteration:
                t2 = None

            if t2 and t2.type == tokenize.NAME and t2.string == "as":
                try:
                    t3 = next_nondrop()
                except StopIteration:
                    t3 = None
                if t3 and t3.type == tokenize.NAME:
                    asname = t3.string
                else:
                    if t3:
                        push_tok(t3)
            else:
                if t2:
                    push_tok(t2)

            if mod_root in tracked_imports:
                name_to_module[asname] = mod_root

            # consume optional comma/newline naturally by loop

    def parse_from_stmt() -> None:
        # after seeing NAME 'from'
        try:
            t = next_nondrop()
        except StopIteration:
            return

        if t.type in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER):
            return
        if t.type != tokenize.NAME:
            return

        mod_parts, _ = parse_module_name(t)
        base = mod_parts[0]

        # expect "import"
        try:
            t2 = next_nondrop()
        except StopIteration:
            return
        if not (t2.type == tokenize.NAME and t2.string == "import"):
            push_tok(t2)
            return

        if base not in tracked_imports:
            # consume until end of statement but don't map aliases
            while True:
                try:
                    t3 = next_nondrop()
                except StopIteration:
                    return
                if t3.type in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER):
                    return
            # unreachable

        # parse imported names list: NAME [as NAME] (, ...)
        while True:
            try:
                t3 = next_nondrop()
            except StopIteration:
                return
            if t3.type in (tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER):
                return
            if t3.type == tokenize.OP and t3.string == ",":
                continue
            if t3.type != tokenize.NAME:
                continue

            local = t3.string

            # optional "as NAME"
            try:
                t4 = next_nondrop()
            except StopIteration:
                t4 = None
            if t4 and t4.type == tokenize.NAME and t4.string == "as":
                try:
                    t5 = next_nondrop()
                except StopIteration:
                    t5 = None
                if t5 and t5.type == tokenize.NAME:
                    local = t5.string
                else:
                    if t5:
                        push_tok(t5)
            else:
                if t4:
                    push_tok(t4)

            name_to_module[local] = base

    while True:
        try:
            t = next_nondrop()
        except StopIteration:
            break
        except tokenize.TokenError:
            return [{"file": str(path), "error": "tokenize_error"}]
        except MemoryError:
            return [{"file": str(path), "error": "tokenize_memory_error"}]

        if t.type in (tokenize.NEWLINE, tokenize.NL):
            continue

        # import / from handling
        if t.type == tokenize.NAME and t.string == "import":
            parse_import_stmt()
            continue
        if t.type == tokenize.NAME and t.string == "from":
            parse_from_stmt()
            continue

        # call detection: NAME ('.' NAME)* '('
        if t.type == tokenize.NAME:
            parts = [t.string]
            lineno, col = t.start

            while True:
                try:
                    t1 = next_nondrop()
                except StopIteration:
                    t1 = None

                if t1 is None:
                    break
                if t1.type in (tokenize.NEWLINE, tokenize.NL):
                    push_tok(t1)
                    break

                if t1.type == tokenize.OP and t1.string == ".":
                    try:
                        t2 = next_nondrop()
                    except StopIteration:
                        break
                    if t2.type == tokenize.NAME:
                        parts.append(t2.string)
                        continue
                    # not a proper dotted chain
                    push_tok(t2)
                    push_tok(t1)
                    break

                if t1.type == tokenize.OP and t1.string == "(":
                    mod, func, qualified = resolve_dotted(parts)
                    if mod and func and qualified and is_tracked_call(mod, func):
                        emit_call(mod, func, qualified, lineno, col)
                    # do not push back '('
                    break

                # any other token breaks the chain
                push_tok(t1)
                break

    return [{"file": str(path), **f} for f in findings]

def scan_file(path: Path, rules):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [{"file": str(path), "error": f"skipped_large_file>{path.stat().st_size}B"}]
    except OSError as e:
        return [{"file": str(path), "error": f"stat_error:{e}"}]

    # Read source robustly (PEP263 + BOM-safe)
    try:
        with tokenize.open(str(path)) as f:
            src = f.read()
    except (SyntaxError, UnicodeDecodeError):
        try:
            data = path.read_bytes()
            src = data.decode("utf-8-sig", errors="replace")
        except Exception as e2:
            return [{"file": str(path), "error": f"read_error:{e2}"}]
    except Exception as e:
        return [{"file": str(path), "error": f"read_error:{e}"}]

    if src.startswith("\ufeff"):
        src = src[1:]

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [{"file": str(path), "error": f"syntax_error:{e}"}]
    except RecursionError as e:
        return [{"file": str(path), "error": f"parse_recursion_error:{e}"}]

    v = RefVisitor(rules)
    try:
        v.visit(tree)
    except AstNodeLimitExceeded:
        # IMPORTANT: do NOT treat this as an error; fall back to tokenize scan
        return scan_tokens_fallback(src, path, rules)
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
    ap.add_argument(
        "--skip-dirs",
        default=",".join(sorted(SKIP_DIRS)),
        help="Comma-separated directory names to skip while walking (default: built-in SKIP_DIRS).",
    )
    args = ap.parse_args()

    rules = DEFAULT_RULES
    if args.rules_file:
        rules = load_rules_json(args.rules_file)

    root = Path(args.path).resolve()
    skip_dirs = {d.strip() for d in args.skip_dirs.split(",") if d.strip()}

    # Human-readable output goes to stdout when writing JSONL to a file,
    # and to stderr when writing JSONL to stdout (to avoid corrupting JSONL).
    human = sys.stderr if args.out == "-" else sys.stdout

    if not args.no_banner:
        banner(file=human)

    total_findings = 0
    total_errors = 0
    files_scanned = 0
    jsonl_lines = 0

    def print_finding(item: dict):
        # Compact CLI line
        sev = item.get("severity", "-")
        cat = item.get("category", "-")
        qn = item.get("qualified_name") or f"{item.get('module')}.{item.get('name')}"
        loc = f"{item.get('file')}:{item.get('lineno')}"
        print(f"[{sev.upper()}][{cat}] {loc}  {qn}", file=human)

    def print_error(item: dict):
        loc = item.get("file", "?")
        err = item.get("error", "unknown_error")
        print(f"[ERROR] {loc}  {err}", file=human)

    def emit(sink, item: dict):
        nonlocal total_findings, total_errors, jsonl_lines
        sink.write(json.dumps(item, ensure_ascii=False) + "\n")
        jsonl_lines += 1

        if isinstance(item, dict) and "error" in item:
            total_errors += 1
            print_error(item)
        else:
            # findings (calls) are what we print as results
            if item.get("kind") == "call":
                total_findings += 1
                print_finding(item)

    if args.out == "-":
        # JSONL to stdout
        for py in iter_py_files(root, skip_dirs):
            files_scanned += 1
            for item in scan_file(py, rules):
                emit(sys.stdout, item)
        out_desc = "stdout (JSONL)"
        out_size = None
    else:
        out_path = Path(args.out).expanduser().resolve()
        with out_path.open("w", encoding="utf-8") as sink:
            for py in iter_py_files(root, skip_dirs):
                files_scanned += 1
                for item in scan_file(py, rules):
                    emit(sink, item)
        out_desc = str(out_path)
        try:
            out_size = out_path.stat().st_size
        except OSError:
            out_size = None

    # Summary
    print("", file=human)
    print("Scan finished.", file=human)
    print(f"Files scanned: {files_scanned}", file=human)
    print(f"Findings: {total_findings}", file=human)
    print(f"Errors: {total_errors}", file=human)
    if out_size is None:
        print(f"JSONL output: {out_desc} (lines: {jsonl_lines})", file=human)
    else:
        print(f"JSONL output: {out_desc} (lines: {jsonl_lines}, bytes: {out_size})", file=human)

    # Non-zero exit code is useful in CI when any IO/parse errors occurred.
    raise SystemExit(1 if total_errors else 0)

if __name__ == "__main__":
    main()