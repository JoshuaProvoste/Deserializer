#!/usr/bin/env python3
import argparse, ast, json, os, re, sys, io, shutil
import concurrent.futures
import multiprocessing
import signal
from pathlib import Path
import tokenize
import warnings
import ctypes
from typing import Union, Any

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
  _____                      _       _ _              
 |  __ \                    (_)     | (_)             
 | |  | | ___  ___  ___ _ __ _  __ _| |_ _______ _ __ 
 | |  | |/ _ \/ __|/ _ \ '__| |/ _` | | |_  / _ \ '__|
 | |__| |  __/\__ \  __/ |  | | (_| | | |/ /  __/ |   
 |_____/ \___||___/\___|_|  |_|\__,_|_|_/___\___|_|   
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
       Python Deserialization AST based Scanner
         coded by @JoshuaProvoste (jp / kw0)

"""
    print(b, file=file)

def setup_windows_ansi():
    """ Enables Virtual Terminal Processing in Windows CMD/PowerShell for ANSI support. """
    if os.name == 'nt':
        try:
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            for handle_id in [-11, -12]:  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
                h = kernel32.GetStdHandle(handle_id)
                mode = wintypes.DWORD()
                if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                    # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                    kernel32.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            pass

def sanitize_template_syntax(src: str) -> str:
    """
    Identifies Jinja2/Mako-like template tags and neutralizes them while 
    preserving line count and (mostly) column offsets.
    """
    import re
    pattern = re.compile(r"(\{%.*?%\}|\{\{.*?\}\}|\{#.*?#\})", re.DOTALL)
    
    parts = []
    last_end = 0
    for match in pattern.finditer(src):
        parts.append(src[last_end:match.start()])
        content = match.group(0)
        
        sub_parts = []
        is_expr = content.startswith('{{')
        first = True
        for c in content:
            if c == '\n':
                sub_parts.append('\n')
            elif is_expr:
                # Replace expressions with a valid identifier T____ to preserve length/grammar
                sub_parts.append('T' if first else '_')
                first = False
            else:
                # Replace blocks/comments with spaces to preserve length/alignment
                sub_parts.append(' ')
        
        parts.append("".join(sub_parts))
        last_end = match.end()
    
    parts.append(src[last_end:])
    sanitized = "".join(parts)
    
    # Post-processing: Fix the 'el  if' -> 'elif' issue common in structural templates
    # This might shift columns by a few characters on these specific lines, but ensures valid parsing.
    sanitized = re.sub(r'\bel\s+if\b', 'elif ', sanitized)
    
    return sanitized

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
    if root.is_file():
        if root.suffix == ".py":
            yield root
        return

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
        self._call_nodes = set()  # prevent double reporting of call targets

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

    def visit_Attribute(self, node: ast.Attribute):
        if id(node) in self._call_nodes:
            return self.generic_visit(node)
        
        mod, func, qualified = self._resolve_dotted_node(node)
        if mod and func and self._is_tracked_call(mod, func):
            self._report(
                node,
                "reference",
                mod,
                func,
                qualified_name=qualified,
                category="reference",
                severity="medium",
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if id(node) in self._call_nodes:
            return self.generic_visit(node)

        mod, func, qualified = self._resolve_dotted_node(node)
        if mod and func and self._is_tracked_call(mod, func):
            self._report(
                node,
                "reference",
                mod,
                func,
                qualified_name=qualified,
                category="reference",
                severity="medium",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Mark the function node so visit_Attribute/visit_Name don't double-report it
        self._call_nodes.add(id(node.func))

        mod, func, qualified = self._resolve_dotted_node(node.func)
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

    def _resolve_dotted_node(self, node):
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

        parts = _dotted_parts(node)
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
    # Sanitize source to avoid tokenization errors on template tags
    src = sanitize_template_syntax(src)
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

    def classify(mod: str, func: str, kind: str = "call") -> tuple[str, str]:
        if kind == "reference":
            return "reference", "medium"
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

    def emit_finding(mod: str, func: str, qualified: str, lineno: int, col: int, kind: str = "call") -> None:
        category, severity = classify(mod, func, kind)
        findings.append(
            {
                "kind": kind,
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
        
        # We must wrap the iteration too, as tokenize.generate_tokens is a generator 
        # that can raise IndentationError during next()
        def wrapped_tok_iter():
            try:
                for t in tok_iter:
                    yield t
            except (tokenize.TokenError, IndentationError, SyntaxError):
                # If tokenization fails (e.g. indentation issues in templates),
                # this generator will stop, and we'll handle it in the loop below.
                return

        gen = wrapped_tok_iter()
    except Exception:
        return scan_regex_fallback(src, path, rules)

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
        try:
            return next(gen)
        except StopIteration:
            raise StopIteration
        except Exception:
            # Ensure we break out of the token scanner loop on any internal error
            raise StopIteration

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
        except (StopIteration, tokenize.TokenError, IndentationError):
            break
        except Exception:
            # Any other crash in the token scanner results in regex fallback
            return scan_regex_fallback(src, path, rules)

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
                        emit_finding(mod, func, qualified, lineno, col, kind="call")
                    # do not push back '('
                    break

                # Not followed by '(', but could be a reference
                mod, func, qualified = resolve_dotted(parts)
                if mod and func and qualified and is_tracked_call(mod, func):
                    emit_finding(mod, func, qualified, lineno, col, kind="reference")
                
                # any other token breaks the chain
                push_tok(t1)
                break

    return [{"file": str(path), **f} for f in findings]

def scan_regex_fallback(src: str, path: Path, rules: dict) -> list[dict]:
    """
    Final emergency fallback: purely regex-based detection.
    Completely ignores syntax and indentation, making it 'unbreakable'.
    """
    import re
    findings = []
    for spec in rules.values():
        for mod, func in spec.get("calls", set()):
            # Detect calls: module.func(
            call_pattern = re.compile(rf"\b{re.escape(mod)}\.{re.escape(func)}\s*\(")
            for m in call_pattern.finditer(src):
                preceding = src[:m.start()]
                lineno = preceding.count('\n') + 1
                last_newline = preceding.rfind('\n')
                col = m.start() - last_newline - 1 if last_newline != -1 else m.start()
                
                findings.append({
                    "kind": "call",
                    "module": mod,
                    "name": func,
                    "lineno": lineno,
                    "col_offset": col,
                    "qualified_name": f"{mod}.{func}",
                    "category": "regex_fallback_call",
                    "severity": "high",
                    "parser": "regex_fallback"
                })

            # Detect references: module.func (not followed by '(')
            ref_pattern = re.compile(rf"\b{re.escape(mod)}\.{re.escape(func)}\b(?!\s*\()")
            for m in ref_pattern.finditer(src):
                preceding = src[:m.start()]
                lineno = preceding.count('\n') + 1
                last_newline = preceding.rfind('\n')
                col = m.start() - last_newline - 1 if last_newline != -1 else m.start()
                
                findings.append({
                    "kind": "reference",
                    "module": mod,
                    "name": func,
                    "lineno": lineno,
                    "col_offset": col,
                    "qualified_name": f"{mod}.{func}",
                    "category": "regex_fallback_ref",
                    "severity": "medium",
                    "parser": "regex_fallback"
                })
def init_worker():
    """ Worker initializer to ignore SIGINT and silence stderr for clean Ctrl+C tracebacks on Windows. """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # Silence stderr in workers so they don't leak technical tracebacks to the console during shutdown.
    sys.stderr = open(os.devnull, 'w')

def scan_file(path: Union[str, Path], rules, max_size=10*1024*1024):
    """ Main entrypoint for scanning a file. Handles AST, Token and Regex passes. """
    path = Path(path)
    try:
        if path.stat().st_size > max_size:
            return [{"file": str(path), "error": f"skipped_large_file>{max_size}B"}]
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
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(src, filename=str(path))
        except SyntaxError:
            sanitized = sanitize_template_syntax(src)
            if sanitized != src:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", SyntaxWarning)
                        tree = ast.parse(sanitized, filename=str(path))
                    src = sanitized
                except (SyntaxError, Exception):
                    return scan_tokens_fallback(src, path, rules)
            else:
                return scan_tokens_fallback(src, path, rules)
        except Exception:
            return scan_tokens_fallback(src, path, rules)
    except RecursionError as e:
        return [{"file": str(path), "error": f"parse_recursion_error:{e}"}]

    v = RefVisitor(rules)
    try:
        v.visit(tree)
    except AstNodeLimitExceeded:
        return scan_tokens_fallback(src, path, rules)
    except RecursionError as e:
        return [{"file": str(path), "error": f"visit_recursion_error:{e}"}]
    except Exception as e:
        return [{"file": str(path), "error": f"visit_error:{type(e).__name__}:{e}"}]

    return [{"file": str(path), **f} for f in v.findings]

def main():
    ap = argparse.ArgumentParser(
        description="Python Deserialization AST based Scanner."
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
    ap.add_argument(
        "-j", "--concurrency",
        type=int,
        default=max(1, (os.cpu_count() or 1) - 2),
        help="Number of concurrent processes (default: CPU cores - 2).",
    )
    ap.add_argument(
        "-t", "--timeout",
        type=float,
        default=None,
        help="Timeout in seconds for each file analysis (only works in parallel mode).",
    )
    ap.add_argument(
        "--max-size",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum file size in bytes to process (default: 10MiB).",
    )
    ap.add_argument(
        "--agent",
        action="store_true",
        help="Run AI-driven deep analysis (Phase 4, optional).",
    )
    ap.add_argument(
        "--agent-provider",
        choices=["huggingface", "local"],
        default="huggingface",
        help="LLM inference provider for AI agent: 'huggingface' or 'local' (default: huggingface).",
    )
    ap.add_argument(
        "--llm-api-url",
        default="http://127.0.0.1:8181/v1",
        help="Base URL for local LLM inference API (default: http://127.0.0.1:8181/v1).",
    )
    ap.add_argument(
        "--agent-model",
        default=None,
        help="Model ID or path name for LLM inference (optional).",
    )
    args = ap.parse_args()
    setup_windows_ansi()

    # Native Windows CTRL+C Handler for 100% responsiveness even during heavy processing.
    if os.name == 'nt':
        def win_handler(ctrl_type):
            if ctrl_type in (0, 1): # CTRL_C_EVENT or CTRL_BREAK_EVENT
                # Direct exit from system thread to bypass blocking executor cleanup.
                sys.stderr.write("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting...\n")
                os._exit(130)
            return 0
        
        # Maintain global reference to the callback to prevent GC (Garbage Collection).
        global _win_handler_ref
        _win_handler_ref = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)(win_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_handler_ref, True)
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
        print("="*80, file=human)
        print(" [>] Starting Static Analysis Scan...", file=human)
        print("="*80, file=human)

    total_findings = 0
    total_errors = 0
    files_scanned = 0
    jsonl_lines = 0
    def print_finding(item: dict):
        if human.isatty():
            # Move down to clear the progress bar line if it exists
            human.write('\033[B\r' + ' ' * 140 + '\r\033[A')
            human.flush()
        # Compact CLI line (restored variables after compaction)
        sev = item.get("severity", "-")
        cat = item.get("category", "-")
        qn = item.get("qualified_name") or f"{item.get('module')}.{item.get('name')}"
        loc = f"{item.get('file')}:{item.get('lineno')}"
        print(f"[{sev.upper()}][{cat}] {loc}  {qn}", file=human)

    def print_error(item: dict):
        if human.isatty():
            # Move down to clear the progress bar line if it exists
            human.write('\033[B\r' + ' ' * 140 + '\r\033[A')
            human.flush()
        loc = item.get("file", "?")
        err = item.get("error", "unknown_error")
        print(f"[ERROR] {loc}  {err}", file=human)

    def emit(sink, item: dict):
        nonlocal total_findings, total_errors, jsonl_lines
        sink.write(json.dumps(item, ensure_ascii=False) + "\n")
        sink.flush()
        jsonl_lines += 1

        if isinstance(item, dict) and "error" in item:
            total_errors += 1
            print_error(item)
        else:
            # findings (calls and references) are what we print as results
            if item.get("kind") in ("call", "reference"):
                total_findings += 1
                print_finding(item)

    all_files = list(iter_py_files(root, skip_dirs))
    total_files = len(all_files)

    def print_progress(current, py_path=None):
        if not human.isatty(): return
        if total_files == 0: return

        # Draw a gap, then the progress bar, then move back UP to the gap line.
        # This keeps the cursor at the spot where the NEXT finding should be printed.
        pct = (current / total_files) * 100
        
        fn = py_path.name if py_path else "..."
        limit = 30
        display_fn = (fn[:limit-3] + "...") if len(fn) > limit else fn
        
        msg = f"\n\rProgress: {pct:5.1f}% | Res: {total_findings} | Scanned: {current}/{total_files} | Current: {display_fn}"
        human.write(msg.ljust(120))
        human.write("\033[A") # Move back up to the gap line
        human.flush()

    # Determine output sink
    if args.out == "-":
        sink = sys.stdout
        out_desc = "stdout (JSONL)"
        out_size = None
    else:
        out_path = Path(args.out).expanduser().resolve()
        out_desc = str(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        sink = out_path.open("w", encoding="utf-8")

    # Sink established, proceed to scanning logic.
    try:
        if args.concurrency > 1 and total_files > 1:
            # Parallel Scan Mode
            with concurrent.futures.ProcessPoolExecutor(
                max_workers=args.concurrency,
                initializer=init_worker
            ) as executor:
                # Map futures to their paths for tracking (pass as string to avoid pickling issues)
                future_to_path = {executor.submit(scan_file, str(py), rules, args.max_size): py for py in all_files}
                
                try:
                    for future in concurrent.futures.as_completed(future_to_path, timeout=None):
                        py = future_to_path[future]
                        files_scanned += 1
                        
                        try:
                            results = future.result(timeout=args.timeout)
                            for item in results:
                                emit(sink, item)
                            
                            print_progress(files_scanned, py)
                        except concurrent.futures.TimeoutError:
                            emit(sink, {"file": str(py), "error": f"timeout_reached({args.timeout}s)"})
                        except Exception as exc:
                            emit(sink, {"file": str(py), "error": f"executor_error:{exc}"})
                except KeyboardInterrupt:
                    # Emergency shutdown on Windows/Linux
                    if args.out != "-": sink.close()
                    print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting...", file=sys.stderr)
                    os._exit(130)
        else:
            # Sequential Scan Mode (Fallback or explicitly requested)
            for idx, py in enumerate(all_files, 1):
                files_scanned = idx
                print_progress(idx, py)
                for item in scan_file(py, rules):
                    emit(sink, item)
    finally:
        if args.out != "-":
            sink.close()
            try:
                out_size = out_path.stat().st_size
            except OSError:
                out_size = None

    # Summary
    print("\n\nScan finished.", file=human)
    print(f"Files scanned: {files_scanned}", file=human)
    print(f"Findings: {total_findings}", file=human)
    print(f"Errors: {total_errors}", file=human)
    print("", file=human)  # Spacing before JSONL info

    if out_size is None:
        print(f"JSONL output: {out_desc} (lines: {jsonl_lines})", file=human)
    else:
        print(f"JSONL output: {out_desc} (lines: {jsonl_lines}, bytes: {out_size})", file=human)

    # --- PHASE 2: RELATIONSHIP MAPPING (Integration) ---
    if total_findings > 0 and args.out != "-":
        print("\n" + "="*80, file=human)
        print(" [>] Starting Relationship Mapping process...", file=human)
        print("="*80, file=human)
        
        try:
            from modules.relationship_mapper import RelationshipMapper
            mapper = RelationshipMapper(args.path)
            
            # Load findings from the JSONL we just created
            findings = []
            with open(out_desc, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        findings.append(json.loads(line))
            
            if findings:
                from modules.result_processor import ResultProcessor
                project_name = ResultProcessor.infer_project_name(findings[0].get("file", ""))
                output_mapper = os.path.join(project_name, "relationship_mapper.jsonl")

                print(f"Identified {len(findings)} findings. Starting bulk mapping...\n", file=human)
                
                # Execute Parallel Mapping via the new map_bulk API
                mapper_results = mapper.map_bulk(findings, args.concurrency)
                
                # Persist results
                with open(output_mapper, 'w', encoding='utf-8') as f:
                    for res in mapper_results:
                        f.write(json.dumps(res, ensure_ascii=False) + '\n')
                
                print(f"Total records processed: {len(mapper_results)}", file=human)
                print(f"Results saved in: {output_mapper}", file=human)
                
                print("\n --- Findings Breakdown ---", file=human)
                for res in mapper_results:
                    root = res.get('root_finding', {})
                    target_f = res.get('target_function', 'N/A')
                    code_rels = len(res.get('relationships', {}).get('code', []))
                    print(f" - {root.get('file')}:{root.get('lineno')} -> {target_f} ({code_rels} relationships)", file=human)
                
                print("\n--- End of Mapping Phase ---", file=human)
                
                # --- PHASE 3: RESULT PROCESSING / REPORT GENERATION (Integration) ---
                print("\n" + "="*80, file=human)
                print(" [>] Starting Security Report Generation...", file=human)
                print("="*80, file=human)
                
                try:
                    from modules.result_processor import ResultProcessor
                    processor = ResultProcessor(output_base_dir="reports")
                    
                    if os.path.exists(output_mapper):
                        count = 0
                        with open(output_mapper, 'r', encoding='utf-8') as f:
                            for idx, line in enumerate(f, 1):
                                if not line.strip(): continue
                                result = json.loads(line)
                                
                                # Use robust inference logic built into the module
                                project_name = ResultProcessor.infer_project_name(
                                    result.get("root_finding", {}).get("file", "")
                                )
                                
                                report_file = processor.generate_report(result, idx, project_name)
                                print(f"  [+] Generated: {report_file}", file=human)
                                count += 1
                        
                        print(f"\n[OK] {count} detailed reports have been generated.", file=human)
                        print(f"Check the 'reports/' folder to see the results.", file=human)

                        # --- PHASE 4: AI ANALYSIS (Integration) ---
                        if args.agent:
                            print("\n" + "="*80, file=human)
                            print(" [>] Starting AI-Driven Security Analysis...", file=human)
                            print("="*80, file=human)
                            
                            try:
                                from modules.ai_orchestrator import AIOrchestrator
                                orchestrator = AIOrchestrator(
                                    provider=args.agent_provider,
                                    llm_api_url=args.llm_api_url,
                                    model_id=args.agent_model
                                )
                                ai_result = orchestrator.run_analysis(project_name, args.path, output_stream=human)
                                
                                print("\n" + "-"*40, file=human)
                                print(f"AI Analysis Result for {project_name}:", file=human)
                                print(ai_result, file=human)
                                print("-" * 40, file=human)
                            except ImportError:
                                print("\n[!] Warning: AI Orchestrator module not found. Skipping...", file=human)
                            except Exception as e:
                                print(f"\n[!] Error during AI Analysis: {e}", file=human)
                        else:
                            # If no agent is requested, we finish here as per requirements.
                            pass
                    else:
                        print(f"[!] Error: Mapper output {output_mapper} not found.", file=human)
                except ImportError:
                    print("\n[!] Warning: Result Processor module not found. Skipping...", file=human)
                except Exception as e:
                    print(f"\n[!] Error during Report Generation: {e}", file=human)

        except ImportError:
            print("\n[!] Warning: Mapping module not found. Skipping...", file=human)
        except Exception as e:
            print(f"\n[!] Error during Relationship Mapping: {e}", file=human)

    # Non-zero exit code is useful in CI when any IO/parse errors occurred.
    raise SystemExit(1 if total_errors else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Avoid printing a messy stack trace on Ctrl+C
        print("\n\n[!] Scan interrupted by user (Ctrl+C). Exiting...", file=sys.stderr)
        sys.exit(130)