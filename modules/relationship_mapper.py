"""
Relationship Mapper (v1.0.0-RC1)
------------------------------
AST-based static analysis tool for mapping relationships and impact radius 
of deserialization vulnerabilities in Python.

Supports recursive caller analysis, inheritance detection, code extraction 
from notebooks (.ipynb), and framework affinity filtering.
"""

import ast
import json
import os
import sys
import signal
from typing import Dict, List, Optional, Set, Any
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

def init_worker():
    """Initializer for worker processes to handle signals and noise."""
    # Ignore SIGINT in workers so the parent can handle it gracefully
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # Re-route stderr to null to avoid noisy AST parse errors in workers
    sys.stderr = open(os.devnull, 'w')

def map_finding_worker(finding: Dict[str, Any], repo_path: str) -> Dict[str, Any]:
    """Top-level worker function for ProcessPoolExecutor."""
    try:
        # Lazy initialization of the mapper inside the worker
        mapper = RelationshipMapper(repo_path)
        return mapper.map_finding(finding)
    except Exception as e:
        return {"error": str(e), "root_finding": finding}

class NotebookCodeExtractor:
    """
    Code extractor for Jupyter notebooks.
    Transforms .ipynb files into flat Python scripts for AST analysis,
    neutralizing IPython magic commands that would break parsing.
    """
    
    @staticmethod
    def extract(file_path: str) -> str:
        """Extracts and cleans code from all 'code' type cells."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                nb = json.load(f)
            
            code_lines = []
            for i, cell in enumerate(nb.get('cells', [])):
                if cell.get('cell_type') == 'code':
                    source = cell.get('source', [])
                    if isinstance(source, list):
                        source = "".join(source)
                    
                    # Neutralize magics (!, %, ?) to avoid syntax errors in AST
                    cleaned_source = []
                    for line in source.splitlines():
                        stripped = line.lstrip()
                        if stripped.startswith(('%', '!', '?')):
                            cleaned_source.append(f"# {line}")
                        else:
                            cleaned_source.append(line)
                    
                    code_lines.append(f"# --- Cell {i} ---\n" + "\n".join(cleaned_source) + "\n")
            
            return "\n".join(code_lines)
        except Exception:
            return ""

class ASTAnalyzer:
    """
    Static analysis engine based on the Python ast module.
    Provides caller search capabilities, enclosing class detection,
    inheritance analysis, and import extraction.
    """
    
    # Common methods requiring affinity filtering to avoid massive false positives
    GENERIC_METHODS = {
        'load', 'save', 'read', 'write', 'get', 'set', 'run', 'call', 
        'loads', 'dumps', 'from_state_dict', 'to_state_dict', 'unbundle', 'bundle'
    }
    
    def __init__(self):
        """Initializes AST and code caches to optimize multi-phase analysis."""
        self.ast_cache: Dict[str, ast.AST] = {}
        self.code_cache: Dict[str, str] = {}
        self.activities: List[Dict[str, Any]] = []

    def log_activity(self, action: str, target: str, result: str = ""):
        """Logs a technical activity for analysis flow tracking."""
        self.activities.append({
            "action": action,
            "target": target,
            "result": result
        })

    def get_ast(self, file_path: str) -> Optional[ast.AST]:
        """Obtains the AST tree of a file (.py or .ipynb), with cache support."""
        if file_path in self.ast_cache:
            return self.ast_cache[file_path]
        
        try:
            if file_path.endswith('.ipynb'):
                self.log_activity("extract_notebook", file_path)
                code = NotebookCodeExtractor.extract(file_path)
            else:
                self.log_activity("read_file", file_path)
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            
            tree = ast.parse(code)
            self.ast_cache[file_path] = tree
            self.code_cache[file_path] = code
            return tree
        except Exception as e:
            self.log_activity("parse_error", file_path, str(e))
            return None

    def find_enclosing_function(self, tree: ast.AST, lineno: int) -> Optional[str]:
        """Identifies the function wrapping a specific line of code."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno <= lineno <= (getattr(node, 'end_lineno', lineno)):
                    return node.name
        return None

    def find_enclosing_class(self, tree: ast.AST, lineno: int) -> Optional[str]:
        """Identifies the class wrapping a specific line of code."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.lineno <= lineno <= (getattr(node, 'end_lineno', lineno)):
                    return node.name
        return None

    def find_internal_callers(self, tree: ast.AST, target_func_name: str) -> List[str]:
        """Searches for callers of a function within the same file (private API pivoting)."""
        internal_callers = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call):
                        name = ""
                        if isinstance(subnode.func, ast.Name):
                            name = subnode.func.id
                        elif isinstance(subnode.func, ast.Attribute):
                            name = subnode.func.attr
                        
                        if name == target_func_name:
                            internal_callers.append(node.name)
                            break
        return list(set(internal_callers))

    def _get_imports(self, tree: ast.AST) -> Set[str]:
        """Analyzes import statements to determine module affinity."""
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
                    parts = node.module.split('.')
                    for i in range(1, len(parts) + 1):
                        imports.add('.'.join(parts[:i]))
                for alias in node.names:
                    imports.add(alias.name)
                    if node.module:
                        imports.add(f"{node.module}.{alias.name}")
        return imports

    def find_callers(self, target_func_name: str, search_path: str, 
                     target_class: Optional[str] = None, 
                     source_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Locates callers throughout the repository with noise reduction logic.
        Implements filtering by framework prefixes (tf/jax) for generic methods.
        """
        callers = []
        exclude_dirs = {'.venv', '.git', '__pycache__', 'node_modules', 'tests'}
        
        is_generic = target_func_name in self.GENERIC_METHODS
        framework_prefix = None
        source_module_parts = []
        if source_file:
            clean_path = source_file.replace('\\', '/').replace('.py', '')
            source_module_parts = [p for p in clean_path.split('/') if p]
            if 'tf' in source_module_parts:
                framework_prefix = 'tf'
            elif 'jax' in source_module_parts:
                framework_prefix = 'jax'
        
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.endswith(('.py', '.ipynb')):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, search_path)
                    clean_rel_path = rel_path.replace('\\', '/')
                    
                    tree = self.get_ast(full_path)
                    if not tree:
                        continue
                    
                    # V4 Filtering Logic: Noise reduction for generic names
                    if is_generic and source_file and rel_path != source_file:
                        imports = self._get_imports(tree)
                        relevant = False
                        
                        if target_class and target_class in imports:
                            relevant = True
                        else:
                            for part in source_module_parts:
                                if len(part) <= 3 or part == "dopamine": continue
                                
                                if framework_prefix:
                                    if f"/{framework_prefix}/" in f"/{clean_rel_path}":
                                        if part in imports or part in clean_rel_path:
                                            relevant = True
                                    else:
                                        for imp in imports:
                                            if part in imp and (f".{framework_prefix}." in imp or imp.startswith(f"{framework_prefix}.")):
                                                relevant = True
                                                break
                                else:
                                    if part in imports:
                                        relevant = True
                                
                                if relevant: break
                                
                        if not relevant:
                            continue
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            func_name = ""
                            if isinstance(node.func, ast.Name):
                                func_name = node.func.id
                            elif isinstance(node.func, ast.Attribute):
                                func_name = node.func.attr
                            
                            if func_name == target_func_name:
                                callers.append({
                                    "file": rel_path,
                                    "lineno": node.lineno,
                                    "col_offset": node.col_offset,
                                    "enclosing_func": self.find_enclosing_function(tree, node.lineno) or "<module>"
                                })
        return callers

    def find_subclasses(self, base_class_name: str, search_path: str) -> List[Dict[str, Any]]:
        """Searches for classes that inherit from a specific base class (V4 Inheritance Analysis)."""
        subclasses = []
        exclude_dirs = {'.venv', '.git', '__pycache__', 'node_modules', 'tests'}
        
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, search_path)
                    
                    tree = self.get_ast(full_path)
                    if not tree: continue
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            is_subclass = False
                            for base in node.bases:
                                if isinstance(base, ast.Name) and base.id == base_class_name:
                                    is_subclass = True
                                elif isinstance(base, ast.Attribute) and base.attr == base_class_name:
                                    is_subclass = True
                            
                            if is_subclass:
                                subclasses.append({
                                    "file": rel_path,
                                    "class": node.name,
                                    "base": base_class_name,
                                    "lineno": node.lineno
                                })
        return subclasses

    def find_doc_mentions(self, target_names: List[str], search_path: str, target_class: Optional[str] = None) -> List[Dict[str, Any]]:
        """Searches for textual mentions in documentation, applying co-occurrence filtering."""
        mentions = []
        doc_extensions = ('.md', '.txt', '.yaml', '.yml', '.json')
        exclude_dirs = {'.venv', '.git', '__pycache__', 'node_modules', '.antigravity', '.gemini', 'tests'}
        
        search_terms = list(set([n for n in target_names if n and n != "<module>"]))
        if not search_terms:
            return []

        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.endswith(doc_extensions):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, search_path)
                    
                    if file.endswith('.ipynb') or 'results' in file:
                        continue
                        
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for term in search_terms:
                                if term in content:
                                    is_generic = term in self.GENERIC_METHODS
                                    if is_generic and target_class and target_class not in content:
                                        continue
                                        
                                    for i, line in enumerate(content.splitlines(), 1):
                                        if term in line:
                                            mentions.append({
                                                "file": rel_path,
                                                "lineno": i,
                                                "term": term,
                                                "context": line.strip()[:100]
                                            })
                                            break
                                    break
                    except Exception:
                        continue
        return mentions

class RelationshipMapper:
    """
    Orchestrator class for relationship mapping.
    Combines code analysis, inheritance, and documentation into a single workflow.
    """
    
    def __init__(self, target_repo_path: str):
        self.repo_path = target_repo_path
        self.analyzer = ASTAnalyzer()

    def trace_recursively(self, func_name: str, depth: int = 0, max_depth: int = 3, 
                           target_class: Optional[str] = None, 
                           source_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """Recursively traces the caller graph."""
        if depth >= max_depth:
            return []
        
        self.analyzer.log_activity("trace_callers_recursive", func_name, f"Depth {depth}")
        callers = self.analyzer.find_callers(func_name, self.repo_path, target_class, source_file)
        
        for caller in callers:
            is_notebook = caller["file"].endswith('.ipynb')
            
            # Avoid infinite recursion and noise in notebooks
            if caller["enclosing_func"] != "<module>" and caller["enclosing_func"] != func_name and not is_notebook:
                caller["indirect_callers"] = self.trace_recursively(
                    caller["enclosing_func"], depth + 1, max_depth, 
                    target_class=None, source_file=source_file 
                )
            else:
                caller["indirect_callers"] = []
                
        return callers

    def map_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the complete mapping process for an input finding."""
        file_rel_path = finding.get('file', '')
        full_file_path = os.path.join(self.repo_path, file_rel_path)
        lineno = finding.get('lineno', 0)
        
        self.analyzer.log_activity("start_mapping", file_rel_path, f"Line {lineno}")
        
        tree = self.analyzer.get_ast(full_file_path)
        if not tree:
            return {"error": f"Could not parse root file: {file_rel_path}"}
        
        target_func = self.analyzer.find_enclosing_function(tree, lineno) or "<module>"
        target_class = self.analyzer.find_enclosing_class(tree, lineno)
        
        search_terms = [target_func]
        if target_class:
            search_terms.append(target_class)
        
        public_apis = []
        if target_func.startswith('_'):
            self.analyzer.log_activity("pivot_to_public_api", target_func, "Private method detected")
            internal_callers = self.analyzer.find_internal_callers(tree, target_func)
            public_apis = [c for c in internal_callers if not c.startswith('_')]
            search_terms.extend(public_apis)
        
        self.analyzer.log_activity("trace_code_relationships", target_func)
        code_relationships = self.trace_recursively(
            target_func, depth=0, 
            target_class=target_class, 
            source_file=file_rel_path
        )
        
        # Systemic impact analysis (Classes and Inheritance)
        affected_classes = set()
        if target_class: affected_classes.add(target_class)
        
        def collect_classes(rels):
            for r in rels:
                full_c_path = os.path.join(self.repo_path, r["file"])
                t = self.analyzer.get_ast(full_c_path)
                if t:
                    c = self.analyzer.find_enclosing_class(t, r["lineno"])
                    if c: affected_classes.add(c)
                collect_classes(r.get("indirect_callers", []))
                
        collect_classes(code_relationships)
        
        inheritance_relationships = []
        for cls_name in list(affected_classes):
            if cls_name:
                self.analyzer.log_activity("trace_inheritance", cls_name)
                subs = self.analyzer.find_subclasses(cls_name, self.repo_path)
                inheritance_relationships.extend(subs)
 
        self.analyzer.log_activity("trace_doc_relationships", ", ".join(search_terms))
        doc_mentions = self.analyzer.find_doc_mentions(search_terms, self.repo_path, target_class=target_class)
        
        return {
            "root_finding": finding,
            "target_function": target_func,
            "context": {
                "class": target_class,
                "public_apis": public_apis,
                "search_terms": search_terms,
                "affected_classes": list(affected_classes)
            },
            "relationships": {
                "code": code_relationships,
                "inheritance": inheritance_relationships,
                "documentation": doc_mentions
            },
            "activities": self.analyzer.activities
        }

    def map_bulk(self, findings: List[Dict[str, Any]], concurrency: int = None) -> List[Dict[str, Any]]:
        """
        Executes bulk mapping of findings using Multiprocessing.
        This provides a programmatic way to leverage the parallel engine from other scripts.
        """
        if concurrency is None:
            concurrency = max(1, cpu_count() - 2)
            
        total_findings = len(findings)
        temp_results = [None] * total_findings
        
        with ProcessPoolExecutor(max_workers=concurrency, initializer=init_worker) as executor:
            future_to_finding = {executor.submit(map_finding_worker, finding, self.repo_path): i for i, finding in enumerate(findings)}
            
            completed = 0
            for future in as_completed(future_to_finding):
                idx = future_to_finding[future]
                try:
                    result = future.result()
                    temp_results[idx] = result
                    completed += 1
                    # Progress update for console-based tools
                    print(f"[{completed}/{total_findings}] Processing: {findings[idx].get('file')}:{findings[idx].get('lineno')}...", end='\r', flush=True)
                except Exception as exc:
                    print(f"\n[!] Error processing record {idx}: {exc}")
            
            print(f"\n[+] Bulk Mapping Completed")
            return [r for r in temp_results if r is not None]

def main(args: List[str]):
    """Command line interface for independent execution."""
    if len(args) < 2:
        print("Usage: python relationship_mapper.py <input_jsonl> <repo_path> [output_path] [record_index] [-j concurrency]")
        sys.exit(1)
    
    # Parse potential -j flag
    concurrency = max(1, cpu_count() - 2)
    clean_args = []
    i = 0
    while i < len(args):
        if args[i] == '-j' and i + 1 < len(args):
            concurrency = int(args[i+1])
            i += 2
        else:
            clean_args.append(args[i])
            i += 1
            
    jsonl_path = clean_args[0]
    repo_path = clean_args[1]
    output_path = clean_args[2] if len(clean_args) > 2 else None
    record_index = int(clean_args[3]) if len(clean_args) > 3 else None
    
    try:
        findings = []
        with open(jsonl_path, 'r') as f:
            for line in f:
                if line.strip():
                    findings.append(json.loads(line))
        
        results = []
        mapper = RelationshipMapper(repo_path)
        
        if record_index is not None:
            # Single-record mapping (Sequential)
            if 0 < record_index <= len(findings):
                finding = findings[record_index - 1]
                result = mapper.map_finding(finding)
                results.append(result)
            else:
                print(f"Error: record_index {record_index} is out of range.")
                sys.exit(1)
        else:
            # Bulk mapping (Programmatic Multiprocessing)
            total_findings = len(findings)
            print(f"Identified {total_findings} findings. Starting bulk mapping (concurrency={concurrency})...")
            results = mapper.map_bulk(findings, concurrency)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                for res in results:
                    f.write(json.dumps(res) + '\n')
            print(f"Mapping completed. Results saved to: {output_path}")
        else:
            for res in results:
                print(json.dumps(res, indent=2))
                
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user. Shutting down...")
        sys.exit(130)
    except Exception as e:
        error_msg = json.dumps({"error": str(e)})
        print(f"\n{error_msg}")

if __name__ == "__main__":
    main(sys.argv[1:])
