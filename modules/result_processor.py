"""
Result Processor v1.0.0
----------------------
Specialized module for transforming JSONL artifacts into readable security 
reports. Manages project-based result segregation and recursive call 
graph flattening.

Usage:
    python modules/result_processor.py <input.jsonl> [project_name]
"""

import json
import os
import sys
from typing import Dict, List, Any

class ResultProcessor:
    """
    Logical processor for generating Markdown reports.
    
    Attributes:
        output_base_dir (str): Root directory where reports will be stored.
    """

    def __init__(self, output_base_dir: str = "reports"):
        """
        Initializes the processor with a specific output directory.
        
        Args:
            output_base_dir (str): Base directory for project folders.
        """
        self.output_base_dir = output_base_dir

    @staticmethod
    def infer_project_name(file_path: str) -> str:
        """
        Infers the project name robustly, handling both absolute 
        Windows paths and relative paths.
        
        Args:
            file_path (str): Path to the finding's file.
            
        Returns:
            str: Suggested name for the project folder.
        """
        if not file_path:
            return "unknown_project"
        
        # 1. Normalize and get absolute path if possible to compare with CWD
        abs_path = os.path.abspath(file_path)
        cwd = os.getcwd()
        
        try:
            # Try to see if the file is "inside" the CWD
            common = os.path.commonpath([abs_path, cwd])
            if os.path.normcase(common) == os.path.normcase(cwd):
                rel = os.path.relpath(abs_path, cwd)
                # If rel is '.', it means the 'file' is the CWD itself
                if rel == ".": return "current_dir"
                # The first component of the relative path is usually the project name
                parts = rel.split(os.sep)
                if parts and parts[0]:
                    return parts[0]
        except ValueError:
            # Fallback if they are on different drives (Windows)
            pass
            
        # 2. Fallback: Process raw path by removing drive
        drive, tail = os.path.splitdrive(os.path.normpath(file_path))
        # Remove leading separators (\ or /)
        parts = [p for p in tail.split(os.sep) if p]
        
        return parts[0] if parts else "unknown_project"

    def _flatten_attack_paths(self, relationships: List[Dict[str, Any]], prefix: str = "") -> List[str]:
        """
        Flattens the recursive 'indirect_callers' tree into a list of attack paths.
        
        Args:
            relationships (List[Dict]): List of relationship nodes from the Mapper.
            prefix (str): Accumulated path prefix (used in recursion).
            
        Returns:
            List[str]: List of strings representing full attack paths.
        """
        paths = []
        for rel in relationships:
            current_node = f"{rel['file']}:{rel['lineno']} ({rel['enclosing_func']})"
            line = f"{prefix} -> {current_node}" if prefix else current_node
            
            paths.append(line)
            
            if rel.get("indirect_callers"):
                # Recursive call to go deeper into the caller graph
                sub_paths = self._flatten_attack_paths(rel["indirect_callers"], prefix=line)
                paths.extend(sub_paths)
        
        return paths

    def generate_report(self, result: Dict[str, Any], index: int, project_name: str):
        """
        Generates an enriched Markdown file for an individual finding record.
        
        Args:
            result (Dict): Raw JSONL data for a mapped finding.
            index (int): Unique index of the finding for the filename.
            project_name (str): Project name for folder organization.
            
        Returns:
            str: Absolute or relative path to the generated report file.
        """
        root = result.get("root_finding", {})
        target_f = result.get("target_function", "N/A")
        context = result.get("context", {})
        relationships = result.get("relationships", {})
        
        # 1. Directory structure management
        project_dir = os.path.join(self.output_base_dir, project_name)
        os.makedirs(project_dir, exist_ok=True)
        
        report_path = os.path.join(project_dir, f"report_{index}.md")
        
        # 2. Markdown content construction
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# Security Report: Finding #{index}\n\n")
            
            # --- SECTION 1: SUMMARY ---
            f.write("## 1. Executive Summary\n")
            f.write(f"- **Project**: `{project_name}`\n")
            f.write(f"- **Vulnerable Entry Point (Sink)**: `{root.get('qualified_name', 'N/A')}`\n")
            f.write(f"- **Code Location**: `{root.get('file')}:{root.get('lineno')}`\n")
            f.write(f"- **Owning Enclosing Function**: `{target_f}`\n\n")
            
            # --- SECTION 2: CONTEXT ---
            f.write("## 2. Attack Surface and Context\n")
            if context.get("class"):
                f.write(f"- **Affected Class**: `{context['class']}`\n")
            
            if context.get("public_apis"):
                f.write("- **Public Pivot APIs**: " + ", ".join([f"`{a}`" for a in context["public_apis"]]) + "\n")
            
            affected_classes = context.get("affected_classes", [])
            if affected_classes:
                f.write(f"- **Inheritance Impact**: {len(affected_classes)} related classes identified.\n")
            f.write("\n")

            # --- SECTION 3: ATTACK PATHS ---
            f.write("## 3. Identified Attack Paths\n")
            f.write("Call sequence allowing interaction with vulnerable code from an external surface.\n\n")
            
            code_rels = relationships.get("code", [])
            if not code_rels:
                f.write("> [!NOTE]\n> No automatic callers were found outside the root file. Check dynamic APIs.\n\n")
            else:
                raw_paths = self._flatten_attack_paths(code_rels)
                # Deduplication for a clean report
                unique_paths = []
                for p in raw_paths:
                    if p not in unique_paths: unique_paths.append(p)
                
                for p in unique_paths:
                    f.write(f"- {p}\n")
                f.write("\n")

            # --- SECTION 4: INHERITANCE ---
            inheritance = relationships.get("inheritance", [])
            if inheritance:
                f.write("## 4. Affected Classes and Subclasses\n")
                f.write("| Class | Base | Location |\n")
                f.write("| :--- | :--- | :--- |\n")
                for sub in inheritance:
                    f.write(f"| `{sub['class']}` | `{sub['base']}` | `{sub['file']}:{sub['lineno']}` |\n")
                f.write("\n")

            # --- SECTION 5: DOCUMENTATION ---
            docs = relationships.get("documentation", [])
            if docs:
                f.write("## 5. Documentation and Guide References\n")
                f.write("Relevant mentions that could indicate legitimate use or public exposure:\n\n")
                for d in docs:
                    f.write(f"- **{d['file']}**: (L{d['lineno']}) `{d['context']}`\n")
                f.write("\n")

            f.write("---\n")
            f.write("*Report automatically generated by Deserializer*\n")

        return report_path

def main():
    """CLI logic for batch processing of findings."""
    if len(sys.argv) < 2:
        print("Usage: python modules/result_processor.py <mapper_output.jsonl> [project_name]")
        sys.exit(1)

    jsonl_path = sys.argv[1]
    project_name_arg = sys.argv[2] if len(sys.argv) > 2 else None
    
    processor = ResultProcessor()
    
    try:
        count = 0
        if not os.path.exists(jsonl_path):
            print(f"Error: File not found: {jsonl_path}")
            sys.exit(1)

        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if not line.strip(): continue
                
                result = json.loads(line)
                
                # Dynamic project name management
                project_name = project_name_arg
                if project_name is None:
                    root_fn = result.get("root_finding", {})
                    file_path = root_fn.get("file", "")
                    project_name = ResultProcessor.infer_project_name(file_path)
                
                report_file = processor.generate_report(result, i, project_name)
                print(f"[+] Report {i} generated: {report_file}")
                count += 1
        
        print(f"\nFinished: {count} reports generated in 'reports/{project_name if project_name else ''}'.")
        
    except json.JSONDecodeError:
        print("Error: Input file is not a valid JSONL.")
    except Exception as e:
        print(f"Unexpected error processing results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
