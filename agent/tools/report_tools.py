import os
from pathlib import Path
from typing import Dict, Any, Optional
from smolagents import Tool

class MarkdownManager(Tool):
    name = "markdown_manager"
    description = "Manages Markdown files: copy, create, edit, or delete .md files. Essential for report generation."
    inputs = {
        "action": {
            "type": "string",
            "description": "Action to perform: 'create', 'read', 'copy', 'edit', 'delete'."
        },
        "target_path": {
            "type": "string",
            "description": "Primary file path."
        },
        "content": {
            "type": "string",
            "description": "Content for create/edit.",
            "nullable": True
        },
        "source_path": {
            "type": "string",
            "description": "Path to copy FROM.",
            "nullable": True
        }
    }
    output_type = "string"

    def forward(self, action: str, target_path: str, content: Optional[str] = None, source_path: Optional[str] = None) -> str:
        try:
            target = Path(target_path).resolve()
            
            if action == "create":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content or "", encoding="utf-8")
                return f"File created: {target_path}"
            
            elif action == "read":
                if not target.is_file():
                    return f"Error: {target_path} not found."
                return target.read_text(encoding="utf-8")
            
            elif action == "copy":
                if not source_path:
                    return "Error: source_path required for copy."
                src = Path(source_path).resolve()
                if not src.is_file():
                    return f"Error: Source {source_path} not found."
                target.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy2(src, target)
                return f"File copied from {source_path} to {target_path}"
            
            elif action == "edit":
                if not target.is_file():
                    return f"Error: {target_path} not found."
                if not content:
                    return "Error: No content provided for edit."
                target.write_text(content, encoding="utf-8")
                return f"File updated: {target_path}"
            
            elif action == "delete":
                if target.is_file():
                    target.unlink()
                    return f"File deleted: {target_path}"
                return f"Error: {target_path} not found."
            
            else:
                return f"Error: Unsupported action '{action}'."
        except Exception as e:
            return f"Error in markdown manager: {str(e)}"
