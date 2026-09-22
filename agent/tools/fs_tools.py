import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from smolagents import Tool

class DirectoryNavigator(Tool):
    name = "directory_navigator"
    description = "Navigates directories and subdirectories recursively. Returns a list of files and folders."
    inputs = {
        "path": {
            "type": "string",
            "description": "The directory path to explore."
        },
        "recursive": {
            "type": "boolean",
            "description": "Whether to search recursively.",
            "nullable": True
        }
    }
    output_type = "string"

    def forward(self, path: str, recursive: bool = True) -> str:
        try:
            target = Path(path).resolve()
            if not target.is_dir():
                return f"Error: {path} is not a directory."
            
            items = []
            if recursive:
                for root, dirs, files in os.walk(target):
                    rel_root = os.path.relpath(root, target)
                    prefix = "" if rel_root == "." else rel_root + "/"
                    for d in dirs:
                        items.append(f"[DIR]  {prefix}{d}")
                    for f in files:
                        items.append(f"[FILE] {prefix}{f}")
            else:
                for entry in target.iterdir():
                    kind = "[DIR] " if entry.is_dir() else "[FILE]"
                    items.append(f"{kind} {entry.name}")
            
            return "\n".join(items) if items else "Directory is empty."
        except Exception as e:
            return f"Error navigating directory: {str(e)}"

class FileInspector(Tool):
    name = "file_inspector"
    description = "Retrieves detailed metadata for a specific file (extension, size, creation/modification dates)."
    inputs = {
        "file_path": {
            "type": "string",
            "description": "The path to the file to inspect."
        }
    }
    output_type = "string"

    def forward(self, file_path: str) -> str:
        try:
            target = Path(file_path).resolve()
            if not target.is_file():
                return f"Error: {file_path} is not a file."
            
            stats = target.stat()
            from datetime import datetime
            
            info = {
                "name": target.name,
                "extension": target.suffix,
                "size_bytes": stats.st_size,
                "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "absolute_path": str(target)
            }
            return "\n".join([f"{k}: {v}" for k, v in info.items()])
        except Exception as e:
            return f"Error inspecting file: {str(e)}"

class SafeSourceReader(Tool):
    name = "safe_source_reader"
    description = "Reads the content of a source file safely, handling various encodings and special characters."
    inputs = {
        "file_path": {
            "type": "string",
            "description": "The path to the file to read."
        }
    }
    output_type = "string"

    def forward(self, file_path: str) -> str:
        try:
            target = Path(file_path).resolve()
            if not target.is_file():
                return f"Error: {file_path} is not a file."
            
            # Robust reading logic similar to the scanner's scan_file
            import tokenize
            try:
                with tokenize.open(str(target)) as f:
                    content = f.read()
            except (SyntaxError, UnicodeDecodeError):
                try:
                    data = target.read_bytes()
                    content = data.decode("utf-8-sig", errors="replace")
                except Exception as e2:
                    return f"Error decoding file: {str(e2)}"
            except Exception as e:
                return f"Error reading file: {str(e)}"
            
            return content
        except Exception as e:
            return f"Error in safe reader: {str(e)}"

class OpenTool(Tool):
    name = "open"
    description = "Opens a file and returns a file stream object (supports standard modes like 'r', 'w', 'a')."
    inputs = {
        "file": {
            "type": "string",
            "description": "Path to the file to open."
        },
        "mode": {
            "type": "string",
            "description": "Mode in which the file is opened ('r', 'w', 'a', etc.).",
            "nullable": True
        },
        "encoding": {
            "type": "string",
            "description": "Encoding for text modes.",
            "nullable": True
        }
    }
    output_type = "any"

    def forward(self, file: str, mode: str = "r", encoding: Optional[str] = "utf-8") -> Any:
        try:
            target = Path(file).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            if mode and "b" in mode:
                return open(target, mode)
            return open(target, mode or "r", encoding=encoding or "utf-8", errors="replace")
        except Exception as e:
            raise RuntimeError(f"Error opening file {file}: {e}")

