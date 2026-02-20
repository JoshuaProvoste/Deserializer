# Pickle RCE Finder (AST-based)

```
C:\pickle-rce-finder>python pickle_rce_finder.py --path artifacts --out artifacts.jsonl

  _____ _      _    _        _____   _____ ______   ______ _           _
 |  __ (_)    | |  | |      |  __ \ / ____|  ____| |  ____(_)         | |
 | |__) |  ___| | _| | ___  | |__) | |    | |__    | |__   _ _ __   __| | ___ _ __
 |  ___/ |/ __| |/ / |/ _ \ |  _  /| |    |  __|   |  __| | | '_ \ / _` |/ _ \ '__|
 | |   | | (__|   <| |  __/ | | \ \| |____| |____  | |    | | | | | (_| |  __/ |
 |_|   |_|\___|_|\_\_|\___| |_|  \_\\_____|______| |_|    |_|_| |_|\__,_|\___|_|

    Pickle Deserialization Parser for Python Source Code
            coded by @JoshuaProvoste (jp / kw0)


[HIGH][deserialize] C:\pickle-rce-finder\artifacts\chemical_components.py:34  pickle.loads
[HIGH][deserialize] C:\pickle-rce-finder\artifacts\json_conversion.py:382  pickle.loads
[HIGH][deserialize] C:\pickle-rce-finder\artifacts\predictor.py:62  pickle.load

Scan finished.
Files scanned: 3
Findings: 3
Errors: 0
JSONL output: C:\pickle-rce-finder\artifacts.jsonl (lines: 3, bytes: 885)
```


**Pickle RCE Finder** is a lightweight, repo-friendly Python static scanner that hunts for risky **Python deserialization entrypoints** (e.g., `pickle.load(s)` and `torch.load`) by parsing source code with the built-in `ast` module. It was designed for quick triage across large codebases: run it on a folder, get **newline-delimited JSON (JSONL)** findings with file/line context, and immediately spot places where an attacker-controlled artifact could turn into **RCE during load**.

## Research writeups that this scanner supported

**Pickle RCE Finder** directly supported my security research and helped me locate insecure deserialization paths that were later documented in these investigations: **AlphaFold 3 (v3.0.1)**, **Vertex AI SDK (v1.121.0)**, and **PyGlove (v0.4.5)**. Concretely, it made it easy to enumerate where projects deserialize model/artifact blobs (like `ccd.pickle` or `model.pkl`) and prioritize the high-risk code paths that execute during `pickle.loads`/`pickle.load` or equivalent loading flows, accelerating root-cause analysis and PoC development.

- AlphaFold 3 (v3.0.1): `chemical_components.py` deserializing `ccd.pickle` via `pickle.loads(...)`
- Vertex AI SDK (v1.121.0): `predictor.py` loading `model.pkl` via `pickle.load(...)`
- PyGlove (v0.4.5): opaque JSON decoding path leading to `pickle.loads(...)` within conversion flow

See the full writeups (with PoCs and reproduction steps):
- https://github.com/JoshuaProvoste/Command-Injection-RCE-AlphaFold-v3.0.1
- https://github.com/JoshuaProvoste/Command-Injection-RCE-Vertex-AI-SDK-v1.121.0
- https://github.com/JoshuaProvoste/Command-Injection-RCE-PyGlove-v0.4.5

## What it does

- Walks a directory tree and parses `.py` files into AST.
- Tracks imports/aliases to resolve calls like:
  - `import pickle as p` → `p.loads(...)`
  - `import torch as t` → `t.load(...)`
  - Deep attributes like `pkg.pickle.loads(...)` or `torch.serialization.load(...)`
- Emits findings as **JSONL**, one object per line, including:
  - file path + location (`lineno`, `col_offset`)
  - `module`, `name`, `qualified_name`
  - `category` and `severity` (extra fields, backwards-compatible)
- Guards against pathological inputs with:
  - max file size (`MAX_FILE_BYTES`)
  - max visited AST nodes (`MAX_AST_NODES`)
- Optional: loads a custom ruleset from `rules.json` and warns on malformed entries/typos.

## Installation

No dependencies.

```bash
python --version
# Python 3.9+ recommended
```

## Usage

Basic scan (write JSONL to a file, print findings + summary to the terminal):

```bash
python pickle_rce_finder.py --path artifacts --out artifacts.jsonl
```

Stream JSONL to stdout (human output goes to stderr so JSONL stays clean):

```bash
python pickle_rce_finder.py --path . --out -
```

Use a custom rules file:

```bash
python pickle_rce_finder.py --path . --rules-file rules.json --out findings.jsonl
```

## CLI flags

- `--path <dir>`  
  Root directory to scan. Default: `.`

- `--rules-file <path>`  
  JSON ruleset path. If provided, it overrides `DEFAULT_RULES`.

- `--out <path|->`  
  Output destination for JSONL. Use `-` to write JSONL to stdout. Default: `-`

- `--no-banner`  
  Disable the ASCII banner.

- `--skip-dirs <comma,separated,names>`  
  Directory names to skip during walking. Default is the built-in `SKIP_DIRS` list.

## Output format (JSONL)

Each line is a standalone JSON object. Example finding:

```json
{
  "file": "some/path/module.py",
  "kind": "call",
  "module": "pickle",
  "name": "loads",
  "qualified_name": "pickle.loads",
  "category": "deserialize",
  "severity": "high",
  "lineno": 34,
  "col_offset": 11
}
```

Errors (parse/read/stat/limits) are also emitted as JSONL objects:

```json
{ "file": "bad.py", "error": "syntax_error:..." }
```

Exit code:
- `0` if no errors occurred during scanning
- `1` if any IO/parse/limit errors occurred (useful for CI)

## Rules file format (`rules.json`)

Rules are a JSON object keyed by a logical module name, with:
- `imports`: list of import roots to track
- `calls`: list of `[module, function]` pairs

Example:

```json
{
  "pickle": {
    "imports": ["pickle"],
    "calls": [["pickle","load"], ["pickle","loads"]]
  },
  "torch": {
    "imports": ["torch"],
    "calls": [["torch","load"]]
  }
}
```

The loader normalizes imports (keeps the root token) and prints warnings to stderr for typos/malformed entries.

## Notes on interpretation

This tool is a **signal amplifier**, not a verdict generator. A `pickle.load(s)` finding is often high-risk, but real exploitability depends on whether an attacker can influence the loaded artifact (local file, downloaded model, CI artifact, bucket object, etc.) and on any integrity/provenance controls in the pipeline.

### License

Copyright (c) 2026 Joshua Provoste. All rights reserved.
No license is granted to use, copy, modify, or distribute this software without explicit permission.