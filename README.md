# Pickle RCE Finder (AST-based)

```
L:\Pickle-RCE-Finder>git clone https://github.com/microsoft/agent-framework
Cloning into 'agent-framework'...
remote: Enumerating objects: 60315, done.
remote: Counting objects: 100% (631/631), done.
remote: Compressing objects: 100% (376/376), done.
Receiving objects: 100% (60315/60315), 84.32 MiB | 30.38 MiB/s, done.59684 (from 3)

Resolving deltas: 100% (43682/43682), done.
Updating files: 100% (3958/3958), done.
Filtering content: 100% (2/2), 334.47 KiB | 227.00 KiB/s, done.

L:\Pickle-RCE-Finder>python pickle_rce_finder.py --path agent-framework --rules-file rules.json -j 4 --out agent-framework/agent-framework.jsonl

  _____ _      _    _        _____   _____ ______   ______ _           _
 |  __ (_)    | |  | |      |  __ \ / ____|  ____| |  ____(_)         | |
 | |__) |  ___| | _| | ___  | |__) | |    | |__    | |__   _ _ __   __| | ___ _ __
 |  ___/ |/ __| |/ / |/ _ \ |  _  /| |    |  __|   |  __| | | '_ \ / _` |/ _ \ '__|
 | |   | | (__|   <| |  __/ | | \ \| |____| |____  | |    | | | | | (_| |  __/ |
 |_|   |_|\___|_|\_\_|\___| |_|  \_\\_____|______| |_|    |_|_| |_|\__,_|\___|_|

    Pickle Deserialization Parser for Python Source Code
            coded by @JoshuaProvoste (jp / kw0)


================================================================================
 [>] Starting Static Analysis Scan...
================================================================================
[HIGH][deserialize] L:\Pickle-RCE-Finder\agent-framework\python\packages\core\agent_framework\_workflows\_checkpoint_encoding.py:270  pickle.loads

Progress: 100.0% | Res: 1 | Scanned: 852/852 | Current: _dependency_bounds_upper_im...
Scan finished.
Files scanned: 852
Findings: 1
Errors: 0

JSONL output: L:\Pickle-RCE-Finder\agent-framework\agent-framework.jsonl (lines: 1, bytes: 312)

================================================================================
 [>] Starting Relationship Mapping process...
================================================================================
Identified 1 findings. Starting bulk mapping...

[1/1] Processing: L:\Pickle-RCE-Finder\agent-framework\python\packages\core\agent_framework\_workflows\_checkpoint_encoding.py:270...

[+] Bulk Mapping Completed
Total records processed: 1
Results saved in: agent-framework\relationship_mapper.jsonl

 --- Findings Breakdown ---
 - L:\Pickle-RCE-Finder\agent-framework\python\packages\core\agent_framework\_workflows\_checkpoint_encoding.py:270 -> _base64_to_unpickle (1 relationships)

--- End of Mapping Phase ---

================================================================================
 [>] Starting Security Report Generation...
================================================================================
  [+] Generated: reports\agent-framework\report_1.md

[OK] 1 detailed reports have been generated.
Check the 'reports/' folder to see the results.

L:\Pickle-RCE-Finder>
```

**Pickle RCE Finder** is a lightweight, repo-friendly Python static scanner that hunts for risky **Python deserialization entrypoints** (e.g., `pickle.load(s)` and `torch.load`) by parsing source code with the built-in `ast` module. It was designed for quick triage across large codebases: run it on a folder, get **newline-delimited JSON (JSONL)** findings with file/line context, and immediately spot places where an attacker-controlled artifact could turn into **RCE during load**.

## Dependencies & Portability

This scanner integrates high-fidelity **AI-Driven Deep Analysis (Phase 4)** as an optional module. Consequently, the project **requires** the installation of external dependencies for AI orchestration, environment management, and inference only when the `--agent` flag is used.

**Installation**:
Before running the scanner, you MUST install the dependencies:
```bash
pip install -r requirements.txt
```

### AI-Driven Deep Analysis (Phase 4)

This phase integrates a specialized AI Security Agent to perform deep code reviews and map complex 0-day RCE vectors. Using the **MiniMax-M2.5** model (via Hugging Face), the agent analyzes findings to reverse "self-command-injection" contexts and generate technical reproduction guides with a multi-platform focus (e.g., Attacker UNIX/Raspberry vs Victim Windows). **Note: This phase is only executed if the `--agent` flag is provided.**

**Setup Requirements**:
- **Environment**: Create a `.env` file in the root directory and add your Hugging Face token:
  ```env
  HF_TOKEN=your_token_here
  ```

## Performance & Multiprocessing

This scanner features a high-performance **parallel execution engine** built on Python's `concurrent.futures.ProcessPoolExecutor`. It is designed to scale across all available CPU cores (controllable via the `-j` or `--concurrency` flag), making it capable of scanning tens of thousands of files in seconds.

- **Non-Blocking UI**: Features a stable, docked progress bar with a one-line gap for clean results presentation.
- **Native Signal Handling**: On Windows, it utilizes a native `SetConsoleCtrlHandler` via `ctypes` to ensure that `Ctrl+C` is 100% responsive, even during heavy processing.
- **Silent Tracebacks**: Worker processes are silented to ensure that interrupts and internal errors don't clutter the technical output.

> [!WARNING]
> **Performance Warning**: When analyzing extremely large or complex files (e.g., over 1MB, 2MB, or 3MB in size), the tool may experience significant slowdowns or appear "stuck" while parsing deep AST trees. If you encounter such bottlenecks, consider using the `--timeout` (to skip slow files) and `--max-size` (to skip huge files) flags to maintain scan velocity.

## Research writeups that this scanner supported

**Pickle RCE Finder** directly supported my security research and helped me locate insecure deserialization paths that were later documented in these investigations: **Brax (v0.14.2)**, **Dopamine (v2.0)**, **PyGlove (v0.4.5)**, **Learned Optimization (v0.0.1)**, and **Vertex AI (v1.147.0)**. Concretely, it made it easy to enumerate where projects deserialize model/artifact blobs and prioritize the high-risk code paths that execute during `pickle` loading flows, accelerating root-cause analysis and PoC development.

- **Brax (v0.14.2)**:
  - **Impact**: Critical RCE on compute nodes and TPU/GPU pods.
  - **Details**: `load_params` in `brax.io.model` uses `etils.epath` to download and deserialize malicious parameters via `pickle.loads` from remote URIs (SMB, GCS, S3).
  - **Pull Request**: https://github.com/google/brax/pull/667
  - **RCE PoC**: [RCE in brax v0.14.2](research/brax_v0.14.2/README.md)
- **Dopamine (v2.0)**:
  - **Impact**: Critical RCE in distributed research clusters.
  - **Details**: `load_statistics` and `Checkpointer` use `tf.io.gfile` to deserialize pickles from attacker-controlled remote paths or malicious `gin-config` injections.
  - **Issue**: https://github.com/google/dopamine/issues/236
  - **RCE PoC**: [RCE in dopamine v2.0](research/dopamine_v2.0/README.md)
- **PyGlove (v0.4.5)**:
  - **Impact**: Critical RCE via JSON APIs and distributed tuning.
  - **Details**: `_OpaqueObject` allows automatic pickle decoding embedded in JSON. Also vulnerable in `sandbox_call` and `fsspec` URI loading flows.
  - **Pull Request**: https://github.com/google/pyglove/pull/404
  - **RCE PoC**: [RCE in pyglove v0.4.5](research/pyglove_v0.4.5/README.md)
- **Learned Optimization (v0.0.1)**:
  - **Impact**: Critical RCE in HPC research environments and TPU/GPU pods.
  - **Details**: `read_npz` in `learned_optimization.baselines.utils` uses `numpy.load(..., allow_pickle=True)` on researcher-controlled paths (GCS, SMB), enabling the execution of arbitrary Python objects during deserialization.
  - **Pull Request**: https://github.com/google/learned_optimization/pull/342
  - **RCE PoC**: [RCE in learned_optimization v0.0.1](research/learned_optimization_v0.0.1/README.md)
- **Vertex AI (v1.147.0)**:
  - **Impact**: Critical RCE on developer workstations, CI/CD runners (MLOps), and research environments.
  - **Details**: Several sinks in Predictors and Agent/Reasoning engines allow loading malicious artifacts via `pickle`/`cloudpickle` from remote URIs (GCS, SMB/UNC). Vulnerabilities can be chained via `AIP_STORAGE_URI` or `staging_bucket` injection for remote exploitation.
  - **Pull Request**: https://github.com/googleapis/python-aiplatform/pull/6589
  - **RCE PoC**: [RCE in google-cloud-aiplatform v1.147.0](research/google_cloud_aiplatform_v1.147.0/README.md)

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

### 1. Basic Scan
Scan the current directory and print findings to the terminal (writes JSONL to stdout by default):
```bash
python pickle_rce_finder.py
```

### 2. Targeted Audit
Scan a specific repository and save findings to a JSONL file:
```bash
python pickle_rce_finder.py --path /path/to/my-repo --out audit_results.jsonl
```

### 3. Turbo Mode (Performance Tuning)
Use 8 concurrent processes and a 5-second timeout per file to keep the scan moving:
```bash
python pickle_rce_finder.py -j 8 --timeout 5 --out findings.jsonl
```

### 4. CI/CD & Pipeline Integration
Disable the banner and stream JSONL directly to stdout for pipe processing (human logs will go to stderr):
```bash
python pickle_rce_finder.py --no-banner --out - | jq .
```

### 5. Hardened / Safety Scan
Limit processing to files under 1MB and skip specific data directories:
```bash
python pickle_rce_finder.py --max-size 1048576 --skip-dirs "data,samples,tests"
```

### 6. Custom Detection Rules
Use a proprietary ruleset to detect logic-specific calls:
```bash
python pickle_rce_finder.py --rules-file my_custom_rules.json --out legacy_audit.jsonl
```

### 7. AI Deep Analysis
Trigger the AI-Driven Deep Analysis (Phase 4) after the scan and mapping are complete:
```bash
python pickle_rce_finder.py --path /path/to/repo --out findings.jsonl --agent
```

## CLI Flags

- `--path <dir>`  
  Root directory to scan. Default: `.`

- `--rules-file <path>`  
  Path to a JSON ruleset. If provided, it overrides the built-in `DEFAULT_RULES`.

- `--out <path|->`  
  Output destination for JSONL results. Use `-` to write JSONL to `stdout`. Default: `-`

- `-j, --concurrency <int>`  
  Number of concurrent processes to use. Default: `(CPU cores - 2)`.

- `-t, --timeout <float>`  
  Timeout in seconds for each file analysis. Only effective in parallel mode. Default: `None` (no timeout).

- `--max-size <bytes>`  
  Maximum file size in bytes to process. Default: `10,485,760` (10 MiB).

- `--skip-dirs <list>`  
  Comma-separated list of directory names to ignore (e.g., `tests,.git,env`).

- `--no-banner`  
  Disable the ASCII branding banner for cleaner output in scripts.

- `--agent`  
  Run AI-driven deep analysis (Phase 4). This phase is optional and requires a valid `HF_TOKEN` in the `.env` file.

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