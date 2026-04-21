# Deserializer (AST-based)

![Deserializer Banner](docs/images/banner.png)

**Deserializer** is an advanced Abstract Syntax Tree (AST) static analysis engine designed to identify insecure object reconstruction and state persistence sinks across the Python ecosystem. Far beyond a simple scanner, it provides a generic, high-performance framework for auditing over 120 libraries and formats—including YAML, Msgpack, CBOR, and custom JSON hooks—where traditional trust in "safe" serialization hides critical logic-based RCE vectors like Type Smuggling. By resolving imports, aliases, and complex dotted attributes, the tool serves as a high-fidelity signal amplifier that prioritizes dangerous code paths in modern distributed architectures and AI/ML repositories.

The project operates through a modular, multi-phased workflow that transitions from raw detection to deep technical audit. Following the initial high-velocity SAST scan, the ecosystem leverages specialized relationship mappers to trace execution flows and result processors to generate detailed security reports. This systematic approach ensures that every finding is contextualized within the application's broader architecture, transforming high-volume telemetry into actionable research assets and structured milestones that simplify the mapping of infrastructure-level attack surfaces.

At its most advanced tier, Deserializer integrates an autonomous AI Security Agent (Phase 4) explicitly designed to navigate "self-command-injection" limitations and synthesize functional reproduction guides. This capability has directly powered the discovery of critical vulnerabilities in industry-leading frameworks like TensorFlow, Django, and LangGraph, proving its efficacy in auditing complex MLOps and agentic AI environments. As the project evolves, it continues to define the frontier of automated vulnerability research by bridging the gap between static analysis and functional exploit development.

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
python deserializer.py
```

### 2. Targeted Audit
Scan a specific repository and save findings to a JSONL file:
```bash
python deserializer.py --path /path/to/my-repo --out audit_results.jsonl
```

### 3. Turbo Mode (Performance Tuning)
Use 8 concurrent processes and a 5-second timeout per file to keep the scan moving:
```bash
python deserializer.py -j 8 --timeout 5 --out findings.jsonl
```

### 4. CI/CD & Pipeline Integration
Disable the banner and stream JSONL directly to stdout for pipe processing (human logs will go to stderr):
```bash
python deserializer.py --no-banner --out - | jq .
```

### 5. Hardened / Safety Scan
Limit processing to files under 1MB and skip specific data directories:
```bash
python deserializer.py --max-size 1048576 --skip-dirs "data,samples,tests"
```

### 6. Custom Detection Rules
Use a proprietary ruleset to detect logic-specific calls:
```bash
python deserializer.py --rules-file my_custom_rules.json --out legacy_audit.jsonl
```

### 7. AI Deep Analysis
Trigger the AI-Driven Deep Analysis (Phase 4) after the scan and mapping are complete:
```bash
python deserializer.py --path /path/to/repo --out findings.jsonl --agent
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