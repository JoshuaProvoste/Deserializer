# Pickle RCE Finder Modules

This directory contains a collection of specialized tools and support libraries for the deep analysis of deserialization vulnerabilities in Python. Each module is designed to be functional independently via its Command Line Interface (CLI) or to be integrated into automated workflows through programmatic imports.

## Dynamic Orchestration and Import Architecture

`pickle_rce_finder.py` serves as the primary engine and orchestrator of the ecosystem. The interaction between the core scanner and the deep analysis submodules is managed through a phased workflow:

1.  **Core Scanning (Phase 1)**: Initial identification of deserialization sinks using AST, Tokenizer, or Regex.
2.  **Relationship Mapping (Phase 2)**: Deep impact analysis, call graph construction, and inheritance tracing.
3.  **Result Processing (Phase 3)**: Human-readable Markdown report generation and project-based segregation.
4.  **AI Deep Analysis (Phase 4)**: Autonomous verification and reproduction guide synthesis using LLM agents.

### Technical Import Mechanism & Exhaustive Analysis

The system implements a sophisticated **Dynamic Orchestration** pattern to manage local dependencies and execution flow. Below is a detailed technical breakdown of this process:

#### 1. Conditional Phase Gating
The transition from Phase 1 to Phase 2/3 is guarded by a conditional gate (`if total_findings > 0 and args.out != "-"`). This ensures that deep analysis only occurs when:
-   At least one high-risk finding has been identified.
-   A physical output file is specified. Because Phase 2 and 3 rely on reading and writing intermediate JSONL states, they are bypassed when the scanner is used in streaming mode (`--out -`) to prevent console output corruption.

#### 2. Local Scope Namespace Injection (Lazy Loading)
To minimize the memory footprint and prevent circular dependency issues, imports are performed at the **Function-Level** within the `main()` orchestrator:
-   **Mapper Loading**: `RelationshipMapper` is imported only at the start of Phase 2.
-   **Processor Loading**: `ResultProcessor` is imported twice—first as a static utility to infer project names and create directory structures, and later as a full instance to handle report generation.
-   **AI Orchestrator Loading**: `AIOrchestrator` is lazy-loaded at the start of Phase 4 to bridge scanning results with external AI intelligence.
This ensures that the specialized analysis libraries are not loaded into the Python interpreter session unless they are explicitly required by the scan results.

#### 3. Error Handling and Resilience (Graceful Degradation)
Each module import is encapsulated in a `try...except ImportError` block. This provides two major design advantages:
-   **Modular Distribution**: The core scanner (`pickle_rce_finder.py`) can be deployed as a standalone script in restricted environments (e.g., CI/CD containers) even if the `modules/` directory is not provided.
-   **Fail-Safe Execution**: If a module is corrupted or missing, the orchestrator catches the error and allows the process to terminate gracefully, ensuring that the primary scan results (Phase 1) are never lost due to reporting failures.

#### 4. Disk-Coupled State Transfer
The interaction between components is **disk-coupled** rather than held in-memory. This architecture is chosen for scalability:
-   **Scan -> Map**: The scanner flushes and closes its output buffer (`sink.close()`) before the mapper starts. The mapper then re-opens the file in read-only mode to process findings one by one.
-   **Map -> Process**: The mapper persists its enriched graph into a project-specific `relationship_mapper.jsonl`. The processor later consumes this file to "flatten" recursive call chains into Markdown.
This sequential, file-based hand-off ensures that the memory usage remains predictable even when analyzing repositories with thousands of files or complex call deep hierarchies.

#### 5. Namespace and Pathing Resolution
The orchestration relies on the `modules` directory being treated as a package. By using the notation `from modules.relationship_mapper import RelationshipMapper`, the system expects the execution context to be the project root. This allows for clean, explicit namespacing and prevents collision with other local library names in the analyzed repositories.

---

## Relationship Mapper (`relationship_mapper.py`)

### Description
An advanced static analysis tool based on **AST (Abstract Syntax Trees)** designed to map the impact radius of identified vulnerabilities. Unlike a simple scanner, the Mapper tracks recursive callers, identifies class inheritance, and locates mentions in documentation to build a comprehensive graph of the attack surface.

### Key Features
- **Framework Analysis**: Intelligent affinity filtering (e.g., distinguishes between TF and JAX in generic methods like `load`).
- **Notebook Support**: Extracts and analyzes code cells in `.ipynb` files.
- **Inheritance Detection**: Identifies affected subclasses that inherit from a vulnerable base.
- **API Pivoting**: Tracks from private methods (`_process`) to their public interfaces.
- **High-Performance Multiprocessing**: Built-in support for parallel execution using `ProcessPoolExecutor` to handle hundreds of findings in seconds.

### Independent Usage (CLI)
You can run the mapper directly on a `.jsonl` findings file previously generated by the scanner:

```bash
python modules/relationship_mapper.py <input_jsonl> <repo_path> [output_jsonl] [record_index] [-j concurrency]
```

- **input_jsonl**: File containing scanner findings.
- **repo_path**: Path to the analyzed repository.
- **output_jsonl** (Optional): File to save the mapping results.
- **record_index** (Optional): Index of the specific record to map (1-based).
- **-j concurrency** (Optional): Number of parallel processes to use. Defaults to `(CPU cores - 2)`.

### Module Usage (Import)
The mapper can be integrated into other Python scripts:

```python
from modules.relationship_mapper import RelationshipMapper

# Initialization
mapper = RelationshipMapper(target_repo_path="./my_project")

# Map a specific finding
finding = {
    "file": "core/io.py",
    "lineno": 45,
    "name": "load"
}
mapping_result = mapper.map_finding(finding)

# Access found relationships
print(mapping_result['relationships']['code'])

# Bulk mapping (Parallel)
findings = load_your_findings()
results = mapper.map_bulk(findings, concurrency=4)
```

---

## Result Processor (`result_processor.py`)

### Description
This module is responsible for the **Report Generation** phase. It takes the `.jsonl` outputs from the Relationship Mapper and transforms them into readable security reports in Markdown format. Its primary value lies in "flattening" recursive call graphs, converting complex JSON structures into a clear attack narrative.

### Key Features
- **Project Segregation**: Automatically creates a `reports/<project>/` folder structure.
- **Individual Reports**: Generates one `.md` file for each processed finding.
- **Path Visualization**: Flattens recursion to show end-to-end attack paths.
- **Systemic Impact**: Summarizes the impact on inheritance and mentions in documentation.

### Independent Usage (CLI)
You can process a mapping results file to generate individual reports:

```bash
python modules/result_processor.py <mapper_output.jsonl> [project_name]
```

- **mapper_output.jsonl**: The file previously generated by `relationship_mapper.py`.
- **project_name** (Optional): Destination folder name. If omitted, it is inferred from the finding's content.

### Module Usage (Import)
The processor can be integrated to automate custom audits:

```python
from modules.result_processor import ResultProcessor

# Initialization
processor = ResultProcessor(output_base_dir="my_reports")

# Generate report for a specific result
# 'result' is a dictionary loaded from the JSONL
processor.generate_report(result, index=1, project_name="my_audit")
```

---

## AI Orchestrator (`ai_orchestrator.py`)

### Description
The **AI Orchestrator** is the final stage of the analysis pipeline. It manages the integration between static scanning results and advanced AI-driven verification. It coordinates a sequential workflow where an AI agent acts as a Senior Security Researcher to perform manual-like code reviews and synthesize multi-platform exploit reproduction guides.

### Key Features
- **Sequential Tasking**: Manages two autonomous sub-phases: **Attack Surface Discovery** and **Reproduction Guide Synthesis**.
- **Dynamic Prompting**: Assembles high-fidelity security prompts in English to achieve maximum model reasoning quality.
- **Advanced Reasoning**: Integrates with the **MiniMax-M2.5** model to reverse "self-command-injection" contexts.
- **Multi-Platform Focus**: Compiles reproduction guides specifically formatted for UNIX (Attacker) and Windows (Victim) environments.

### Independent Usage (CLI)
Phase 4 can be run as a standalone process on a project that has already undergone Phases 1-3:

```bash
python modules/ai_orchestrator.py <project_name> [repo_path]
```

- **project_name**: The name of the project folder (used to locate generated reports).
- **repo_path** (Optional): Path to the analyzed repository. Defaults to `.`.

### Module Usage (Import)
The orchestrator is designed to be lazily loaded by the main scanner for deep analysis:

```python
from modules.ai_orchestrator import AIOrchestrator

# Initialization (auto-loads .env for HF_TOKEN)
orchestrator = AIOrchestrator()

# Execute the full Phase 4 analysis
# Generates {project_name}/ATTACK_SURFACE.md and {project_name}/REPRODUCTION_GUIDE.md
orchestrator.run_analysis(project_name="agent-framework", repo_path="agent-framework")
```
