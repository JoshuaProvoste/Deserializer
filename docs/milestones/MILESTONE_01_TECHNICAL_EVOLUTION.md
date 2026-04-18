# Technical Landmark: Evolution from Pickle Hunting to Generic Deserialization SAST

## Executive Summary

This document records a critical milestone in the development and research methodology of **Pickle RCE Finder** (`v1.1.0`). What began as a specialized tool for hunting "vulnerable by design" `pickle` entry points has evolved into a comprehensive **AST-based Static Analysis Security Testing (SAST)** engine. This architectural flexibility has proven essential for identifying modern RCE vectors in libraries and formats traditionally considered "safe" by the security community.

---

## 1. Architectural Foundation: The AST Signal Amplifier

At its core, the scanner utilizes Python's `ast` (Abstract Syntax Tree) module to map complex code paths and resolve imports/aliases. This approach provides several key advantages over traditional grep-based security tools:

- **Contextual Awareness**: The engine tracks how modules are imported (e.g., `import pickle as p`) and follows references through nested attributes (`pkg.sub.pickle.loads`).
- **Signal Amplification**: By identifying 120+ modules in `rules.json`, the tool acts as a signal amplifier for any API that handles object reconstruction, state persistence, or distributed task execution.
- **Parser Robustness**: The multi-pass approach (AST -> Tokenization -> Regex) ensures that findings are detected even in "broken" or templated Python files (e.g., Jinja2/Mako integration).

---

## 2. The LangGraph Discovery: A Paradigm Shift

A pivotal moment in the project's research was the discovery within **LangGraph (v1.1.6)**. This investigation demonstrated that the industry's shift away from `pickle` toward "safe" binary formats like `msgpack` and `ormsgpack` has introduced a new class of **Logic-based Deserialization** vulnerabilities.

### The "Msgpack Extension" Vector
While `msgpack` is structurally safe, its support for **custom extensions** (specifically Code 0 / `EXT_CONSTRUCTOR_SINGLE_ARG`) can be abused to trigger arbitrary module imports and function calls. If a framework maintains a permissive extension policy (`allowed_msgpack_modules=True`), an attacker can achieve RCE by switching from a `pickle` payload to a crafted `msgpack` blob.

**Key Insight**: The trust placed in "modern" serialization formats often hides structural weaknesses in type handling, leading to what we define as **Type Smuggling**.

---

## 3. Expanding the Attack Surface: Modern Deserialization Sinks

The project now recognizes a broader spectrum of risky modules that should be prioritized in modern security audits. Each presents a unique mechanism for code execution or state manipulation:

### A. PyYAML (The Classic Vector)
PyYAML serves as the closest historical parallel to `pickle` in terms of risk. 
- **Mechanism**: The use of `yaml.load()` without an explicit `SafeLoader` allows for the instantiation of arbitrary Python objects.
- **Current Status**: While modern versions enforce safe loading by default, legacy systems and specific configurations using `UnsafeLoader` or `FullLoader` remain critically vulnerable to immediate RCE via maliciously crafted YAML documents.

### B. CBOR (cbor2)
An increasingly popular binary format in edge computing and distributed systems.
- **Mechanism**: Similar to `msgpack`, CBOR supports "tags" for custom type resolution. 
- **Risk**: If the decoder is configured to automatically resolve these tags without a rigorous whitelist, an attacker can inject specific tags that trigger dangerous side-effects during the deserialization phase.

### C. JSON (Standard Library & SimpleJSON)
Often considered "safe" due to its descriptive nature, but vulnerable when extended.
- **Mechanism**: The `json.loads()` function accepts an `object_hook` parameter.
- **Risk**: If an application implements automated decoders based on specific keys (e.g., `__type__` or `__class__`) to "rehydrate" complex objects, it creates a **Logic-based Deserialization** vector identical to the one discovered in the LangGraph research.

### D. Marshmallow & Pydantic
These are validation and transformation engines rather than binary serializers, yet they present critical infrastructure risks.
- **Mechanism**: The risk lies in the "rehydration" of objects from untrusted dictionaries.
- **Risk**: If models allow dynamic type loading or utilize validators with side-effects (e.g., database calls or dynamic code execution), they can be exploited through the injection of malicious data structures during the parsing/validation stage.

### E. Dill & Cloudpickle
Already tracked in `rules.json`, these deserve special mention as "Pickle on Steroids."
- **Mechanism**: Designed specifically to serialize entire functions, classes, and lambdas including their global state.
- **Risk**: By design, these modules represent "RCE-as-a-Service" if the byte source is external, as the deserialization process is literally intended to restore executable code structures.

---

## 4. Current Detection Landscape in `rules.json`

| Module | Risk Mechanism | Maturity in rules.json |
| :--- | :--- | :--- |
| **Pickle / Torch** | Native insecure deserialization (Opcode-based). | **Complete** |
| **Dill / Cloudpickle**| Functional serialization (RCE-by-design). | **Complete** |
| **PyYAML** | `UnsafeLoader` / `FullLoader` object instantiation. | **Partial** |
| **Msgpack / ormsgpack**| Permissive extension policies (Type Smuggling). | **Missing** |
| **CBOR (cbor2)** | Automatic tag resolution side-effects. | **Missing** |
| **JSON (standard)** | Insecure `object_hook` implementations. | **Missing** |
| **Pydantic** | Side-effect-heavy validation/rehydration. | **Missing** |

---

## 5. Future Strategic Path: Hunting Logic-Based 0-Days

The future of **Pickle RCE Finder** lies in transitioning from hunting "obvious" sinks to auditing **complex configuration-driven deserialization**. As AI/ML frameworks increasingly rely on distributed state backends (Redis, Memcached) and remote model artifacts (UNC/SMB shares), identifying where "safe" formats meet "insecure logic" is the next frontier for 0-day hunting.

The inclusion of `msgpack`, `ormsgpack`, `cbor2`, and advanced `json` hooks into the core ruleset is the immediate technical priority to maintain the scanner's role as a leading edge tool for high-fidelity security research.


---

## 6. Advanced Technical Proposal: Expanded Detection Matrix

To bridge the gap between "native" and "logic-based" deserialization risks, the following updates to `rules.json` are proposed. This expansion focuses on identifying modern "Type Smuggling" sinks while maintaining the high-fidelity signal the project is known for.

### 6.1. Proposed Core Rule Additions

> [!IMPORTANT]
> **Technical Note**: The following proposal utilizes an extended JSON schema (including `severity` and `description` fields). To be fully functional, this requires developmental updates to `pickle_rce_finder.py` (specifically `load_rules_json` and the `RefVisitor` reporting logic), as the current version only processes `imports` and `calls`.

```json
{
    "msgpack": {
        "imports": ["msgpack"],
        "calls": [
            ["msgpack", "load"], 
            ["msgpack", "unpack"], 
            ["msgpack", "unpackb"]
        ],
        "severity": "high",
        "description": "Risk of RCE via permissive extension factories (Code 0)."
    },
    "ormsgpack": {
        "imports": ["ormsgpack"],
        "calls": [["ormsgpack", "unpackb"]],
        "severity": "high",
        "description": "Native msgpack bypass vector for Type Smuggling."
    },
    "yaml": {
        "imports": ["yaml"],
        "calls": [
            ["yaml", "load"], 
            ["yaml", "unsafe_load"], 
            ["yaml", "full_load"]
        ],
        "severity": "critical",
        "category": "deserialization_sink"
    },
    "cbor2": {
        "imports": ["cbor2"],
        "calls": [
            ["cbor2", "load"], 
            ["cbor2", "loads"]
        ],
        "severity": "medium",
        "description": "Susceptible to tag-based injection attacks."
    },
    "pydantic": {
        "imports": ["pydantic"],
        "calls": [
            ["pydantic", "parse_obj"], 
            ["pydantic", "parse_raw"],
            ["pydantic", "model_validate"],
            ["pydantic", "model_validate_json"]
        ],
        "severity": "medium",
        "category": "data_rehydration"
    }
}
```

### 6.2. Compatible Core Rule Additions (Immediate Implementation)

For immediate deployment without modifying the scanner's source code, the following block utilizes the current `rules.json` schema. While it lacks enriched metadata, it enables the detection of these new vectors using the default severity ("medium").

```json
{
    "msgpack": {
        "imports": ["msgpack"],
        "calls": [["msgpack", "load"], ["msgpack", "unpack"], ["msgpack", "unpackb"]]
    },
    "ormsgpack": {
        "imports": ["ormsgpack"],
        "calls": [["ormsgpack", "unpackb"]]
    },
    "yaml": {
        "imports": ["yaml"],
        "calls": [["yaml", "load"], ["yaml", "unsafe_load"], ["yaml", "full_load"]]
    },
    "cbor2": {
        "imports": ["cbor2"],
        "calls": [["cbor2", "load"], ["cbor2", "loads"]]
    },
    "pydantic": {
        "imports": ["pydantic"],
        "calls": [
            ["pydantic", "parse_obj"], 
            ["pydantic", "parse_raw"],
            ["pydantic", "model_validate"],
            ["pydantic", "model_validate_json"]
        ]
    }
}
```

### 6.3. Logic-Based JSON Hook Detection

Detecting risky `json.loads` calls requires an AST-aware filtering strategy since JSON is typically safe. The scanner should flag `json.loads` (and `simplejson`) specifically when the following keyword arguments are present in the AST node:
- `object_hook`
- `object_pairs_hook`

### 6.4. Summary of Implementation Impact

1.  **Reduced Blind Spots**: Captures the "safe format" bypasses used in modern AI/ML orchestration (LangGraph, etc.).
2.  **Infrastructure Context**: By tracking `pydantic` and `marshmallow`, the tool moves "left" in the attack chain, identifying where raw untrusted input is first converted into complex Python state.
3.  **Severity Layering**: Criticality is assigned based on exploitability—`yaml.load` and `msgpack` (with extensions) are prioritized alongside native `pickle`.

---
