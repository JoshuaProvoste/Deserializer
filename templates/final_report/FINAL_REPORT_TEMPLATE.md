<!--
================================================================================
REPRODUCTION GUIDE — FINAL REPORT TEMPLATE
(structure derived EXCLUSIVELY from the reference document:
 PYPI-scrapling-0.4.15/REPRODUCTION_GUIDE.md — keep sections, order and heading
 levels IDENTICAL in every final REPRODUCTION_GUIDE.md)
================================================================================
HOW TO USE THIS TEMPLATE (agent instructions — remove this comment block from
the final document):

1. Copy this file into the package project dir as REPRODUCTION_GUIDE.md.
2. Replace every {{PLACEHOLDER_TOKEN}} with the real value.
3. Replace every LOREM-IPSUM paragraph with the real verified content.
4. NEVER delete or reorder sections. If a subsection is not applicable (e.g.
   there are no alternative vectors or no advanced payloads for this package),
   keep the heading with "N/A — one-line reason".
5. Only write claims that were EMPIRICALLY verified in the lab. Anything
   unverified is marked explicitly as "(not verified — theoretical)".
6. Every command block is followed by its observed/expected output block and,
   where a screenshot exists, its ![image](name.png) reference on the next line.
7. Keep lab conventions: attacker Raspberry Pi (UNIX) with Samba share hosting
   the payload in ~/lab_attack; victim Windows machine; "or {}" stability
   pattern and payload patterns documented per exploit_development/README.md.
================================================================================
-->

# `{{PACKAGE_NAME_WITH_VERSION}}` - Unauthenticated RCE via {{TRIGGER_MECHANISM_TITLE}} based on sink `{{SINK_CALL}}` (Insecure Deserialization from {{REMOTE_SOURCES_IN_PARENS}})

## Introduction

Lorem ipsum dolor sit amet. This document provides a detailed, step-by-step reproduction guide for the **{{VULN_TITLE}}** vulnerability identified in `{{PACKAGE_NAME_WITH_VERSION}}`, a Python {{ONE_LINER_CATEGORY}}.

* **Pypi**: {{PYPI_URL}}
* **Github**: {{GITHUB_URL}}

**Vulnerability Type**: {{VULNERABILITY_TYPE_VIA_PRIMITIVE}}

---

## Vulnerability Summary

Lorem ipsum dolor sit amet, consectetur adipiscing elit. The `{{METHOD}}` method in `{{CODE_PATH_IN_PACKAGE}}` uses `{{DANGEROUS_CALL}}` to deserialize {{ARTIFACT_TYPE}} without validation. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.

Vulnerable code — `{{CODE_PATH_IN_PACKAGE}}` (lines {{LINE_RANGE}} as shipped in {{PACKAGE_VERSION}}):

```python
{{REAL_VERBATIM_VULNERABLE_CODE_SLICE_WITH_SINK}}
```

Key properties of the sink (`{{SINK_CALL}}`, line {{SINK_LINE}}):

- {{PROPERTY_ONE}}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
- {{PROPERTY_TWO}}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
- {{PROPERTY_THREE}}: Lorem ipsum dolor sit amet, consectetur adipiscing elit.

---

## Attack Scenario Overview

| Role | Device | IP Address | Purpose |
|------|--------|------------|---------|
| **Attacker** | Raspberry Pi (UNIX) | 192.168.1.92 | {{PURPOSE_ONE_LINE}} |
| **Victim** | Windows Machine | 192.168.1.88 | {{PURPOSE_ONE_LINE}} |

---

## Reproduction Steps

### Phase 1: Attacker Setup (Raspberry Pi) - 192.168.1.92

#### Step 1.1: Configure {{ATTACK_INFRASTRUCTURE}}

On the Raspberry Pi (attacker), set up {{ATTACK_INFRASTRUCTURE}} to host the malicious {{ARTIFACT_TYPE_WITH_EXT}}:

```bash
{{ATTACKER_INFRA_COMMANDS}}
```

#### Step 1.2: Generate Malicious {{ARTIFACT_TYPE_WITH_EXT}}

Create `{{PAYLOAD_GENERATOR_PY}}` script on the Raspberry Pi:

```python
# payload_generator.py - Run on Raspberry Pi (Attacker)
# Header comment block documents: what the payload does, protocol/opcodes or
# gadget chain mechanics, stability pattern, and environment assumptions.
{{PAYLOAD_GENERATOR_CODE_VERBATIM}}
```

Run the exploit generator:

```bash
python payload_generator.py
```

**Expected Output**:
```
{{VERBATIM_GENERATOR_OUTPUT}}
```

![image]({{ATTACKER_SCREENSHOT_PNG}})

---

### Phase 2: Victim Setup (Windows Machine) - 192.168.1.88

#### Step 2.1: Environment Configuration

On the Windows machine, install the vulnerable library and required packages:

```powershell
{{PIP_INSTALL_COMMANDS}}
```
```
{{VERBATIM_PIP_SHOW_VERSIONS_THE_PYTHON_VERSION_AND_VENV_PROMPT}}
```

#### Step 2.2: {{ACCESS_SETUP_SUCH_AS_MAP_NETWORK_DRIVE}}

Connect to the attacker's {{SHARE_PROTOCOL}} share:

```powershell
{{VICTIM_ACCESS_COMMANDS}}
```

#### Step 2.3: Verify Victim IP

```powershell
ipconfig | Select-String "IPv4"
```

![image]({{VICTIM_SETUP_SCREENSHOT_PNG}})

---

### Phase 3: Exploitation

#### Step 3.1: Trigger the Vulnerability

On the Windows victim, execute the following to trigger RCE:

**Option A: {{DIRECT_TRIGGER_NAME}}**

```
{{DIRECT_TRIGGER_SESSION_TRANSCRIPT}}
```

![image]({{DIRECT_TRIGGER_SCREENSHOT_PNG}})

**Option B: Simulating {{REALISTIC_USAGE_NAME}} (Executing `{{PACKAGE_NAME_WITH_VERSION}}` as {{HOW_DOES_A_CONSUMER_USE_IT}})**

In real-world scenarios, the victim does not {{REPRODUCE_THE_SINK_MANUALLY}}: {{REALISTIC_TRIGGER_NARRATIVE_LONG_FORM}}:

```python
# {{VICTIM_SCRIPT_PY}} - Run on Windows (Victim)
{{REALISTIC_VICTIM_SCRIPT_CODE_VERBATIM}}
```

Step by step:

1. {{ATTACKER_SIDE_PREPARATION_IN_ONE_LINE}}
2. (Windows victim) Save the script above as `{{VICTIM_SCRIPT_PY}}` in the package virtualenv and run it:

```bash
(.venv) PS {{PROJECT_DIR}}> python {{VICTIM_SCRIPT_PY}}
```

![image]({{REALISTIC_TRIGGER_SCREENSHOT_PNG}})

3. Execution path (verified): {{VERIFIED_EXECUTION_PATH_NARRATIVE}}. The {{PAYLOAD_EFFECT_SUCH_AS_CALC_EXE}} spawns during `{{SINK_CALL}}`, before any further activity.

```text
{{VERBATIM_VICTIM_LOG_OUTPUT}}
```

Note: {{STABILITY_OR_CLEANUP_NOTE}}. Re-run the generator (Step 1.2) if you want to repeat the test.

![image]({{PHASE3_END_SCREENSHOT_PNG}})

---

## Alternative Attack Vectors

### Web or API Endpoint Exploitation

Lorem ipsum dolor sit amet, consectetur adipiscing elit. If `{{PACKAGE_NAME_WITH_VERSION}}` exposes {{API_SURFACE}} that accepts {{USER_SUPPLIED_INPUT}} for {{SINK_TRIGGER_CONTEXT}}:

```python
# {{ALTERNATIVE_VECTOR_SCRIPT_PY}} - Run on Windows (Victim)
{{ALTERNATIVE_VECTOR_CODE_VERBATIM}}
```

Step by step:

1. {{ATTACKER_SIDE_PREPARATION_IN_ONE_LINE}}
2. (Victim) {{VICTIM_SERVICE_SETUP_AND_START}}:

```powershell
{{VICTIM_SERVICE_START_TRANSCRIPT}}
```

3. (Raspberry Pi, attacker) Trigger the RCE with {{REMOTE_TRIGGER_TOOL_SUCH_AS_CURL}}. {{SHELL_QUOTING_WARNING_IF_ANY}}:

```bash
{{ATTACKER_TRIGGER_COMMAND_AND_TRANSCRIPT}}
```

![image]({{ALTERNATIVE_VECTOR_SCREENSHOT_PNG}})

(SHELL-SPECIFICO: {{CURLSHELLIMPO}})

Verified execution path (tested locally over {{PROTOCOL}}): {{OBSERVED_EXECUTION_PATH_NARRATIVE}}:

```text
{{VERBATIM_OBSERVED_RESPONSE}}
```

Victim-side observation ({{WHERE_THE_LOG_APPEARS}}):

```text
{{VERBATIM_VICTIM_SIDE_LOG}}
```

---

## Advanced Exploit Payloads

### Reverse Shell Payload (Windows Target)

For high-interaction exploitation, a PowerShell reverse shell connects back to the Raspberry Pi. This adapts the pattern documented in `exploit_development/README.md` ("Reverse Shell Implementation - Windows Target" + "Graceful Error Handling" + "Binary Payload Pattern") to the {{SINK_ARTIFACT_TYPE}}:

- **Binary Payload (Protocol 0)**: {{WHY_BINARY_ASCII_PAYLOAD}}, environment independent — no `{{EXPLOIT_CLASS}}` class needed on the victim.
- **Non-blocking spawn**: {{NON_BLOCKING_SPAWN_NARRATIVE}}.
- **Stability pattern (`or {}` trick, adapted)**: the `{{CALLABLE}}` expression returns {{STABLE_SURROGATE_SHAPE}}, matching the shape `{{CONSUMER_EXPECTED_SHAPING}}` — the {{LOAD_OPERATION}} completes cleanly instead of dying with `{{POSSIBLE_ERROR_MESSAGE}}`.

Create the generator on the Raspberry Pi (attacker), which writes the payload straight into the share root (`{{SHARE_DIR}}`, as configured in Step 1.1):

```python
# reverse_payload_generator.py - Run on Raspberry Pi (Attacker, 192.168.1.92)
{{REVERSE_SHELL_GENERATOR_CODE_VERBATIM}}
```

Step by step:

1. (Raspberry Pi, attacker) Start the connect-back listener:

```bash
{{LISTENER_SESSION_TRANSCRIPT}}
```

2. (Windows victim) Run the automated-resume victim script documented in Phase 3, **Option B** (`{{VICTIM_SCRIPT_PY}}`, with `{{CRAWLDIR_OR_EQUIVALENT}}`), from an interactive console, allowing the attacker to take control of Windows Victim Machine:

```powershell
{{VICTIM_TRANSCRIPT_WITH_REVERSE_SHELL_CONNECTION}}
```

![image]({{REVERSE_SHELL_SCREENSHOT_PNG}})

<!-- END OF TEMPLATE — keep section order EXACTLY as in this file -->
