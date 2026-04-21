# AI Security Analyst Agent

This directory contains the core logic for **Phase 4: AI-Driven Security Analysis**. The agent is designed to bridge the gap between static analysis findings and actionable exploit reproduction by performing autonomous manual code reviews.

## Overview

The AI Security Analyst is a specialized agent built on the **smolagents** framework. It acts as a "Senior 0-day Vulnerability Hunter," taking the raw outputs from the static scanner and the relationship mapper to synthesize deep technical reports and reproduction guides.

## Core Architecture

### 1. Engine: smolagents
The agent utilizes a `CodeAgent` implementation. Unlike standard LLM chains, a `CodeAgent` can write and execute small Python snippets to interact with its environment. This allows the agent to:
- Navigate deep and complex directory structures (monorepos).
- Read and analyze large source code files programmatically.
- Generate structured markdown reports and reproduction scripts.

### 2. Inference Model: MiniMax-M2.5
The agent is powered by **MiniMax-M2.5**, accessed via the Hugging Face `InferenceClientModel`. This model was chosen for its high fidelity in technical reasoning and its ability to follow complex, multi-step security instructions.

## Sequential Execution Flow

The analysis is orchestrated in two distinct, autonomous phases to prevent context dilution and ensure technical accuracy:

### Phase 4.1: Attack Surface Discovery
- **Goal**: Generate `ATTACK_SURFACE.md`.
- **Logic**: The agent uses the static analysis reports as a "technical map" to navigate the source code. It traces data execution flows from external inputs (checkpoints, API endpoints, storage) to vulnerable sinks (`pickle.loads`).
- **Context Reversal**: Its primary objective is to prove that "self-command-injection" assumptions are invalid by identifying infrastructure-level entry points.

### Phase 4.2: Reproduction Guide Synthesis
- **Goal**: Generate `REPRODUCTION_GUIDE.md`.
- **Logic**: Acting as an Exploit Engineer, the agent analyzes the identified vectors and synthesizes a step-by-step reproduction guide.
- **Multi-Platform Context**: Instructions are generated assuming a high-fidelity scenario:
    - **Attacker**: Raspberry Pi (UNIX-based).
    - **Victim**: Windows local host.
- **Exploit Generation**: The agent is tasked with writing functional Python scripts for payload generation and exploit execution for each vector.

## Specialized Tooling

The agent is equipped with a custom-built toolset (`agent/tools/`):

- **DirectoryNavigator**: Allows the agent to list and explore files recursively.
- **FileInspector**: Provides metadata about files (size, extensions) to prioritize analysis.
- **SafeSourceReader**: Enables reading source code snippets safely while managing context window limits.
- **MarkdownManager**: A specialized tool for creating and copying markdown templates, ensuring the generated reports adhere to the project's visual standards.

## Integration & Orchestration

The `AIOrchestrator` (located in `modules/`) serves as the bridge between the scanner and the agent:
1. It assembles dynamic, context-aware prompts based on the project name and findings.
2. It initializes the `SecurityAnalystAgent` with the required `HF_TOKEN`.
3. It manages the sequential hand-off between Phase 4.1 and Phase 4.2.

## Requirement & Setup

To enable the AI Agent, ensure your environment is correctly configured:

1. **Token**: Add your Hugging Face API token to a `.env` file at the root:
   ```env
   HF_TOKEN=your_token_here
   ```
2. **Configuration**: The agent is configured with `max_steps=30` to handle large codebases like the Microsoft Agent Framework.
