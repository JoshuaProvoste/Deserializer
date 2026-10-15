import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

class AIOrchestrator:
    """
    Orchestrator for Phase 4: AI Deep Analysis.
    Bridges the scanning results and report maps with the AI Security Analyst.
    """

    PROMPT_TEMPLATE = """
1. General Instruction: Act as a 0-day Vulnerability Hunter and Senior Exploit Developer, specialist in Manual Code Review.
2. Important Tool Rules: You MUST use the provided custom tools (directory_navigator, file_inspector, safe_source_reader, markdown_manager) to interact with files and directories. 
   - DO NOT import tool names or modules (e.g. `from custom_tools import ...` or `import markdown_manager` is STRICTLY FORBIDDEN). All tools are already loaded into your global scope.
   - Note: `directory_navigator(...)` returns a MULTI-LINE STRING. To get a Python list of files, split the output string by newlines (e.g. `raw_output.splitlines()`).
   - Use `directory_navigator(path='reports/{project_name}/', recursive=False)` to find all report file paths.
   - Use `markdown_manager(action='copy', source_path='templates/attack_surface/ATTACK_SURFACE_UNIFIED_TEMPLATE.md', target_path='{project_name}/ATTACK_SURFACE.md')` to initialize the attack surface file.
    - Use `markdown_manager(action='edit', target_path='{project_name}/ATTACK_SURFACE.md', content=...)` to update its content.
    - MANDATORY FINAL STEP: Inside your Python code snippet, immediately after `markdown_manager(...)`, you MUST call `final_answer("Analysis complete and ATTACK_SURFACE.md generated.")`. DO NOT use `print(...)` to finish; you MUST call `final_answer(...)`.
    - REPETITION RULE: If a Python code block yields empty or unchanged output, DO NOT execute the exact same code block in the next step. Proceed with your analysis or generate the output file and call `final_answer(...)`.
    - SCOPE RULE: Stay strictly within `reports/{project_name}/` and `{project_name}/`. DO NOT explore parent, root or system directories (never search outside `{project_name}/`).
    - EXECUTION DISCIPLINE: Read the finding report in `reports/{project_name}/`, inspect the vulnerable code lines, copy the template with `markdown_manager(action='copy', ...)` and update `{project_name}/ATTACK_SURFACE.md` with `markdown_manager(action='edit', ...)`. Then immediately invoke `final_answer(...)`.
3. General Context (Technical): Insecure deserialization vulnerabilities on Python source code are generally related to the deserialization of a "pickle file" or a Python object (etc.). However, if the vulnerability requires user interaction (user victim) and social engineering procedures (like for example, sending a specially crafted email containing malicious pickle file or convince the victim user to execute a malicious file themselves) to be exploited, the deserialization can't be categorized as valid vulnerability and it is rejected on Bug Bounty platforms, because "impact cannot be demonstrated," even though it is possible to convert it into command injection over the Operating System, because the bug bounty triagers argue "access to the server or the user's machine is required to modify the file being deserialized," turning the vulnerability into a sort of out-of-scope "self-command-injection." for every experienced, and/or senior, and/or expert bug bounty triager.
4. Objective: 
    - Act as a 0-day Vulnerability Hunter and Senior Exploit Developer, specialist in Manual Code Review, and use the following "Guidelines for reversing and solve the 'General Context (Technical)'" to perform a technical analysis that allows identifying WITH CERTAINTY AND TECHNICAL FIDELITY the real alternatives that break's and solve's the set of problems raised into the "General Context (Technical)", providing a new context where an attacker has control to execute a deserialization without authentication (unauthenticated Remote Code Execution or Code Injection) and without requiring the "user victim" interaction.
5. Guidelines for reversing and solve the "General Context (Technical)":
    - List the files in `reports/{project_name}/` using `directory_navigator`, then read each file with `safe_source_reader`.
    - Use these markdown reports as technical navigation maps of the project's source code in the path: {project_name}/
    - Follow the routes and execution flows of the deserializations, related files, affected classes (etc.), and perform the analysis required in "Objective" to reverse, break's and solve's the "General Context (Technical)". 
    - The result of the analysis should aim to achieve results technically superior to the research documented in the path research/, because we need "0" user interaction. In other words, we need for example, an HTTP request under total control of the attacker to trigger the deserialization vulnerability with RCE or CI result, without user interaction, or social engineering procedures.
    - The result of the analysis must be documented in markdown format at the following path: {project_name}/ATTACK_SURFACE.md
    - To create the ATTACK_SURFACE.md file, copy the template from `templates/attack_surface/ATTACK_SURFACE_UNIFIED_TEMPLATE.md` using `markdown_manager`. Fill in the corresponding content, keeping its structure intact. Once completed, invoke `final_answer(...)` inside your Python code.
"""

    REPRODUCTION_PROMPT_TEMPLATE = """
1. Role: Act as a Senior Exploit Engineer and Security Researcher.
2. Important Tool Rules: You MUST use the provided custom tools (directory_navigator, file_inspector, safe_source_reader, markdown_manager) to interact with files.
   - DO NOT import tool names as Python modules (e.g. `import markdown_manager` is FORBIDDEN). The tools are already available directly in your execution context as functions.
   - Use `markdown_manager(action='read', target_path='{project_name}/ATTACK_SURFACE.md')` or `safe_source_reader('{project_name}/ATTACK_SURFACE.md')` to read the attack surface.
   - Use `markdown_manager(action='create', target_path='{project_name}/REPRODUCTION_GUIDE.md', content=...)` or `markdown_manager(action='edit', ...)` to write the deliverable.
   - MANDATORY FINAL STEP: Inside your Python code snippet, immediately after `markdown_manager(...)`, you MUST call `final_answer("Reproduction guide complete and REPRODUCTION_GUIDE.md generated.")`. DO NOT use `print(...)` to finish; you MUST call `final_answer(...)`.
   - REPETITION RULE: If a Python code block yields empty or unchanged output, DO NOT execute the exact same code block in the next step. Proceed directly to create the file and call `final_answer(...)`.
3. Purpose: Based on the previously generated {project_name}/ATTACK_SURFACE.md, create a detailed, step-by-step reproduction guide for each identified vulnerability vector.
4. Deliverable: Create a file named {project_name}/REPRODUCTION_GUIDE.md.
5. Mandatory Instructions:
    - Document a step-by-step configuration and deployment process to reproduce the vulnerability for EACH vector identified in the Attack Surface report.
    - For each vector, include a functional Python script for payload or exploit generation.
    - The reproduction MUST be designed to run on localhost for testing purposes.
    - Base the style and technical depth on the examples found in the research/ directory.
    - Multi-platform Context: Use a Raspberry Pi (UNIX-based) as the ATTACKER and a Windows machine as the VICTIM, mimicking the high-fidelity scenarios in research/.
    - Technical Focus: Prioritize scenarios that enable an API endpoint, use Samba shares, or exploit network-accessible serialization sinks to demonstrate infrastructure-level RCE.
    - Content Fidelity: Ensure all paths, class names, and technical details match the actual project source code and the identified vulnerabilities. Once completed, invoke `final_answer(...)` inside your Python code.
"""

    def __init__(
        self,
        token: Optional[str] = None,
        provider: str = "huggingface",
        llm_api_url: str = "http://127.0.0.1:8181/v1",
        model_id: Optional[str] = None,
        max_steps: int = 25
    ):
        self.provider = provider.lower()
        self.llm_api_url = llm_api_url
        self.model_id = model_id
        self.max_steps = max_steps

        if self.provider == "huggingface":
            if not token:
                load_dotenv()
                self.token = os.getenv("HF_TOKEN")
            else:
                self.token = token

            if not self.token:
                raise ValueError("HF_TOKEN missing. Please provide it in .env or via argument.")
        elif self.provider == "openai":
            if not token:
                load_dotenv()
                self.token = os.getenv("HA_LLM_TOKEN") or os.getenv("OPENAI_API_KEY")
            else:
                self.token = token

            if not self.token:
                raise ValueError("HA_LLM_TOKEN or OPENAI_API_KEY missing. Please provide it in .env or via argument.")
        else:
            if not token:
                load_dotenv()
                self.token = os.getenv("HA_LLM_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("LOCAL_LLM_KEY")
            else:
                self.token = token

    def run_analysis(self, project_name: str, repo_path: str, output_stream=sys.stdout) -> str:
        """
        Initializes the AI agent and executes the security analysis workflow in two phases.
        """
        try:
            # Dynamic import of the agent
            from agent.ai_agent import SecurityAnalystAgent
            
            # Initialize agent once to preserve context if possible (though smolagents calls are atomic)
            agent = SecurityAnalystAgent(
                token=self.token,
                provider=self.provider,
                llm_api_url=self.llm_api_url,
                model_id=self.model_id,
                max_steps=self.max_steps
            )
            
            print(f"\n[+] AI Agent initialized for project: {project_name}", file=output_stream)
            print(f"================================================================================", file=output_stream)
            print(f" [>] Phase 4.1: Attack Surface Discovery", file=output_stream)
            print(f"================================================================================", file=output_stream)
            
            # Phase 4.1: Discovery
            discovery_prompt = self.PROMPT_TEMPLATE.format(project_name=project_name)
            discovery_result = agent.run(discovery_prompt)
            
            print(f"\n[+] Phase 4.1 Completed.", file=output_stream)

            # Resiliencia: verificar si ATTACK_SURFACE.md se generó; si no, inicializar desde plantilla para la Fase 4.2
            attack_surface_file = Path(project_name) / "ATTACK_SURFACE.md"
            if not attack_surface_file.is_file():
                template_file = Path("templates/attack_surface/ATTACK_SURFACE_UNIFIED_TEMPLATE.md")
                if template_file.is_file():
                    import shutil
                    attack_surface_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(template_file, attack_surface_file)
                    print(f" [!] Notice: Inicializado {attack_surface_file} desde plantilla como respaldo para la Fase 4.2.", file=output_stream)
            
            # Phase 4.2: Reproduction Guide
            print(f"================================================================================", file=output_stream)
            print(f" [>] Phase 4.2: Reproduction Guide Synthesis", file=output_stream)
            print(f"================================================================================", file=output_stream)
            
            repro_prompt = self.REPRODUCTION_PROMPT_TEMPLATE.format(project_name=project_name)
            repro_result = agent.run(repro_prompt)
            
            print(f"\n[+] Phase 4.2 Completed.", file=output_stream)
            
            return f"Strategic Analysis and Reproduction Guide generated successfully in {project_name}/."
        except Exception as e:
            return f"Error during AI Analysis phase: {str(e)}"

def main():
    """CLI logic for standalone Phase 4 execution."""
    if len(sys.argv) < 2:
        print("Usage: python modules/ai_orchestrator.py <project_name> [repo_path]")
        sys.exit(1)

    project_name = sys.argv[1]
    repo_path = sys.argv[2] if len(sys.argv) > 2 else "."
    
    try:
        orchestrator = AIOrchestrator()
        result = orchestrator.run_analysis(project_name, repo_path)
        print("\n" + "="*80)
        print(" [>] AI Phase Results Summary")
        print("="*80)
        print(result)
        print("="*80)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
