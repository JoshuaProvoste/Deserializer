import os
from typing import Optional
from dotenv import load_dotenv
from smolagents import CodeAgent, InferenceClientModel, OpenAIServerModel
from .tools.fs_tools import DirectoryNavigator, FileInspector, SafeSourceReader, OpenTool
from .tools.report_tools import MarkdownManager

class SecurityAnalystAgent:
    """
    Main AI Agent responsible for performing manual code review
    to identify 0-day RCE vectors in Python projects.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        provider: str = "huggingface",
        llm_api_url: str = "http://127.0.0.1:8181/v1",
        model_id: Optional[str] = None
    ):
        self.provider = provider.lower()
        self.llm_api_url = llm_api_url

        # Initialize tools
        self.tools = [
            DirectoryNavigator(),
            FileInspector(),
            SafeSourceReader(),
            MarkdownManager(),
            OpenTool()
        ]

        # Initialize model based on provider
        if self.provider == "local":
            chosen_model = model_id or "local-model"
            self.model = OpenAIServerModel(
                model_id=chosen_model,
                api_base=self.llm_api_url,
                api_key="none"
            )
        elif self.provider == "openai":
            if not token:
                load_dotenv()
                self.token = os.getenv("HA_LLM_TOKEN") or os.getenv("OPENAI_API_KEY")
            else:
                self.token = token

            if not self.token:
                raise ValueError("HA_LLM_TOKEN or OPENAI_API_KEY must be provided in .env or as an argument when using OpenAI provider.")

            chosen_model = model_id or "gpt-4o"
            self.model = OpenAIServerModel(
                model_id=chosen_model,
                api_base=self.llm_api_url,
                api_key=self.token
            )
        else:
            if not token:
                load_dotenv()
                self.token = os.getenv("HF_TOKEN")
            else:
                self.token = token

            if not self.token:
                raise ValueError("HF_TOKEN must be provided in .env or as an argument when using Hugging Face provider.")

            chosen_model = model_id or "MiniMaxAI/MiniMax-M2.5"
            self.model = InferenceClientModel(
                model_id=chosen_model,
                token=self.token
            )

        # Initialize the agent
        # CodeAgent allows for more flexibility in navigating and analyzing code
        max_steps = 10 if self.provider == "local" else 20
        self.agent = CodeAgent(
            model=self.model,
            tools=self.tools,
            additional_authorized_imports=["os", "shutil", "json", "pathlib"],
            name="SecurityAnalystAgent",
            description="Agent specialized in 0-day vulnerability hunting and RCE manual code review.",
            max_steps=max_steps,
            verbosity_level=1
        )

    def run(self, prompt: str) -> str:
        """
        Executes the agent with the provided deterministic and dynamic prompt.
        """
        return self.agent.run(prompt)
