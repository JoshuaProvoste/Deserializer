import os
from typing import Optional
from dotenv import load_dotenv
from smolagents import CodeAgent, InferenceClientModel
from .tools.fs_tools import DirectoryNavigator, FileInspector, SafeSourceReader
from .tools.report_tools import MarkdownManager

class SecurityAnalystAgent:
    """
    Main AI Agent responsible for performing manual code review
    to identify 0-day RCE vectors in Python projects.
    """

    def __init__(self, token: Optional[str] = None):
        # Load environment variables if token not provided
        if not token:
            load_dotenv()
            self.token = os.getenv("HF_TOKEN")
        else:
            self.token = token

        if not self.token:
            raise ValueError("HF_TOKEN must be provided in .env or as an argument.")

        # Initialize tools
        self.tools = [
            DirectoryNavigator(),
            FileInspector(),
            SafeSourceReader(),
            MarkdownManager()
        ]

        # Initialize model
        # Using InferenceClientModel (smolagents 1.24.0 replacement for HfApiModel)
        self.model = InferenceClientModel(
            model_id="MiniMaxAI/MiniMax-M2.5",
            token=self.token
        )

        # Initialize the agent
        # CodeAgent allows for more flexibility in navigating and analyzing code
        self.agent = CodeAgent(
            model=self.model,
            tools=self.tools,
            name="SecurityAnalystAgent",
            description="Agent specialized in 0-day vulnerability hunting and RCE manual code review.",
            max_steps=30,
            verbosity_level=1
        )

    def run(self, prompt: str) -> str:
        """
        Executes the agent with the provided deterministic and dynamic prompt.
        """
        return self.agent.run(prompt)
