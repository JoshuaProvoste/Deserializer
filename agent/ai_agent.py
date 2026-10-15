import os
from typing import Optional
from dotenv import load_dotenv
from smolagents import CodeAgent, InferenceClientModel, OpenAIServerModel
from .tools.fs_tools import DirectoryNavigator, FileInspector, SafeSourceReader, OpenTool
from .tools.report_tools import MarkdownManager

class ResilientInferenceClientModel(InferenceClientModel):
    """
    Subclase resiliente de InferenceClientModel que amplía el timeout por defecto
    y aplica reintentos automáticos ante congestión o timeouts en router.huggingface.co.
    """
    def __init__(self, *args, max_retries: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_retries = max_retries

    def generate(self, *args, **kwargs):
        import time

        for attempt in range(1, self.max_retries + 1):
            try:
                return super().generate(*args, **kwargs)
            except Exception as e:
                err_str = str(e).lower()
                is_transient = (
                    "read timed out" in err_str
                    or "readtimeouterror" in err_str
                    or "timeout" in err_str
                    or "504" in err_str
                    or "503" in err_str
                    or "502" in err_str
                    or "connection error" in err_str
                )
                if not is_transient or attempt == self.max_retries:
                    raise
                wait_time = attempt * 10
                print(f"\n[!] Hugging Face API timeout o congestión detectada (intento {attempt}/{self.max_retries}). Reintentando en {wait_time}s...")
                time.sleep(wait_time)

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
        model_id: Optional[str] = None,
        max_steps: int = 25
    ):
        self.provider = provider.lower()
        self.llm_api_url = llm_api_url
        self.max_steps = max_steps

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
            if not token:
                load_dotenv()
                self.token = os.getenv("HA_LLM_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("LOCAL_LLM_KEY") or "none"
            else:
                self.token = token
            chosen_model = model_id or "local-model"
            self.model = OpenAIServerModel(
                model_id=chosen_model,
                api_base=self.llm_api_url,
                api_key=self.token
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
            hf_timeout = int(os.getenv("HF_TIMEOUT", "300"))
            self.model = ResilientInferenceClientModel(
                model_id=chosen_model,
                token=self.token,
                timeout=hf_timeout,
                max_retries=3
            )

        # Initialize the agent
        # CodeAgent allows for more flexibility in navigating and analyzing code
        self.agent = CodeAgent(
            model=self.model,
            tools=self.tools,
            additional_authorized_imports=["os", "shutil", "json", "pathlib"],
            name="SecurityAnalystAgent",
            description="Agent specialized in 0-day vulnerability hunting and RCE manual code review.",
            max_steps=self.max_steps,
            verbosity_level=1
        )

    def run(self, prompt: str) -> str:
        """
        Executes the agent with the provided deterministic and dynamic prompt.
        """
        return self.agent.run(prompt)
