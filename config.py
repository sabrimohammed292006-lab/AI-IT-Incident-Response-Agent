
import os

from dotenv import load_dotenv
from agents.tracing import get_trace_provider

load_dotenv()

MODEL_NAME = os.getenv(
    "MODEL_NAME",
    "qwen-local:latest",
)

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434/v1",
)

OLLAMA_API_KEY = "ollama"

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    "incident_memory.db",
)

APP_TITLE = "AI IT Incident Response Agent"

MAX_EVALUATION_ITERATIONS = 3

HUMAN_REVIEW_SEVERITIES = {"high", "critical"}

TRACING_ENABLED = False

if not TRACING_ENABLED:
    get_trace_provider().set_disabled(True)


def get_model_name() -> str:
    """Return the configured local model name."""
    return MODEL_NAME


def get_ollama_base_url() -> str:
    """Return the Ollama OpenAI-compatible API endpoint."""
    return OLLAMA_BASE_URL


def is_tracing_enabled() -> bool:
    """Return whether SDK tracing is enabled."""
    return TRACING_ENABLED
