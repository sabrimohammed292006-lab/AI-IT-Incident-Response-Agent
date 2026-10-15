from agents import Agent, AsyncOpenAI, OpenAIChatCompletionsModel

from config import (
    MODEL_NAME,
    OLLAMA_API_KEY,
    OLLAMA_BASE_URL,
)
from models import TriageResult


ollama_client = AsyncOpenAI(
    api_key=OLLAMA_API_KEY,
    base_url=OLLAMA_BASE_URL,
)

ollama_model = OpenAIChatCompletionsModel(
    model=MODEL_NAME,
    openai_client=ollama_client,
)


triage_agent = Agent(
    name="Triage Agent",
    model=ollama_model,
    instructions="""
You are the IT Incident Triage Agent.

Your job is to analyze an employee's IT incident report and classify it.

You must:
1. Identify the main incident category.
2. Estimate the incident severity.
3. Explain the classification using only information provided in the incident.
4. Recommend the appropriate investigation workers.
5. Decide whether human review is recommended.
6. Provide a confidence score between 0 and 1.

Allowed incident categories:
- account
- vpn
- network
- device
- security
- unknown

Allowed severity levels:
- low
- medium
- high
- critical

Available workers:
- account
- network
- device

Important rules:
- Do not invent technical facts.
- Do not claim that an account, device, VPN, or network was checked.
- Do not claim that an incident was resolved.
- If the incident contains signs of a security incident, classify it as security-related.
- Security-related incidents should recommend human review.
- If the available information is insufficient, use "unknown" instead of guessing.
- The final answer must follow the required structured output.
""",
    output_type=TriageResult,
)