AI IT Incident Response Agent
An AI-powered IT incident analysis system built as a DEPI training project. It helps classify IT incidents, investigate them using diagnostic tools, and recommend next steps while requiring human review when the available evidence is insufficient.
Features

Incident Triage: Classifies incidents by category and severity.
AI Agents: Uses specialized agents for triage, investigation, and reporting.
Diagnostic Tools: Checks network, device, account, and VPN status.
Investigation Reports: Summarizes available evidence and recommends next steps.
Human-in-the-Loop: Routes incidents for human review when necessary.
Guardrails: Validates tool inputs and outputs and supports access-control checks.
Memory: Uses SQLite for incident-related persistence.
Local LLM: Configured to use Ollama for local model inference.
Web Interface: Provides a Gradio interface for submitting and reviewing incidents.
Automated Tests: Includes tests for project behavior and safety checks.

Technology Stack

Python
OpenAI Agents SDK
Ollama
Pydantic
Gradio
SQLite
Pytest

Project Status
The automated test suite passed 145 tests in the latest recorded run.
A sample incident was also tested through the Gradio interface. The system routed the incident to human_review because a verified root cause could not be established from the available evidence.
Running the Project
Activate the project's virtual environment, ensure the configured Ollama model is available, and start the application:
python app.py

To run the project tests from the project root:
python -m pytest Test -v

Safety and Limitations
The system should not treat an unverified diagnostic result as a confirmed root cause. Incidents with insufficient evidence or unresolved issues should be reviewed by a human IT specialist.
Project Purpose
This project demonstrates the application of AI agents, tool calling, diagnostic workflows, guardrails, and human oversight to IT incident response.
