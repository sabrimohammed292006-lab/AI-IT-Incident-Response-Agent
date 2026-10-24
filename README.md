# 🤖 AI IT Incident Response Agent

An enterprise-grade, multi-agent AI system engineered to automate IT incident classification, triage, intelligent diagnosis, safety guardrail enforcement, and resolution workflows with a seamless Human-in-the-Loop review mechanism.

The system combines modular Python orchestration, structured data validation, local knowledge retrieval, diagnostic tools, and automated safety checks to support a structured IT incident-response workflow.

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Architecture Overview](#-architecture-overview)
3. [Core Capabilities](#-core-capabilities)
4. [Technical Specifications](#-technical-specifications)
5. [Repository Structure](#-repository-structure)
6. [Installation & Setup](#-installation--setup)
7. [Running the Application](#-running-the-application)
8. [Incident Response Workflow](#-incident-response-workflow)
9. [Engineering Safeguards](#-engineering-safeguards)
10. [Testing](#-testing)
11. [Privacy & Local Processing](#-privacy--local-processing)
12. [Main Components](#-main-components)
13. [Project Highlights](#-project-highlights)
14. [Author](#-author)
15. [Project Purpose](#-project-purpose)

---

## 🌟 Overview

The **AI IT Incident Response Agent** addresses operational bottlenecks in IT infrastructure management by automating incident triage, severity assessment, and initial technical investigation.

Traditional IT helpdesks can experience delays caused by manual ticket routing and diagnosis. This project uses modular Python orchestration, Pydantic schemas, local knowledge stores, and safety guardrails to process incoming IT incidents through a structured workflow.

The system is designed to distinguish between standard incidents that can proceed to investigation and high-risk incidents that require human review.

---

## 🏗️ Architecture Overview

The system operates through a structured pipeline that connects incident submission, validation, triage, investigation, and reporting.

```text
                         ┌─────────────────────────────────────┐
                         │          Gradio Web UI              │
                         │       Incident Submission           │
                         └──────────────────┬──────────────────┘
                                            │
                                            ▼
                         ┌─────────────────────────────────────┐
                         │     Validation & Safety Layer       │
                         │  • Input Validation                 │
                         │  • Pydantic Schemas                 │
                         │  • Safety Guardrails                │
                         └──────────────────┬──────────────────┘
                                            │
                                            ▼
                         ┌─────────────────────────────────────┐
                         │           Triage Agent              │
                         │    Severity Assessment & Routing    │
                         └──────────────┬───────────────┬──────┘
                                        │               │
                           High Risk /  │               │ Standard /
                           Security     │               │ Low-Medium
                                        ▼               ▼
                         ┌────────────────────┐   ┌───────────────────────┐
                         │   Human Review     │   │ Investigation Agent   │
                         │     Required       │   │       + RAG           │
                         └─────────┬──────────┘   └───────────┬───────────┘
                                   │                          │
                                   │                          ▼
                                   │              ┌───────────────────────┐
                                   │              │ Knowledge & Diagnostic│
                                   │              │        Tools          │
                                   │              └───────────┬───────────┘
                                   │                          │
                                   └──────────────┬───────────┘
                                                  ▼
                         ┌─────────────────────────────────────┐
                         │     Resolution / Evaluator Agent    │
                         │       Analysis & Reporting          │
                         └──────────────────┬──────────────────┘
                                            │
                                            ▼
                         ┌─────────────────────────────────────┐
                         │       Final Actionable Report       │
                         │   Diagnosis • Severity • Guidance   │
                         └─────────────────────────────────────┘
```

### Architecture Workflow

1. **Intake & Validation:** Users submit incidents through the Gradio interface in `app.py`. The input is processed through validation schemas and safety checks.

2. **Triage & Routing:** The Triage Agent assesses the incident and determines the appropriate routing path. High-risk or security-sensitive incidents are directed to `human_review`.

3. **Investigation & Diagnosis:** Standard incidents proceed to the Investigation Agent, which can use local IT knowledge and diagnostic tools to investigate potential root causes.

4. **Resolution & Reporting:** The workflow compiles the available investigation results into a structured technical report containing diagnosis and resolution guidance.

---

## ✨ Core Capabilities

- **🧠 Multi-Agent Orchestration:** Coordinates specialized agents for triage, investigation, safety validation, evaluation, and resolution.

- **🛡️ Built-in Safety & Guardrails:** Dedicated validation layers detect security risks, unauthorized access patterns, prompt injection attempts, and high-risk incident payloads.

- **👥 Human-in-the-Loop Escalation:** High-severity and security-sensitive incidents are automatically routed to `human_review` instead of being handled entirely through automated remediation.

- **📚 Local Knowledge Retrieval (RAG):** The investigation workflow queries local IT documentation and mock system data stored inside `it_support/data/`.

- **🔍 Intelligent Incident Diagnosis:** Diagnostic tools provide structured information that helps the investigation workflow identify potential root causes.

- **🖥️ Interactive Gradio Interface:** Provides a local web interface for submitting incidents and reviewing generated analysis.

- **🧪 Automated Testing:** Includes unit and integration tests using Pytest across core workflows and safety mechanisms.

- **💾 Persistent Incident Memory:** Uses SQLite to maintain incident-related data and support persistence across executions.

---

## 🛠️ Technical Specifications

| Layer | Technology | Function | Resource / Runtime |
|---|---|---|---|
| **Core Language** | Python | Application logic and orchestration | CPU |
| **UI Framework** | Gradio | Local interactive incident-response dashboard | Local HTTP Server |
| **Data Validation** | Pydantic | Structured schemas and input validation | Lightweight |
| **Incident Memory** | SQLite | Local incident persistence and memory | Disk-based |
| **Knowledge Retrieval** | Local JSON Data | IT documentation and support knowledge | Disk-based |
| **Safety Layer** | Python Guardrails | Security and high-risk validation | CPU |
| **Testing** | Pytest | Unit and integration testing | CPU |
| **Version Control** | Git / GitHub | Source control and collaboration | — |

---

## 📂 Repository Structure

```text
AI-IT-Incident-Response-Agent/
│
├── app.py
│   └── Gradio web interface and application entry point
│
├── orchestration.py
│   └── Core multi-agent orchestration workflow
│
├── config.py
│   └── System configuration and runtime settings
│
├── models.py
│   └── Pydantic models and structured data schemas
│
├── requirements.txt
│   └── Python runtime dependencies
│
├── pytest.ini
│   └── Pytest configuration
│
├── test_results.txt
│   └── Test execution results
│
├── incident_memory.db
│   └── SQLite incident memory database, if present
│
├── it_support/
│   └── IT support modules, tools, safety logic,
│       knowledge retrieval, and diagnostic utilities
│
├── tests/
│   └── Automated unit and integration tests
│
└── docs/
    └── Project documentation assets
```

---

## ⚙️ Installation & Setup

### 1. System Requirements

- Python 3.10 or higher.
- Git.
- Windows, Linux, or macOS.
- Sufficient CPU and memory to run the configured dependencies.

### 2. Clone the Repository

Clone the project from GitHub and navigate into its directory.

```bash
git clone https://github.com/sabrimohammed292006-lab/AI-IT-Incident-Response-Agent.git
cd AI-IT-Incident-Response-Agent
```

### 3. Create a Virtual Environment

**Windows — PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Dependencies

Upgrade pip and install the dependencies listed in the project.

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🚀 Running the Application

Launch the local Gradio interface using the project's entry-point file.

```bash
python app.py
```

Once the application starts, open the local URL displayed in the terminal. A typical Gradio address is:

```text
http://127.0.0.1:7860
```

The interface allows users to submit incident information and review the resulting analysis.

The exact URL and available interface features depend on the application's runtime configuration.

---

## 🔄 Incident Response Workflow

### 1. Intake & Validation

The incident is submitted through the Gradio interface.

The input passes through the application's validation and safety mechanisms before entering the main workflow.

**Relevant components:**

- `app.py`
- `models.py`
- `it_support/guardrails.py`
- `it_support/safety.py`

### 2. Triage & Routing

The Triage Agent evaluates the incident and determines its severity and routing path.

- **High-risk or security-sensitive incidents:** Routed to `human_review`.
- **Standard incidents:** Can proceed to the investigation stage according to the workflow's routing logic.

### 3. Investigation & Diagnosis

The Investigation Agent analyzes the available incident information and uses the configured knowledge and diagnostic tools.

**Relevant components:**

- `it_support/knowledge_tools.py`
- `it_support/check_tools.py`
- Local knowledge resources under `it_support/data/`

### 4. Resolution & Evaluation

The workflow evaluates the available investigation results and compiles a technical report with relevant diagnosis and resolution guidance.

The resulting report is based on the information available to the workflow.

---

## 🛡️ Engineering Safeguards

The project includes dedicated safety and validation components to support controlled incident processing.

### Security Risk Detection

The safety layer is designed to identify potentially dangerous or unauthorized access patterns and other security-sensitive inputs.

### Human Review Escalation

High-risk incidents can be routed to `human_review`, establishing a human-oversight boundary for sensitive cases.

### Input Validation

Pydantic schemas provide structured validation for incident data before it is processed by the application.

### Separation of Automation & Remediation

The workflow separates incident analysis and investigation from sensitive remediation activities. Human review is used for incidents that require additional oversight.

### Controlled Processing

The orchestration workflow coordinates the stages of the incident-response pipeline rather than treating every submitted incident as an action that should be executed automatically.

---

## 🧪 Testing

The project uses Pytest for automated testing.

Run the test suite with:

```bash
pytest -v
```

The tests are intended to verify the behavior of the application's implemented workflows and safety mechanisms.

Areas covered may include:

- Core orchestration behavior.
- Incident classification and routing.
- Validation and guardrails.
- Human-review escalation.
- Integration between workflow components.

Refer to the actual test files and execution results for the precise coverage and current test status.

---

## 🔐 Privacy & Local Processing

The project uses local components for incident processing and persistence.

- **SQLite:** Stores incident-related data in a local database.
- **Local knowledge resources:** Provide IT documentation and supporting data for the investigation workflow.
- **Gradio:** Provides a local web interface when running the application on the host machine.

Local storage does not, by itself, guarantee that every operation is offline. Network usage depends on the configured models, tools, and application code.

---

## 📁 Main Components

### `app.py`

The application's entry point, responsible for launching the Gradio web interface and supporting incident submission.

### `orchestration.py`

Coordinates the main stages of the multi-agent incident-response workflow.

### `config.py`

Contains configuration and runtime settings used by the application.

### `models.py`

Defines Pydantic models and structured schemas for incident data.

### `it_support/`

Contains supporting IT functionality, including safety checks, knowledge tools, and diagnostic utilities.

### `tests/`

Contains automated tests used to validate the implemented application behavior.

### `requirements.txt`

Lists the Python packages required to install the project dependencies.

---

## 📊 Project Highlights

| Capability | Technology / Implementation |
|---|---|
| Multi-Agent Architecture | Modular Python orchestration |
| Incident Triage | Triage and routing workflow |
| Severity Assessment | Structured incident analysis |
| Human Oversight | `human_review` routing |
| Safety Validation | Guardrails and validation modules |
| Knowledge Retrieval | Local IT knowledge resources |
| Diagnostic Support | IT support tools |
| Interactive Interface | Gradio |
| Persistent Storage | SQLite |
| Automated Testing | Pytest |
| Version Control | Git and GitHub |

---

## 👨‍💻 Author

**Sabri Mohammed**

*AI Engineering & Software Automation*

---

## 📌 Project Purpose

The **AI IT Incident Response Agent** demonstrates how multi-agent orchestration can be applied to IT operations through structured incident analysis, safety validation, diagnostic tools, local knowledge retrieval, and human oversight.

The project combines AI-oriented workflow design with software engineering practices such as:

- Modular architecture.
- Structured data validation.
- Safety engineering.
- Automated testing.
- Local data persistence.
- Tool-based investigation.
- Human-in-the-Loop review.

---
