
import asyncio
from dataclasses import asdict, is_dataclass
from enum import Enum

import gradio as gr
from pydantic import BaseModel, ValidationError

from models import IncidentReport
from orchestration import orchestrate_incident


def to_json_safe(value):
    """Convert project models into values Gradio can display."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")

    if is_dataclass(value) and not isinstance(value, type):
        return to_json_safe(asdict(value))

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, dict):
        return {
            str(key): to_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [to_json_safe(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


async def process_incident(
    incident_id: str,
    description: str,
    affected_service: str,
):
    incident_id = (incident_id or "").strip()
    description = (description or "").strip()
    affected_service = (affected_service or "").strip()

    if not incident_id or not description or not affected_service:
        return (
            "### Missing information\nPlease fill in all three fields.",
            {},
            {},
        )

    try:
        incident = IncidentReport(
            incident_id=incident_id,
            description=description,
            affected_service=affected_service,
        )
    except ValidationError as exc:
        errors = "\n".join(
            f"- {error['loc'][0]}: {error['msg']}"
            for error in exc.errors()
        )
        return (
            f"### Invalid incident information\n{errors}",
            {},
            {},
        )

    try:
        result = await orchestrate_incident(incident)

        triage_data = to_json_safe(result.triage)
        investigation_data = to_json_safe(result.investigation)

        status = (
            "### Human review required"
            if result.human_review_required
            else "### Investigation completed"
        )

        summary = (
            f"{status}\n\n"
            f"**Incident ID:** {result.incident_id}\n\n"
            f"**Route:** `{result.route}`\n\n"
            f"**Suggested workers:** "
            f"{', '.join(result.suggested_workers) or 'None'}\n\n"
            f"**Message:** {result.message}"
        )

        return summary, triage_data, investigation_data

    except Exception:
        return (
            "### Processing error\n"
            "The incident could not be processed. "
            "Check the application terminal logs. "
            "Do not treat the incident as resolved.",
            {},
            {},
        )


def process_incident_sync(
    incident_id: str,
    description: str,
    affected_service: str,
):
    return asyncio.run(
        process_incident(
            incident_id,
            description,
            affected_service,
        )
    )


with gr.Blocks(title="AI IT Incident Response Agent") as demo:
    gr.Markdown(
        """
        # AI IT Incident Response Agent

        Submit an IT incident for classification and investigation.
        High-risk and security incidents may require human review.
        """
    )

    with gr.Row():
        incident_id = gr.Textbox(
            label="Incident ID",
            placeholder="INC-1001",
        )
        affected_service = gr.Textbox(
            label="Affected service",
            placeholder="VPN, email, laptop...",
        )

    description = gr.Textbox(
        label="Incident description",
        placeholder="Describe the IT problem...",
        lines=5,
    )

    submit_button = gr.Button(
        "Analyze incident",
        variant="primary",
    )

    status_output = gr.Markdown(label="Workflow status")

    with gr.Accordion("Triage result", open=True):
        triage_output = gr.JSON(label="Classification")

    with gr.Accordion("Investigation result", open=True):
        investigation_output = gr.JSON(label="Evidence and recommendations")

    submit_button.click(
        fn=process_incident_sync,
        inputs=[
            incident_id,
            description,
            affected_service,
        ],
        outputs=[
            status_output,
            triage_output,
            investigation_output,
        ],
    )


if __name__ == "__main__":
    demo.launch()
