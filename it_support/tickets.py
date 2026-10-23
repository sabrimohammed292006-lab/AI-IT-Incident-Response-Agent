"""create_incident_ticket: stores incident tickets in SQLite.

This is NOT a Function Tool on purpose. Only the Python workflow
(workflow.finalize_incident) calls it, after the safety checks ran.
Agents can never create, change or close tickets by themselves.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .safety import employee_exists, is_it_staff
from .schemas import Category, Finding, Severity, ToolError, utc_now
from .validators import normalize_employee_id

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "tickets.db"
TicketStatus = Literal["open", "pending_human_review", "closed"]
OPEN_STATUSES = ("open", "pending_human_review")
MAX_SUMMARY_LENGTH = 500

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def get_db_path(db_path: str | Path | None = None) -> Path:
    return Path(db_path or os.environ.get("IT_TICKETS_DB") or DEFAULT_DB_PATH)


class TicketRequest(BaseModel):
    """Everything needed to open a ticket. Built by the workflow, not by an Agent."""

    requester_id: str
    employee_id: str | None = None
    category: Category
    severity: Severity
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    root_cause: str | None = None
    recommended_steps: list[str] = Field(default_factory=list)
    needs_human_review: bool
    escalation_reasons: list[str] = Field(default_factory=list)
    linked_outage_id: str | None = None

    @field_validator("summary")
    @classmethod
    def clean_summary(cls, v: str) -> str:
        v = _CONTROL_CHARS.sub("", v).strip()
        if not v:
            raise ValueError("Summary must not be empty.")
        return v[:MAX_SUMMARY_LENGTH]


class TicketResult(BaseModel):
    success: bool
    ticket_id: str | None = None
    status: TicketStatus | None = None
    duplicate: bool = False
    error: ToolError | None = None


def init_db(db_path: str | Path | None = None) -> Path:
    path = get_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                employee_id TEXT,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                root_cause TEXT,
                findings TEXT NOT NULL,
                recommended_steps TEXT NOT NULL,
                needs_human_review INTEGER NOT NULL,
                escalation_reasons TEXT NOT NULL,
                linked_outage_id TEXT,
                closed_by TEXT
            )
            """
        )
    return path


def _fail(code: str, message: str) -> TicketResult:
    return TicketResult(success=False, error=ToolError(code=code, message=message))


def create_incident_ticket(request: TicketRequest | dict,
                           db_path: str | Path | None = None) -> TicketResult:
    """Validate, check permissions, prevent duplicates, then save the ticket."""
    try:
        req = request if isinstance(request, TicketRequest) else TicketRequest.model_validate(request)
    except Exception as exc:
        return _fail("INVALID_INPUT", f"Invalid ticket data: {exc}")

    requester = normalize_employee_id(req.requester_id)
    if requester is None or not employee_exists(requester):
        return _fail("UNAUTHORIZED", "Requester could not be verified as an employee.")

    employee = None
    if req.employee_id is not None:
        employee = normalize_employee_id(req.employee_id)
        if employee is None or not employee_exists(employee):
            return _fail("NOT_FOUND", f"Employee '{req.employee_id}' does not exist.")
        if employee != requester and not is_it_staff(requester):
            return _fail("UNAUTHORIZED",
                         f"{requester} cannot open a ticket for another employee ({employee}).")

    status: TicketStatus = "pending_human_review" if req.needs_human_review else "open"

    try:
        path = init_db(db_path)
        with closing(sqlite3.connect(path)) as conn, conn:
            # Duplicate check: same outage, or same employee + category still open.
            placeholders = ",".join("?" * len(OPEN_STATUSES))
            if req.linked_outage_id:
                row = conn.execute(
                    f"SELECT ticket_id, status FROM tickets WHERE linked_outage_id = ? "
                    f"AND status IN ({placeholders}) ORDER BY id LIMIT 1",
                    (req.linked_outage_id, *OPEN_STATUSES)).fetchone()
            elif employee:
                row = conn.execute(
                    f"SELECT ticket_id, status FROM tickets WHERE employee_id = ? AND category = ? "
                    f"AND status IN ({placeholders}) ORDER BY id LIMIT 1",
                    (employee, req.category, *OPEN_STATUSES)).fetchone()
            else:
                row = None
            if row:
                return TicketResult(success=True, ticket_id=row[0], status=row[1], duplicate=True)

            now = utc_now()
            cur = conn.execute(
                """INSERT INTO tickets (created_at, updated_at, requester_id, employee_id, category,
                   severity, status, summary, root_cause, findings, recommended_steps,
                   needs_human_review, escalation_reasons, linked_outage_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (now, now, requester, employee, req.category, req.severity, status, req.summary,
                 req.root_cause,
                 json.dumps([f.model_dump() for f in req.findings], ensure_ascii=False),
                 json.dumps(req.recommended_steps, ensure_ascii=False),
                 int(req.needs_human_review),
                 json.dumps(req.escalation_reasons, ensure_ascii=False),
                 req.linked_outage_id),
            )
            ticket_id = f"INC-{now[:10].replace('-', '')}-{cur.lastrowid:04d}"
            conn.execute("UPDATE tickets SET ticket_id = ? WHERE id = ?", (ticket_id, cur.lastrowid))
    except sqlite3.Error as exc:
        return _fail("DATA_UNAVAILABLE", f"Ticket database error: {type(exc).__name__}.")

    return TicketResult(success=True, ticket_id=ticket_id, status=status)


def get_ticket(ticket_id: str, db_path: str | Path | None = None) -> dict | None:
    path = init_db(db_path)
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if row is None:
        return None
    ticket = dict(row)
    for key in ("findings", "recommended_steps", "escalation_reasons"):
        ticket[key] = json.loads(ticket[key])
    ticket["needs_human_review"] = bool(ticket["needs_human_review"])
    return ticket


def list_tickets(status: str | None = None, db_path: str | Path | None = None) -> list[dict]:
    path = init_db(db_path)
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        if status:
            rows = conn.execute("SELECT ticket_id, created_at, employee_id, category, severity, "
                                "status, summary FROM tickets WHERE status = ? ORDER BY id DESC",
                                (status,)).fetchall()
        else:
            rows = conn.execute("SELECT ticket_id, created_at, employee_id, category, severity, "
                                "status, summary FROM tickets ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def close_ticket(ticket_id: str, closed_by: str, *, actor: Literal["human", "agent"] = "agent",
                 db_path: str | Path | None = None) -> TicketResult:
    """Close a ticket. Only a human IT staff member can do this, never an Agent."""
    if actor != "human":
        return _fail("UNAUTHORIZED", "Agents are not allowed to close tickets.")
    if not is_it_staff(closed_by):
        return _fail("UNAUTHORIZED", f"{closed_by} is not IT staff and cannot close tickets.")
    ticket = get_ticket(ticket_id, db_path)
    if ticket is None:
        return _fail("NOT_FOUND", f"Ticket {ticket_id} not found.")
    if ticket["status"] == "closed":
        return TicketResult(success=True, ticket_id=ticket_id, status="closed")
    path = get_db_path(db_path)
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("UPDATE tickets SET status = 'closed', closed_by = ?, updated_at = ? "
                     "WHERE ticket_id = ?", (normalize_employee_id(closed_by), utc_now(), ticket_id))
    return TicketResult(success=True, ticket_id=ticket_id, status="closed")
