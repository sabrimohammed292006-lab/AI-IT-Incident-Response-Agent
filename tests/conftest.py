import pytest
from agents import set_tracing_disabled

# Tests never call OpenAI, so don't try to upload traces.
set_tracing_disabled(True)


@pytest.fixture
def db_path(tmp_path):
    """A fresh, empty tickets database for each test."""
    return tmp_path / "tickets_test.db"
