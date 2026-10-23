
import logging
from pathlib import Path


LOG_FILE = Path("incident_workflow.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(
            LOG_FILE,
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
    force=True,
)

workflow_logger = logging.getLogger("incident_workflow")
