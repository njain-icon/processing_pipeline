import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class AuditWriter:
    """
    Writes audit events to an NDJSON file.
    """
    def __init__(self, log_path: str, run_id: str, context: Dict[str, Any] = None):
        """
        Initialize the AuditWriter.

        Args:
            log_path: Path to the output NDJSON file.
            run_id: Unique identifier for the current run.
            context: Base context dictionary to include in all events.
        """
        self.log_path = log_path
        self.run_id = run_id
        self.context = context or {}
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        
        # Write start event
        self.write_event("run_start", {"timestamp": self._get_timestamp()})

    def _get_timestamp(self) -> str:
        """Get current UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def write_event(self, event_type: str, data: Dict[str, Any] = None):
        """
        Write an event to the audit log.

        Args:
            event_type: Name of the event.
            data: Dictionary of event data.
        """
        if data is None:
            data = {}

        event = {
            "event": event_type,
            "run_id": self.run_id,
            "timestamp": self._get_timestamp(),
            "data": data,
            "context": self.context
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            # Fallback to stderr if writing fails
            print(f"ERROR: Failed to write audit event: {e}")

    def _write_event(self, event_type: str, data: Dict[str, Any] = None):
        """Internal alias for write_event to match reference usage."""
        self.write_event(event_type, data)

    def run_failed(self, reason: str, details: Dict[str, Any] = None):
        """
        Log a run failure event.

        Args:
            reason: Short reason string.
            details: Optional details dictionary.
        """
        data = {"reason": reason}
        if details:
            data.update(details)
        self.write_event("run_failed", data)

    def run_completed(self, stats: Dict[str, Any] = None):
        """
        Log a run completion event.

        Args:
            stats: Optional statistics dictionary.
        """
        self.write_event("run_completed", stats)
