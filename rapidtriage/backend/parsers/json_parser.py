"""
RapidTriage JSON Parser
Validates and parses JSON files into standardized forensic event records.
"""

import json
from typing import List, Dict, Any, Tuple
from rapidtriage.backend.parsers.normalizer import normalize_timestamp, infer_artifact_type

def parse_json_bytes(content: bytes) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Parses JSON array or dictionary into standardized forensic events.
    Returns: (success, error_or_message, parsed_events)
    """
    try:
        data = json.loads(content.decode("utf-8"))
        raw_items = []
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            if "events" in data and isinstance(data["events"], list):
                raw_items = data["events"]
            elif "records" in data and isinstance(data["records"], list):
                raw_items = data["records"]
            else:
                raw_items = [data]
        else:
            return False, "Invalid JSON structure. Root element must be an array or object containing events.", []

        if not raw_items:
            return False, "JSON contains no event records.", []

        records: List[Dict[str, Any]] = []
        for idx, item in enumerate(raw_items):
            if not isinstance(item, dict):
                continue

            raw_ts = item.get("timestamp") or item.get("time") or item.get("datetime")
            if not raw_ts:
                return False, f"Record at index {idx} is missing required 'timestamp' property.", []

            display_ts, full_ts = normalize_timestamp(raw_ts)

            event_type = item.get("event_type") or item.get("event") or item.get("action") or "Activity"
            process = item.get("process") or item.get("process_name") or ""
            path = item.get("path") or item.get("file_path") or item.get("url") or item.get("file") or ""
            user = item.get("user") or item.get("username") or "Admin"
            desc = item.get("description") or f"{event_type} - {process or path}"

            artifact = infer_artifact_type(item)

            evt = {
                "id": f"EVT-{101 + idx}",
                "timestamp": display_ts,
                "raw_timestamp": full_ts,
                "artifact": artifact,
                "event_type": event_type,
                "process": process,
                "process_id": str(item.get("pid") or item.get("process_id") or "1000"),
                "path": path,
                "user": user,
                "description": desc,
                "details": {k: v for k, v in item.items() if k not in ["timestamp", "description"]},
                "risk_status": "normal",
                "risk_score": 0,
                "risk_reasons": [],
                "correlation_id": None
            }
            records.append(evt)

        return True, f"Successfully parsed {len(records)} events from JSON.", records

    except Exception as e:
        return False, f"Failed to parse JSON: {str(e)}", []
