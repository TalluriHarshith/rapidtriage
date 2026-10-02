"""
RapidTriage CSV Parser
Validates columns, parses CSV data, normalizes timestamps, and extracts event records.
"""

import io
import pandas as pd
from typing import List, Dict, Any, Tuple
from rapidtriage.backend.parsers.normalizer import normalize_timestamp, infer_artifact_type

REQUIRED_COLUMNS = ["timestamp"]
KNOWN_COLUMNS = ["timestamp", "event_type", "process", "path", "user", "file", "url", "source", "artifact", "description"]

def validate_csv_columns(df: pd.DataFrame) -> Tuple[bool, str]:
    """
    Validates CSV header. Requires at least 'timestamp' (case-insensitive).
    """
    lower_cols = [c.lower().strip() for c in df.columns]
    
    if "timestamp" not in lower_cols and "time" not in lower_cols and "datetime" not in lower_cols:
        return False, "Unable to analyze dataset. Missing column: timestamp. Expected columns can include: timestamp, event_type, process, path, user, file, url, source."
    
    return True, ""

def parse_csv_bytes(content: bytes) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Parses CSV content into standardized records.
    Returns: (success, error_or_message, parsed_events)
    """
    try:
        # Detect encoding
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            text = content.decode('latin-1')

        df = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False)
        df.columns = [c.strip() for c in df.columns]

        is_valid, err = validate_csv_columns(df)
        if not is_valid:
            return False, err, []

        # Find timestamp column
        ts_col = None
        for col in df.columns:
            if col.lower().strip() in ["timestamp", "time", "datetime"]:
                ts_col = col
                break

        records: List[Dict[str, Any]] = []
        for idx, row in df.iterrows():
            row_dict = {k.lower().strip(): (v if pd.notna(v) else "") for k, v in row.to_dict().items()}
            
            raw_ts = row_dict.get(ts_col.lower() if ts_col else "timestamp", "")
            display_ts, full_ts = normalize_timestamp(raw_ts)

            # Fallbacks and field mappings
            event_type = row_dict.get("event_type") or row_dict.get("event") or row_dict.get("action") or "Endpoint Activity"
            process = row_dict.get("process") or row_dict.get("process_name") or row_dict.get("image") or ""
            path = row_dict.get("path") or row_dict.get("file_path") or row_dict.get("url") or row_dict.get("file") or ""
            user = row_dict.get("user") or row_dict.get("username") or "Admin"
            desc = row_dict.get("description") or f"{event_type} on {process or path or 'endpoint'}"

            artifact = infer_artifact_type(row_dict)

            evt = {
                "id": f"EVT-{101 + idx}",
                "timestamp": display_ts,
                "raw_timestamp": full_ts,
                "artifact": artifact,
                "event_type": event_type,
                "process": process,
                "process_id": row_dict.get("pid") or row_dict.get("process_id") or "1000",
                "path": path,
                "user": user,
                "description": desc,
                "details": {k: v for k, v in row_dict.items() if v != "" and k not in ["timestamp", "description"]},
                "risk_status": "normal",
                "risk_score": 0,
                "risk_reasons": [],
                "correlation_id": None
            }
            records.append(evt)

        return True, f"Successfully parsed {len(records)} events from CSV.", records

    except Exception as e:
        return False, f"Failed to parse CSV: {str(e)}", []
