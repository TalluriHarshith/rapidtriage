"""
RapidTriage Normalizer
Normalizes timestamps, process names, file paths, and artifact categories.
"""

import re
from datetime import datetime
from typing import Dict, Any, Tuple

def normalize_timestamp(val: Any) -> Tuple[str, str]:
    """
    Normalizes arbitrary timestamp inputs into:
    (formatted_display_time, full_iso_or_raw)
    Handles:
    - "10:30:12"
    - "2026-10-01 10:30:12"
    - ISO strings "2026-10-01T10:30:12Z"
    - Unix epoch (seconds or milliseconds)
    """
    if val is None or val == "":
        now = datetime.utcnow()
        return now.strftime("%H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")

    val_str = str(val).strip()

    # Check for Unix epoch
    if re.match(r"^\d{10}(\.\d+)?$", val_str):
        try:
            dt = datetime.utcfromtimestamp(float(val_str))
            return dt.strftime("%H:%M:%S"), dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    if re.match(r"^\d{13}$", val_str):
        try:
            dt = datetime.utcfromtimestamp(float(val_str) / 1000.0)
            return dt.strftime("%H:%M:%S"), dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    # Already HH:MM:SS
    if re.match(r"^\d{2}:\d{2}:\d{2}$", val_str):
        return val_str, f"{datetime.utcnow().strftime('%Y-%m-%d')} {val_str}"

    # Try common datetime patterns
    patterns = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]

    for p in patterns:
        try:
            dt = datetime.strptime(val_str[:26], p)
            return dt.strftime("%H:%M:%S"), dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            continue

    # Fallback to string slice or raw
    return val_str[:8] if len(val_str) >= 8 else val_str, val_str

def infer_artifact_type(row: Dict[str, Any]) -> str:
    """Infers artifact category ('browser', 'usb', 'execution', 'network') from event properties."""
    artifact = str(row.get("artifact", "")).lower()
    if artifact in ["browser", "usb", "execution", "network"]:
        return artifact

    event_type = str(row.get("event_type", "")).lower()
    proc = str(row.get("process", "")).lower()
    path = str(row.get("path", "")).lower()
    url = str(row.get("url", "")).lower()

    if "usbstor" in path or "usb" in event_type or "device connected" in event_type or "removable" in event_type:
        return "usb"
    if "chrome" in proc or "firefox" in proc or "edge" in proc or "download" in event_type or "website" in event_type or url.startswith("http"):
        return "browser"
    if "connection" in event_type or "tcp" in event_type or ":" in path and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", path):
        return "network"
    if "prefetch" in event_type or "executed" in event_type or "process" in event_type or proc.endswith(".exe"):
        return "execution"

    return "execution"
