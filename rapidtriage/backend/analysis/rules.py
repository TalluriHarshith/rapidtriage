"""
RapidTriage Forensic Detection Rules
Rule 1: AppData Execution
Rule 2: Download to Execution within temporal threshold
Rule 3: Network connection from executed binary
Rule 4: Child discovery / command line execution
Rule 5: USB storage temporal proximity
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

def parse_time_seconds(time_str: str) -> Optional[float]:
    """Parses HH:MM:SS or full ISO datetime to seconds from midnight or epoch."""
    if not time_str:
        return None
    time_str = str(time_str).strip()
    # If HH:MM:SS
    match = re.match(r"^(\d{2}):(\d{2}):(\d{2})$", time_str)
    if match:
        h, m, s = map(int, match.groups())
        return h * 3600 + m * 60 + s
    
    # Try ISO
    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        pass
    return None

def check_appdata_execution(event: Dict[str, Any]) -> Tuple[bool, str, int]:
    """
    Rule 1: Detects process execution from AppData or Temp directories.
    Returns: (is_triggered, explanation, score_contribution)
    """
    if event.get("artifact") != "execution" and "executed" not in event.get("event_type", "").lower():
        return False, "", 0

    path = str(event.get("path", "")).lower()
    process = str(event.get("process", "")).lower()

    suspicious_paths = [
        r"\appdata\local\temp",
        r"\appdata\roaming",
        r"\appdata\local",
        r"/tmp",
        r"/var/tmp",
        r"users\public",
        r"windows\temp"
    ]

    for sp in suspicious_paths:
        if sp in path or sp in process:
            return (
                True,
                f"Binary '{event.get('process')}' executed from user-writable directory ({event.get('path')})",
                30
            )

    return False, "", 0

def check_download_to_execution(
    download_event: Dict[str, Any],
    exec_event: Dict[str, Any],
    threshold_minutes: int = 5
) -> Tuple[bool, str, int, float]:
    """
    Rule 2: Detects process executed shortly after a browser download event.
    """
    dl_time = parse_time_seconds(download_event.get("timestamp"))
    ex_time = parse_time_seconds(exec_event.get("timestamp"))

    if dl_time is None or ex_time is None:
        return False, "", 0, 0

    diff_seconds = ex_time - dl_time
    if 0 <= diff_seconds <= (threshold_minutes * 60):
        # Match filenames or paths
        dl_file = str(download_event.get("path") or download_event.get("details", {}).get("file", "")).lower()
        ex_proc = str(exec_event.get("process") or exec_event.get("path", "")).lower()

        # Check if process name is in download path or vice-versa
        file_base = dl_file.replace("\\", "/").split("/")[-1].replace(".exe", "")
        proc_base = ex_proc.replace("\\", "/").split("/")[-1].replace(".exe", "")

        matches = (file_base and file_base in proc_base) or (proc_base and proc_base in file_base) or diff_seconds <= 180

        if matches:
            mins = int(diff_seconds // 60)
            secs = int(diff_seconds % 60)
            time_span_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            return (
                True,
                f"Process executed {time_span_str} after browser download",
                25,
                diff_seconds
            )

    return False, "", 0, 0

def check_network_after_execution(
    exec_event: Dict[str, Any],
    net_event: Dict[str, Any],
    threshold_seconds: int = 300
) -> Tuple[bool, str, int]:
    """
    Rule 3: Detects outbound network connection shortly following binary execution.
    """
    ex_time = parse_time_seconds(exec_event.get("timestamp"))
    net_time = parse_time_seconds(net_event.get("timestamp"))

    if ex_time is None or net_time is None:
        return False, "", 0

    diff = net_time - ex_time
    if 0 <= diff <= threshold_seconds:
        # Check same process or PID
        ex_p = str(exec_event.get("process", "")).lower()
        net_p = str(net_event.get("process", "")).lower()
        if ex_p and (ex_p in net_p or net_p in ex_p):
            return (
                True,
                f"Process '{exec_event.get('process')}' initiated outbound network connection {int(diff)}s after launch",
                20
            )

    return False, "", 0
