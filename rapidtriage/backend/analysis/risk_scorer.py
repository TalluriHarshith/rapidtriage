"""
RapidTriage Risk Scorer
Computes explainable, transparent 0-100 risk score and indicator breakdown.
"""

from typing import List, Dict, Any, Tuple

def calculate_case_risk(
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]]
) -> Tuple[int, str, List[Dict[str, Any]]]:
    """
    Computes overall investigation risk score from 0-100.
    Returns: (score, risk_level, list_of_indicators)
    """
    indicators = []
    total_points = 0

    # Indicator 1: AppData execution
    appdata_events = [
        e for e in events
        if any("appdata" in str(r).lower() or "user-writable" in str(r).lower() for r in e.get("risk_reasons", []))
    ]
    if appdata_events:
        points = 30
        total_points += points
        indicators.append({
            "title": "Execution from User AppData Directory",
            "points": points,
            "description": f"Executable '{appdata_events[0].get('process')}' launched from user-writable AppData location.",
            "category": "Execution"
        })

    # Indicator 2: Download-to-Execution within window
    dl_exec_events = [
        e for e in events
        if any("download" in str(r).lower() and "executed" in str(r).lower() for r in e.get("risk_reasons", []))
    ]
    if dl_exec_events or findings:
        points = 25
        total_points += points
        indicators.append({
            "title": "Download-to-Execution Temporal Proximity",
            "points": points,
            "description": "Binary executed in rapid sequence after browser download.",
            "category": "Correlation"
        })

    # Indicator 3: Immediate Outbound Network
    net_events = [
        e for e in events
        if e.get("artifact") == "network" and e.get("risk_status") == "suspicious"
    ]
    if net_events:
        points = 20
        total_points += points
        indicators.append({
            "title": "Outbound Network Activity from Suspicious Process",
            "points": points,
            "description": f"Process established direct outbound connection to {net_events[0].get('path')}.",
            "category": "Network"
        })

    # Indicator 4: USB connection
    usb_events = [e for e in events if e.get("artifact") == "usb"]
    if usb_events and total_points > 0:
        points = 10
        total_points += points
        indicators.append({
            "title": "Removable USB Storage Insertion",
            "points": points,
            "description": "Mass storage device mounted during the active investigation window.",
            "category": "Peripherals"
        })

    # Indicator 5: Child process discovery
    child_events = [
        e for e in events
        if any("child" in str(r).lower() or "discovery" in str(r).lower() for r in e.get("risk_reasons", []))
    ]
    if child_events:
        points = 15
        total_points += points
        indicators.append({
            "title": "Spawned Child Discovery / Command Line Execution",
            "points": points,
            "description": "Host discovery or command interpreter spawned by unverified process.",
            "category": "Execution"
        })

    # Cap score at 100
    final_score = min(100, max(0, total_points))

    # Determine Risk Level
    if final_score >= 76:
        risk_level = "High Investigation Priority"
    elif final_score >= 51:
        risk_level = "Elevated"
    elif final_score >= 26:
        risk_level = "Review"
    else:
        risk_level = "Low"

    return final_score, risk_level, indicators
