"""
RapidTriage Temporal Correlator
Chains standardized events across artifact categories within a configurable time window.
"""

from typing import List, Dict, Any, Tuple
from rapidtriage.backend.analysis.rules import (
    parse_time_seconds,
    check_appdata_execution,
    check_download_to_execution,
    check_network_after_execution
)

def run_correlation(
    events: List[Dict[str, Any]],
    temporal_window_minutes: int = 5
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Performs multi-artifact temporal correlation.
    Returns: (updated_events_with_correlation_and_risk, findings_list)
    """
    # Sort events chronologically by timestamp
    def get_sort_key(ev):
        t = parse_time_seconds(ev.get("timestamp"))
        return t if t is not None else 0

    sorted_events = sorted(events, key=get_sort_key)
    findings = []
    corr_counter = 1

    # First pass: identify AppData executions
    appdata_execs = []
    for ev in sorted_events:
        is_appdata, reason, score = check_appdata_execution(ev)
        if is_appdata:
            ev["risk_status"] = "suspicious"
            ev["risk_score"] = max(ev.get("risk_score", 0), score + 50)
            if reason not in ev.get("risk_reasons", []):
                ev.setdefault("risk_reasons", []).append(reason)
            appdata_execs.append(ev)

    # Second pass: Correlate downloads, executions, network connections
    used_event_ids = set()

    for app_exec in appdata_execs:
        corr_id = f"CORR-{corr_counter:03d}"
        corr_events = [app_exec]
        finding_reasons = list(app_exec.get("risk_reasons", []))

        # Look for preceding downloads
        for ev in sorted_events:
            if ev["id"] in used_event_ids:
                continue
            is_dl = ev.get("artifact") == "browser" and ("download" in ev.get("event_type", "").lower() or "file" in ev.get("event_type", "").lower())
            if is_dl:
                is_dl_match, dl_reason, dl_score, diff = check_download_to_execution(ev, app_exec, temporal_window_minutes)
                if is_dl_match:
                    ev["correlation_id"] = corr_id
                    ev["risk_status"] = "review"
                    ev["risk_score"] = max(ev.get("risk_score", 0), 45)
                    if dl_reason not in ev.get("risk_reasons", []):
                        ev.setdefault("risk_reasons", []).append(dl_reason)
                    corr_events.append(ev)
                    finding_reasons.append(dl_reason)
                    used_event_ids.add(ev["id"])

        # Look for succeeding network connections or child process executions
        for ev in sorted_events:
            if ev["id"] in used_event_ids:
                continue
            is_net = ev.get("artifact") == "network" or "connection" in ev.get("event_type", "").lower()
            if is_net:
                is_net_match, net_reason, net_score = check_network_after_execution(app_exec, ev)
                if is_net_match:
                    ev["correlation_id"] = corr_id
                    ev["risk_status"] = "suspicious"
                    ev["risk_score"] = max(ev.get("risk_score", 0), 85)
                    if net_reason not in ev.get("risk_reasons", []):
                        ev.setdefault("risk_reasons", []).append(net_reason)
                    corr_events.append(ev)
                    finding_reasons.append(net_reason)
                    used_event_ids.add(ev["id"])

            # Check child discovery execution (cmd.exe, whoami, etc.)
            is_child = (
                ev.get("artifact") == "execution"
                and ev["id"] != app_exec["id"]
                and (
                    "whoami" in ev.get("path", "")
                    or "cmd.exe" in ev.get("process", "")
                    or str(ev.get("details", {}).get("parent_pid")) == str(app_exec.get("process_id"))
                )
            )
            if is_child:
                ev["correlation_id"] = corr_id
                ev["risk_status"] = "suspicious"
                ev["risk_score"] = max(ev.get("risk_score", 0), 80)
                reason = f"Spawned child command line discovery ({ev.get('process')})"
                if reason not in ev.get("risk_reasons", []):
                    ev.setdefault("risk_reasons", []).append(reason)
                corr_events.append(ev)
                finding_reasons.append(reason)
                used_event_ids.add(ev["id"])

        if len(corr_events) > 1:
            app_exec["correlation_id"] = corr_id
            used_event_ids.add(app_exec["id"])

            # Calculate time span
            sorted_corr = sorted(corr_events, key=get_sort_key)
            start_t = sorted_corr[0]["timestamp"]
            end_t = sorted_corr[-1]["timestamp"]
            
            s_sec = parse_time_seconds(start_t) or 0
            e_sec = parse_time_seconds(end_t) or 0
            diff_sec = max(0, int(e_sec - s_sec))
            time_span_str = f"{diff_sec // 60}m {diff_sec % 60}s" if diff_sec >= 60 else f"{diff_sec}s"

            finding = {
                "id": f"FND-{corr_counter:03d}",
                "correlation_id": corr_id,
                "title": f"Download followed by AppData Execution and Network Activity ({app_exec.get('process')})",
                "description": f"Standardized triage detected {len(corr_events)} correlated endpoint events: binary downloaded, launched from user AppData path, followed by network or discovery actions within {time_span_str}.",
                "risk_score": 85,
                "priority": "High Priority",
                "start_time": start_t,
                "end_time": end_t,
                "time_span": time_span_str,
                "reasons": list(dict.fromkeys(finding_reasons)), # unique reasons
                "event_ids": [e["id"] for e in sorted_corr]
            }
            findings.append(finding)
            corr_counter += 1

    return sorted_events, findings
