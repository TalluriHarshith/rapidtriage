/**
 * RapidTriage - Forensic Analysis & Correlation Engine
 * Implements Rule 1 (AppData Execution), Rule 2 (Download to Execution),
 * Rule 3 (Temporal Correlation Chaining), Risk Score (0-100),
 * and CSV/JSON Dataset Validation & Parsing.
 */

import {
  StandardizedEvent,
  CorrelationFinding,
  RiskLevel,
  RiskIndicator,
  OverallRiskSummary,
  ForensicArtifactType,
} from '../types/forensics';

/**
 * Checks if a path is located inside any AppData user directory
 */
export function isAppDataPath(path?: string): boolean {
  if (!path) return false;
  const normalized = path.toLowerCase().replace(/\//g, '\\');
  return (
    normalized.includes('\\appdata\\roaming\\') ||
    normalized.includes('\\appdata\\local\\') ||
    normalized.includes('\\appdata\\local\\temp\\') ||
    normalized.includes('%appdata%') ||
    normalized.includes('%localappdata%')
  );
}

/**
 * Computes difference in milliseconds between two standard date-time strings
 */
export function getTimeDifferenceSeconds(timeStrA: string, timeStrB: string): number {
  const dateA = new Date(timeStrA.replace(' ', 'T') + 'Z').getTime();
  const dateB = new Date(timeStrB.replace(' ', 'T') + 'Z').getTime();
  return Math.abs(dateA - dateB) / 1000;
}

/**
 * Formats a duration in seconds to "Xm Ys"
 */
export function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  if (mins === 0) return `${secs}s`;
  return `${mins}m ${secs.toString().padStart(2, '0')}s`;
}

/**
 * Computes Risk Level from 0-100 score
 */
export function getRiskLevel(score: number): RiskLevel {
  if (score >= 75) return 'High Investigation Priority';
  if (score >= 50) return 'Elevated';
  if (score >= 25) return 'Review';
  return 'Low';
}

/**
 * Calculates transparent, explainable Investigation Risk Score (0-100)
 * Uses specified weights:
 * +30 — Execution from AppData
 * +25 — Executable shortly after browser download
 * +20 — Related network activity
 * +10 — USB activity associated with sequence
 * +15 — Additional correlated suspicious event
 */
export function calculateRiskScore(
  events: StandardizedEvent[],
  hasAppDataExec: boolean,
  hasDownloadFollowed: boolean,
  hasNetworkActivity: boolean,
  hasUsbAssociation: boolean,
  additionalSuspiciousCount: number
): {
  score: number;
  level: RiskLevel;
  indicators: RiskIndicator[];
} {
  const indicators: RiskIndicator[] = [];

  if (hasAppDataExec) {
    indicators.push({
      id: 'IND_APPDATA',
      name: 'Execution from AppData',
      points: 30,
      description: 'Process executed from user AppData directory (%AppData% / %LocalAppData%).',
    });
  }

  if (hasDownloadFollowed) {
    indicators.push({
      id: 'IND_DOWNLOAD_EXEC',
      name: 'Execution shortly after browser download',
      points: 25,
      description: 'Process execution occurred shortly after an external browser download.',
    });
  }

  if (hasNetworkActivity) {
    indicators.push({
      id: 'IND_NETWORK',
      name: 'Related network activity',
      points: 20,
      description: 'Outbound network socket initiated by executing process.',
    });
  }

  if (hasUsbAssociation) {
    indicators.push({
      id: 'IND_USB',
      name: 'USB activity associated with sequence',
      points: 10,
      description: 'Removable USB mass storage activity observed within correlation window.',
    });
  }

  if (additionalSuspiciousCount > 0) {
    indicators.push({
      id: 'IND_ADDITIONAL',
      name: 'Additional correlated suspicious event',
      points: Math.min(15, additionalSuspiciousCount * 15),
      description: 'Further unverified launch records or follow-up socket beacons detected.',
    });
  }

  const rawSum = indicators.reduce((sum, ind) => sum + ind.points, 0);
  const score = Math.min(100, Math.max(0, rawSum));
  const level = getRiskLevel(score);

  return {
    score,
    level,
    indicators,
  };
}

/**
 * Calculates overall case risk summary across all events and findings
 */
export function calculateCaseRiskSummary(
  events: StandardizedEvent[],
  findings: CorrelationFinding[]
): OverallRiskSummary {
  if (findings.length === 0) {
    // Check if there are any isolated suspicious events
    const suspiciousEvents = events.filter((e) => e.risk_status === 'suspicious');
    if (suspiciousEvents.length > 0) {
      const hasAppData = suspiciousEvents.some((e) => isAppDataPath(e.path));
      const ind: RiskIndicator[] = [];
      if (hasAppData) {
        ind.push({
          id: 'IND_APPDATA',
          name: 'Execution from AppData',
          points: 30,
          description: 'Process executed from user AppData directory.',
        });
      }
      const score = Math.min(100, ind.reduce((s, i) => s + i.points, 0));
      return {
        score,
        level: getRiskLevel(score),
        indicators: ind,
        formulaExplanation: 'Score calculated from isolated suspicious endpoint events.',
      };
    }

    return {
      score: 10,
      level: 'Low',
      indicators: [
        {
          id: 'IND_BASELINE',
          name: 'Baseline Activity',
          points: 10,
          description: 'Routine endpoint execution and network events observed with no anomalies.',
        },
      ],
      formulaExplanation: 'Baseline routine endpoint activity with no high-risk sequences identified.',
    };
  }

  // Find highest scoring finding as primary anchor, or union of all active indicators
  const highestFinding = [...findings].sort((a, b) => b.riskScore - a.riskScore)[0];

  return {
    score: highestFinding.riskScore,
    level: highestFinding.riskLevel,
    indicators: highestFinding.riskIndicators,
    formulaExplanation: `Highest priority correlation chain (${highestFinding.correlation_id}) produced a score of ${highestFinding.riskScore}/100.`,
  };
}

/**
 * Run forensic analysis pipeline across chronological events:
 * 1. Rule 1: AppData execution detection
 * 2. Rule 2: Download-to-execution temporal proximity
 * 3. Rule 3: Temporal correlation grouping into Correlation Findings with explainable Risk Score
 */
export function analyzeAndCorrelateEvents(
  rawEvents: StandardizedEvent[],
  windowMinutes: number = 5
): {
  analyzedEvents: StandardizedEvent[];
  findings: CorrelationFinding[];
  caseRiskSummary: OverallRiskSummary;
} {
  // Ensure strict chronological sort (oldest to newest)
  const sorted = [...rawEvents].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const windowSeconds = windowMinutes * 60;
  const analyzed: StandardizedEvent[] = sorted.map((evt) => ({
    ...evt,
    rule_flags: [...(evt.rule_flags || [])],
  }));

  // Step 1: Detect AppData execution (Rule 1)
  analyzed.forEach((event) => {
    if (event.artifact === 'execution' && event.path && isAppDataPath(event.path)) {
      if (!event.rule_flags?.includes('RULE_APPDATA_EXECUTION')) {
        event.rule_flags = [...(event.rule_flags || []), 'RULE_APPDATA_EXECUTION'];
      }
      event.risk_status = 'suspicious';
      if (!event.reason) {
        event.reason = 'Process executed from a user AppData directory.';
      }
    }
  });

  // Step 2: Download -> Execution correlation (Rule 2)
  const downloads = analyzed.filter(
    (e) => e.artifact === 'browser' && e.event_type.toLowerCase().includes('download')
  );

  downloads.forEach((downloadEvt) => {
    const downloadedFileName = downloadEvt.file?.toLowerCase();
    if (!downloadedFileName) return;

    // Search forward for execution of this binary within download correlation window (10 min)
    const forwardExecutions = analyzed.filter((candidate) => {
      if (candidate.artifact !== 'execution') return false;
      if (candidate.timestamp <= downloadEvt.timestamp) return false;

      const diffSec = getTimeDifferenceSeconds(downloadEvt.timestamp, candidate.timestamp);
      if (diffSec > 600) return false;

      const candidateProcess = (candidate.process || candidate.file || '').toLowerCase();
      return candidateProcess.includes(downloadedFileName) || downloadedFileName.includes(candidateProcess);
    });

    forwardExecutions.forEach((execEvt) => {
      if (!execEvt.rule_flags?.includes('RULE_DOWNLOAD_TO_EXECUTION')) {
        execEvt.rule_flags = [...(execEvt.rule_flags || []), 'RULE_DOWNLOAD_TO_EXECUTION'];
      }
      execEvt.risk_status = 'suspicious';
      execEvt.reason = 'Executable execution occurred shortly after a browser download.';
    });
  });

  // Step 3: Rule 3 - Temporal Correlation Window Grouping (Chaining related events)
  const findings: CorrelationFinding[] = [];
  let correlationCounter = 1;

  const suspiciousExecutions = analyzed.filter(
    (e) => e.artifact === 'execution' && e.risk_status === 'suspicious'
  );

  suspiciousExecutions.forEach((execEvt) => {
    const execProcessName = (execEvt.process || execEvt.file || '').toLowerCase();
    const correlationId = `CORR-${correlationCounter.toString().padStart(3, '0')}`;

    // Look for precursor downloads within window
    const precursorDownloads = analyzed.filter((candidate) => {
      if (candidate.artifact !== 'browser' || !candidate.event_type.toLowerCase().includes('download')) {
        return false;
      }
      if (candidate.timestamp > execEvt.timestamp) return false;
      const diff = getTimeDifferenceSeconds(candidate.timestamp, execEvt.timestamp);
      if (diff > windowSeconds) return false;

      const downFile = (candidate.file || '').toLowerCase();
      return execProcessName.includes(downFile) || downFile.includes(execProcessName) || downFile.endsWith('.exe');
    });

    // Look for precursor/coinciding USB events within window
    const nearbyUsb = analyzed.filter((candidate) => {
      if (candidate.artifact !== 'usb') return false;
      const diff = getTimeDifferenceSeconds(candidate.timestamp, execEvt.timestamp);
      return diff <= windowSeconds;
    });

    // Look for outbound network connections by same process shortly after
    const successorNetworks = analyzed.filter((candidate) => {
      if (candidate.artifact !== 'network') return false;
      if (candidate.timestamp < execEvt.timestamp) return false;
      const diff = getTimeDifferenceSeconds(execEvt.timestamp, candidate.timestamp);
      if (diff > windowSeconds) return false;

      const netProc = (candidate.process || '').toLowerCase();
      return netProc === execProcessName || (execEvt.pid && candidate.pid === execEvt.pid);
    });

    // Additional related execution records (UserAssist or follow-up spawn)
    const followUpEvents = analyzed.filter((candidate) => {
      if (candidate.event_id === execEvt.event_id) return false;
      if (candidate.artifact !== 'execution') return false;
      const proc = (candidate.process || '').toLowerCase();
      if (proc !== execProcessName) return false;
      const diff = getTimeDifferenceSeconds(candidate.timestamp, execEvt.timestamp);
      return diff <= windowSeconds;
    });

    const relatedEventList = [
      ...precursorDownloads,
      ...nearbyUsb,
      execEvt,
      ...successorNetworks,
      ...followUpEvents,
    ];

    // De-duplicate
    const uniqueRelatedMap = new Map<string, StandardizedEvent>();
    relatedEventList.forEach((e) => uniqueRelatedMap.set(e.event_id, e));
    const uniqueRelated = Array.from(uniqueRelatedMap.values()).sort((a, b) =>
      a.timestamp.localeCompare(b.timestamp)
    );

    if (uniqueRelated.length >= 2) {
      uniqueRelated.forEach((ev) => {
        ev.correlation_id = correlationId;
      });

      const startTime = uniqueRelated[0].timestamp.split(' ')[1] || uniqueRelated[0].timestamp;
      const endTime =
        uniqueRelated[uniqueRelated.length - 1].timestamp.split(' ')[1] ||
        uniqueRelated[uniqueRelated.length - 1].timestamp;

      const durationSec = getTimeDifferenceSeconds(
        uniqueRelated[0].timestamp,
        uniqueRelated[uniqueRelated.length - 1].timestamp
      );

      const hasAppData = isAppDataPath(execEvt.path);
      const hasDownload = precursorDownloads.length > 0;
      const hasNetwork = successorNetworks.length > 0;
      const hasUsb = nearbyUsb.length > 0;
      const additionalCount = followUpEvents.length > 0 || successorNetworks.length > 1 ? 1 : 0;

      const riskCalc = calculateRiskScore(
        uniqueRelated,
        hasAppData,
        hasDownload,
        hasNetwork,
        hasUsb,
        additionalCount
      );

      const reasons: string[] = [];
      if (hasAppData) {
        reasons.push('AppData execution');
      }
      if (hasDownload) {
        reasons.push('Execution followed download');
      }
      if (hasNetwork) {
        reasons.push('Network activity followed execution');
      }
      if (hasUsb) {
        reasons.push('USB activity in proximity');
      }

      findings.push({
        correlation_id: correlationId,
        title: 'Download → Execution → Network',
        startTime,
        endTime,
        timeSpan: formatDuration(durationSec),
        eventsCount: uniqueRelated.length,
        eventIds: uniqueRelated.map((e) => e.event_id),
        reasons,
        priority: 'Requires Investigation',
        riskScore: riskCalc.score,
        riskLevel: riskCalc.level,
        riskIndicators: riskCalc.indicators,
        involvedProcess: execEvt.process,
        involvedArtifacts: Array.from(new Set(uniqueRelated.map((e) => e.artifact))),
      });

      correlationCounter++;
    }
  });

  const caseRiskSummary = calculateCaseRiskSummary(analyzed, findings);

  return {
    analyzedEvents: analyzed,
    findings,
    caseRiskSummary,
  };
}

/**
 * Deterministic SHA-256 simulator for read-only integrity verification
 */
export async function computeSha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Robust CSV line splitter that respects quoted strings
 */
function parseCSVLine(line: string): string[] {
  const values: string[] = [];
  let currentValue = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        currentValue += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(currentValue.trim());
      currentValue = '';
    } else {
      currentValue += char;
    }
  }
  values.push(currentValue.trim());
  return values;
}

/**
 * Normalizes user-provided timestamp into standard YYYY-MM-DD HH:mm:ss format
 */
export function normalizeTimestampString(raw: string): string {
  if (!raw) return '2026-10-02 00:00:00';
  const trimmed = raw.trim();

  // If already standard YYYY-MM-DD HH:mm:ss
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)) {
    return trimmed;
  }

  // If ISO 8601 with T
  if (trimmed.includes('T')) {
    const replaced = trimmed.replace('T', ' ').substring(0, 19);
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(replaced)) {
      return replaced;
    }
  }

  // If only time provided: HH:mm:ss -> prepend default date 2026-10-02
  if (/^\d{2}:\d{2}:\d{2}$/.test(trimmed)) {
    return `2026-10-02 ${trimmed}`;
  }

  // Attempt Date parse
  const parsed = new Date(trimmed);
  if (!isNaN(parsed.getTime())) {
    return parsed.toISOString().replace('T', ' ').substring(0, 19);
  }

  return trimmed;
}

/**
 * Validates and extracts records from raw CSV or JSON text
 */
export function validateAndParseDataset(
  content: string,
  fileName: string
): {
  success: boolean;
  error?: string;
  headers: string[];
  records: Array<Record<string, string>>;
} {
  const isJSON = fileName.toLowerCase().endsWith('.json') || content.trim().startsWith('[');

  if (isJSON) {
    try {
      const parsed = JSON.parse(content);
      if (!Array.isArray(parsed) || parsed.length === 0) {
        return {
          success: false,
          error: 'JSON must contain an array of event objects.',
          headers: [],
          records: [],
        };
      }

      // Check required field
      const first = parsed[0];
      const headers = Object.keys(first);
      const hasTimestamp = headers.some((h) => h.toLowerCase() === 'timestamp');

      if (!hasTimestamp) {
        return {
          success: false,
          error: 'Missing required column: timestamp. Expected columns can include: timestamp, event_type, process, path, user, file, url, source',
          headers,
          records: [],
        };
      }

      const records = parsed.map((item) => {
        const rec: Record<string, string> = {};
        Object.entries(item).forEach(([k, v]) => {
          rec[k] = v !== null && v !== undefined ? String(v) : '';
        });
        return rec;
      });

      return {
        success: true,
        headers,
        records,
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Invalid JSON syntax: ${err?.message || 'Could not parse JSON file.'}`,
        headers: [],
        records: [],
      };
    }
  }

  // CSV Parsing
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) {
    return {
      success: false,
      error: 'CSV file must contain a header row and at least one data row.',
      headers: [],
      records: [],
    };
  }

  const rawHeaders = parseCSVLine(lines[0]);
  const normalizedHeaders = rawHeaders.map((h) => h.toLowerCase().replace(/['"]/g, ''));

  // Validate required column: timestamp
  const timestampIndex = normalizedHeaders.findIndex(
    (h) => h === 'timestamp' || h === 'time' || h === 'datetime'
  );

  if (timestampIndex === -1) {
    return {
      success: false,
      error: 'Missing column: timestamp. Expected columns can include: timestamp, event_type, process, path, user, file, url, source',
      headers: rawHeaders,
      records: [],
    };
  }

  const records: Array<Record<string, string>> = [];
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    const rec: Record<string, string> = {};
    rawHeaders.forEach((headerName, idx) => {
      rec[headerName] = values[idx] || '';
    });
    records.push(rec);
  }

  return {
    success: true,
    headers: rawHeaders,
    records,
  };
}

/**
 * Converts validated records into StandardizedEvent models
 */
export function convertRecordsToStandardizedEvents(
  records: Array<Record<string, string>>
): StandardizedEvent[] {
  return records.map((rec, index) => {
    const lowerKeys: Record<string, string> = {};
    Object.entries(rec).forEach(([k, v]) => {
      lowerKeys[k.toLowerCase()] = v;
    });

    const rawTime =
      lowerKeys['timestamp'] || lowerKeys['time'] || lowerKeys['datetime'] || '10:00:00';
    const normalizedTime = normalizeTimestampString(rawTime);

    // Infer artifact type
    let artifact: ForensicArtifactType = 'execution';
    const explicitArtifact = lowerKeys['artifact']?.toLowerCase();
    const eventType = lowerKeys['event_type'] || lowerKeys['event'] || 'Endpoint Event';
    const process = lowerKeys['process'] || lowerKeys['proc'] || '';
    const path = lowerKeys['path'] || lowerKeys['filepath'] || '';
    const url = lowerKeys['url'] || '';
    const device = lowerKeys['device'] || lowerKeys['usb'] || '';
    const localAddr = lowerKeys['local_address'] || lowerKeys['local_ip'] || '';
    const remoteAddr = lowerKeys['remote_address'] || lowerKeys['remote_ip'] || '';

    if (explicitArtifact && ['browser', 'usb', 'execution', 'network'].includes(explicitArtifact)) {
      artifact = explicitArtifact as ForensicArtifactType;
    } else if (url || eventType.toLowerCase().includes('download') || eventType.toLowerCase().includes('browser')) {
      artifact = 'browser';
    } else if (device || eventType.toLowerCase().includes('usb') || path.toLowerCase().startsWith('e:\\')) {
      artifact = 'usb';
    } else if (remoteAddr || localAddr || eventType.toLowerCase().includes('connect') || eventType.toLowerCase().includes('socket')) {
      artifact = 'network';
    } else {
      artifact = 'execution';
    }

    const description =
      lowerKeys['description'] ||
      lowerKeys['desc'] ||
      (process ? `${process} - ${eventType}` : eventType);

    return {
      event_id: lowerKeys['event_id'] || `EVT-${(100 + index + 1).toString()}`,
      timestamp: normalizedTime,
      raw_timestamp: rawTime,
      artifact,
      event_type: eventType,
      source: lowerKeys['source'] || `${artifact.toUpperCase()} Artifact Extractor`,
      user: lowerKeys['user'] || lowerKeys['username'] || 'WIN-DC892\\Admin',
      process: process || undefined,
      pid: lowerKeys['pid'] ? parseInt(lowerKeys['pid'], 10) : undefined,
      file: lowerKeys['file'] || (process ? process : undefined),
      path: path || undefined,
      device: device || undefined,
      serial: lowerKeys['serial'] || undefined,
      url: url || undefined,
      local_address: localAddr || undefined,
      remote_address: remoteAddr || undefined,
      description,
      risk_status: 'normal',
      rule_flags: [],
    };
  });
}

/**
 * Standard Sample CSV content ready for user download & demonstration
 */
export const SAMPLE_CSV_CONTENT = `timestamp,artifact,event_type,process,path,user,file,url,local_address,remote_address,device,description
2026-10-02 10:28:44,browser,Website Visited,chrome.exe,,WIN-DC892\\Admin,,https://learn.microsoft.com/en-us/sysinternals/,,,Visited Microsoft Sysinternals documentation
2026-10-02 10:29:15,execution,Process Execution,msedge.exe,C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe,WIN-DC892\\Admin,msedge.exe,,,,msedge.exe executed from Program Files
2026-10-02 10:30:12,browser,Website Visited,chrome.exe,,WIN-DC892\\Admin,,https://software-dist-cdn.net/portal/update.php,,,Visited external download portal: software-dist-cdn.net
2026-10-02 10:30:18,browser,File Downloaded,chrome.exe,C:\\Users\\Admin\\Downloads\\update.exe,WIN-DC892\\Admin,update.exe,https://software-dist-cdn.net/files/update.exe,,,File downloaded: update.exe
2026-10-02 10:32:05,network,Connection Established,svchost.exe,,NT AUTHORITY\\SYSTEM,,,,192.168.1.105:54210,192.168.1.1:53,,DNS resolution query via svchost.exe
2026-10-02 10:34:10,execution,Process Execution,explorer.exe,C:\\Windows\\explorer.exe,WIN-DC892\\Admin,explorer.exe,,,,Windows Explorer interactive folder access
2026-10-02 10:35:20,usb,USB Device Detected,,,SYSTEM,,,,,Kingston DataTraveler 3.0,USB device detected: Kingston DataTraveler 3.0 (Drive E:)
2026-10-02 10:36:02,execution,Process Execution,update.exe,C:\\Users\\Admin\\AppData\\Roaming\\update.exe,WIN-DC892\\Admin,update.exe,,,,update.exe executed from AppData directory
2026-10-02 10:36:10,network,Connection Established,update.exe,,WIN-DC892\\Admin,,192.168.1.105:49812,185.220.101.45:443,,,update.exe: Outbound HTTPS connection established to 185.220.101.45:443
2026-10-02 10:37:15,execution,UserAssist Launch Recorded,update.exe,C:\\Users\\Admin\\AppData\\Roaming\\update.exe,WIN-DC892\\Admin,update.exe,,,,UserAssist recorded execution count increment for update.exe
2026-10-02 10:38:00,network,Connection Established,update.exe,,WIN-DC892\\Admin,,192.168.1.105:49818,185.220.101.45:443,,,update.exe: Secondary outbound socket established to 185.220.101.45:443
2026-10-02 10:41:22,browser,Website Visited,chrome.exe,,WIN-DC892\\Admin,,https://portal.office.com/landing,,,Normal user browsing: Office 365 portal
2026-10-02 10:43:10,usb,USB Volume Unmounted,,,SYSTEM,,,,,Kingston DataTraveler 3.0,USB storage volume dismounted`;

