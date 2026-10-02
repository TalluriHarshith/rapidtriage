/**
 * RapidTriage - Core Forensic Types & Data Contract
 * Standardized Windows endpoint artifact schema
 */

export type ForensicArtifactType = 'browser' | 'usb' | 'execution' | 'network';

export type RiskStatus = 'normal' | 'review' | 'suspicious';

export type RiskLevel = 'Low' | 'Review' | 'Elevated' | 'High Investigation Priority';

export interface RiskIndicator {
  id: string;
  name: string;
  points: number;
  description: string;
}

export interface OverallRiskSummary {
  score: number; // 0 - 100
  level: RiskLevel;
  indicators: RiskIndicator[];
  formulaExplanation: string;
}

export interface StandardizedEvent {
  event_id: string; // e.g. "EVT-101"
  timestamp: string; // Normalized ISO 8601 (YYYY-MM-DD HH:mm:ss)
  raw_timestamp?: string; // Original artifact timestamp (e.g. WebKit epoch, FILETIME)
  artifact: ForensicArtifactType; // 'browser' | 'usb' | 'execution' | 'network'
  event_type: string; // "File Downloaded", "Process Execution", "USB Device Detected", "Connection Established"
  source: string; // e.g. "Windows Prefetch", "Chrome History SQLite", "SYSTEM Registry Hive"
  user?: string; // e.g. "WIN-DC892\\Admin"
  process?: string; // e.g. "update.exe"
  pid?: number; // e.g. 4892
  file?: string; // e.g. "update.exe"
  path?: string; // e.g. "C:\\Users\\Admin\\AppData\\Roaming\\update.exe"
  device?: string; // e.g. "Kingston DataTraveler 3.0"
  serial?: string; // e.g. "0014D1237A8B"
  url?: string; // e.g. "https://cdn-download-pkg.org/update.exe"
  local_address?: string; // e.g. "192.168.1.105:49812"
  remote_address?: string; // e.g. "185.220.101.45:443"
  description: string; // Human readable event summary
  risk_status: RiskStatus; // 'normal' | 'review' | 'suspicious'
  reason?: string; // Why this event was flagged (e.g., "Process executed from a user AppData directory.")
  correlation_id?: string; // Grouping identifier (e.g., "CORR-001")
  rule_flags?: string[]; // Triggered detection rules
}

export interface ArtifactSourceSummary {
  type: ForensicArtifactType;
  title: string;
  sourceDesc: string; // e.g. "Chrome / Firefox SQLite"
  status: 'Uncollected' | 'Acquiring' | 'Extracted & Verified';
  extractedEventsCount: number;
  lastProcessedTime: string;
  sourcePath: string;
  evidenceCopyPath: string;
  fileSize: string;
  sha256: string;
  verified: boolean;
  notes: string;
}

export interface CorrelationFinding {
  correlation_id: string;
  title: string; // "Download → Execution → Network"
  startTime: string; // "10:30:18"
  endTime: string; // "10:36:10"
  timeSpan: string; // "5m 52s"
  eventsCount: number;
  eventIds: string[];
  reasons: string[];
  priority: 'Requires Investigation';
  riskScore: number; // 0 - 100
  riskLevel: RiskLevel;
  riskIndicators: RiskIndicator[];
  involvedProcess?: string;
  involvedArtifacts: ForensicArtifactType[];
}

export interface CaseDetails {
  caseId: string;
  endpoint: string;
  os: string;
  status: 'Triage Ready' | 'Evidence Extracted' | 'Requires Investigation' | 'Awaiting Acquisition';
  analyst: string;
  acquisitionTime: string;
  analysisTime?: string;
  temporalWindowMinutes: number; // e.g. 5
  isDemoData: boolean;
  investigationNotes?: string;
}

export interface CSVUploadPreview {
  fileName: string;
  fileSizeBytes: number;
  totalRows: number;
  headers: string[];
  previewRows: Array<Record<string, string>>;
  rawContent: string;
  format: 'csv' | 'json';
}

