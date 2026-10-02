/**
 * RapidTriage - Frontend API Client
 * Connects frontend views with the FastAPI backend REST endpoints.
 */

import {
  CaseDetails,
  ArtifactSourceSummary,
  StandardizedEvent,
  CorrelationFinding,
  OverallRiskSummary,
} from '../types/forensics';

export async function fetchCurrentCase(): Promise<{
  caseDetails: CaseDetails;
  artifactSummaries: ArtifactSourceSummary[];
  stats: {
    totalEvents: number;
    totalFindings: number;
    riskScore: number;
    riskLevel: string;
  };
} | null> {
  try {
    const res = await fetch('/api/cases/current');
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.warn('Backend currently initializing or unreachable:', err);
    return null;
  }
}

export async function fetchBackendTimeline(params?: {
  caseId?: string;
  artifact?: string;
  riskStatus?: string;
  correlationId?: string;
  search?: string;
}): Promise<StandardizedEvent[]> {
  try {
    const query = new URLSearchParams();
    if (params?.caseId) query.set('case_id', params.caseId);
    if (params?.artifact && params.artifact !== 'all') query.set('artifact', params.artifact);
    if (params?.riskStatus && params.riskStatus !== 'all') query.set('risk_status', params.riskStatus);
    if (params?.correlationId) query.set('correlation_id', params.correlationId);
    if (params?.search) query.set('search', params.search);

    const res = await fetch(`/api/timeline?${query.toString()}`);
    if (!res.ok) return [];
    return await res.json();
  } catch (err) {
    console.warn('Failed to fetch timeline from backend:', err);
    return [];
  }
}

export async function fetchBackendFindings(caseId?: string): Promise<{
  findings: CorrelationFinding[];
  riskSummary: OverallRiskSummary;
} | null> {
  try {
    const url = caseId ? `/api/findings?case_id=${encodeURIComponent(caseId)}` : '/api/findings';
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.warn('Failed to fetch findings from backend:', err);
    return null;
  }
}

export async function apiAcquireEvidence(): Promise<{ success: boolean; caseId: string } | null> {
  try {
    const res = await fetch('/api/cases/acquire', { method: 'POST' });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.warn('Failed to trigger evidence acquisition:', err);
    return null;
  }
}

export async function apiLoadSampleCase(): Promise<{ success: boolean; caseId: string } | null> {
  try {
    const res = await fetch('/api/cases/sample', { method: 'POST' });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.warn('Failed to load sample case:', err);
    return null;
  }
}

export async function apiUploadEvidence(file: File, temporalWindow: number = 5): Promise<any> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('temporal_window', temporalWindow.toString());

  const res = await fetch('/api/evidence/upload', {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Failed to upload evidence' }));
    throw new Error(errorData.detail || errorData.error || 'Upload error');
  }

  return await res.json();
}

export async function apiUpdateNotes(caseId: string, notes: string): Promise<boolean> {
  try {
    const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes }),
    });
    return res.ok;
  } catch (err) {
    console.warn('Failed to update case notes on backend:', err);
    return false;
  }
}
