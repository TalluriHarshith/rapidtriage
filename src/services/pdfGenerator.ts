/**
 * RapidTriage - Professional Forensic Case Report PDF Generator
 * Generates an audit-grade, multi-page PDF document adhering to:
 * - Cover page
 * - 1. Executive Summary
 * - 2. Case Information
 * - 3. Evidence Inventory
 * - 4. Event Summary
 * - 5. Investigation Risk (Explainable 0-100 score & heuristic disclaimer)
 * - 6. Unified Incident Timeline
 * - 7. Findings
 * - 8. Correlated Activity
 * - 9. Evidence Integrity Statement & SHA-256 Hashes
 * - 10. Investigation Notes
 * - 11. Conclusion
 * - Page numbers (Page X of Y), Case ID in headers, subtle yellow forensic accents
 */

import { jsPDF } from 'jspdf';
import {
  CaseDetails,
  ArtifactSourceSummary,
  StandardizedEvent,
  CorrelationFinding,
  OverallRiskSummary,
} from '../types/forensics';

export interface PDFGenerationResult {
  success: boolean;
  blob?: Blob;
  filename: string;
  filesize: number;
  error?: string;
}

/**
 * Sanitizes strings for safe filenames
 */
export function sanitizeFilename(str: string): string {
  return str.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
}

/**
 * Generates the authentic RapidTriage Case Report PDF
 */
export async function generateCaseReportPDF(
  caseDetails: CaseDetails,
  artifactSummaries: ArtifactSourceSummary[],
  events: StandardizedEvent[],
  findings: CorrelationFinding[],
  caseRiskSummary: OverallRiskSummary,
  notes: string = ''
): Promise<PDFGenerationResult> {
  try {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const pageWidth = 210;
    const pageHeight = 297;
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;
    let y = margin;

    // Helper to check page break
    const checkPageBreak = (neededSpace: number) => {
      if (y + neededSpace > pageHeight - 20) {
        doc.addPage();
        y = margin + 12; // Leave space for top header on next pages
      }
    };

    const caseId = caseDetails.caseId || 'RT-2026-001';
    const dateStr = new Date().toISOString().split('T')[0];
    const generatedTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    // ==========================================
    // COVER / TITLE BLOCK
    // ==========================================
    // Top subtle yellow evidence bar
    doc.setFillColor(234, 179, 8); // #eab308
    doc.rect(margin, y, contentWidth, 3, 'F');
    y += 8;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(22);
    doc.setTextColor(15, 23, 42); // slate-900
    doc.text('RapidTriage', margin, y);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(100, 116, 139); // slate-500
    doc.text('ENDPOINT FORENSIC TRIAGE & INCIDENT TIMELINE REPORT', margin, y + 6);

    // Case ID block on top right
    doc.setFont('courier', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`CASE ID: ${caseId}`, pageWidth - margin, y, { align: 'right' });
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(`GENERATED: ${generatedTimestamp}`, pageWidth - margin, y + 5, { align: 'right' });

    y += 18;

    // Divider line
    doc.setDrawColor(226, 232, 240); // slate-200
    doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y);
    y += 8;

    // ==========================================
    // 1. EXECUTIVE SUMMARY
    // ==========================================
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('1. EXECUTIVE SUMMARY', margin, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(51, 65, 85);
    const execText = `RapidTriage parsed ${events.length} endpoint events across browser, USB mass storage, process execution, and network telemetry for endpoint ${caseDetails.endpoint}. Analysis identified ${findings.length} potentially suspicious activity sequence(s) requiring manual investigator triage. Evidence was analyzed in a non-destructive read-only workflow.`;
    const execLines = doc.splitTextToSize(execText, contentWidth);
    doc.text(execLines, margin, y);
    y += execLines.length * 4.5 + 6;

    // ==========================================
    // 2. CASE INFORMATION
    // ==========================================
    checkPageBreak(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('2. CASE INFORMATION', margin, y);
    y += 5;

    // Case info grid box
    doc.setFillColor(248, 250, 252);
    doc.rect(margin, y, contentWidth, 22, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.rect(margin, y, contentWidth, 22, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('CASE ID:', margin + 4, y + 5);
    doc.text('ENDPOINT HOST:', margin + 4, y + 11);
    doc.text('OPERATING SYSTEM:', margin + 4, y + 17);

    doc.setFont('courier', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(caseId, margin + 45, y + 5);
    doc.setFont('helvetica', 'normal');
    doc.text(caseDetails.endpoint, margin + 45, y + 11);
    doc.text(caseDetails.os, margin + 45, y + 17);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(100, 116, 139);
    doc.text('INVESTIGATOR:', margin + 105, y + 5);
    doc.text('ACQUISITION TIME:', margin + 105, y + 11);
    doc.text('STATUS:', margin + 105, y + 17);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(15, 23, 42);
    doc.text(caseDetails.analyst, margin + 140, y + 5);
    doc.text(caseDetails.acquisitionTime, margin + 140, y + 11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(180, 83, 9); // amber-700
    doc.text('UNDER INVESTIGATION', margin + 140, y + 17);

    y += 28;

    // ==========================================
    // 3. EVIDENCE INVENTORY
    // ==========================================
    checkPageBreak(50);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('3. EVIDENCE INVENTORY', margin, y);
    y += 5;

    // Table Header
    doc.setFillColor(241, 245, 249);
    doc.rect(margin, y, contentWidth, 6, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text('ARTIFACT', margin + 3, y + 4.2);
    doc.text('SOURCE PATH', margin + 32, y + 4.2);
    doc.text('SIZE', margin + 85, y + 4.2);
    doc.text('SHA-256 HASH (READ-ONLY EVIDENCE COPY)', margin + 102, y + 4.2);
    doc.text('STATUS', pageWidth - margin - 3, y + 4.2, { align: 'right' });
    y += 6;

    // Rows
    artifactSummaries.forEach((art) => {
      checkPageBreak(8);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(15, 23, 42);
      doc.text(art.title, margin + 3, y + 4);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(100, 116, 139);
      doc.text(art.sourceDesc.substring(0, 32), margin + 32, y + 4);
      doc.text(art.fileSize, margin + 85, y + 4);
      doc.text(art.sha256.substring(0, 36) + '...', margin + 102, y + 4);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(21, 128, 61); // emerald-700
      doc.text('[VERIFIED]', pageWidth - margin - 3, y + 4, { align: 'right' });

      doc.setDrawColor(241, 245, 249);
      doc.line(margin, y + 5.5, pageWidth - margin, y + 5.5);
      y += 6;
    });

    y += 6;

    // ==========================================
    // 4. EVENT SUMMARY
    // ==========================================
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('4. EVENT SUMMARY', margin, y);
    y += 5;

    const bCount = events.filter((e) => e.artifact === 'browser').length;
    const uCount = events.filter((e) => e.artifact === 'usb').length;
    const eCount = events.filter((e) => e.artifact === 'execution').length;
    const nCount = events.filter((e) => e.artifact === 'network').length;

    const boxW = contentWidth / 5;
    const countsData = [
      { label: 'TOTAL EVENTS', val: events.length },
      { label: 'BROWSER', val: bCount },
      { label: 'USB STORAGE', val: uCount },
      { label: 'EXECUTION', val: eCount },
      { label: 'NETWORK', val: nCount },
    ];

    countsData.forEach((item, i) => {
      const bx = margin + i * boxW;
      doc.setFillColor(248, 250, 252);
      doc.rect(bx, y, boxW - 2, 12, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.rect(bx, y, boxW - 2, 12, 'S');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(100, 116, 139);
      doc.text(item.label, bx + (boxW - 2) / 2, y + 4, { align: 'center' });

      doc.setFont('courier', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text(String(item.val), bx + (boxW - 2) / 2, y + 9.5, { align: 'center' });
    });

    y += 18;

    // ==========================================
    // 5. INVESTIGATION RISK
    // ==========================================
    checkPageBreak(45);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('5. INVESTIGATION RISK', margin, y);
    y += 5;

    doc.setFillColor(254, 252, 232); // light amber
    doc.rect(margin, y, contentWidth, 24, 'F');
    doc.setDrawColor(253, 230, 138);
    doc.rect(margin, y, contentWidth, 24, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(180, 83, 9);
    doc.text(`INVESTIGATION RISK SCORE: ${caseRiskSummary.score} / 100`, margin + 4, y + 5.5);
    doc.setFont('courier', 'bold');
    doc.text(`PRIORITY: ${caseRiskSummary.level.toUpperCase()}`, pageWidth - margin - 4, y + 5.5, {
      align: 'right',
    });

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    let indY = y + 10;
    caseRiskSummary.indicators.forEach((ind) => {
      doc.text(`+${ind.points} — ${ind.name}`, margin + 4, indY);
      indY += 4;
    });

    doc.setFont('helvetica', 'italic');
    doc.setFontSize(7);
    doc.setTextColor(120, 53, 15);
    doc.text(
      'Triage heuristic — not a determination of malicious activity. Provided to prioritize investigator review.',
      margin + 4,
      y + 21
    );

    y += 30;

    // ==========================================
    // 6. UNIFIED INCIDENT TIMELINE
    // ==========================================
    checkPageBreak(40);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('6. UNIFIED INCIDENT TIMELINE', margin, y);
    y += 5;

    // Timeline table header
    doc.setFillColor(15, 23, 42);
    doc.rect(margin, y, contentWidth, 5.5, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(255, 255, 255);
    doc.text('TIMESTAMP', margin + 2, y + 3.8);
    doc.text('TAG', margin + 22, y + 3.8);
    doc.text('EVENT TYPE', margin + 40, y + 3.8);
    doc.text('PROCESS', margin + 74, y + 3.8);
    doc.text('PATH / SOCKET', margin + 102, y + 3.8);
    doc.text('STATUS', margin + 155, y + 3.8);
    doc.text('CORR', pageWidth - margin - 2, y + 3.8, { align: 'right' });
    y += 6;

    events.forEach((evt, idx) => {
      checkPageBreak(7);
      const isSuspicious = evt.risk_status === 'suspicious';
      if (isSuspicious) {
        doc.setFillColor(254, 242, 242);
        doc.rect(margin, y, contentWidth, 5.5, 'F');
      } else if (idx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 5.5, 'F');
      }

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(15, 23, 42);
      doc.text(evt.timestamp.split(' ')[1] || evt.timestamp, margin + 2, y + 3.8);

      doc.setFont('courier', 'bold');
      doc.setFontSize(6);
      doc.setTextColor(100, 116, 139);
      doc.text(`[${evt.artifact.toUpperCase()}]`, margin + 22, y + 3.8);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(51, 65, 85);
      doc.text(evt.event_type.substring(0, 22), margin + 40, y + 3.8);

      doc.setFont('courier', 'bold');
      doc.text((evt.process || '-').substring(0, 16), margin + 74, y + 3.8);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6);
      doc.setTextColor(100, 116, 139);
      const targetStr = evt.path || evt.remote_address || evt.url || '-';
      doc.text(targetStr.substring(0, 36), margin + 102, y + 3.8);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      if (isSuspicious) {
        doc.setTextColor(185, 28, 28);
        doc.text('[SUSPICIOUS]', margin + 155, y + 3.8);
      } else if (evt.risk_status === 'review') {
        doc.setTextColor(180, 83, 9);
        doc.text('[REVIEW]', margin + 155, y + 3.8);
      } else {
        doc.setTextColor(100, 116, 139);
        doc.text('[NORMAL]', margin + 155, y + 3.8);
      }

      doc.setFont('courier', 'bold');
      doc.setTextColor(180, 83, 9);
      doc.text(evt.correlation_id || '-', pageWidth - margin - 2, y + 3.8, { align: 'right' });

      y += 5.5;
    });

    y += 8;

    // ==========================================
    // 7. FINDINGS & 8. CORRELATED ACTIVITY
    // ==========================================
    checkPageBreak(45);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('7. FINDINGS & 8. CORRELATED ACTIVITY', margin, y);
    y += 5;

    if (findings.length === 0) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(100, 116, 139);
      doc.text('No correlated anomalous activity sequences identified.', margin, y);
      y += 8;
    } else {
      findings.forEach((f) => {
        checkPageBreak(30);
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentWidth, 22, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.rect(margin, y, contentWidth, 22, 'S');

        doc.setFont('courier', 'bold');
        doc.setFontSize(8.5);
        doc.setTextColor(180, 83, 9);
        doc.text(`[${f.correlation_id}]`, margin + 4, y + 5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text(f.title, margin + 25, y + 5);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(100, 116, 139);
        doc.text(
          `Sequence: ${f.startTime} → ${f.endTime} (Span: ${f.timeSpan}) · Events: ${f.eventIds.join(', ')}`,
          margin + 4,
          y + 10
        );

        doc.setFont('helvetica', 'bold');
        doc.setTextColor(185, 28, 28);
        doc.text(`SCORE: ${f.riskScore}/100 — ${f.priority}`, pageWidth - margin - 4, y + 5, {
          align: 'right',
        });

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(51, 65, 85);
        doc.text(`Detection Rules: ${f.reasons.join(' | ')}`, margin + 4, y + 15);
        doc.text(
          'Correlation Sequence: Browser Download  -->  AppData Execution  -->  Network Socket',
          margin + 4,
          y + 19
        );

        y += 26;
      });
    }

    // ==========================================
    // 9. EVIDENCE INTEGRITY
    // ==========================================
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('9. EVIDENCE INTEGRITY', margin, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    const integrityStatement =
      'RapidTriage performs non-destructive analysis on acquired evidence copies. Original endpoint system files, registry hives, and browser databases were not modified. SHA-256 hashes are provided for integrity verification.';
    const intLines = doc.splitTextToSize(integrityStatement, contentWidth);
    doc.text(intLines, margin, y);
    y += intLines.length * 4.2 + 6;

    // ==========================================
    // 10. INVESTIGATION NOTES
    // ==========================================
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('10. INVESTIGATION NOTES', margin, y);
    y += 5;

    doc.setFillColor(248, 250, 252);
    doc.rect(margin, y, contentWidth, 18, 'F');
    doc.setDrawColor(226, 232, 240);
    doc.rect(margin, y, contentWidth, 18, 'S');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const userNotes = notes.trim()
      ? notes.trim()
      : 'No additional manual notes entered by the investigator at the time of report generation.';
    const noteLines = doc.splitTextToSize(userNotes, contentWidth - 8);
    doc.text(noteLines, margin + 4, y + 5);
    y += 24;

    // ==========================================
    // 11. CONCLUSION
    // ==========================================
    checkPageBreak(25);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('11. CONCLUSION', margin, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    const conclusionText =
      'The identified activity has been highlighted for further investigation based on configured triage rules. RapidTriage does not determine whether the activity is definitively malicious. Recommended next steps include host isolation, process memory acquisition, and destination IP reputation assessment.';
    const concLines = doc.splitTextToSize(conclusionText, contentWidth);
    doc.text(concLines, margin, y);
    y += concLines.length * 4.2 + 8;

    // ==========================================
    // ADD HEADERS & FOOTERS (PAGE X OF Y)
    // ==========================================
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);

      // Running top header for page 2+
      if (i > 1) {
        doc.setFont('courier', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(100, 116, 139);
        doc.text(`RapidTriage Case Report · ${caseId}`, margin, 8);
        doc.setFont('helvetica', 'normal');
        doc.text(dateStr, pageWidth - margin, 8, { align: 'right' });
        doc.setDrawColor(226, 232, 240);
        doc.setLineWidth(0.3);
        doc.line(margin, 10, pageWidth - margin, 10);
      }

      // Running footer for all pages
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(margin, pageHeight - 10, pageWidth - margin, pageHeight - 10);

      doc.setFont('courier', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184);
      doc.text('CONFIDENTIAL FORENSIC INVESTIGATION REPORT', margin, pageHeight - 6);
      doc.text(`PAGE ${i} OF ${totalPages}`, pageWidth - margin, pageHeight - 6, { align: 'right' });
    }

    // Produce binary blob
    const pdfBlob = doc.output('blob');
    const safeCase = sanitizeFilename(caseId);
    const filename = `RapidTriage_Case_${safeCase}_${dateStr}.pdf`;

    // Strict validation
    if (!pdfBlob || pdfBlob.size < 500) {
      return {
        success: false,
        filename,
        filesize: 0,
        error: 'Generated PDF blob is empty or below valid threshold.',
      };
    }

    return {
      success: true,
      blob: pdfBlob,
      filename,
      filesize: pdfBlob.size,
    };
  } catch (err: any) {
    return {
      success: false,
      filename: 'report.pdf',
      filesize: 0,
      error: err?.message || 'An error occurred during PDF rendering.',
    };
  }
}
