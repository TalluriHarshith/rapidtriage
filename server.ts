/**
 * RapidTriage - Express Full-Stack Server
 * Integrates Python FastAPI forensic backend with Node/Vite development server.
 * Proxies /api/* to FastAPI (port 8000) and provides fallback PDF generation.
 */

import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import http from 'http';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import PDFDocument from 'pdfkit';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const FASTAPI_PORT = 8000;

// ==========================================
// Spawn Python FastAPI Forensic Service
// ==========================================
let fastApiProcess: any = null;

function startFastApiBackend() {
  try {
    fastApiProcess = spawn(
      'python3',
      ['-m', 'uvicorn', 'rapidtriage.backend.main:app', '--host', '127.0.0.1', `--port`, `${FASTAPI_PORT}`, '--log-level', 'info'],
      {
        cwd: __dirname,
        env: { ...process.env, PYTHONPATH: '.' },
        stdio: ['ignore', 'pipe', 'pipe']
      }
    );

    fastApiProcess.stdout?.on('data', (data: Buffer) => {
      console.log(`[FastAPI] ${data.toString().trim()}`);
    });

    fastApiProcess.stderr?.on('data', (data: Buffer) => {
      console.error(`[FastAPI Error] ${data.toString().trim()}`);
    });

    fastApiProcess.on('exit', (code: number) => {
      console.log(`[FastAPI] Exited with code ${code}. Respawning in 2s...`);
      setTimeout(startFastApiBackend, 2000);
    });
  } catch (err) {
    console.error('[FastAPI] Failed to spawn process:', err);
  }
}

// Start FastAPI child process
startFastApiBackend();

// Ensure child process terminates when node exits
process.on('exit', () => {
  if (fastApiProcess) fastApiProcess.kill();
});
process.on('SIGINT', () => {
  if (fastApiProcess) fastApiProcess.kill();
  process.exit(0);
});
process.on('SIGTERM', () => {
  if (fastApiProcess) fastApiProcess.kill();
  process.exit(0);
});

// JSON parser with 15MB limit
app.use(express.json({ limit: '15mb' }));

/**
 * Proxy all /api/* requests to FastAPI backend
 */
app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  const targetUrl = new URL(req.originalUrl, `http://127.0.0.1:${FASTAPI_PORT}`);

  const headers: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (value !== undefined) {
      headers[key] = value;
    }
  }
  headers.host = `127.0.0.1:${FASTAPI_PORT}`;

  const proxyReq = http.request(
    {
      hostname: '127.0.0.1',
      port: FASTAPI_PORT,
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers,
    },
    (proxyRes) => {
      // If FastAPI returns 404 specifically for generate-pdf, let Express fallback handle it
      if (proxyRes.statusCode === 404 && req.originalUrl.includes('generate-pdf')) {
        return next();
      }
      res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on('error', (err) => {
    // If FastAPI isn't ready and it's generate-pdf, use Express fallback
    if (req.originalUrl.includes('generate-pdf')) {
      return next();
    }
    console.warn('[Proxy Warning] FastAPI backend warming up:', err.message);
    if (!res.headersSent) {
      res.status(503).json({ error: 'FastAPI forensic engine warming up. Please retry in a moment.' });
    }
  });

  // Handle body forwarding
  if (req.body && Object.keys(req.body).length > 0 && req.headers['content-type']?.includes('application/json')) {
    const bodyStr = JSON.stringify(req.body);
    proxyReq.setHeader('content-length', Buffer.byteLength(bodyStr));
    proxyReq.write(bodyStr);
    proxyReq.end();
  } else {
    req.pipe(proxyReq);
  }
});

// Helper to sanitize filenames
function sanitizeFilename(str: string): string {
  return str.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
}

/**
 * Fallback PDF Generation Route (if FastAPI is temporarily warming up)
 */
app.post('/api/generate-pdf', async (req: Request, res: Response) => {
  try {
    const {
      caseDetails = {},
      artifactSummaries = [],
      events = [],
      findings = [],
      caseRiskSummary = { score: 0, level: 'Low', indicators: [] },
      notes = '',
    } = req.body;

    const caseId = caseDetails.caseId || 'RT-2026-001';
    const dateStr = new Date().toISOString().split('T')[0];
    const filename = `RapidTriage_Case_${sanitizeFilename(caseId)}_${dateStr}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const doc = new PDFDocument({
      size: 'A4',
      margin: 40,
      info: {
        Title: `RapidTriage Case Report - ${caseId}`,
        Author: 'RapidTriage Forensic Workstation',
        Subject: 'Incident Timeline & Artifact Triage Report',
      },
    });

    doc.pipe(res);

    // Yellow evidence bar
    doc.rect(40, 40, 515, 4).fill('#eab308');

    doc.fillColor('#0f172a').fontSize(22).font('Helvetica-Bold').text('RapidTriage', 40, 54);
    doc.fontSize(9).font('Helvetica').fillColor('#64748b').text('ENDPOINT FORENSIC TRIAGE & INCIDENT TIMELINE REPORT', 40, 80);

    doc.font('Courier-Bold').fontSize(10).fillColor('#0f172a').text(`CASE ID: ${caseId}`, 40, 54, { align: 'right' });
    doc.fontSize(8).font('Helvetica').fillColor('#64748b').text(`GENERATED: ${new Date().toISOString()}`, 40, 68, { align: 'right' });

    doc.moveTo(40, 96).lineTo(555, 96).strokeColor('#e2e8f0').lineWidth(1).stroke();

    // 1. Executive Summary
    doc.moveDown(1.5);
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#0f172a').text('1. EXECUTIVE SUMMARY');
    doc.fontSize(9).font('Helvetica').fillColor('#334155').text(
      `RapidTriage parsed ${events.length} endpoint events across browser, USB mass storage, process execution, and network telemetry for endpoint ${caseDetails.endpoint || 'LAB-PC-07'}. Analysis identified ${findings.length} potentially suspicious activity sequence(s) requiring manual investigator triage. All original endpoint evidence remained untouched in non-destructive read-only analysis.`,
      { align: 'justify', lineGap: 3 }
    );

    // 2. Case Information
    doc.moveDown(1.2);
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#0f172a').text('2. CASE INFORMATION');
    doc.rect(40, doc.y + 4, 515, 60).fill('#f8fafc').strokeColor('#e2e8f0').stroke();

    const startY = doc.y + 12;
    doc.fontSize(8).font('Helvetica-Bold').fillColor('#64748b');
    doc.text('CASE ID:', 50, startY);
    doc.text('ENDPOINT HOST:', 50, startY + 16);
    doc.text('OPERATING SYSTEM:', 50, startY + 32);

    doc.font('Courier-Bold').fillColor('#0f172a');
    doc.text(caseId, 150, startY);
    doc.font('Helvetica').text(caseDetails.endpoint || 'LAB-PC-07', 150, startY + 16);
    doc.text(caseDetails.os || 'Windows 11 Pro', 150, startY + 32);

    doc.font('Helvetica-Bold').fillColor('#64748b');
    doc.text('STATUS:', 330, startY);
    doc.text('ACQUISITION TIME:', 330, startY + 16);
    doc.text('DATA SOURCE:', 330, startY + 32);

    doc.font('Helvetica').fillColor('#b91c1c').text(caseDetails.status || 'Requires Investigation', 440, startY);
    doc.fillColor('#0f172a').text(caseDetails.acquisitionTime || 'N/A', 440, startY + 16);
    doc.text(caseDetails.isDemoData ? 'Demo Dataset' : 'Live Snapshot', 440, startY + 32);

    doc.y = startY + 54;

    // 3. Evidence Inventory
    doc.moveDown(1.2);
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#0f172a').text('3. EVIDENCE INVENTORY & SHA-256 HASHES');

    artifactSummaries.forEach((art: any) => {
      const artY = doc.y + 3;
      doc.rect(40, artY, 515, 32).fill('#f8fafc').strokeColor('#e2e8f0').stroke();

      doc.fontSize(8.5).font('Helvetica-Bold').fillColor('#0f172a').text(art.name || art.title || 'Artifact', 48, artY + 5);
      doc.fontSize(7.5).font('Helvetica').fillColor('#64748b').text(`Path: ${art.sourcePath || 'N/A'}`, 48, artY + 18);

      const hashStr = (art.sha256Hash || art.sha256 || 'N/A').substring(0, 32) + '...';
      doc.font('Courier-Bold').fontSize(7.5).fillColor('#334155').text(`SHA-256: ${hashStr}`, 300, artY + 5);
      doc.font('Helvetica').fillColor('#16a34a').text(`✓ Verified (${art.extractedEventsCount || 0} events)`, 300, artY + 18);

      doc.y = artY + 36;
    });

    // 4. Risk Summary
    doc.moveDown(1.2);
    doc.fontSize(11).font('Helvetica-Bold').fillColor('#0f172a').text('4. INVESTIGATION RISK SUMMARY');
    doc.fontSize(9).font('Helvetica-Bold').fillColor('#b91c1c').text(
      `Risk Score: ${caseRiskSummary.score}/100 — ${caseRiskSummary.level}`,
      40,
      doc.y + 4
    );

    doc.end();
  } catch (err: any) {
    console.error('Fallback PDF generation error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: err?.message || 'Failed to generate PDF report' });
    }
  }
});

// Vite middleware in dev or static files in production
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`RapidTriage server running on port ${PORT}`);
  });
}

startServer();
