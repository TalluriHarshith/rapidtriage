/**
 * RapidTriage - Evidence View
 * Case header, 4 standardized artifact cards, and forensic evidence acquisition.
 * Fully supports Light and Dark themes.
 */

import React, { useState } from 'react';
import {
  Globe,
  HardDrive,
  Cpu,
  Radio,
  CheckCircle2,
  RefreshCw,
  Play,
  Upload,
  Download,
  Info,
  ArrowRight,
  Database,
  FileCheck,
} from 'lucide-react';
import { CaseDetails, ArtifactSourceSummary, ForensicArtifactType } from '../types/forensics';
import { SAMPLE_CSV_CONTENT } from '../services/forensicEngine';

interface EvidenceViewProps {
  caseDetails: CaseDetails;
  artifactSummaries: ArtifactSourceSummary[];
  isAcquiring: boolean;
  onAcquireEvidence: () => void;
  onLoadSampleEvidence: () => void;
  onOpenUploadModal: () => void;
  onNavigateToTimeline: () => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({
  caseDetails,
  artifactSummaries,
  isAcquiring,
  onAcquireEvidence,
  onLoadSampleEvidence,
  onOpenUploadModal,
  onNavigateToTimeline,
}) => {
  const [showFormatExample, setShowFormatExample] = useState(false);

  const getArtifactIcon = (type: ForensicArtifactType) => {
    switch (type) {
      case 'browser':
        return <Globe className="w-5 h-5 text-sky-500" />;
      case 'usb':
        return <HardDrive className="w-5 h-5 text-emerald-500" />;
      case 'execution':
        return <Cpu className="w-5 h-5 text-purple-500" />;
      case 'network':
        return <Radio className="w-5 h-5 text-indigo-500" />;
    }
  };

  const getArtifactTag = (type: ForensicArtifactType) => {
    switch (type) {
      case 'browser':
        return '[BROWSER]';
      case 'usb':
        return '[USB]';
      case 'execution':
        return '[EXECUTION]';
      case 'network':
        return '[NETWORK]';
    }
  };

  const totalExtracted = artifactSummaries.reduce(
    (acc, curr) => acc + curr.extractedEventsCount,
    0
  );

  const handleDownloadSampleCSV = () => {
    const blob = new Blob([SAMPLE_CSV_CONTENT], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'RapidTriage_Sample_Dataset.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-y-auto p-8 transition-colors duration-150 bg-slate-50 text-slate-900 dark:bg-[#0c1017] dark:text-slate-100">
      <div className="max-w-4xl mx-auto w-full space-y-6">
        {/* Top Header & Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
              FORENSIC EVIDENCE ACQUISITION
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mt-0.5">
              Evidence Collection & Sources
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Acquire endpoint artifacts non-destructively or upload forensic triage packages.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={onOpenUploadModal}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-bold rounded-md transition-colors border shadow-xs bg-yellow-500 hover:bg-yellow-400 text-slate-950 border-yellow-600"
            >
              <Upload className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>UPLOAD EVIDENCE (.CSV/.JSON)</span>
            </button>

            <button
              onClick={onLoadSampleEvidence}
              disabled={isAcquiring}
              className="px-3 py-2 text-xs font-semibold rounded-md transition-colors border disabled:opacity-50 bg-white hover:bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200 dark:border-slate-700"
            >
              Load Sample Evidence
            </button>

            <button
              onClick={onAcquireEvidence}
              disabled={isAcquiring}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-md transition-colors shadow-xs disabled:opacity-50 bg-slate-900 hover:bg-slate-800 text-white dark:bg-slate-100 dark:hover:bg-white dark:text-slate-950"
            >
              {isAcquiring ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Acquiring Artifacts...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Acquire Evidence</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Sample CSV Download Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-lg border text-xs bg-white border-slate-200 shadow-xs dark:bg-[#101520] dark:border-slate-800">
          <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
            <Database className="w-4 h-4 text-yellow-600 dark:text-yellow-400 shrink-0" />
            <span>Need a ready-to-use forensic dataset or format template?</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleDownloadSampleCSV}
              className="flex items-center gap-1.5 text-yellow-700 dark:text-yellow-400 hover:underline font-bold transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Sample CSV</span>
            </button>
            <span className="text-slate-300 dark:text-slate-700 font-mono">·</span>
            <button
              onClick={() => setShowFormatExample(!showFormatExample)}
              className="text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 text-[11px] font-mono transition-colors"
            >
              {showFormatExample ? 'Hide Format Example' : 'CSV Format Example'}
            </button>
          </div>
        </div>

        {/* Collapsible Format Example */}
        {showFormatExample && (
          <div className="p-4 rounded-lg border text-[11px] font-mono space-y-2 animate-in fade-in bg-slate-100 border-slate-300 text-slate-800 dark:bg-[#090d14] dark:border-slate-800 dark:text-slate-300">
            <div className="flex items-center justify-between font-semibold uppercase text-slate-600 dark:text-slate-400">
              <span>Standard CSV Header Columns:</span>
              <span className="text-slate-500 text-[10px] font-normal">Only 'timestamp' is strictly required</span>
            </div>
            <div className="p-2.5 rounded border text-[11px] break-all select-all font-mono bg-white border-slate-200 text-yellow-800 dark:bg-[#0e131d] dark:border-slate-800 dark:text-yellow-300">
              timestamp, artifact, event_type, process, path, user, file, url, local_address, remote_address, device, description
            </div>
            <div className="text-[11px] text-slate-500 font-sans leading-relaxed">
              Missing optional values remain empty without fabricating evidence. Timestamps can be ISO 8601 (<code>YYYY-MM-DD HH:mm:ss</code>) or standard times (<code>10:30:18</code>).
            </div>
          </div>
        )}

        {/* Case File Metadata Bar */}
        <div className="rounded-lg border p-5 bg-white border-slate-200 shadow-xs dark:bg-[#10151f] dark:border-slate-800">
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold mb-3">
            CASE PARAMETERS & CONTEXT
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">CASE ID</span>
              <span className="font-bold text-slate-900 dark:text-slate-100 mt-0.5 block">
                {caseDetails.caseId}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">ENDPOINT</span>
              <span className="font-medium text-slate-800 dark:text-slate-200 mt-0.5 block truncate">
                {caseDetails.endpoint}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">OPERATING SYSTEM</span>
              <span className="text-slate-800 dark:text-slate-300 mt-0.5 block truncate" title={caseDetails.os}>
                {caseDetails.os}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">EVIDENCE STATUS</span>
              <span className="mt-0.5 inline-flex items-center gap-1.5 text-xs font-bold text-amber-700 dark:text-amber-400">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-500"></span>
                {caseDetails.status === 'Requires Investigation' ? 'UNDER INVESTIGATION' : caseDetails.status}
              </span>
            </div>
          </div>
        </div>

        {/* Four Core Artifact Cards with Forensic Tags */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
              Standardized Artifact Sources
            </span>
            <span className="text-xs font-mono text-slate-500">
              {totalExtracted} events extracted across 4 sources
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {artifactSummaries.map((art) => (
              <div
                key={art.type}
                className="relative overflow-hidden rounded-lg border p-5 space-y-4 transition-all hover:shadow-xs bg-white border-slate-200 dark:bg-[#111722] dark:border-slate-800"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded border bg-slate-50 border-slate-200 dark:bg-slate-900 dark:border-slate-800">
                      {getArtifactIcon(art.type)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] font-bold text-slate-500 uppercase">
                          {getArtifactTag(art.type)}
                        </span>
                        <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                          {art.title}
                        </h3>
                      </div>
                      <p className="text-xs text-slate-500 font-mono mt-0.5">{art.sourceDesc}</p>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border tracking-wider bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/50 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>[VERIFIED]</span>
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-100 dark:border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Extracted Events</span>
                    <span className="text-slate-900 dark:text-slate-100 text-sm font-bold">
                      {art.extractedEventsCount}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block">Last Processed</span>
                    <span className="text-slate-700 dark:text-slate-400 text-xs">{art.lastProcessedTime}</span>
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-500 truncate p-2 rounded border bg-slate-50 border-slate-200 dark:bg-slate-900/60 dark:border-slate-800/80">
                  <span className="text-slate-400">Src: </span>
                  {art.sourcePath}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Proceed to Timeline CTA */}
        <div className="pt-2 flex items-center justify-between p-4 rounded-lg border bg-white border-slate-200 shadow-xs dark:bg-slate-900/40 dark:border-slate-800">
          <div className="text-xs text-slate-600 dark:text-slate-300">
            All 4 artifact sources extracted and correlated into the chronological timeline.
          </div>
          <button
            onClick={onNavigateToTimeline}
            className="flex items-center gap-2 px-4 py-2 text-xs font-bold rounded transition-colors bg-yellow-500 hover:bg-yellow-400 text-slate-950 shadow-xs cursor-pointer"
          >
            <span>PROCEED TO TIMELINE</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
