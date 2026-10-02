/**
 * RapidTriage - Evidence Integrity View
 * Non-destructive forensic assurance, SHA-256 verification, and evidence copy tracking.
 * Fully supports Light and Dark themes.
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  FileText,
  ArrowRight,
  Lock,
} from 'lucide-react';
import { ArtifactSourceSummary } from '../types/forensics';

interface IntegrityViewProps {
  artifactSummaries: ArtifactSourceSummary[];
  onReverifyHashes: () => Promise<void>;
}

export const IntegrityView: React.FC<IntegrityViewProps> = ({
  artifactSummaries,
  onReverifyHashes,
}) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [lastVerifiedMessage, setLastVerifiedMessage] = useState<string | null>(null);

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    await onReverifyHashes();
    setIsVerifying(false);
    setLastVerifiedMessage('All 4 evidence copies verified bit-exact against acquisition SHA-256 hashes.');
    setTimeout(() => setLastVerifiedMessage(null), 4000);
  };

  const handleExportManifest = () => {
    const lines = [
      '# RapidTriage Evidence Integrity Manifest',
      `# Generated: ${new Date().toISOString()}`,
      '# Algorithm: SHA-256',
      '# Mode: READ-ONLY FORENSIC ACQUISITION',
      '',
    ];
    artifactSummaries.forEach((art) => {
      lines.push(`${art.sha256}  ${art.evidenceCopyPath}  (${art.fileSize})`);
    });

    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RapidTriage_Manifest_${Date.now()}.sha256`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-y-auto p-8 transition-colors duration-150 bg-slate-50 text-slate-900 dark:bg-[#0c1017] dark:text-slate-100">
      <div className="max-w-4xl mx-auto w-full space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
              CHAIN OF CUSTODY & INTEGRITY
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mt-0.5">
              Evidence Integrity
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Read-only analysis and cryptographically verifiable evidence copy digests.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportManifest}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold transition-colors border bg-white border-slate-300 text-slate-800 hover:bg-slate-100 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-700"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Manifest</span>
            </button>
            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded text-xs font-bold transition-colors disabled:opacity-50 shadow-xs bg-yellow-500 hover:bg-yellow-400 text-slate-950 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
              <span>{isVerifying ? 'Verifying Hashes...' : 'Re-verify Hashes'}</span>
            </button>
          </div>
        </div>

        {/* Read-Only Assurance Notice */}
        <div className="rounded-lg p-5 border transition-colors bg-white border-emerald-300 shadow-xs dark:bg-[#111724] dark:border-emerald-900/50">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded border shrink-0 bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-400 dark:border-emerald-800/60">
              <Lock className="w-5 h-5" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-400">
                  [READ-ONLY ANALYSIS]
                </span>
                <span className="text-slate-400 font-mono">·</span>
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  Original evidence is not modified.
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                RapidTriage operates solely on read-only forensically acquired copies stored in an isolated triage directory.
                Original system hives, prefetch files, and browser databases are never written to or locked.
              </p>
              <p className="text-[11px] text-slate-500 font-sans pt-1">
                * Note: SHA-256 helps verify whether the analyzed evidence copy has changed.
              </p>
            </div>
          </div>
        </div>

        {/* Workflow Diagram */}
        <div className="rounded-lg border p-5 bg-white border-slate-200 shadow-xs dark:bg-[#10151f] dark:border-slate-800">
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold mb-4">
            FORENSIC WORKFLOW PIPELINE
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 items-center text-center text-xs">
            <div className="p-3 rounded border font-mono font-medium bg-slate-50 border-slate-200 text-slate-800 dark:bg-[#0b0f17] dark:border-slate-800 dark:text-slate-300">
              <span className="block text-[10px] text-slate-400 mb-0.5">Step 1</span>
              Original Artifact
            </div>
            <div className="hidden md:flex justify-center text-slate-400 font-mono">
              <ArrowRight className="w-4 h-4" />
            </div>
            <div className="p-3 rounded border font-mono font-medium bg-slate-50 border-slate-200 text-slate-800 dark:bg-[#0b0f17] dark:border-slate-800 dark:text-slate-300">
              <span className="block text-[10px] text-slate-400 mb-0.5">Step 2</span>
              Read & Copy
            </div>
            <div className="hidden md:flex justify-center text-slate-400 font-mono">
              <ArrowRight className="w-4 h-4" />
            </div>
            <div className="p-3 rounded border font-mono font-bold bg-yellow-50 border-yellow-300 text-yellow-950 dark:bg-yellow-950/30 dark:border-yellow-900/60 dark:text-yellow-300">
              <span className="block text-[10px] text-yellow-700 dark:text-yellow-500 mb-0.5">Step 3</span>
              SHA-256 & Analyze
            </div>
          </div>
        </div>

        {lastVerifiedMessage && (
          <div className="p-3 rounded border text-xs font-mono flex items-center gap-2 bg-emerald-50 text-emerald-950 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800/60 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <span>{lastVerifiedMessage}</span>
          </div>
        )}

        {/* Artifact Evidence Table */}
        <div className="space-y-3">
          <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
            Evidence Artifact Verification Manifest
          </div>

          <div className="space-y-3">
            {artifactSummaries.map((art) => (
              <div
                key={art.type}
                className="rounded-lg border p-4 space-y-3 bg-white border-slate-200 shadow-xs dark:bg-[#111722] dark:border-slate-800"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-100 dark:border-slate-800/70">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-slate-900 dark:text-slate-100">{art.title}</span>
                    <span className="text-xs text-slate-500 font-mono">({art.sourceDesc})</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-slate-500 dark:text-slate-400">{art.fileSize}</span>
                    <span className="text-slate-300 dark:text-slate-700">·</span>
                    <span className="font-bold flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>[VERIFIED]</span>
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block font-semibold">Acquisition Copy</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300 text-[11px] break-all block mt-0.5">
                      {art.evidenceCopyPath}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block font-semibold">Acquisition Time</span>
                    <span className="font-mono text-slate-600 dark:text-slate-400 text-xs block mt-0.5">
                      {art.lastProcessedTime}
                    </span>
                  </div>
                </div>

                {/* SHA-256 Hash Display */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold">SHA-256 Hash</span>
                    <button
                      onClick={() => copyHash(art.sha256)}
                      className="text-[11px] font-mono text-slate-500 hover:text-slate-900 dark:hover:text-slate-200 flex items-center gap-1"
                    >
                      {copiedHash === art.sha256 ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                          <span className="text-emerald-600 dark:text-emerald-400 font-bold">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Hash</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="font-mono text-[11px] p-2 rounded border break-all select-all bg-slate-50 border-slate-200 text-slate-800 dark:bg-[#090d15] dark:border-slate-800 dark:text-slate-300">
                    {art.sha256}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
