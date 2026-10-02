/**
 * RapidTriage - First Screen Experience
 * Section 32 & 33: Subtle evidence tape & case file branding
 * Direct, minimal, professional, full Light & Dark mode support.
 */

import React from 'react';
import { Play, FolderOpen, RefreshCw } from 'lucide-react';

interface WelcomeScreenProps {
  onAcquireEvidence: () => void;
  onLoadSampleCase: () => void;
  isAcquiring: boolean;
}

export const WelcomeScreen: React.FC<WelcomeScreenProps> = ({
  onAcquireEvidence,
  onLoadSampleCase,
  isAcquiring,
}) => {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-8 text-center select-none transition-colors duration-150 bg-slate-50 text-slate-900 dark:bg-[#0c1017] dark:text-slate-100 min-h-screen">
      {/* Evidence Case File Card */}
      <div className="max-w-md w-full rounded-xl border shadow-xl overflow-hidden bg-white border-slate-200 dark:bg-[#111722] dark:border-slate-800">
        {/* Signature Yellow Evidence Tape Strip */}
        <div className="h-2 w-full evidence-tape-diagonal"></div>

        <div className="p-8 space-y-6">
          {/* Brand Lockup */}
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded border text-[11px] font-mono uppercase font-bold tracking-wider bg-yellow-50 text-yellow-900 border-yellow-300 dark:bg-yellow-950/40 dark:text-yellow-300 dark:border-yellow-800/80 mb-1">
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-500"></span>
              <span>ENDPOINT FORENSIC TRIAGE</span>
            </div>

            <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
              RapidTriage
            </h1>
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
              Investigate endpoint activity in minutes.
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed pt-1">
              Collect endpoint artifacts, reconstruct the incident timeline, and identify activity that requires investigation.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="space-y-3 pt-2">
            <button
              onClick={onAcquireEvidence}
              disabled={isAcquiring}
              className="w-full flex items-center justify-center gap-2.5 py-3 px-4 rounded-md font-bold text-xs uppercase tracking-wider transition-colors shadow-sm disabled:opacity-50 cursor-pointer bg-yellow-500 hover:bg-yellow-400 text-slate-950"
            >
              {isAcquiring ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Acquiring Endpoint Artifacts...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Acquire Evidence</span>
                </>
              )}
            </button>

            <button
              onClick={onLoadSampleCase}
              disabled={isAcquiring}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-md font-semibold text-xs transition-colors border disabled:opacity-50 cursor-pointer bg-white hover:bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800/90 dark:hover:bg-slate-700 dark:text-slate-200 dark:border-slate-700"
            >
              <FolderOpen className="w-4 h-4 text-slate-400" />
              <span>Load Sample Case</span>
            </button>
          </div>

          <div className="text-[11px] font-mono text-slate-400 dark:text-slate-500 pt-4 border-t border-slate-100 dark:border-slate-800">
            From scattered endpoint evidence to one clear incident timeline.
          </div>
        </div>
      </div>
    </div>
  );
};
