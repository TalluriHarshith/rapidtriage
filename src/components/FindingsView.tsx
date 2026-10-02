/**
 * RapidTriage - Findings View (Evidence Board Style)
 * Section 39: Digital evidence board with yellow evidence-strip accent
 * Section 50: Minimal, professional Investigation Risk Score assessment
 * Full Light and Dark theme support
 */

import React from 'react';
import {
  ArrowRight,
  Clock,
  CheckCircle2,
  Sliders,
  ShieldAlert,
  Info,
  Tag,
} from 'lucide-react';
import { CorrelationFinding, OverallRiskSummary } from '../types/forensics';

interface FindingsViewProps {
  findings: CorrelationFinding[];
  caseRiskSummary: OverallRiskSummary;
  temporalWindowMinutes: number;
  onChangeTemporalWindow: (minutes: number) => void;
  onViewTimelineForFinding: (correlationId: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  caseRiskSummary,
  temporalWindowMinutes,
  onChangeTemporalWindow,
  onViewTimelineForFinding,
}) => {
  return (
    <div className="flex-1 flex flex-col h-full overflow-y-auto p-8 transition-colors duration-150 bg-slate-50 text-slate-900 dark:bg-[#0c1017] dark:text-slate-100">
      <div className="max-w-4xl mx-auto w-full space-y-6">
        {/* Header & Correlation Window Configuration */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
              CASE EVIDENCE BOARD
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100 mt-0.5">
              Correlated Findings
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Cross-artifact sequences and anomalies flagged for manual investigator attention.
            </p>
          </div>

          {/* Temporal Window Config */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs font-mono bg-white border-slate-300 dark:bg-[#121824] dark:border-slate-800">
            <Sliders className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500 text-[11px] uppercase">Temporal Window:</span>
            <div className="flex items-center gap-1">
              {[3, 5, 10, 15].map((mins) => (
                <button
                  key={mins}
                  onClick={() => onChangeTemporalWindow(mins)}
                  className={`px-2 py-0.5 rounded text-xs transition-colors font-medium ${
                    temporalWindowMinutes === mins
                      ? 'bg-slate-900 text-white font-bold dark:bg-slate-700 dark:text-slate-100'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                  }`}
                >
                  {mins}m
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Section 50: Minimal Investigation Risk Score Visual */}
        <div className="relative overflow-hidden rounded-lg border transition-colors bg-white border-slate-200 shadow-xs dark:bg-[#111722] dark:border-slate-800">
          {/* Subtle Top Yellow Evidence Strip */}
          <div className="h-1.5 w-full evidence-tape-diagonal"></div>

          <div className="p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
                  TRIAGE ASSESSMENT
                </span>
                <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-700 dark:text-slate-300 mt-0.5">
                  INVESTIGATION RISK
                </h2>
                <div className="mt-1 flex items-baseline gap-3">
                  <span className="text-3xl font-black font-mono tracking-tight text-slate-900 dark:text-yellow-400">
                    {caseRiskSummary.score} / 100
                  </span>
                  <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800">
                    {caseRiskSummary.level}
                  </span>
                </div>
              </div>

              <div className="text-right text-[11px] font-mono text-slate-500">
                Rule-Based Weighted Heuristic
              </div>
            </div>

            {/* Contributing Indicators Checklist */}
            <div className="space-y-2">
              <div className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                Contributing Indicators (Why this score?):
              </div>
              <div className="space-y-1.5 p-3 rounded border font-mono text-xs bg-slate-50 border-slate-200 dark:bg-[#090d15] dark:border-slate-800">
                {caseRiskSummary.indicators.map((ind) => (
                  <div
                    key={ind.id}
                    className="flex items-center justify-between text-slate-700 dark:text-slate-300"
                  >
                    <span>
                      <strong className="text-yellow-600 dark:text-yellow-400 font-bold">
                        +{ind.points}
                      </strong>{' '}
                      {ind.name}
                    </span>
                    <span className="text-slate-400 text-[11px]">{ind.points} pts</span>
                  </div>
                ))}
                <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between font-bold text-slate-900 dark:text-slate-100">
                  <span>TOTAL SCORE</span>
                  <span className="text-yellow-600 dark:text-yellow-400">
                    {caseRiskSummary.score}
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-slate-500 font-sans leading-relaxed pt-1">
                * Note: The score is a triage prioritization metric to assist investigator focus, not a probability or confirmation of malware.
              </p>
            </div>
          </div>
        </div>

        {/* Section 39: Evidence Board Finding Cards */}
        {findings.length === 0 ? (
          <div className="p-12 text-center border border-dashed rounded-lg bg-white border-slate-300 dark:bg-[#111722] dark:border-slate-800">
            <CheckCircle2 className="w-10 h-10 text-emerald-600 dark:text-emerald-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
              No anomalous sequences identified
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              No AppData execution or download-to-execution chains were observed within the {temporalWindowMinutes}-minute window.
            </p>
          </div>
        ) : (
          <div className="space-y-5">
            <div className="text-xs font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-2 font-semibold">
              <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
              <span>Correlated Evidence Items ({findings.length})</span>
            </div>

            {findings.map((finding, idx) => (
              <div
                key={finding.correlation_id}
                className="relative overflow-hidden rounded-lg border transition-all hover:shadow-md bg-white border-slate-200 dark:bg-[#111722] dark:border-slate-800 dark:hover:border-slate-700"
              >
                {/* Yellow evidence-strip accent on top edge */}
                <div className="h-1 w-full evidence-tape-diagonal"></div>

                <div className="p-5 space-y-4">
                  {/* Header Row: Finding ID & Title */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded border bg-yellow-50 text-yellow-900 border-yellow-300 dark:bg-yellow-950/50 dark:text-yellow-300 dark:border-yellow-800">
                          FINDING FND-00{idx + 1}
                        </span>
                        <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                          {finding.title}
                        </h2>
                      </div>

                      <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400 mt-2">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>{finding.startTime}</span>
                        <ArrowRight className="w-3 h-3 text-slate-400" />
                        <span>{finding.endTime}</span>
                        <span>·</span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          {finding.eventsCount} events
                        </span>
                        <span>·</span>
                        <span>Correlation: {finding.correlation_id}</span>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="font-mono font-black text-lg text-slate-900 dark:text-yellow-400">
                        {finding.riskScore} / 100
                      </div>
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800">
                        {finding.priority}
                      </span>
                    </div>
                  </div>

                  {/* Reasons / Observed Indicators */}
                  <div className="space-y-1.5 pt-1">
                    <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
                      Observed Sequence Indicators:
                    </div>
                    {finding.reasons.map((reason, rIdx) => (
                      <div
                        key={rIdx}
                        className="flex items-center gap-2 text-xs text-slate-800 dark:text-slate-200"
                      >
                        <span className="text-yellow-600 dark:text-yellow-400 font-bold font-mono">
                          ✓
                        </span>
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>

                  {/* Related Evidence Event Tags */}
                  <div className="pt-2">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold block mb-1.5">
                      Related Evidence Records:
                    </span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {finding.eventIds.map((eventId) => (
                        <span
                          key={eventId}
                          className="text-xs font-mono px-2 py-0.5 rounded border font-semibold bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900 dark:text-slate-300 dark:border-slate-800"
                        >
                          {eventId}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Card Action Row */}
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
                    <span className="text-[11px] text-slate-500 font-sans">
                      Inspect chain on chronological incident timeline.
                    </span>
                    <button
                      onClick={() => onViewTimelineForFinding(finding.correlation_id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold transition-colors bg-yellow-500 hover:bg-yellow-400 text-slate-950 shadow-xs cursor-pointer"
                    >
                      <span>VIEW TIMELINE</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
