/**
 * RapidTriage - Event Detail Panel (Right Docked)
 * Clean, technical forensic inspection.
 * Fully supports Light & Dark themes.
 */

import React, { useState } from 'react';
import { X, Link2, Copy, Check, FileCode, Tag } from 'lucide-react';
import { StandardizedEvent } from '../types/forensics';

interface EventDetailPanelProps {
  event: StandardizedEvent | null;
  onClose: () => void;
  onViewRelatedEvents: (correlationId: string) => void;
}

export const EventDetailPanel: React.FC<EventDetailPanelProps> = ({
  event,
  onClose,
  onViewRelatedEvents,
}) => {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  if (!event) return null;

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const getStatusBadge = () => {
    switch (event.risk_status) {
      case 'suspicious':
        return (
          <span className="font-mono text-xs font-bold px-2 py-1 rounded border tracking-wider bg-red-50 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800">
            [POTENTIALLY SUSPICIOUS]
          </span>
        );
      case 'review':
        return (
          <span className="font-mono text-xs font-semibold px-2 py-1 rounded border tracking-wider bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800">
            [REQUIRES REVIEW]
          </span>
        );
      default:
        return (
          <span className="font-mono text-xs px-2 py-1 rounded border tracking-wider bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            [NORMAL]
          </span>
        );
    }
  };

  return (
    <aside className="w-88 xl:w-96 border-l flex flex-col h-full overflow-y-auto shrink-0 select-text z-20 transition-colors duration-150 bg-white border-slate-200 text-slate-900 dark:bg-[#0a0e17] dark:border-slate-800 dark:text-slate-100">
      {/* Panel Header */}
      <div className="p-4 border-b flex items-center justify-between sticky top-0 backdrop-blur-sm z-10 bg-white/95 border-slate-200 dark:bg-[#0a0e17]/95 dark:border-slate-800">
        <div>
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
            FORENSIC RECORD
          </span>
          <h2 className="text-sm font-bold font-mono text-slate-900 dark:text-slate-100">
            {event.event_id}
          </h2>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          title="Close details"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-4 text-xs">
        {/* Status & Reason */}
        <div className="space-y-1.5">
          <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
            STATUS
          </div>
          <div>{getStatusBadge()}</div>

          {event.reason && (
            <div className="mt-2 text-xs p-2.5 rounded border font-sans leading-relaxed bg-red-50 text-red-900 border-red-200 dark:bg-red-950/30 dark:text-red-300 dark:border-red-900/60">
              <span className="font-semibold block text-[10px] uppercase font-mono tracking-wider mb-0.5 text-red-700 dark:text-red-400">
                INVESTIGATION REASON
              </span>
              {event.reason}
            </div>
          )}
        </div>

        {/* Correlation Group Banner */}
        {event.correlation_id && (
          <div className="p-3 rounded-md border space-y-2 bg-amber-50/60 border-amber-200 dark:bg-slate-900/80 dark:border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-600 dark:text-slate-400">
                Correlation Sequence
              </span>
              <span className="text-xs font-mono font-bold text-amber-700 dark:text-amber-400">
                {event.correlation_id}
              </span>
            </div>
            <button
              onClick={() => onViewRelatedEvents(event.correlation_id!)}
              className="w-full flex items-center justify-center gap-1.5 py-1.5 px-3 rounded text-xs font-semibold transition-colors bg-yellow-500 hover:bg-yellow-400 text-slate-950 shadow-xs"
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>View Related Events</span>
            </button>
          </div>
        )}

        {/* Primary Forensic Fields */}
        <div className="space-y-3 pt-1">
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              TIMESTAMP
            </div>
            <div className="font-mono text-slate-900 dark:text-slate-200 mt-0.5 font-medium">
              {event.timestamp}
            </div>
            {event.raw_timestamp && (
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                Raw: {event.raw_timestamp}
              </div>
            )}
          </div>

          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              ARTIFACT & EVENT TYPE
            </div>
            <div className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 font-medium uppercase">
              [{event.artifact}] · {event.event_type}
            </div>
          </div>

          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              EVIDENCE SOURCE
            </div>
            <div className="font-mono text-slate-700 dark:text-slate-300 mt-0.5 break-all">
              {event.source}
            </div>
          </div>

          {event.process && (
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                PROCESS
              </div>
              <div className="font-mono text-slate-900 dark:text-slate-200 mt-0.5 font-semibold">
                {event.process} {event.pid ? `(PID ${event.pid})` : ''}
              </div>
            </div>
          )}

          {event.path && (
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold flex items-center justify-between">
                <span>FILE PATH</span>
                <button
                  onClick={() => copyToClipboard(event.path!, 'path')}
                  className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-[10px] flex items-center gap-1 font-mono"
                >
                  {copiedField === 'path' ? (
                    <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>{copiedField === 'path' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="font-mono text-slate-800 dark:text-slate-300 mt-0.5 p-2 rounded border text-[11px] break-all bg-slate-50 border-slate-200 dark:bg-slate-900/60 dark:border-slate-800">
                {event.path}
              </div>
            </div>
          )}

          {event.url && (
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold flex items-center justify-between">
                <span>URL ADDRESS</span>
                <button
                  onClick={() => copyToClipboard(event.url!, 'url')}
                  className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-[10px] flex items-center gap-1 font-mono"
                >
                  {copiedField === 'url' ? (
                    <Check className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>{copiedField === 'url' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="font-mono text-slate-800 dark:text-slate-300 mt-0.5 p-2 rounded border text-[11px] break-all bg-slate-50 border-slate-200 dark:bg-slate-900/60 dark:border-slate-800">
                {event.url}
              </div>
            </div>
          )}

          {event.device && (
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                USB STORAGE DEVICE
              </div>
              <div className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 font-medium">
                {event.device}
              </div>
              {event.serial && (
                <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                  Serial: {event.serial}
                </div>
              )}
            </div>
          )}

          {(event.local_address || event.remote_address) && (
            <div className="space-y-1">
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                NETWORK SOCKETS
              </div>
              {event.local_address && (
                <div className="font-mono text-slate-700 dark:text-slate-300 text-[11px]">
                  <span className="text-slate-500">Local: </span>
                  {event.local_address}
                </div>
              )}
              {event.remote_address && (
                <div className="font-mono text-slate-700 dark:text-slate-300 text-[11px]">
                  <span className="text-slate-500">Remote: </span>
                  {event.remote_address}
                </div>
              )}
            </div>
          )}

          {event.user && (
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
                SECURITY CONTEXT
              </div>
              <div className="font-mono text-slate-700 dark:text-slate-300 mt-0.5">
                {event.user}
              </div>
            </div>
          )}

          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase font-semibold">
              DESCRIPTION
            </div>
            <div className="text-slate-700 dark:text-slate-300 mt-0.5 leading-relaxed font-sans">
              {event.description}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
